// SPDX-License-Identifier: Apache-2.0
//! Signed policies and rule auto-approval.
//!
//! A policy is accepted only when signed by an active trusted owner/member device
//! (`aipass:v1:policy:<digest>`). `auto_approve` is honoured only for `rule` mode on a
//! `test` resource whose operations are all read-only — checked when the policy is
//! stored **and** again on every use (the resource environment may change later).
//! A rule grant lasts `grant_ttl_seconds` with the policy's limits; at most one rule grant
//! is created per policy per TTL window, so a rule's budget cannot be refreshed by
//! exhausting grants (A08).

use std::collections::BTreeSet;

use aipass_crypto::SealedBox;
use aipass_types::approval::{self, MAX_TASK_TTL_SECS};
use aipass_types::error::{ApiError, ErrorCode};
use aipass_types::exec::{DelegationAad, NormalizedRequest};
use aipass_types::ids::{DeviceId, GrantId, PolicyId};
use aipass_types::models::{
    AppConnection, ApprovalMode, ConnectionStatus, DelegateCredentialRequest, Grant, GrantStatus,
    GrantUsage, PoliciesResponse, Policy, PolicyStatus, Resource, RevocationLevel, SideEffectClass,
};
use aipass_types::policy::{auto_approve_allowed, policy_digest, verify_policy};
use rusqlite::params;
use serde_json::json;

use super::{Broker, ExecutorSlot};
use super::operations::scope_allows;
use crate::audit::{self, Audit};
use crate::db::{dec, enc, i, unix};
use crate::principal::Actor;
use crate::store::{self, CredState, GrantRow};
use crate::types::DelegateResponse;

impl Broker {
    /// Whether every operation named by the policy is read-only at this executor.
    fn policy_read_only(&self, slot: &ExecutorSlot, resource: &Resource, p: &Policy) -> bool {
        let specs = self.specs_for(slot, resource.connector.as_str());
        let ops: BTreeSet<&String> = p.scope.operations.iter().chain(p.allowed_operations.iter()).collect();
        !ops.is_empty()
            && ops.iter().all(|op| {
                specs
                    .iter()
                    .find(|s| &&s.name == op)
                    .is_some_and(|s| s.side_effect == SideEffectClass::Read)
            })
    }

    /// `GET /v1/policies`.
    pub async fn list_policies(&self) -> Result<PoliciesResponse, ApiError> {
        let rows = self.db.call(|c| store::list_policies(c)).await?;
        Ok(PoliciesResponse {
            policies: rows.iter().map(store::PolicyRow::view).collect(),
        })
    }

    /// `POST /v1/policies` — store a device-signed policy (new id or higher version).
    pub async fn create_policy(&self, actor: &Actor, policy: Policy) -> Result<Policy, ApiError> {
        if policy.status != PolicyStatus::Active {
            return Err(ApiError::invalid_request("只能提交启用状态的策略", "Only active policies can be submitted."));
        }
        let signer = policy.signed_by.clone();
        let device = self
            .db
            .call(move |c| store::get_device(c, &signer))
            .await?
            .filter(|d| d.is_active_approver())
            .ok_or_else(|| ApiError::identity_unverified().with_message("策略签名设备不是有效的可信设备", "The policy signer is not an active trusted device."))?;
        verify_policy(&policy, &device.device.sign_pk).map_err(|_| ApiError::integrity_failed().with_detail("reason", "policy signature"))?;

        let rid = policy.resource_id.clone();
        let res_row = self
            .db
            .call(move |c| store::get_resource(c, &rid))
            .await?
            .ok_or_else(|| ApiError::invalid_request("资源不存在", "unknown resource").with_detail("field", "resource_id"))?;
        let resource = res_row.resource;
        if policy.project_id != resource.project_id || policy.executor_id != resource.executor_id {
            return Err(ApiError::invalid_request("策略的项目或执行设备与资源不一致", "Policy project/executor does not match the resource."));
        }
        let cid = policy.subject_connection_id.clone();
        let conn = self
            .db
            .call(move |c| store::get_connection(c, &cid))
            .await?
            .filter(|r| r.conn.status != ConnectionStatus::Removed)
            .ok_or_else(|| ApiError::invalid_request("连接不存在", "unknown connection").with_detail("field", "subject_connection_id"))?;
        let _ = conn;
        if policy.scope.operations.is_empty()
            || policy
                .scope
                .operations
                .iter()
                .chain(policy.allowed_operations.iter())
                .any(|o| !resource.operations.contains(o))
        {
            return Err(ApiError::invalid_request("策略中的操作不属于该资源", "Policy operations must be offered by the resource.").with_detail("field", "scope"));
        }
        if policy.grant_ttl_seconds == 0 || policy.grant_ttl_seconds > MAX_TASK_TTL_SECS {
            return Err(ApiError::invalid_request("grant_ttl_seconds 必须在 1 到 86400 之间", "grant_ttl_seconds must be between 1 and 86400").with_detail("field", "grant_ttl_seconds"));
        }
        if !policy.limits.within(&self.cfg.max_limits) {
            return Err(ApiError::invalid_request("策略额度超出允许范围", "Policy limits exceed what this broker allows").with_detail("field", "limits"));
        }
        if !policy.output_recipients.contains(&policy.subject_connection_id) {
            return Err(ApiError::invalid_request("结果接收方必须包含该连接", "output_recipients must include the subject connection").with_detail("field", "output_recipients"));
        }
        if policy.auto_approve {
            let slot = self
                .executor_slot(&resource.executor_id)
                .ok_or_else(|| ApiError::new(ErrorCode::ExecutorOffline))?;
            let ro = self.policy_read_only(&slot, &resource, &policy);
            if !auto_approve_allowed(&policy, resource.environment, ro) {
                return Err(ApiError::invalid_request(
                    "自动批准只适用于测试环境中只读操作的持续规则",
                    "auto_approve is only allowed for rule-mode policies on test resources with read-only operations.",
                )
                .with_detail("field", "auto_approve"));
            }
        }
        let now = self.now();
        let digest = policy_digest(&policy)?;
        let (p2, act) = (policy.clone(), actor.audit_name());
        let old_version = self
            .db
            .call(move |c| {
                let tx = c.transaction()?;
                let existing = store::get_policy(&tx, &p2.policy_id)?;
                if let Some(e) = &existing
                    && p2.version <= e.signed.version {
                        return Err(ApiError::invalid_request("策略版本必须递增", "Policy version must increase.").with_detail("field", "version").into());
                    }
                store::upsert_policy(&tx, &p2, &now)?;
                audit::append(
                    &tx,
                    now,
                    Audit::new(act, "policy.created").resource(&p2.resource_id).detail(json!({
                        "policy_id": p2.policy_id.as_str(),
                        "version": p2.version,
                        "digest": digest,
                        "auto_approve": p2.auto_approve,
                        "signed_by": p2.signed_by.as_str(),
                    })),
                )?;
                tx.commit()?;
                Ok(existing.map(|e| e.signed.version))
            })
            .await?;
        if old_version.is_some() {
            self.revoke_policy_grants(actor, &policy.policy_id, Some(policy.version)).await?;
        }
        Ok(policy)
    }

    /// `POST /v1/policies/{id}/disable` (no signature needed: it only removes permission).
    pub async fn disable_policy(&self, actor: &Actor, id: &PolicyId) -> Result<Policy, ApiError> {
        let now = self.now();
        let (pid, act) = (id.clone(), actor.audit_name());
        let row = self
            .db
            .call(move |c| {
                let tx = c.transaction()?;
                let row = store::get_policy(&tx, &pid)?.ok_or_else(ApiError::not_found)?;
                tx.execute(
                    "UPDATE policies SET disabled_at = COALESCE(disabled_at, ?2) WHERE policy_id = ?1",
                    params![pid.as_str(), unix(&now)],
                )?;
                audit::append(&tx, now, Audit::new(act, "policy.disabled").resource(&row.signed.resource_id).detail(json!({ "policy_id": pid.as_str() })))?;
                tx.commit()?;
                Ok(store::PolicyRow {
                    signed: row.signed,
                    disabled: true,
                })
            })
            .await?;
        self.revoke_policy_grants(actor, id, None).await?;
        Ok(row.view())
    }

    async fn revoke_policy_grants(&self, actor: &Actor, id: &PolicyId, keep_version: Option<u64>) -> Result<(), ApiError> {
        let pid = id.clone();
        let grants = self
            .db
            .call(move |c| store::query_grants(c, "policy_id = ?1 AND status IN ('active', 'exhausted')", &[&pid.as_str()]))
            .await?;
        let ids = grants
            .into_iter()
            .filter(|g| keep_version.is_none() || g.grant.policy_version != keep_version)
            .map(|g| g.grant.grant_id)
            .collect();
        self.revoke_grants(actor, ids, RevocationLevel::EndSessions).await?;
        Ok(())
    }

    /// Rule auto-approval for one request (§6.2 rule 5, second branch).
    pub(crate) async fn try_auto_approve(
        &self,
        conn: &AppConnection,
        resource: &Resource,
        slot: &ExecutorSlot,
        n: &NormalizedRequest,
    ) -> Result<Option<GrantRow>, ApiError> {
        let (cid, rid) = (conn.connection_id.clone(), resource.resource_id.clone());
        let rows = self.db.call(move |c| store::policies_for(c, &cid, &rid)).await?;
        let now = self.now();
        for row in rows.into_iter().filter(store::PolicyRow::is_active) {
            let p = row.signed;
            if p.executor_id != resource.executor_id || p.project_id != resource.project_id || p.approval_mode != ApprovalMode::Rule {
                continue;
            }
            if !p.output_recipients.contains(&conn.connection_id) {
                continue;
            }
            // Re-verify the signature and the signer's standing on every use.
            let signer = p.signed_by.clone();
            let Some(dev) = self.db.call(move |c| store::get_device(c, &signer)).await? else {
                continue;
            };
            if !dev.is_active_approver() || verify_policy(&p, &dev.device.sign_pk).is_err() {
                continue;
            }
            if !auto_approve_allowed(&p, resource.environment, self.policy_read_only(slot, resource, &p)) {
                continue;
            }
            if !scope_allows(&p.scope, n) || !slot.backend.scope_covers(&p.scope, &p.limits, n) {
                continue;
            }
            let ttl = p.grant_ttl_seconds.min(MAX_TASK_TTL_SECS);
            let window_start = aipass_types::time::add_secs(&now, -(ttl as i64));
            let digest = policy_digest(&p)?;
            let grant = GrantRow {
                grant: Grant {
                    grant_id: GrantId::generate(),
                    approval_request_id: None,
                    policy_id: Some(p.policy_id.clone()),
                    policy_version: Some(p.version),
                    connection_id: conn.connection_id.clone(),
                    resource_id: resource.resource_id.clone(),
                    executor_id: resource.executor_id.clone(),
                    scope: approval::normalize_scope(&p.scope),
                    limits: p.limits,
                    mode: ApprovalMode::Rule,
                    digest: digest.clone(),
                    status: GrantStatus::Active,
                    usage: GrantUsage::default(),
                    created_at: now,
                    expires_at: aipass_types::time::add_secs(&now, ttl as i64),
                    revoked_at: None,
                    revocation: None,
                },
                reserved_rows: 0,
                cred: CredState::None,
                approved_by: Some(p.signed_by.as_str().to_owned()),
                bound_operation: None,
            };
            let (g2, p2) = (grant.clone(), p.clone());
            let created = self
                .db
                .call(move |c| {
                    let tx = c.transaction()?;
                    let recent: i64 = tx.query_row(
                        "SELECT COUNT(*) FROM grants WHERE policy_id = ?1 AND policy_version = ?2 AND created_at > ?3",
                        params![p2.policy_id.as_str(), i(p2.version), unix(&window_start)],
                        |r| r.get(0),
                    )?;
                    if recent > 0 {
                        return Ok(false);
                    }
                    store::insert_grant(&tx, &g2)?;
                    audit::append(
                        &tx,
                        now,
                        Audit::new(p2.signed_by.as_str(), "rule.auto_approved")
                            .resource(&g2.grant.resource_id)
                            .grant(&g2.grant.grant_id)
                            .detail(json!({
                                "policy_id": p2.policy_id.as_str(),
                                "policy_version": p2.version,
                                "digest": g2.grant.digest,
                                "connection_id": g2.grant.connection_id.as_str(),
                            })),
                    )?;
                    tx.commit()?;
                    Ok(true)
                })
                .await?;
            if !created {
                continue;
            }
            self.install_rule_credential(&grant, resource, &p, &digest).await;
            return Ok(Some(grant));
        }
        Ok(None)
    }

    async fn install_rule_credential(&self, grant: &GrantRow, resource: &Resource, p: &Policy, digest: &str) {
        let (pid, ver) = (p.policy_id.clone(), p.version);
        let delegated: Option<SealedBox> = self
            .db
            .call(move |c| {
                let e: Option<String> = rusqlite::OptionalExtension::optional(c.query_row(
                    "SELECT envelope FROM policy_credentials WHERE policy_id = ?1 AND policy_version = ?2",
                    params![pid.as_str(), i(ver)],
                    |r| r.get(0),
                ))?;
                e.map(|s| dec::<SealedBox>(&s)).transpose()
            })
            .await
            .ok()
            .flatten();
        if let (Some(env), Some(src)) = (delegated, self.credential_source())
            && self.cfg.experimental && src.supports_delegation() {
                let aad = DelegationAad {
                    policy_id: p.policy_id.clone(),
                    policy_digest: digest.to_owned(),
                    executor_id: grant.grant.executor_id.clone(),
                };
                let ok = src.install_delegated(&grant.grant.grant_id, &env, &aad).await.is_ok();
                let gid = grant.grant.grant_id.clone();
                let st = if ok { CredState::Installed } else { CredState::Failed };
                let _ = self.db.call(move |c| store::set_cred_state(c, &gid, st)).await;
                if ok {
                    return;
                }
            }
        self.install_credential_for(grant, resource, None).await;
    }

    /// `POST /v1/credentials/delegate` (experimental V1.1, off by default): store a
    /// credential envelope sealed to the executor with [`DelegationAad`] for an
    /// auto-approve rule. Requires `experimental` and a [`crate::CredentialSource`] that
    /// supports delegation; otherwise `NOT_SUPPORTED`.
    pub async fn delegate_credential(&self, device: &DeviceId, req: DelegateCredentialRequest) -> Result<DelegateResponse, ApiError> {
        let supported = self.cfg.experimental && self.credential_source().is_some_and(|s| s.supports_delegation());
        if !supported {
            return Err(ApiError::new(ErrorCode::NotSupported).with_message(
                "无人值守委托是实验性功能，当前执行设备未启用",
                "Unattended delegation is experimental and not enabled on this executor.",
            ));
        }
        let pid = req.policy_id.clone();
        let row = self
            .db
            .call(move |c| store::get_policy(c, &pid))
            .await?
            .ok_or_else(ApiError::not_found)?;
        if !row.is_active() || !row.signed.auto_approve {
            return Err(ApiError::invalid_request("只能为启用的自动批准规则委托凭证", "Credentials can only be delegated to active auto-approve rules."));
        }
        let now = self.now();
        let (p, dev, env) = (row.signed.clone(), device.clone(), req.credential_envelope.clone());
        self.db
            .call(move |c| {
                let tx = c.transaction()?;
                tx.execute(
                    "INSERT INTO policy_credentials (policy_id, policy_version, envelope, delegated_by, created_at) VALUES (?1, ?2, ?3, ?4, ?5)
                     ON CONFLICT(policy_id, policy_version) DO UPDATE SET envelope = excluded.envelope, delegated_by = excluded.delegated_by, created_at = excluded.created_at",
                    params![p.policy_id.as_str(), i(p.version), enc(&env)?, dev.as_str(), unix(&now)],
                )?;
                audit::append(
                    &tx,
                    now,
                    Audit::new(dev.as_str(), "credential.delegated").resource(&p.resource_id).detail(json!({
                        "policy_id": p.policy_id.as_str(),
                        "policy_version": p.version,
                        "experimental": true,
                    })),
                )?;
                tx.commit()?;
                Ok(())
            })
            .await?;
        Ok(DelegateResponse {
            policy_id: row.signed.policy_id,
            policy_version: row.signed.version,
            status: "stored".into(),
        })
    }
}
