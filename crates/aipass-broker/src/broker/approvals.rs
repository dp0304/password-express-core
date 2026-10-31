// SPDX-License-Identifier: Apache-2.0
//! Approval requests and signed decisions (CONTRACTS §7).
//!
//! A decision is accepted only when: the signer is an active trusted owner/member
//! device; the request is still pending and inside its window (an expired request is
//! **never** approved — A10); the digest recomputed from the stored request matches; the
//! Ed25519 signature verifies; `approved ⊆ requested`; and
//! `expires_at ≤ now + requested.duration_seconds + 60`. Anything else is rejected and
//! audited (A05).

use std::collections::BTreeSet;
use std::sync::Arc;

use aipass_types::approval::{self, ACCESS_APPROVAL_TTL_SECS, DEFAULT_TASK_TTL_SECS, MAX_TASK_TTL_SECS};
use aipass_types::error::{ApiError, ErrorCode, Lang};
use aipass_types::exec::CredentialAad;
use aipass_types::ids::{ApprovalRequestId, ConnectionId, GrantId, OperationId, ResourceId};
use aipass_types::models::{
    AccessRequest, AccessRequestResponse, AccessSpec, ApprovalConnection, ApprovalDecision,
    ApprovalExecutor, ApprovalKind, ApprovalMode, ApprovalRequest, ApprovalResource,
    ApprovalStatus, ApprovalsResponse, Connector, Decision, DecisionResponse, Grant, GrantScope, GrantStatus,
    GrantUsage, HttpApiScope, Limits, OperationResponse, OperationStatus, Recipient, ResourceStatus,
};
use rusqlite::params;
use serde_json::json;

use super::Broker;
use super::operations::{RunPlan, check_throttle, scope_allows};
use crate::audit::{self, Audit};
use crate::db::{enum_str, unix};
use crate::notify::BrokerEvent;
use crate::principal::ConnectionPrincipal;
use crate::store::{self, CredState, GrantRow, OpUpdate, StoredError};
use crate::summary::{OpLabel, SummaryInput, approval_summary, excluded_fields};

fn limits_within_max(l: &Limits, max: &Limits) -> bool {
    l.within(max)
        && l.max_rows_per_operation > 0
        && l.max_rows_per_grant > 0
        && l.max_requests_per_grant > 0
        && l.max_result_bytes > 0
}

impl Broker {
    // ------------------------------------------------------------- listing

    /// `GET /v1/approvals?status=` (default `pending`). Expired requests are expired
    /// before listing so a stale request is never shown as approvable.
    pub async fn list_approvals(&self, status: Option<ApprovalStatus>) -> Result<ApprovalsResponse, ApiError> {
        self.expire_due_approvals().await?;
        let rows = self.db.call(move |c| store::list_approvals(c, status)).await?;
        Ok(ApprovalsResponse {
            approvals: rows.into_iter().map(|r| r.req).collect(),
        })
    }

    /// One approval request (trusted clients).
    pub async fn get_approval(&self, id: &ApprovalRequestId) -> Result<ApprovalRequest, ApiError> {
        self.expire_if_due(id).await?;
        let id = id.clone();
        self.db
            .call(move |c| Ok(store::get_approval(c, &id)?.map(|r| r.req)))
            .await?
            .ok_or_else(ApiError::not_found)
    }

    // ------------------------------------------------------------- expiry

    async fn expire_if_due(&self, id: &ApprovalRequestId) -> Result<(), ApiError> {
        let id2 = id.clone();
        let row = self.db.call(move |c| store::get_approval(c, &id2)).await?;
        if let Some(r) = row
            && r.req.status == ApprovalStatus::Pending && self.now() >= r.req.expires_at {
                self.expire_approval(id).await?;
            }
        Ok(())
    }

    /// Expire every pending request past its window. Returns how many expired.
    pub(crate) async fn expire_due_approvals(&self) -> Result<u64, ApiError> {
        let now = self.now();
        let ids = self
            .db
            .call(move |c| {
                let mut stmt = c.prepare("SELECT approval_request_id FROM approvals WHERE status = 'pending' AND expires_at <= ?1")?;
                let rows = stmt.query_map(params![unix(&now)], |r| r.get::<_, String>(0))?;
                let mut out = Vec::new();
                for r in rows {
                    out.push(ApprovalRequestId::parse(&r?)?);
                }
                Ok(out)
            })
            .await?;
        let mut n = 0;
        for id in ids {
            if self.expire_approval(&id).await? {
                n += 1;
            }
        }
        Ok(n)
    }

    /// `pending → expired` for one request; its waiting operation becomes `expired`
    /// with `APPROVAL_EXPIRED`. Never approves.
    pub(crate) async fn expire_approval(&self, id: &ApprovalRequestId) -> Result<bool, ApiError> {
        let now = self.now();
        let id2 = id.clone();
        let changed = self
            .db
            .call(move |c| {
                let tx = c.transaction()?;
                let Some(row) = store::get_approval(&tx, &id2)? else {
                    return Ok(None);
                };
                if !store::resolve_approval(&tx, &id2, ApprovalStatus::Expired, &now, Some("system"), None)? {
                    return Ok(None);
                }
                if let Some(op) = &row.req.operation_id {
                    let e = StoredError::from_api(&ApiError::new(ErrorCode::ApprovalExpired));
                    store::transition(
                        &tx,
                        op,
                        &[OperationStatus::AwaitingApproval],
                        OperationStatus::Expired,
                        &now,
                        OpUpdate {
                            error: Some(&e),
                            ..Default::default()
                        },
                    )?;
                }
                let mut a = Audit::new("system", "approval.expired")
                    .resource(&row.req.resource.resource_id)
                    .outcome("expired")
                    .detail(json!({ "approval_request_id": id2.as_str() }));
                if let Some(op) = &row.req.operation_id {
                    a = a.operation(op);
                }
                a.error_code = Some(ErrorCode::ApprovalExpired);
                audit::append(&tx, now, a)?;
                tx.commit()?;
                Ok(Some(row.req))
            })
            .await?;
        let Some(req) = changed else {
            return Ok(false);
        };
        if let Some(op) = &req.operation_id {
            self.emit(BrokerEvent::OperationUpdated {
                operation_id: op.clone(),
                connection_id: req.connection.connection_id.clone(),
                status: OperationStatus::Expired,
            });
        }
        self.approval_gone(id, ApprovalStatus::Expired, "expired", None).await;
        Ok(true)
    }

    /// Cancel pending approvals (and their waiting operations) of a connection.
    pub(crate) async fn cancel_pending_approvals_for_connection(&self, conn: &ConnectionId, reason: &str) {
        let v = conn.as_str().to_owned();
        if let Ok(ids) = self.db.call(move |c| store::pending_approval_ids(c, "connection_id", &v)).await {
            for id in ids {
                let _ = self.cancel_approval(&id, reason).await;
            }
        }
    }

    /// Cancel pending approvals of a resource.
    pub(crate) async fn cancel_pending_approvals_for_resource(&self, res: &ResourceId, reason: &str) {
        let v = res.as_str().to_owned();
        if let Ok(ids) = self.db.call(move |c| store::pending_approval_ids(c, "resource_id", &v)).await {
            for id in ids {
                let _ = self.cancel_approval(&id, reason).await;
            }
        }
    }

    async fn cancel_approval(&self, id: &ApprovalRequestId, reason: &str) -> Result<bool, ApiError> {
        let now = self.now();
        let (id2, reason2) = (id.clone(), reason.to_owned());
        let changed = self
            .db
            .call(move |c| {
                let tx = c.transaction()?;
                let Some(row) = store::get_approval(&tx, &id2)? else {
                    return Ok(false);
                };
                if !store::resolve_approval(&tx, &id2, ApprovalStatus::Cancelled, &now, Some("system"), None)? {
                    return Ok(false);
                }
                if let Some(op) = &row.req.operation_id {
                    store::transition(&tx, op, &[OperationStatus::AwaitingApproval], OperationStatus::Cancelled, &now, OpUpdate::default())?;
                }
                audit::append(
                    &tx,
                    now,
                    Audit::new("system", "approval.cancelled")
                        .resource(&row.req.resource.resource_id)
                        .outcome("cancelled")
                        .detail(json!({ "approval_request_id": id2.as_str(), "reason": reason2 })),
                )?;
                tx.commit()?;
                Ok(true)
            })
            .await?;
        if changed {
            self.approval_gone(id, ApprovalStatus::Cancelled, reason, None).await;
        }
        Ok(changed)
    }

    // ------------------------------------------------------------- decisions

    /// `POST /v1/approvals/{id}/decision` and relay `approval.decision`. The decision must
    /// carry a valid device signature regardless of who relays it. On approval the
    /// credential envelope is installed at the executor and a waiting operation is
    /// resumed and run (the response waits up to `decision_wait`, without result data).
    pub async fn submit_decision(self: &Arc<Self>, decision: ApprovalDecision) -> Result<DecisionResponse, ApiError> {
        let result = self.submit_decision_inner(&decision).await;
        if let Err(e) = &result {
            self.audit(
                Audit::new(decision.signer_device_id.as_str(), "approval.decision_rejected")
                    .error(e.code)
                    .outcome("rejected")
                    .detail(json!({
                        "approval_request_id": decision.approval_request_id.as_str(),
                        "decision": enum_str(&decision.decision),
                    })),
            )
            .await;
        }
        result
    }

    async fn submit_decision_inner(self: &Arc<Self>, decision: &ApprovalDecision) -> Result<DecisionResponse, ApiError> {
        let id = decision.approval_request_id.clone();
        self.expire_if_due(&id).await?;
        let id2 = id.clone();
        let row = self
            .db
            .call(move |c| store::get_approval(c, &id2))
            .await?
            .ok_or_else(ApiError::not_found)?;
        let request = row.req;
        let signer_id = decision.signer_device_id.clone();
        let device = self
            .db
            .call(move |c| store::get_device(c, &signer_id))
            .await?
            .filter(|d| d.is_active_approver())
            .ok_or_else(|| {
                ApiError::identity_unverified().with_message("签名设备不是有效的可信设备", "The signing device is not an active trusted device.")
            })?;
        let now = self.now();
        approval::verify_decision(decision, &request, &device.device.sign_pk, &now)?;
        self.check_waiting_operation(&request).await?;
        match decision.decision {
            Decision::Deny => self.apply_denial(&request, decision).await,
            Decision::Approve => self.apply_approval(&request, decision).await,
        }
    }

    /// §7 v2: the digest covered `operation_id` / `parameters_digest` of the stored
    /// request; make sure they still describe the operation that is actually waiting (same
    /// operation, connection, resource, normalized parameters, linked to this request), so
    /// a signature never authorizes parameters the user did not see. `INTEGRITY_FAILED`
    /// otherwise. Access requests carry no binding (checked by `verify_decision`).
    async fn check_waiting_operation(&self, request: &ApprovalRequest) -> Result<(), ApiError> {
        if request.kind != ApprovalKind::Operation {
            return Ok(());
        }
        let mismatch = || ApiError::integrity_failed().with_detail("reason", "operation binding mismatch");
        let (Some(op_id), Some(pd)) = (request.operation_id.clone(), request.parameters_digest.clone()) else {
            return Err(mismatch());
        };
        let row = self.db.call(move |c| store::get_op(c, &op_id)).await?.ok_or_else(mismatch)?;
        let op = &row.op;
        let linked = op.approval_request_id.as_ref() == Some(&request.approval_request_id);
        let normalized_ok = row.normalized.as_ref().is_none_or(|n| n.parameters_digest == pd && n.operation == op.operation);
        if op.parameters_digest != pd
            || !normalized_ok
            || op.connection_id != request.connection.connection_id
            || op.resource_id != request.resource.resource_id
            || !request.requested.operations.iter().all(|o| *o == op.operation)
            || !linked
        {
            return Err(mismatch());
        }
        Ok(())
    }

    async fn apply_denial(&self, request: &ApprovalRequest, decision: &ApprovalDecision) -> Result<DecisionResponse, ApiError> {
        let now = self.now();
        let (req, signer) = (request.clone(), decision.signer_device_id.clone());
        let digest = decision.digest.clone();
        let changed = self
            .db
            .call(move |c| {
                let tx = c.transaction()?;
                if !store::resolve_approval(&tx, &req.approval_request_id, ApprovalStatus::Denied, &now, Some(signer.as_str()), None)? {
                    return Ok(false);
                }
                for op in &req.requested.operations {
                    store::record_denial(&tx, &req.connection.connection_id, &req.resource.resource_id, op, &now)?;
                }
                if let Some(op) = &req.operation_id {
                    let e = StoredError::from_api(&ApiError::new(ErrorCode::ApprovalDenied));
                    store::transition(
                        &tx,
                        op,
                        &[OperationStatus::AwaitingApproval],
                        OperationStatus::Denied,
                        &now,
                        OpUpdate {
                            error: Some(&e),
                            ..Default::default()
                        },
                    )?;
                }
                let mut a = Audit::new(signer.as_str(), "approval.denied")
                    .resource(&req.resource.resource_id)
                    .outcome("denied")
                    .detail(json!({
                        "approval_request_id": req.approval_request_id.as_str(),
                        "digest": digest,
                    }));
                a.error_code = Some(ErrorCode::ApprovalDenied);
                if let Some(op) = &req.operation_id {
                    a = a.operation(op);
                }
                audit::append(&tx, now, a)?;
                tx.commit()?;
                Ok(true)
            })
            .await?;
        if !changed {
            return Err(ApiError::invalid_request("该审批请求已处理", "This approval request was already handled."));
        }
        if let Some(op) = &request.operation_id {
            self.emit(BrokerEvent::OperationUpdated {
                operation_id: op.clone(),
                connection_id: request.connection.connection_id.clone(),
                status: OperationStatus::Denied,
            });
        }
        self.approval_gone(&request.approval_request_id, ApprovalStatus::Denied, "denied", Some(decision.signer_device_id.clone()))
            .await;
        let operation = match &request.operation_id {
            Some(op) => Some(self.operation_summary(op).await?),
            None => None,
        };
        Ok(DecisionResponse {
            status: ApprovalStatus::Denied,
            grant_id: None,
            operation,
        })
    }

    async fn apply_approval(self: &Arc<Self>, request: &ApprovalRequest, decision: &ApprovalDecision) -> Result<DecisionResponse, ApiError> {
        let approved = decision.approved.clone().ok_or_else(|| ApiError::invalid_request("批准缺少 approved 字段", "approve decision without approved scope"))?;
        if approved.mode == ApprovalMode::Rule {
            return Err(ApiError::invalid_request("规则授权需通过签名策略创建", "Standing rules must be created as signed policies."));
        }
        let now = self.now();
        // Effective scope: operations ∩ scope.operations, normalized.
        let ops: BTreeSet<String> = approved.operations.iter().cloned().collect();
        let mut scope = approval::normalize_scope(&approved.scope);
        scope.operations = if scope.operations.is_empty() {
            ops.iter().cloned().collect()
        } else {
            scope.operations.into_iter().filter(|o| ops.contains(o)).collect()
        };
        let grant = GrantRow {
            grant: Grant {
                grant_id: GrantId::generate(),
                approval_request_id: Some(request.approval_request_id.clone()),
                policy_id: None,
                policy_version: None,
                connection_id: request.connection.connection_id.clone(),
                resource_id: request.resource.resource_id.clone(),
                executor_id: request.executor.executor_id.clone(),
                scope,
                limits: approved.limits,
                mode: approved.mode,
                digest: decision.digest.clone(),
                status: GrantStatus::Active,
                usage: GrantUsage::default(),
                created_at: now,
                expires_at: decision.expires_at,
                revoked_at: None,
                revocation: None,
            },
            reserved_rows: 0,
            cred: CredState::None,
            approved_by: Some(decision.signer_device_id.as_str().to_owned()),
            // A `once` approval of a concrete operation covers that operation only: no
            // other request in the same scope (different parameters the user never saw)
            // may consume it, even while the approved one is still being resumed (A05).
            bound_operation: match (&request.kind, approved.mode, &request.operation_id) {
                (ApprovalKind::Operation, ApprovalMode::Once, Some(op)) => Some(op.clone()),
                _ => None,
            },
        };
        let (g2, req2) = (grant.clone(), request.clone());
        let signer = decision.signer_device_id.clone();
        let changed = self
            .db
            .call(move |c| {
                let tx = c.transaction()?;
                if !store::resolve_approval(
                    &tx,
                    &req2.approval_request_id,
                    ApprovalStatus::Approved,
                    &now,
                    Some(signer.as_str()),
                    Some(&g2.grant.grant_id),
                )? {
                    return Ok(false);
                }
                store::insert_grant(&tx, &g2)?;
                let mut a = Audit::new(signer.as_str(), "approval.approved")
                    .resource(&req2.resource.resource_id)
                    .grant(&g2.grant.grant_id)
                    .detail(json!({
                        "approval_request_id": req2.approval_request_id.as_str(),
                        "digest": g2.grant.digest,
                        "mode": enum_str(&g2.grant.mode),
                        "narrowed": approved != req2.requested,
                        "expires_at": aipass_types::time::format_rfc3339(&g2.grant.expires_at),
                    }));
                if let Some(op) = &req2.operation_id {
                    a = a.operation(op);
                }
                audit::append(&tx, now, a)?;
                audit::append(
                    &tx,
                    now,
                    Audit::new(signer.as_str(), "grant.created")
                        .grant(&g2.grant.grant_id)
                        .resource(&g2.grant.resource_id)
                        .detail(json!({
                            "connection_id": g2.grant.connection_id.as_str(),
                            "operations": g2.grant.scope.operations,
                            "limits": serde_json::to_value(g2.grant.limits)?,
                        })),
                )?;
                tx.commit()?;
                Ok(true)
            })
            .await?;
        if !changed {
            return Err(ApiError::invalid_request("该审批请求已处理", "This approval request was already handled."));
        }
        self.emit(BrokerEvent::GrantUpdated {
            grant_id: grant.grant.grant_id.clone(),
            status: GrantStatus::Active,
        });
        self.approval_gone(&request.approval_request_id, ApprovalStatus::Approved, "approved", Some(decision.signer_device_id.clone()))
            .await;

        // Credential: sealed envelope from the approving device, else in-process source.
        let rid = request.resource.resource_id.clone();
        let resource = self.db.call(move |c| store::get_resource(c, &rid)).await?;
        if let Some(res_row) = &resource {
            let envelope = decision.credential_envelope.as_ref().map(|e| {
                (
                    e,
                    CredentialAad {
                        approval_request_id: request.approval_request_id.clone(),
                        digest: decision.digest.clone(),
                        executor_id: request.executor.executor_id.clone(),
                    },
                )
            });
            self.install_credential_for(&grant, &res_row.resource, envelope).await;
        }

        let operation = match &request.operation_id {
            Some(op) => self.resume_operation(op, &grant).await?,
            None => None,
        };
        Ok(DecisionResponse {
            status: ApprovalStatus::Approved,
            grant_id: Some(grant.grant.grant_id),
            operation,
        })
    }

    /// Resume an operation that waited for approval: re-check the new grant covers it,
    /// `awaiting_approval → authorized`, run. Returns its state (no result data — the
    /// result goes only to the requesting connection).
    async fn resume_operation(self: &Arc<Self>, op_id: &OperationId, grant: &GrantRow) -> Result<Option<OperationResponse>, ApiError> {
        let now = self.now();
        let oid = op_id.clone();
        let Some(row) = self.db.call(move |c| store::get_op(c, &oid)).await? else {
            return Ok(None);
        };
        if row.op.status != OperationStatus::AwaitingApproval {
            return Ok(Some(self.operation_summary(op_id).await?));
        }
        let rid = row.op.resource_id.clone();
        let res = self.db.call(move |c| store::get_resource(c, &rid)).await?;
        let slot = res.as_ref().and_then(|r| self.executor_slot(&r.resource.executor_id));
        let normalized = row.normalized.clone();
        let spec = match (&res, &slot) {
            (Some(r), Some(s)) => self.specs_for(s, r.resource.connector.as_str()).into_iter().find(|sp| sp.name == row.op.operation),
            _ => None,
        };
        let (Some(res), Some(slot), Some(normalized), Some(spec)) = (res, slot, normalized, spec) else {
            self.deny_waiting(op_id, ApiError::new(ErrorCode::ExecutorOffline)).await?;
            return Ok(Some(self.operation_summary(op_id).await?));
        };
        if res.entry_conflict || res.resource.status == ResourceStatus::SyncConflict {
            self.deny_waiting(op_id, ApiError::new(ErrorCode::SyncConflict)).await?;
            return Ok(Some(self.operation_summary(op_id).await?));
        }
        if !scope_allows(&grant.grant.scope, &normalized) || !slot.backend.scope_covers(&grant.grant.scope, &grant.remaining(), &normalized) {
            self.deny_waiting(
                op_id,
                ApiError::scope_denied().with_message("批准的范围不包含本次操作", "The approved scope does not cover this operation."),
            )
            .await?;
            return Ok(Some(self.operation_summary(op_id).await?));
        }
        let (oid, gid) = (op_id.clone(), grant.grant.grant_id.clone());
        let cid = row.op.connection_id.clone();
        let moved = self
            .db
            .call(move |c| {
                let tx = c.transaction()?;
                let ok = store::transition(
                    &tx,
                    &oid,
                    &[OperationStatus::AwaitingApproval],
                    OperationStatus::Authorized,
                    &now,
                    OpUpdate {
                        grant_id: Some(&gid),
                        ..Default::default()
                    },
                )?;
                if ok {
                    audit::append(&tx, now, Audit::new(cid.as_str(), "operation.authorized").operation(&oid).grant(&gid))?;
                }
                tx.commit()?;
                Ok(ok)
            })
            .await?;
        if !moved {
            return Ok(Some(self.operation_summary(op_id).await?));
        }
        let handle = self.spawn_run(RunPlan {
            op_id: op_id.clone(),
            connection_id: row.op.connection_id.clone(),
            grant_id: grant.grant.grant_id.clone(),
            resource: res.resource.clone(),
            normalized,
            spec,
            slot,
        });
        let _ = tokio::time::timeout(self.cfg.decision_wait, handle).await;
        Ok(Some(self.operation_summary(op_id).await?))
    }

    async fn deny_waiting(&self, op: &OperationId, e: ApiError) -> Result<(), ApiError> {
        let now = self.now();
        let oid = op.clone();
        self.db
            .call(move |c| {
                let tx = c.transaction()?;
                let stored = StoredError::from_api(&e);
                if store::transition(
                    &tx,
                    &oid,
                    &[OperationStatus::AwaitingApproval],
                    OperationStatus::Denied,
                    &now,
                    OpUpdate {
                        error: Some(&stored),
                        ..Default::default()
                    },
                )? {
                    let mut a = Audit::new("system", "operation.denied").operation(&oid).outcome("denied");
                    a.error_code = Some(e.code);
                    audit::append(&tx, now, a)?;
                }
                tx.commit()?;
                Ok(())
            })
            .await
    }

    /// Operation state for trusted devices — never the result body.
    async fn operation_summary(&self, op: &OperationId) -> Result<OperationResponse, ApiError> {
        let oid = op.clone();
        let row = self
            .db
            .call(move |c| store::get_op(c, &oid))
            .await?
            .ok_or_else(ApiError::not_found)?;
        let mut r = self.op_response(row, Lang::ZhCn).await?;
        r.result = None;
        Ok(r)
    }

    // ------------------------------------------------------------- access.request (C)

    /// `POST /v1/access/requests` — an explicit request for a scope (TTL 600 s). Always
    /// shown to the user; the `reason` is displayed as self-declared and never widens
    /// anything.
    pub async fn request_access(&self, p: &ConnectionPrincipal, req: AccessRequest) -> Result<AccessRequestResponse, ApiError> {
        let conn = self.active_connection(p).await?;
        let row = self.visible_resource(&conn, &req.resource_id).await?;
        let resource = row.resource.clone();
        if row.entry_conflict || resource.status == ResourceStatus::SyncConflict {
            return Err(ApiError::new(ErrorCode::SyncConflict));
        }
        if resource.status == ResourceStatus::Disabled {
            return Err(ApiError::scope_denied().with_message("该资源已停用", "This resource is disabled."));
        }
        let slot = self
            .executor_slot(&resource.executor_id)
            .ok_or_else(|| ApiError::new(ErrorCode::ExecutorOffline))?;
        slot.ready()?;
        let ops: Vec<String> = approval::normalize_operations(&req.operations);
        if ops.is_empty() || ops.len() > 32 {
            return Err(ApiError::invalid_request("operations 需要 1 到 32 项", "operations must have 1 to 32 entries").with_detail("field", "operations"));
        }
        let specs = self.specs_for(&slot, resource.connector.as_str());
        let mut labels = Vec::new();
        for op in &ops {
            let spec = specs.iter().find(|s| &s.name == op).filter(|_| resource.operations.contains(op)).ok_or_else(|| {
                ApiError::scope_denied()
                    .with_message("该资源未提供此操作", "This resource does not offer that operation.")
                    .with_detail("operation", op.clone())
            })?;
            labels.push(OpLabel {
                name: spec.name.clone(),
                zh: spec.description_zh.clone(),
                en: spec.description_en.clone(),
            });
        }
        let mut scope: GrantScope = req.scope.clone().unwrap_or_default();
        scope = approval::normalize_scope(&scope);
        if scope.operations.iter().any(|o| !ops.contains(o)) {
            return Err(ApiError::invalid_request("scope.operations 必须包含于 operations", "scope.operations must be a subset of operations").with_detail("field", "scope"));
        }
        scope.operations = ops.clone();
        // A scope without the connector's section would grant nothing useful; ask for it
        // explicitly (http_api scopes default to the requested operation names).
        match resource.connector {
            Connector::Postgres if scope.postgres.is_none() => {
                return Err(ApiError::invalid_request("请在 scope.postgres 中指定视图和字段", "Specify views and fields in scope.postgres.").with_detail("field", "scope"));
            }
            Connector::Github if scope.github.is_none() => {
                return Err(ApiError::invalid_request("请在 scope.github 中指定仓库", "Specify repositories in scope.github.").with_detail("field", "scope"));
            }
            Connector::HttpApi if scope.http_api.is_none() => {
                scope.http_api = Some(HttpApiScope { operations: ops.clone() });
            }
            _ => {}
        }
        let limits = req.limits.unwrap_or(self.cfg.default_limits);
        if !limits_within_max(&limits, &self.cfg.max_limits) {
            return Err(ApiError::invalid_request("请求的额度超出允许范围", "Requested limits exceed what this broker allows").with_detail("field", "limits"));
        }
        let duration = req.duration_seconds.unwrap_or(DEFAULT_TASK_TTL_SECS);
        if duration == 0 || duration > MAX_TASK_TTL_SECS {
            return Err(ApiError::invalid_request("duration_seconds 必须在 1 到 86400 之间", "duration_seconds must be between 1 and 86400").with_detail("field", "duration_seconds"));
        }
        let requested = AccessSpec {
            operations: ops,
            scope,
            limits,
            duration_seconds: duration,
            mode: ApprovalMode::Task,
        };
        let info = slot.backend.info();
        let excluded = excluded_fields(&resource, &requested.scope);
        let summary = approval_summary(&SummaryInput {
            connection_name: &conn.display_name,
            resource: &resource,
            ops: &labels,
            spec: &requested,
            excluded: &excluded,
            executor_name: &info.name,
            protection: info.protection_level,
            reason: req.reason.as_deref(),
        });
        let now = self.now();
        let apr = ApprovalRequest {
            approval_request_id: ApprovalRequestId::generate(),
            kind: ApprovalKind::Access,
            connection: ApprovalConnection {
                connection_id: conn.connection_id.clone(),
                display_name: conn.display_name.clone(),
                host_type: conn.host_type,
                verified: true,
            },
            resource: ApprovalResource {
                resource_id: resource.resource_id.clone(),
                alias: resource.alias.clone(),
                service: resource.service.clone(),
                environment: resource.environment,
            },
            summary,
            requested,
            excluded_fields: excluded,
            executor: ApprovalExecutor {
                executor_id: resource.executor_id.clone(),
                name: info.name.clone(),
                protection_level: info.protection_level,
            },
            recipients: vec![Recipient {
                connection_id: conn.connection_id.clone(),
                display_name: conn.display_name.clone(),
            }],
            status: ApprovalStatus::Pending,
            created_at: now,
            expires_at: aipass_types::time::add_secs(&now, ACCESS_APPROVAL_TTL_SECS as i64),
            operation_id: None,
            parameters_digest: None,
        };
        let apr2 = apr.clone();
        let result = self
            .db
            .call(move |c| {
                let tx = c.transaction()?;
                check_throttle(&tx, &apr2.connection.connection_id, &apr2.resource.resource_id, &apr2.requested.operations, &now)?;
                store::insert_approval(&tx, &apr2)?;
                audit::append(
                    &tx,
                    now,
                    Audit::new(apr2.connection.connection_id.as_str(), "approval.requested")
                        .resource(&apr2.resource.resource_id)
                        .outcome("pending")
                        .detail(json!({
                            "approval_request_id": apr2.approval_request_id.as_str(),
                            "kind": "access",
                            "operations": apr2.requested.operations,
                            "duration_seconds": apr2.requested.duration_seconds,
                        })),
                )?;
                tx.commit()?;
                Ok(())
            })
            .await;
        if let Err(e) = result {
            self.audit(
                Audit::new(conn.connection_id.as_str(), "access.rejected")
                    .resource(&req.resource_id)
                    .error(e.code)
                    .outcome(if e.code == ErrorCode::RateLimited { "throttled" } else { "denied" }),
            )
            .await;
            return Err(e);
        }
        self.announce_approval(&apr).await;
        Ok(AccessRequestResponse {
            approval_request_id: apr.approval_request_id,
            status: ApprovalStatus::Pending,
            grant_id: None,
        })
    }

    /// `GET /v1/access/requests/{id}` — own requests only.
    pub async fn get_access_request(&self, p: &ConnectionPrincipal, id: &ApprovalRequestId) -> Result<AccessRequestResponse, ApiError> {
        let conn = self.active_connection(p).await?;
        self.expire_if_due(id).await?;
        let (id2, cid) = (id.clone(), conn.connection_id.clone());
        let row = self
            .db
            .call(move |c| Ok(store::get_approval(c, &id2)?.filter(|r| r.req.connection.connection_id == cid)))
            .await?
            .ok_or_else(ApiError::not_found)?;
        Ok(AccessRequestResponse {
            approval_request_id: row.req.approval_request_id,
            status: row.req.status,
            grant_id: row.grant_id,
        })
    }
}
