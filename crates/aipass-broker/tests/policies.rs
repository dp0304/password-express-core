// SPDX-License-Identifier: Apache-2.0
//! Signed rule policies: auto-approve only for test + read-only, signature checks, budget
//! window, disabling, environment change, credential sources.

mod common;

use std::collections::BTreeMap;
use std::sync::Arc;

use aipass_broker::{Actor, CredentialSource};
use aipass_crypto::DeviceIdentity;
use aipass_types::error::{ApiError, ErrorCode, Lang};
use aipass_types::exec::CredentialMaterial;
use aipass_types::ids::PolicyId;
use aipass_types::models::{
    ApprovalMode, ControlChannelLostAction, Environment, Grant, GrantScope, GrantStatus, Limits,
    OperationStatus, Policy, PolicyStatus, PostgresScope, Resource, ResourcePatch,
    HttpApiScope,
};
use aipass_types::policy::sign_policy;
use async_trait::async_trait;
use common::*;

struct Vault {
    material: CredentialMaterial,
}

#[async_trait]
impl CredentialSource for Vault {
    async fn material_for_grant(&self, _g: &Grant, _r: &Resource) -> Result<Option<CredentialMaterial>, ApiError> {
        Ok(Some(self.material.clone()))
    }
}

fn policy(h: &Harness, res: &Resource, signer: &DeviceIdentity, limits: Limits) -> Policy {
    let mut p = Policy {
        policy_id: PolicyId::generate(),
        version: 1,
        subject_connection_id: h.conn.connection_id().clone(),
        project_id: res.project_id.clone(),
        resource_id: res.resource_id.clone(),
        executor_id: res.executor_id.clone(),
        allowed_operations: vec!["postgres.query_view".into()],
        allowed_views: vec!["analytics.subscription_daily".into()],
        allowed_fields: vec!["day".into(), "plan".into(), "subscriptions".into()],
        scope: GrantScope {
            operations: vec!["postgres.query_view".into()],
            postgres: Some(PostgresScope {
                views: BTreeMap::from([(
                    "analytics.subscription_daily".to_string(),
                    vec!["day".to_string(), "plan".to_string(), "subscriptions".to_string()],
                )]),
            }),
            github: None,
            http_api: None,
        },
        limits,
        grant_ttl_seconds: 900,
        approval_mode: ApprovalMode::Rule,
        auto_approve: true,
        on_control_channel_lost: ControlChannelLostAction::DenyNewOperations,
        output_recipients: vec![h.conn.connection_id().clone()],
        status: PolicyStatus::Active,
        created_at: h.clock.now_ts(),
        signed_by: h.device_id.clone(),
        signature: String::new(),
    };
    sign_policy(&mut p, signer).unwrap();
    p
}

async fn with_vault(h: &Harness) {
    h.broker.set_credential_source(Arc::new(Vault {
        material: h.material(&h.resource),
    }));
}

#[tokio::test]
async fn rule_auto_approves_test_read_only_and_is_summarised() {
    let h = Harness::new().await;
    with_vault(&h).await;
    let p = policy(&h, &h.resource, &h.device, Limits::default());
    h.broker.create_policy(&Actor::Device(h.device_id.clone()), p.clone()).await.unwrap();
    let r = h.broker.request_operation(&h.conn, h.query("a", &["day", "plan"]), Lang::ZhCn).await.unwrap();
    assert_eq!(r.status, OperationStatus::Succeeded, "{r:?}");
    let grants = h.broker.list_grants(Some(GrantStatus::Active)).await.unwrap().grants;
    assert_eq!(grants.len(), 1);
    assert_eq!(grants[0].policy_id.as_ref(), Some(&p.policy_id));
    assert_eq!(grants[0].mode, ApprovalMode::Rule);
    let audit = h.broker.audit_events(0, 1000).await.unwrap();
    assert!(audit.events.iter().any(|e| e.action == "rule.auto_approved"));
    let summary = h.broker.activity_summary(None).await.unwrap();
    assert_eq!(summary.auto_approved_count, 1);
    // fields outside the rule still need a person
    let r = h.broker.request_operation(&h.conn, h.query("b", &["email"]), Lang::ZhCn).await.unwrap();
    assert_eq!(r.status, OperationStatus::AwaitingApproval);
}

#[tokio::test]
async fn auto_approve_refused_for_production_and_writes() {
    let h = Harness::new().await;
    let prod = h.add_resource(Environment::Production).await;
    let p = policy(&h, &prod, &h.device, Limits::default());
    let e = h.broker.create_policy(&Actor::Admin, p).await.unwrap_err();
    assert_eq!(e.code, ErrorCode::InvalidRequest);

    let api = h.add_api_resource(Environment::Test).await;
    let mut p = policy(&h, &api, &h.device, Limits::default());
    p.allowed_operations = vec!["demo.create_order".into()];
    p.scope = GrantScope {
        operations: vec!["demo.create_order".into()],
        postgres: None,
        github: None,
        http_api: Some(HttpApiScope {
            operations: vec!["demo.create_order".into()],
        }),
    };
    sign_policy(&mut p, &h.device).unwrap();
    assert_eq!(h.broker.create_policy(&Actor::Admin, p).await.unwrap_err().code, ErrorCode::InvalidRequest);

    // task-mode policy with auto_approve is invalid as well
    let mut p = policy(&h, &h.resource, &h.device, Limits::default());
    p.approval_mode = ApprovalMode::Task;
    sign_policy(&mut p, &h.device).unwrap();
    assert_eq!(h.broker.create_policy(&Actor::Admin, p).await.unwrap_err().code, ErrorCode::InvalidRequest);
}

#[tokio::test]
async fn environment_change_disables_auto_approval() {
    let h = Harness::new().await;
    with_vault(&h).await;
    h.broker.create_policy(&Actor::Admin, policy(&h, &h.resource, &h.device, Limits::default())).await.unwrap();
    assert_eq!(
        h.broker.request_operation(&h.conn, h.query("a", &["day"]), Lang::ZhCn).await.unwrap().status,
        OperationStatus::Succeeded
    );
    h.broker
        .update_resource(&Actor::Admin, &h.resource.resource_id, ResourcePatch { environment: Some(Environment::Production), ..Default::default() })
        .await
        .unwrap();
    let r = h.broker.request_operation(&h.conn, h.query("b", &["day"]), Lang::ZhCn).await.unwrap();
    assert_eq!(r.status, OperationStatus::AwaitingApproval, "production reads are never auto-approved");
}

#[tokio::test]
async fn signatures_and_signers_are_checked() {
    let h = Harness::new().await;
    // tampered after signing
    let mut p = policy(&h, &h.resource, &h.device, Limits::default());
    p.limits.max_rows_per_grant = 99_999;
    assert_eq!(h.broker.create_policy(&Actor::Admin, p).await.unwrap_err().code, ErrorCode::IntegrityFailed);
    // signed by a key that is not the named trusted device
    let rogue = DeviceIdentity::generate();
    let p = policy(&h, &h.resource, &rogue, Limits::default());
    assert_eq!(h.broker.create_policy(&Actor::Admin, p).await.unwrap_err().code, ErrorCode::IntegrityFailed);
    // signer not in the approver set
    let mut p = policy(&h, &h.resource, &rogue, Limits::default());
    p.signed_by = aipass_types::ids::DeviceId::generate();
    sign_policy(&mut p, &rogue).unwrap();
    assert_eq!(h.broker.create_policy(&Actor::Admin, p).await.unwrap_err().code, ErrorCode::IdentityUnverified);
    // versions must increase
    let p = policy(&h, &h.resource, &h.device, Limits::default());
    h.broker.create_policy(&Actor::Admin, p.clone()).await.unwrap();
    assert_eq!(h.broker.create_policy(&Actor::Admin, p).await.unwrap_err().code, ErrorCode::InvalidRequest);
}

#[tokio::test]
async fn rule_budget_is_not_refreshed_by_exhausting_grants() {
    let h = Harness::new().await;
    with_vault(&h).await;
    let limits = Limits {
        max_rows_per_operation: 10,
        max_rows_per_grant: 100,
        max_requests_per_grant: 2,
        max_result_bytes: 262_144,
    };
    h.broker.create_policy(&Actor::Admin, policy(&h, &h.resource, &h.device, limits)).await.unwrap();
    for k in ["a", "b"] {
        assert_eq!(h.broker.request_operation(&h.conn, h.query(k, &["day"]), Lang::ZhCn).await.unwrap().status, OperationStatus::Succeeded);
    }
    let r = h.broker.request_operation(&h.conn, h.query("c", &["day"]), Lang::ZhCn).await.unwrap();
    assert_eq!(r.status, OperationStatus::AwaitingApproval, "no second rule grant inside the TTL window");
    // after the window, the rule grants a fresh short-lived grant
    h.clock.advance(901);
    h.broker.sweep().await.unwrap();
    let r = h.broker.request_operation(&h.conn, h.query("d", &["day"]), Lang::ZhCn).await.unwrap();
    assert_eq!(r.status, OperationStatus::Succeeded);
}

#[tokio::test]
async fn disabling_a_policy_revokes_its_grants() {
    let h = Harness::new().await;
    with_vault(&h).await;
    let p = policy(&h, &h.resource, &h.device, Limits::default());
    h.broker.create_policy(&Actor::Admin, p.clone()).await.unwrap();
    h.broker.request_operation(&h.conn, h.query("a", &["day"]), Lang::ZhCn).await.unwrap();
    let disabled = h.broker.disable_policy(&Actor::Admin, &p.policy_id).await.unwrap();
    assert_eq!(disabled.status, PolicyStatus::Disabled);
    assert!(h.broker.list_grants(Some(GrantStatus::Active)).await.unwrap().grants.is_empty());
    let r = h.broker.request_operation(&h.conn, h.query("b", &["day"]), Lang::ZhCn).await.unwrap();
    assert_eq!(r.status, OperationStatus::AwaitingApproval);
    let listed = h.broker.list_policies().await.unwrap().policies;
    assert_eq!(listed[0].status, PolicyStatus::Disabled);
}

#[tokio::test]
async fn rule_grant_without_credential_source_is_secret_unavailable() {
    let h = Harness::new().await;
    h.broker.create_policy(&Actor::Admin, policy(&h, &h.resource, &h.device, Limits::default())).await.unwrap();
    let r = h.broker.request_operation(&h.conn, h.query("a", &["day"]), Lang::ZhCn).await.unwrap();
    assert_eq!(r.status, OperationStatus::Failed);
    assert_eq!(r.error.unwrap().code, ErrorCode::SecretUnavailable);
}

#[tokio::test]
async fn delegation_is_experimental_and_off_by_default() {
    let h = Harness::new().await;
    let p = policy(&h, &h.resource, &h.device, Limits::default());
    h.broker.create_policy(&Actor::Admin, p.clone()).await.unwrap();
    let env = aipass_crypto::hpke::seal(&h.exe.kem.public_key(), aipass_crypto::info::CREDENTIAL, b"aad", b"x").unwrap();
    let e = h
        .broker
        .delegate_credential(&h.device_id, aipass_types::models::DelegateCredentialRequest { policy_id: p.policy_id, credential_envelope: env })
        .await
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::NotSupported);
}

/// BRK-03: changing a resource's credential entry (same environment) disables its standing
/// rules — after the rule TTL window a request needs a person again, not a silent
/// auto-approval against the new credential.
#[tokio::test]
async fn credential_change_disables_rules_even_after_the_ttl_window() {
    let h = Harness::new().await;
    with_vault(&h).await;
    let p = policy(&h, &h.resource, &h.device, Limits::default());
    h.broker.create_policy(&Actor::Device(h.device_id.clone()), p.clone()).await.unwrap();
    assert_eq!(
        h.broker.request_operation(&h.conn, h.query("a", &["day"]), Lang::ZhCn).await.unwrap().status,
        OperationStatus::Succeeded
    );
    h.broker
        .update_resource(
            &Actor::Admin,
            &h.resource.resource_id,
            ResourcePatch { credential_entry_id: Some(aipass_types::ids::EntryId::generate()), ..Default::default() },
        )
        .await
        .unwrap();
    h.clock.advance(p.grant_ttl_seconds as i64 + 1);
    let r = h.broker.request_operation(&h.conn, h.query("b", &["day"]), Lang::ZhCn).await.unwrap();
    assert_eq!(r.status, OperationStatus::AwaitingApproval, "rule must not carry over to a new credential");
    let listed = h.broker.list_policies().await.unwrap();
    let after = listed.policies.iter().find(|x| x.policy_id == p.policy_id).unwrap();
    assert_eq!(after.status, PolicyStatus::Disabled);
    // a cosmetic change (alias) does not touch rules of a re-signed policy
    let mut p2 = policy(&h, &h.resource, &h.device, Limits::default());
    p2.policy_id = PolicyId::generate();
    aipass_types::policy::sign_policy(&mut p2, &h.device).unwrap();
    h.broker.create_policy(&Actor::Device(h.device_id.clone()), p2.clone()).await.unwrap();
    h.broker
        .update_resource(&Actor::Admin, &h.resource.resource_id, ResourcePatch { alias: Some("新别名".into()), ..Default::default() })
        .await
        .unwrap();
    assert_eq!(
        h.broker.request_operation(&h.conn, h.query("c", &["day"]), Lang::ZhCn).await.unwrap().status,
        OperationStatus::Succeeded
    );
}

/// BRK-03: revoke-all also disables the connection's standing rules.
#[tokio::test]
async fn revoke_all_disables_rules() {
    let h = Harness::new().await;
    with_vault(&h).await;
    let p = policy(&h, &h.resource, &h.device, Limits::default());
    h.broker.create_policy(&Actor::Device(h.device_id.clone()), p.clone()).await.unwrap();
    assert_eq!(
        h.broker.request_operation(&h.conn, h.query("a", &["day"]), Lang::ZhCn).await.unwrap().status,
        OperationStatus::Succeeded
    );
    h.broker
        .control_connection(&Actor::Admin, h.conn.connection_id(), aipass_types::relay::ControlAction::RevokeAll)
        .await
        .unwrap();
    h.clock.advance(p.grant_ttl_seconds as i64 + 1);
    let r = h.broker.request_operation(&h.conn, h.query("b", &["day"]), Lang::ZhCn).await.unwrap();
    assert_eq!(r.status, OperationStatus::AwaitingApproval, "rule access must not come back after revoke-all");
}
