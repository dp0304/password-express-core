// SPDX-License-Identifier: Apache-2.0
//! A04 — forged client names and copied IDs never cross connections.

mod common;

use aipass_broker::{Actor, NewConnection};
use aipass_crypto::Ed25519Keypair;
use aipass_types::error::{ErrorCode, Lang};
use aipass_types::models::{AllowedProjects, CreateProjectRequest, HostType, OperationStatus, Transport};
use common::*;

#[tokio::test]
async fn copied_ids_from_another_connection_are_not_found() {
    let h = Harness::new().await;
    // A: an operation with a grant and an access request
    let r = h.broker.request_operation(&h.conn, h.query("a", &["day"]), Lang::ZhCn).await.unwrap();
    let grant = h.approve(r.approval_request_id.as_ref().unwrap()).await.grant_id.unwrap();
    let acc = h
        .broker
        .request_access(
            &h.conn,
            aipass_types::models::AccessRequest {
                resource_id: h.resource.resource_id.clone(),
                operations: vec!["postgres.query_view".into()],
                scope: Some(aipass_types::models::GrantScope {
                    operations: vec!["postgres.query_view".into()],
                    postgres: Some(aipass_types::models::PostgresScope {
                        views: [("analytics.subscription_daily".to_string(), vec!["plan".to_string()])].into(),
                    }),
                    github: None,
                    http_api: None,
                }),
                limits: None,
                duration_seconds: None,
                reason: None,
            },
        )
        .await
        .unwrap();

    // B claims the same display name — a label, never identity
    let b = h.new_connection("Claude Code").await;
    let e = h.broker.get_operation(&b, &r.operation_id, Lang::ZhCn).await.unwrap_err();
    assert_eq!(e.code, ErrorCode::NotFound);
    let e = h.broker.cancel_operation(&b, &r.operation_id, Lang::ZhCn).await.unwrap_err();
    assert_eq!(e.code, ErrorCode::NotFound);
    let e = h.broker.release_grant(&b, &grant).await.unwrap_err();
    assert_eq!(e.code, ErrorCode::NotFound);
    let e = h.broker.get_access_request(&b, &acc.approval_request_id).await.unwrap_err();
    assert_eq!(e.code, ErrorCode::NotFound);

    // B's identical query (even with A's idempotency key and task id) does not ride A's grant
    let mut q = h.query("a", &["day"]);
    q.task_id = Some(r.operation_id.as_str().to_owned());
    let rb = h.broker.request_operation(&b, q, Lang::ZhCn).await.unwrap();
    assert_eq!(rb.status, OperationStatus::AwaitingApproval);
    assert_ne!(rb.operation_id, r.operation_id);
    let apr = h.request(rb.approval_request_id.as_ref().unwrap()).await;
    assert_eq!(apr.connection.connection_id, *b.connection_id());
    assert_eq!(apr.recipients.len(), 1);
    assert_eq!(apr.recipients[0].connection_id, *b.connection_id());
    // A's grant is untouched
    assert_eq!(h.broker.get_grant(&grant).await.unwrap().usage.requests, 1);

    // nonexistent / garbage IDs look the same as foreign ones
    let e = h.broker.get_operation(&b, &aipass_types::ids::OperationId::generate(), Lang::ZhCn).await.unwrap_err();
    assert_eq!(e.code, ErrorCode::NotFound);
}

#[tokio::test]
async fn resources_outside_allowed_projects_are_invisible() {
    let h = Harness::new().await;
    let other_project = h
        .broker
        .create_project(&Actor::Admin, CreateProjectRequest { name: "secret project".into() })
        .await
        .unwrap();
    let c = h
        .broker
        .create_connection(
            &Actor::Admin,
            NewConnection {
                host_type: HostType::Cursor,
                display_name: "Cursor".into(),
                transport: Transport::Stdio,
                allowed_projects: AllowedProjects::Only([other_project.project_id.clone()].into()),
                public_key: Some(Ed25519Keypair::generate().public_key_b64u()),
            },
        )
        .await
        .unwrap();
    let p = aipass_broker::ConnectionPrincipal::in_process(c.connection.connection_id);
    assert!(h.broker.list_resources(&p, None, None, Lang::ZhCn).await.unwrap().resources.is_empty());
    let e = h.broker.request_operation(&p, h.query("x", &["day"]), Lang::ZhCn).await.unwrap_err();
    assert_eq!(e.code, ErrorCode::NotFound, "same answer as for a resource that does not exist");
    let e = h
        .broker
        .request_access(
            &p,
            aipass_types::models::AccessRequest {
                resource_id: h.resource.resource_id.clone(),
                operations: vec!["postgres.query_view".into()],
                scope: None,
                limits: None,
                duration_seconds: None,
                reason: None,
            },
        )
        .await
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::NotFound);

    // ResourceView never exposes config or credential references
    let v = h.broker.list_resources(&h.conn, None, None, Lang::ZhCn).await.unwrap();
    let text = serde_json::to_string(&v).unwrap();
    assert!(!text.contains("db.internal"));
    assert!(!text.contains(h.resource.credential_entry_id.as_str()));
    assert!(!text.contains("allowed_views"));
}

#[tokio::test]
async fn unknown_connections_are_unverified() {
    let h = Harness::new().await;
    let ghost = aipass_broker::ConnectionPrincipal::in_process(aipass_types::ids::ConnectionId::generate());
    let e = h.broker.request_operation(&ghost, h.query("x", &["day"]), Lang::ZhCn).await.unwrap_err();
    assert_eq!(e.code, ErrorCode::IdentityUnverified);
}

#[tokio::test]
async fn connection_handle_mirrors_the_c_endpoints() {
    let h = Harness::new().await;
    let handle = h.broker.connection_handle(h.conn.clone(), Lang::En);
    assert_eq!(handle.list_resources(None, Some("postgres")).await.unwrap().resources.len(), 1);
    assert!(handle.list_resources(None, Some("github")).await.unwrap().resources.is_empty());
    let r = handle.request_operation(&h.query("h1", &["day"])).await.unwrap();
    assert_eq!(r.status, OperationStatus::AwaitingApproval);
    assert_eq!(r.message.as_deref(), Some(aipass_types::models::APPROVAL_REQUIRED_MESSAGE_EN));
    assert_eq!(handle.get_operation(&r.operation_id).await.unwrap().operation_id, r.operation_id);
    let c = handle.cancel_operation(&r.operation_id).await.unwrap();
    assert!(c.cancelled);
    assert_eq!(c.message, "Cancelled; nothing was sent to the external service.");
    let other = h.broker.connection_handle(h.new_connection("x").await, Lang::ZhCn);
    assert_eq!(other.get_operation(&r.operation_id).await.unwrap_err().code, ErrorCode::NotFound);
}
