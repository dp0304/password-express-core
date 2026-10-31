// SPDX-License-Identifier: Apache-2.0
//! Endpoint handlers. Each one: check the auth class, parse, call the broker, render.

use aipass_types::error::ApiError;
use aipass_types::ids::{
    ApprovalRequestId, ConnectionId, DeviceId, EntryId, GrantId, OperationId, PairingId, PolicyId,
    ProjectId, ResourceId,
};
use aipass_types::models::{
    AccessRequest, ApprovalDecision, ApprovalStatus, ApproveConnectionRequest, CreateProjectRequest,
    DelegateCredentialRequest, GrantStatus, OperationRequest, PairConnectionRequest, Policy,
    ResourceInput, ResourcePatch, RevokeRequest,
};
use aipass_types::relay::ControlAction;
use aipass_types::vault::DevicePublic;
use axum::Extension;
use axum::body::Bytes;
use axum::extract::rejection::{PathRejection, QueryRejection};
use axum::extract::{Path, Query, State};
use serde::Deserialize;
use serde_json::json;

use super::{BrokerState, HResult, ReqCtx, json, parse_json};
use crate::db::enum_parse;
use crate::types::{EntryConflictRequest, NewConnection, PairingInput};

type P<T> = Result<Path<T>, PathRejection>;
type Q<T> = Result<Query<T>, QueryRejection>;

/// Path ids that do not parse are reported as `NOT_FOUND` (no oracle on id formats).
fn path_id<T, F: FnOnce(&str) -> Result<T, aipass_types::ids::IdError>>(p: P<String>, parse: F) -> Result<T, ApiError> {
    let Path(s) = p.map_err(|_| ApiError::not_found())?;
    parse(&s).map_err(|_| ApiError::not_found())
}

fn query<T: Default>(q: Q<T>) -> Result<T, ApiError> {
    match q {
        Ok(Query(v)) => Ok(v),
        Err(_) => Err(ApiError::invalid_request("查询参数无效", "Invalid query parameters.")),
    }
}

// ------------------------------------------------------------------ P

pub(super) async fn health(State(st): State<BrokerState>) -> HResult {
    Ok(json(200, &st.broker.health()))
}

pub(super) async fn not_found() -> HResult {
    Err(ApiError::not_found().into())
}

pub(super) async fn pair(State(st): State<BrokerState>, Extension(ctx): Extension<ReqCtx>, body: Bytes) -> HResult {
    if !st.broker.public_limiter.check(&ctx.peer) {
        return Err(ApiError::new(aipass_types::error::ErrorCode::RateLimited).into());
    }
    let req: PairConnectionRequest = parse_json(&body)?;
    let r = st
        .broker
        .begin_pairing_from(
            PairingInput {
                host_type: req.host_type,
                display_name: req.display_name,
                transport: req.transport,
                public_key: Some(req.public_key),
            },
            Some(&ctx.peer),
        )
        .await?;
    Ok(json(201, &r))
}

pub(super) async fn pair_status(State(st): State<BrokerState>, Extension(ctx): Extension<ReqCtx>, p: P<String>) -> HResult {
    let id = path_id(p, PairingId::parse)?;
    let caller = ctx.connection()?;
    Ok(json(200, &st.broker.pair_status(&id, caller.connection_id()).await?))
}

// ------------------------------------------------------------------ C

#[derive(Debug, Default, Deserialize)]
pub(super) struct ResourcesQuery {
    project_id: Option<String>,
    service: Option<String>,
}

pub(super) async fn resources(State(st): State<BrokerState>, Extension(ctx): Extension<ReqCtx>, q: Q<ResourcesQuery>) -> HResult {
    let p = ctx.connection()?;
    let q = query(q)?;
    let project = match q.project_id.as_deref().filter(|s| !s.is_empty()) {
        Some(s) => Some(ProjectId::parse(s).map_err(|_| ApiError::invalid_request("project_id 无效", "invalid project_id"))?),
        None => None,
    };
    let r = st
        .broker
        .list_resources(&p, project.as_ref(), q.service.as_deref().filter(|s| !s.is_empty()), ctx.lang)
        .await?;
    Ok(json(200, &r))
}

pub(super) async fn operation_request(State(st): State<BrokerState>, Extension(ctx): Extension<ReqCtx>, body: Bytes) -> HResult {
    let p = ctx.connection()?;
    let req: OperationRequest = parse_json(&body)?;
    let r = st.broker.request_operation(&p, req, ctx.lang).await?;
    Ok(json(r.http_status(), &r))
}

pub(super) async fn operation_get(State(st): State<BrokerState>, Extension(ctx): Extension<ReqCtx>, p: P<String>) -> HResult {
    let principal = ctx.connection()?;
    let id = path_id(p, OperationId::parse)?;
    let r = st.broker.get_operation(&principal, &id, ctx.lang).await?;
    Ok(json(r.http_status(), &r))
}

pub(super) async fn operation_cancel(State(st): State<BrokerState>, Extension(ctx): Extension<ReqCtx>, p: P<String>) -> HResult {
    let principal = ctx.connection()?;
    let id = path_id(p, OperationId::parse)?;
    Ok(json(200, &st.broker.cancel_operation(&principal, &id, ctx.lang).await?))
}

pub(super) async fn access_request(State(st): State<BrokerState>, Extension(ctx): Extension<ReqCtx>, body: Bytes) -> HResult {
    let p = ctx.connection()?;
    let req: AccessRequest = parse_json(&body)?;
    Ok(json(202, &st.broker.request_access(&p, req).await?))
}

pub(super) async fn access_request_get(State(st): State<BrokerState>, Extension(ctx): Extension<ReqCtx>, p: P<String>) -> HResult {
    let principal = ctx.connection()?;
    let id = path_id(p, ApprovalRequestId::parse)?;
    Ok(json(200, &st.broker.get_access_request(&principal, &id).await?))
}

pub(super) async fn grant_release(State(st): State<BrokerState>, Extension(ctx): Extension<ReqCtx>, p: P<String>) -> HResult {
    let principal = ctx.connection()?;
    let id = path_id(p, GrantId::parse)?;
    Ok(json(200, &st.broker.release_grant(&principal, &id).await?))
}

// ------------------------------------------------------------------ D, A

#[derive(Debug, Default, Deserialize)]
pub(super) struct StatusQuery {
    status: Option<String>,
}

pub(super) async fn approvals(State(st): State<BrokerState>, Extension(ctx): Extension<ReqCtx>, q: Q<StatusQuery>) -> HResult {
    ctx.trusted()?;
    let q = query(q)?;
    let status = match q.status.as_deref() {
        None | Some("") => Some(ApprovalStatus::Pending),
        Some("all") => None,
        Some(s) => Some(enum_parse::<ApprovalStatus>(s).map_err(|_| ApiError::invalid_request("status 无效", "invalid status"))?),
    };
    Ok(json(200, &st.broker.list_approvals(status).await?))
}

pub(super) async fn approval_get(State(st): State<BrokerState>, Extension(ctx): Extension<ReqCtx>, p: P<String>) -> HResult {
    ctx.trusted()?;
    let id = path_id(p, ApprovalRequestId::parse)?;
    Ok(json(200, &st.broker.get_approval(&id).await?))
}

pub(super) async fn approval_decision(State(st): State<BrokerState>, Extension(ctx): Extension<ReqCtx>, p: P<String>, body: Bytes) -> HResult {
    ctx.trusted()?;
    let id = path_id(p, ApprovalRequestId::parse)?;
    let decision: ApprovalDecision = parse_json(&body)?;
    if decision.approval_request_id != id {
        return Err(ApiError::invalid_request("路径与决定中的审批请求不一致", "approval_request_id does not match the path").into());
    }
    Ok(json(200, &st.broker.submit_decision(decision).await?))
}

pub(super) async fn connections(State(st): State<BrokerState>, Extension(ctx): Extension<ReqCtx>) -> HResult {
    // D/A only (C principals are refused by `trusted()`): pending rows include the
    // pairing code so a trusted client can compare it with the one the AI host shows.
    ctx.trusted()?;
    Ok(json(200, &st.broker.list_connection_views().await?))
}

pub(super) async fn connection_get(State(st): State<BrokerState>, Extension(ctx): Extension<ReqCtx>, p: P<String>) -> HResult {
    ctx.trusted()?;
    let id = path_id(p, ConnectionId::parse)?;
    Ok(json(200, &st.broker.get_connection_view(&id).await?))
}

pub(super) async fn connection_action(
    State(st): State<BrokerState>,
    Extension(ctx): Extension<ReqCtx>,
    p: Result<Path<(String, String)>, PathRejection>,
    body: Bytes,
) -> HResult {
    let Path((id, action)) = p.map_err(|_| ApiError::not_found())?;
    let id = ConnectionId::parse(&id).map_err(|_| ApiError::not_found())?;
    let b = &st.broker;
    match action.as_str() {
        "token" => {
            let actor = ctx.admin()?;
            Ok(json(201, &b.issue_connection_token(&actor, &id).await?))
        }
        "approve" => {
            let actor = ctx.trusted()?;
            let req: ApproveConnectionRequest = parse_json(&body)?;
            Ok(json(200, &b.approve_connection(&actor, &id, req.allowed_projects).await?))
        }
        "deny" => {
            let actor = ctx.trusted()?;
            Ok(json(200, &b.deny_connection(&actor, &id).await?))
        }
        "pause" | "resume" | "remove" | "revoke_all" => {
            let actor = ctx.trusted()?;
            let action_enum: ControlAction = enum_parse(&action).map_err(|_| ApiError::not_found())?;
            let out = b.control_connection(&actor, &id, action_enum).await?;
            if action_enum == ControlAction::RevokeAll {
                Ok(json(200, &out))
            } else {
                Ok(json(200, &out.connection))
            }
        }
        _ => Err(ApiError::not_found().into()),
    }
}

pub(super) async fn projects(State(st): State<BrokerState>, Extension(ctx): Extension<ReqCtx>) -> HResult {
    ctx.trusted()?;
    Ok(json(200, &st.broker.list_projects().await?))
}

pub(super) async fn project_create(State(st): State<BrokerState>, Extension(ctx): Extension<ReqCtx>, body: Bytes) -> HResult {
    let actor = ctx.trusted()?;
    let req: CreateProjectRequest = parse_json(&body)?;
    Ok(json(201, &st.broker.create_project(&actor, req).await?))
}

pub(super) async fn admin_resources(State(st): State<BrokerState>, Extension(ctx): Extension<ReqCtx>) -> HResult {
    ctx.trusted()?;
    Ok(json(200, &st.broker.admin_list_resources().await?))
}

pub(super) async fn admin_resource_create(State(st): State<BrokerState>, Extension(ctx): Extension<ReqCtx>, body: Bytes) -> HResult {
    let actor = ctx.trusted()?;
    let req: ResourceInput = parse_json(&body)?;
    Ok(json(201, &st.broker.create_resource(&actor, req).await?))
}

pub(super) async fn admin_resource_get(State(st): State<BrokerState>, Extension(ctx): Extension<ReqCtx>, p: P<String>) -> HResult {
    ctx.trusted()?;
    let id = path_id(p, ResourceId::parse)?;
    Ok(json(200, &st.broker.get_resource(&id).await?))
}

pub(super) async fn admin_resource_patch(State(st): State<BrokerState>, Extension(ctx): Extension<ReqCtx>, p: P<String>, body: Bytes) -> HResult {
    let actor = ctx.trusted()?;
    let id = path_id(p, ResourceId::parse)?;
    let patch: ResourcePatch = parse_json(&body)?;
    Ok(json(200, &st.broker.update_resource(&actor, &id, patch).await?))
}

pub(super) async fn admin_resource_delete(State(st): State<BrokerState>, Extension(ctx): Extension<ReqCtx>, p: P<String>) -> HResult {
    let actor = ctx.trusted()?;
    let id = path_id(p, ResourceId::parse)?;
    st.broker.delete_resource(&actor, &id).await?;
    Ok(json(200, &json!({ "resource_id": id, "status": "deleted" })))
}

pub(super) async fn entry_conflict(State(st): State<BrokerState>, Extension(ctx): Extension<ReqCtx>, p: P<String>, body: Bytes) -> HResult {
    let actor = ctx.trusted()?;
    let id = path_id(p, EntryId::parse)?;
    let req: EntryConflictRequest = parse_json(&body)?;
    Ok(json(200, &st.broker.set_entry_conflict(&actor, &id, req.conflict).await?))
}

pub(super) async fn policies(State(st): State<BrokerState>, Extension(ctx): Extension<ReqCtx>) -> HResult {
    ctx.trusted()?;
    Ok(json(200, &st.broker.list_policies().await?))
}

pub(super) async fn policy_create(State(st): State<BrokerState>, Extension(ctx): Extension<ReqCtx>, body: Bytes) -> HResult {
    let actor = ctx.trusted()?;
    let policy: Policy = parse_json(&body)?;
    Ok(json(201, &st.broker.create_policy(&actor, policy).await?))
}

pub(super) async fn policy_disable(State(st): State<BrokerState>, Extension(ctx): Extension<ReqCtx>, p: P<String>) -> HResult {
    let actor = ctx.trusted()?;
    let id = path_id(p, PolicyId::parse)?;
    Ok(json(200, &st.broker.disable_policy(&actor, &id).await?))
}

pub(super) async fn grants(State(st): State<BrokerState>, Extension(ctx): Extension<ReqCtx>, q: Q<StatusQuery>) -> HResult {
    ctx.trusted()?;
    let q = query(q)?;
    let status = match q.status.as_deref() {
        None | Some("") | Some("all") => None,
        Some(s) => Some(enum_parse::<GrantStatus>(s).map_err(|_| ApiError::invalid_request("status 无效", "invalid status"))?),
    };
    Ok(json(200, &st.broker.list_grants(status).await?))
}

pub(super) async fn grant_get(State(st): State<BrokerState>, Extension(ctx): Extension<ReqCtx>, p: P<String>) -> HResult {
    ctx.trusted()?;
    let id = path_id(p, GrantId::parse)?;
    Ok(json(200, &st.broker.get_grant(&id).await?))
}

pub(super) async fn grant_revoke(State(st): State<BrokerState>, Extension(ctx): Extension<ReqCtx>, p: P<String>, body: Bytes) -> HResult {
    let actor = ctx.trusted()?;
    let id = path_id(p, GrantId::parse)?;
    let req: RevokeRequest = parse_json(&body)?;
    Ok(json(200, &st.broker.revoke_grant(&actor, &id, req.level).await?))
}

#[derive(Debug, Default, Deserialize)]
pub(super) struct LimitQuery {
    limit: Option<u64>,
}

pub(super) async fn operations_list(State(st): State<BrokerState>, Extension(ctx): Extension<ReqCtx>, q: Q<LimitQuery>) -> HResult {
    ctx.trusted()?;
    let q = query(q)?;
    Ok(json(200, &st.broker.list_operations(q.limit.unwrap_or(100)).await?))
}

#[derive(Debug, Default, Deserialize)]
pub(super) struct AuditQuery {
    after_seq: Option<u64>,
    limit: Option<u64>,
}

pub(super) async fn audit(State(st): State<BrokerState>, Extension(ctx): Extension<ReqCtx>, q: Q<AuditQuery>) -> HResult {
    ctx.trusted()?;
    let q = query(q)?;
    Ok(json(200, &st.broker.audit_events(q.after_seq.unwrap_or(0), q.limit.unwrap_or(200)).await?))
}

pub(super) async fn audit_verify(State(st): State<BrokerState>, Extension(ctx): Extension<ReqCtx>) -> HResult {
    ctx.trusted()?;
    Ok(json(200, &st.broker.verify_audit().await?))
}

#[derive(Debug, Default, Deserialize)]
pub(super) struct SinceQuery {
    since: Option<String>,
}

pub(super) async fn activity(State(st): State<BrokerState>, Extension(ctx): Extension<ReqCtx>, q: Q<SinceQuery>) -> HResult {
    ctx.trusted()?;
    let q = query(q)?;
    let since = match q.since.as_deref().filter(|s| !s.is_empty()) {
        Some(s) => Some(aipass_types::time::parse_rfc3339(s).map_err(|_| ApiError::invalid_request("since 必须是 RFC 3339 时间", "since must be an RFC 3339 timestamp"))?),
        None => None,
    };
    Ok(json(200, &st.broker.activity_summary(since).await?))
}

pub(super) async fn executors(State(st): State<BrokerState>, Extension(ctx): Extension<ReqCtx>) -> HResult {
    ctx.trusted()?;
    Ok(json(200, &st.broker.list_executors().await?))
}

pub(super) async fn state(State(st): State<BrokerState>, Extension(ctx): Extension<ReqCtx>) -> HResult {
    ctx.trusted()?;
    Ok(json(200, &st.broker.state_snapshot().await?))
}

// ------------------------------------------------------------------ A

pub(super) async fn devices(State(st): State<BrokerState>, Extension(ctx): Extension<ReqCtx>) -> HResult {
    ctx.admin()?;
    Ok(json(200, &st.broker.list_devices().await?))
}

pub(super) async fn device_add(State(st): State<BrokerState>, Extension(ctx): Extension<ReqCtx>, body: Bytes) -> HResult {
    let actor = ctx.admin()?;
    let d: DevicePublic = parse_json(&body)?;
    Ok(json(201, &st.broker.add_trusted_device(&actor, d).await?))
}

pub(super) async fn device_revoke(State(st): State<BrokerState>, Extension(ctx): Extension<ReqCtx>, p: P<String>) -> HResult {
    let actor = ctx.admin()?;
    let id = path_id(p, DeviceId::parse)?;
    Ok(json(200, &st.broker.revoke_device(&actor, &id).await?))
}

pub(super) async fn admin_connection_create(State(st): State<BrokerState>, Extension(ctx): Extension<ReqCtx>, body: Bytes) -> HResult {
    let actor = ctx.admin()?;
    let req: NewConnection = parse_json(&body)?;
    Ok(json(201, &st.broker.create_connection(&actor, req).await?))
}

// ------------------------------------------------------------------ D

pub(super) async fn delegate(State(st): State<BrokerState>, Extension(ctx): Extension<ReqCtx>, body: Bytes) -> HResult {
    let device = ctx.device()?;
    let req: DelegateCredentialRequest = parse_json(&body)?;
    Ok(json(201, &st.broker.delegate_credential(&device, req).await?))
}
