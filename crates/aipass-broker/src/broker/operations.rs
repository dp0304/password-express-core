// SPDX-License-Identifier: Apache-2.0
//! The operation pipeline (CONTRACTS §6.2), re-checked on **every** operation:
//!
//! 1. authenticate the connection, require `active` (`IDENTITY_UNVERIFIED` /
//!    `CONNECTION_PAUSED`);
//! 2. idempotency on `(connection_id, idempotency_key)`;
//! 3. resource visibility (`NOT_FOUND` — also for other principals' objects) and entry
//!    conflicts (`SYNC_CONFLICT`);
//! 4. `ExecutorBackend::normalize`;
//! 5. grant match → signed rule policy with auto-approve → throttle → approval request
//!    (never blocks waiting for a phone, never approves on timeout);
//! 6. run: executor online, control channel, credential installed; request usage is
//!    reserved atomically before execution, rows/bytes settled after — cumulative limits
//!    hold under pagination and concurrency (A08);
//! 7. outcome: filtered result / `unknown` + `UPSTREAM_OUTCOME_UNKNOWN` (automatic retry
//!    only for `retry_safe` operations).
//!
//! Executions run in their own task: a caller that disconnects never leaves an operation
//! half-settled.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use aipass_types::approval::{self, DEFAULT_TASK_TTL_SECS, OPERATION_APPROVAL_TTL_SECS};
use aipass_types::canonical::jcs_sha256_b64u;
use aipass_types::error::{ApiError, ErrorCode, Lang};
use aipass_types::exec::{ExecutionOutcome, ExecutionRequest, NormalizedRequest, OperationSpec};
use aipass_types::ids::{ApprovalRequestId, ConnectionId, GrantId, OperationId, ResourceId};
use aipass_types::models::{
    APPROVAL_REQUIRED_MESSAGE, APPROVAL_REQUIRED_MESSAGE_EN, AccessSpec, AppConnection, ApprovalConnection,
    ApprovalExecutor, ApprovalKind, ApprovalMode, ApprovalRequest, ApprovalResource, ApprovalStatus,
    CancelResponse, ConnectionStatus, GrantScope, GrantStatus, Limits, Operation, OperationRequest,
    OperationResponse, OperationResult, OperationStatus, OperationsResponse, Recipient, Resource,
    ResourceStatus, SideEffectClass, SideEffects,
};
use aipass_types::relay::{ApprovalCancelled, RelayMessage};
use futures::FutureExt;
use serde::Serialize;
use serde_json::{Value, json};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use super::{Broker, ExecutorSlot, Inflight};
use crate::audit::{self, Audit};
use crate::db::{enum_str, i, unix};
use crate::error::{SResult, err};
use crate::notify::BrokerEvent;
use crate::principal::ConnectionPrincipal;
use crate::redact::summarize_params;
use crate::store::{self, CredState, GrantRow, OpRow, OpUpdate, ResourceRow, StoredError};
use crate::summary::{OpLabel, SummaryInput, approval_summary, excluded_fields};

/// Throttle window after a denial (design doc §11.4).
pub const DENIAL_THROTTLE_SECS: i64 = 600;
/// More than this many pending approvals per connection → `RATE_LIMITED`.
pub const MAX_PENDING_APPROVALS_PER_CONNECTION: u64 = 5;

/// Everything needed to execute one authorized operation.
pub(crate) struct RunPlan {
    pub op_id: OperationId,
    pub connection_id: ConnectionId,
    pub grant_id: GrantId,
    pub resource: Resource,
    pub normalized: NormalizedRequest,
    pub spec: OperationSpec,
    pub slot: Arc<ExecutorSlot>,
}

struct Reservation {
    rows: u64,
    remaining: Limits,
}

/// Final classification of a run.
struct Settlement {
    status: OperationStatus,
    result: Option<OperationResult>,
    error: Option<ApiError>,
    side_effects: SideEffects,
    rows_used: u64,
    bytes_used: u64,
    attempts: u32,
}

enum Raced {
    Done(Result<ExecutionOutcome, ApiError>),
    Cancelled,
    TimedOut,
}

struct InflightGuard {
    broker: Arc<Broker>,
    op_id: OperationId,
    inflight: Arc<Inflight>,
}

impl Drop for InflightGuard {
    fn drop(&mut self) {
        if let Ok(mut m) = self.broker.inflight.lock() {
            m.remove(&self.op_id);
        }
        self.inflight.done.send_replace(true);
    }
}

/// `b64u(SHA-256(JCS({resource_id, operation, parameters})))` of the raw request — the
/// fast idempotency path (exact replays need no normalization).
fn request_digest(req: &OperationRequest) -> Result<String, ApiError> {
    #[derive(Serialize)]
    struct D<'a> {
        resource_id: &'a str,
        operation: &'a str,
        parameters: &'a Value,
    }
    Ok(jcs_sha256_b64u(&D {
        resource_id: req.resource_id.as_str(),
        operation: &req.operation,
        parameters: &req.parameters,
    })?)
}

/// Generic coverage check the broker applies in addition to the executor's
/// `scope_covers`: the operation is granted and the required scope is a subset.
pub(crate) fn scope_allows(scope: &GrantScope, n: &NormalizedRequest) -> bool {
    scope.operations.iter().any(|o| o == &n.operation) && approval::scope_is_subset(&n.required_scope, scope)
}

fn with_operation(scope: &GrantScope, op: &str) -> GrantScope {
    let mut s = approval::normalize_scope(scope);
    if !s.operations.iter().any(|o| o == op) {
        s.operations.push(op.to_owned());
        s.operations.sort();
    }
    s
}

fn side_effects_if_interrupted(spec: &OperationSpec) -> SideEffects {
    if spec.side_effect == SideEffectClass::Read {
        SideEffects::None
    } else {
        SideEffects::Possible
    }
}

impl Broker {
    // ------------------------------------------------------------- operations.request

    /// `POST /v1/operations` / MCP `operations_request`.
    ///
    /// Errors decided before an operation exists (auth, validation, idempotency conflict,
    /// visibility, normalization, conflicts, executor state, throttling) are returned as
    /// `Err`. Once an operation exists the response is an [`OperationResponse`]: `202`
    /// while pending, `200` when terminal — failures carry `error`.
    pub async fn request_operation(
        self: &Arc<Self>,
        p: &ConnectionPrincipal,
        req: OperationRequest,
        lang: Lang,
    ) -> Result<OperationResponse, ApiError> {
        let result = self.request_operation_inner(p, &req, lang).await;
        if let Err(e) = &result {
            let a = Audit::new(p.connection_id().as_str(), "operation.rejected")
                .outcome(if e.code == ErrorCode::RateLimited { "throttled" } else { "denied" })
                .error(e.code)
                .resource(&req.resource_id)
                .detail(json!({
                    "operation": truncate(&req.operation, 128),
                    "request_digest": request_digest(&req).unwrap_or_default(),
                }));
            self.audit(a).await;
        }
        result
    }

    async fn request_operation_inner(
        self: &Arc<Self>,
        p: &ConnectionPrincipal,
        req: &OperationRequest,
        lang: Lang,
    ) -> Result<OperationResponse, ApiError> {
        req.validate()?;
        // 1. connection
        let conn = self.active_connection(p).await?;
        // 2. idempotency — exact replay fast path
        let rdigest = request_digest(req)?;
        let (cid, key) = (conn.connection_id.clone(), req.idempotency_key.clone());
        let existing = self.db.call(move |c| store::get_op_by_key(c, &cid, &key)).await?;
        if let Some(ex) = &existing
            && ex.request_digest == rdigest {
                return self.op_response(ex.clone(), lang).await;
            }
        // 3. visibility
        let row = self.visible_resource(&conn, &req.resource_id).await?;
        let resource = row.resource.clone();
        let slot = self
            .executor_slot(&resource.executor_id)
            .ok_or_else(|| ApiError::new(ErrorCode::ExecutorOffline))?;
        if !resource.operations.iter().any(|o| o == &req.operation) {
            return Err(ApiError::scope_denied()
                .with_message("该资源未提供此操作", "This resource does not offer that operation.")
                .with_detail("operation", truncate(&req.operation, 128)));
        }
        let spec = self
            .specs_for(&slot, resource.connector.as_str())
            .into_iter()
            .find(|s| s.name == req.operation)
            .ok_or_else(|| {
                ApiError::scope_denied().with_message("执行设备不提供此操作", "The executor does not offer that operation.")
            })?;
        // 4. normalize (schema validation + allowlists)
        let mut normalized = slot.backend.normalize(&resource, &req.operation, &req.parameters)?;
        if normalized.operation != req.operation {
            return Err(ApiError::scope_denied());
        }
        normalized.parameters_digest = aipass_types::exec::parameters_digest(&normalized.operation, &normalized.params)?;
        // 2b. idempotency on normalized parameters
        if let Some(ex) = existing {
            if ex.op.resource_id == resource.resource_id
                && ex.op.operation == normalized.operation
                && ex.op.parameters_digest == normalized.parameters_digest
            {
                return self.op_response(ex, lang).await;
            }
            return Err(ApiError::new(ErrorCode::IdempotencyConflict).with_detail("idempotency_key", req.idempotency_key.clone()));
        }
        // 3b. conflicts / disabled
        if row.entry_conflict || resource.status == ResourceStatus::SyncConflict {
            return Err(ApiError::new(ErrorCode::SyncConflict));
        }
        if resource.status == ResourceStatus::Disabled {
            return Err(ApiError::scope_denied().with_message("该资源已停用", "This resource is disabled."));
        }
        slot.ready()?;
        if self.inflight_for_connection(&conn.connection_id).len() >= self.cfg.max_inflight_per_connection {
            return Err(err(
                ErrorCode::RateLimited,
                "同时进行的操作过多，请稍后再试",
                "Too many operations in flight; try again shortly.",
            ));
        }
        // 5. grant → rule → approval
        if let Some(g) = self.find_grant(&conn, &resource, &slot, &normalized).await? {
            return self
                .start_with_grant(&conn, &resource, &slot, spec, normalized, rdigest, req, g, lang)
                .await;
        }
        if let Some(g) = self.try_auto_approve(&conn, &resource, &slot, &normalized).await? {
            return self
                .start_with_grant(&conn, &resource, &slot, spec, normalized, rdigest, req, g, lang)
                .await;
        }
        self.create_operation_approval(&conn, &row, &slot, &spec, normalized, rdigest, req, lang)
            .await
    }

    /// Resource visible to `conn` (allowed projects) or `NOT_FOUND`.
    pub(crate) async fn visible_resource(&self, conn: &AppConnection, id: &ResourceId) -> Result<ResourceRow, ApiError> {
        let rid = id.clone();
        let row = self
            .db
            .call(move |c| store::get_resource(c, &rid))
            .await?
            .ok_or_else(ApiError::not_found)?;
        if !store::visible(conn, &row.resource.project_id) {
            return Err(ApiError::not_found());
        }
        Ok(row)
    }

    /// An active, unexpired grant of this connection for this resource and executor
    /// whose scope covers the request and whose budget remains. Grants bound to one
    /// operation (`once` operation approvals) are never matched for a new request.
    pub(crate) async fn find_grant(
        &self,
        conn: &AppConnection,
        resource: &Resource,
        slot: &ExecutorSlot,
        n: &NormalizedRequest,
    ) -> Result<Option<GrantRow>, ApiError> {
        let now = self.now();
        let (cid, rid, eid) = (
            conn.connection_id.clone(),
            resource.resource_id.clone(),
            resource.executor_id.clone(),
        );
        let rows = self
            .db
            .call(move |c| {
                store::query_grants(
                    c,
                    "connection_id = ?1 AND resource_id = ?2 AND executor_id = ?3 AND status = 'active' AND expires_at > ?4 AND bound_operation_id IS NULL ORDER BY expires_at ASC",
                    &[&cid.as_str(), &rid.as_str(), &eid.as_str(), &unix(&now)],
                )
            })
            .await?;
        for g in rows {
            if !g.has_budget() {
                continue;
            }
            if !scope_allows(&g.grant.scope, n) {
                continue;
            }
            if !slot.backend.scope_covers(&g.grant.scope, &g.remaining(), n) {
                continue;
            }
            return Ok(Some(g));
        }
        Ok(None)
    }

    #[allow(clippy::too_many_arguments)]
    async fn start_with_grant(
        self: &Arc<Self>,
        conn: &AppConnection,
        resource: &Resource,
        slot: &Arc<ExecutorSlot>,
        spec: OperationSpec,
        normalized: NormalizedRequest,
        rdigest: String,
        req: &OperationRequest,
        grant: GrantRow,
        lang: Lang,
    ) -> Result<OperationResponse, ApiError> {
        let now = self.now();
        let op = new_operation(conn, resource, &normalized, req, now);
        let op_id = op.operation_id.clone();
        let row = OpRow {
            op,
            error: None,
            request_digest: rdigest.clone(),
            normalized: Some(normalized.clone()),
        };
        let gid = grant.grant.grant_id.clone();
        let task_id = req.task_id.clone();
        let summary = summarize_params(&normalized.params);
        let (oid, g2) = (op_id.clone(), gid.clone());
        let inserted = self
            .db
            .call(move |c| {
                let tx = c.transaction()?;
                if !store::insert_op(&tx, &row, task_id.as_deref())? {
                    return Ok(false);
                }
                store::transition(&tx, &oid, &[OperationStatus::Received], OperationStatus::PolicyChecked, &now, OpUpdate::default())?;
                store::transition(
                    &tx,
                    &oid,
                    &[OperationStatus::PolicyChecked],
                    OperationStatus::Authorized,
                    &now,
                    OpUpdate {
                        grant_id: Some(&g2),
                        ..Default::default()
                    },
                )?;
                audit::append(
                    &tx,
                    now,
                    Audit::new(row.op.connection_id.as_str(), "operation.authorized")
                        .operation(&oid)
                        .resource(&row.op.resource_id)
                        .grant(&g2)
                        .detail(json!({
                            "operation": row.op.operation,
                            "parameters_digest": row.op.parameters_digest,
                            "parameters": summary,
                        })),
                )?;
                tx.commit()?;
                Ok(true)
            })
            .await?;
        if !inserted {
            return self.idempotency_race(conn, req, &rdigest, &normalized, lang).await;
        }
        self.emit(BrokerEvent::OperationUpdated {
            operation_id: op_id.clone(),
            connection_id: conn.connection_id.clone(),
            status: OperationStatus::Authorized,
        });
        let handle = self.spawn_run(RunPlan {
            op_id,
            connection_id: conn.connection_id.clone(),
            grant_id: gid,
            resource: resource.clone(),
            normalized,
            spec,
            slot: slot.clone(),
        });
        let settled = handle.await.map_err(|_| ApiError::internal())??;
        self.op_response(settled, lang).await
    }

    async fn idempotency_race(
        &self,
        conn: &AppConnection,
        req: &OperationRequest,
        rdigest: &str,
        normalized: &NormalizedRequest,
        lang: Lang,
    ) -> Result<OperationResponse, ApiError> {
        let (cid, key) = (conn.connection_id.clone(), req.idempotency_key.clone());
        let ex = self
            .db
            .call(move |c| store::get_op_by_key(c, &cid, &key))
            .await?
            .ok_or_else(ApiError::internal)?;
        if ex.request_digest == rdigest
            || (ex.op.resource_id == req.resource_id
                && ex.op.operation == normalized.operation
                && ex.op.parameters_digest == normalized.parameters_digest)
        {
            return self.op_response(ex, lang).await;
        }
        Err(ApiError::new(ErrorCode::IdempotencyConflict))
    }

    #[allow(clippy::too_many_arguments)]
    async fn create_operation_approval(
        self: &Arc<Self>,
        conn: &AppConnection,
        row: &ResourceRow,
        slot: &Arc<ExecutorSlot>,
        spec: &OperationSpec,
        normalized: NormalizedRequest,
        rdigest: String,
        req: &OperationRequest,
        lang: Lang,
    ) -> Result<OperationResponse, ApiError> {
        let now = self.now();
        let resource = &row.resource;
        let info = slot.backend.info();
        let op = new_operation(conn, resource, &normalized, req, now);
        let op_id = op.operation_id.clone();
        let requested = AccessSpec {
            operations: vec![normalized.operation.clone()],
            scope: with_operation(&normalized.required_scope, &normalized.operation),
            limits: self.cfg.default_limits,
            duration_seconds: DEFAULT_TASK_TTL_SECS,
            mode: ApprovalMode::Task,
        };
        let excluded = excluded_fields(resource, &requested.scope);
        let summary = approval_summary(&SummaryInput {
            connection_name: &conn.display_name,
            resource,
            ops: &[OpLabel {
                name: spec.name.clone(),
                zh: spec.description_zh.clone(),
                en: spec.description_en.clone(),
            }],
            spec: &requested,
            excluded: &excluded,
            executor_name: &info.name,
            protection: info.protection_level,
            reason: None,
        });
        let apr = ApprovalRequest {
            approval_request_id: ApprovalRequestId::generate(),
            kind: ApprovalKind::Operation,
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
            expires_at: aipass_types::time::add_secs(&now, OPERATION_APPROVAL_TTL_SECS as i64),
            operation_id: Some(op_id.clone()),
            // §7 v2: the signed digest binds the exact normalized parameters the user sees.
            parameters_digest: Some(normalized.parameters_digest.clone()),
        };
        let row_op = OpRow {
            op,
            error: None,
            request_digest: rdigest.clone(),
            normalized: Some(normalized.clone()),
        };
        let task_id = req.task_id.clone();
        let params_summary = summarize_params(&normalized.params);
        let (apr2, oid) = (apr.clone(), op_id.clone());
        let inserted = self
            .db
            .call(move |c| {
                let tx = c.transaction()?;
                check_throttle(&tx, &apr2.connection.connection_id, &apr2.resource.resource_id, &apr2.requested.operations, &now)?;
                if !store::insert_op(&tx, &row_op, task_id.as_deref())? {
                    return Ok(false);
                }
                store::transition(&tx, &oid, &[OperationStatus::Received], OperationStatus::PolicyChecked, &now, OpUpdate::default())?;
                store::transition(
                    &tx,
                    &oid,
                    &[OperationStatus::PolicyChecked],
                    OperationStatus::AwaitingApproval,
                    &now,
                    OpUpdate {
                        approval_request_id: Some(&apr2.approval_request_id),
                        ..Default::default()
                    },
                )?;
                store::insert_approval(&tx, &apr2)?;
                audit::append(
                    &tx,
                    now,
                    Audit::new(apr2.connection.connection_id.as_str(), "approval.requested")
                        .operation(&oid)
                        .resource(&apr2.resource.resource_id)
                        .outcome("pending")
                        .detail(json!({
                            "approval_request_id": apr2.approval_request_id.as_str(),
                            "kind": "operation",
                            "operation": row_op.op.operation,
                            "parameters_digest": row_op.op.parameters_digest,
                            "parameters": params_summary,
                            "expires_at": aipass_types::time::format_rfc3339(&apr2.expires_at),
                        })),
                )?;
                tx.commit()?;
                Ok(true)
            })
            .await?;
        if !inserted {
            return self.idempotency_race(conn, req, &rdigest, &normalized, lang).await;
        }
        self.announce_approval(&apr).await;
        let mut resp = OperationResponse::approval_required(op_id, apr.approval_request_id.clone(), OPERATION_APPROVAL_TTL_SECS);
        if lang == Lang::En {
            resp.message = Some(APPROVAL_REQUIRED_MESSAGE_EN.to_owned());
        }
        Ok(resp)
    }

    /// Emit + relay a freshly created approval request.
    pub(crate) async fn announce_approval(&self, apr: &ApprovalRequest) {
        self.emit(BrokerEvent::ApprovalRequested {
            request: Box::new(apr.clone()),
        });
        if let Some(op) = &apr.operation_id {
            self.emit(BrokerEvent::OperationUpdated {
                operation_id: op.clone(),
                connection_id: apr.connection.connection_id.clone(),
                status: OperationStatus::AwaitingApproval,
            });
        }
        self.notify_devices(RelayMessage::ApprovalRequest(Box::new(apr.clone())), None).await;
    }

    // ------------------------------------------------------------- execution

    pub(crate) fn spawn_run(self: &Arc<Self>, plan: RunPlan) -> JoinHandle<Result<OpRow, ApiError>> {
        let (done, _) = watch::channel(false);
        let inflight = Arc::new(Inflight {
            connection_id: plan.connection_id.clone(),
            grant_id: plan.grant_id.clone(),
            executor_id: plan.resource.executor_id.clone(),
            token: CancellationToken::new(),
            started: std::sync::atomic::AtomicBool::new(false),
            reason: std::sync::Mutex::new(None),
            done,
        });
        if let Ok(mut m) = self.inflight.lock() {
            m.insert(plan.op_id.clone(), inflight.clone());
        }
        let me = self.clone();
        tokio::spawn(async move {
            // Removes the registry entry and signals waiters even if the run unwinds.
            let guard = InflightGuard {
                broker: me.clone(),
                op_id: plan.op_id.clone(),
                inflight: inflight.clone(),
            };
            let out = me.run_op(&plan, &inflight).await;
            drop(guard);
            me.maybe_drop_credential(&plan.grant_id).await;
            if let Ok(row) = &out {
                me.emit(BrokerEvent::OperationUpdated {
                    operation_id: plan.op_id.clone(),
                    connection_id: plan.connection_id.clone(),
                    status: row.op.status,
                });
            }
            out
        })
    }

    async fn run_op(&self, plan: &RunPlan, f: &Inflight) -> Result<OpRow, ApiError> {
        // Queue: wait for an executor slot (the `authorized` state stop_access rejects).
        let permit = tokio::select! {
            biased;
            _ = f.token.cancelled() => None,
            p = plan.slot.permits.clone().acquire_owned() => p.ok(),
        };
        let Some(_permit) = permit else {
            return self.finish_unstarted(plan, f.cancel_reason(), true).await;
        };
        if f.token.is_cancelled() {
            return self.finish_unstarted(plan, f.cancel_reason(), true).await;
        }
        // Run checks.
        if let Err(e) = plan.slot.ready() {
            return self.finish_unstarted_err(plan, e).await;
        }
        if !self.ensure_credential(plan).await {
            return self
                .finish_unstarted_err(
                    plan,
                    ApiError::new(ErrorCode::SecretUnavailable),
                )
                .await;
        }
        // Counted as running from here on: a revocation racing the reservation must treat
        // it as possibly executing (conservative `end_sessions` reporting).
        f.started.store(true, Ordering::SeqCst);
        let reservation = match self.reserve(plan).await? {
            Ok(r) => r,
            Err((code, cancelled)) => {
                let e = ApiError::new(code);
                return if cancelled {
                    self.finish_unstarted(plan, Some(e.code), true).await
                } else {
                    self.finish_unstarted_err(plan, e).await
                };
            }
        };
        let settlement = self.execute_guarded(plan, f, &reservation).await;
        self.settle(plan, &reservation, settlement).await
    }

    /// Credential present at the executor (or obtainable from the in-process source).
    async fn ensure_credential(&self, plan: &RunPlan) -> bool {
        let gid = plan.grant_id.clone();
        let Ok(Some(row)) = self.db.call(move |c| store::get_grant(c, &gid)).await else {
            return false;
        };
        if row.cred == CredState::Installed {
            return true;
        }
        if self.credential_source().is_some() {
            return self.install_credential_for(&row, &plan.resource, None).await == CredState::Installed;
        }
        false
    }

    /// Atomic budget reservation + `authorized → running`.
    async fn reserve(&self, plan: &RunPlan) -> Result<Result<Reservation, (ErrorCode, bool)>, ApiError> {
        let now = self.now();
        let (gid, cid, oid, rid) = (
            plan.grant_id.clone(),
            plan.connection_id.clone(),
            plan.op_id.clone(),
            plan.resource.resource_id.clone(),
        );
        self.db
            .call(move |c| {
                let tx = c.transaction()?;
                let Some(g) = store::get_grant(&tx, &gid)? else {
                    return Ok(Err((ErrorCode::GrantRevoked, true)));
                };
                // A grant bound to another operation never pays for this one (BRK-01).
                if g.bound_operation.as_ref().is_some_and(|b| b != &oid) {
                    return Ok(Err((ErrorCode::ScopeDenied, false)));
                }
                let conn = store::get_connection(&tx, &cid)?;
                match conn.as_ref().map(|r| r.conn.status) {
                    Some(ConnectionStatus::Active) => {}
                    Some(ConnectionStatus::Paused) => return Ok(Err((ErrorCode::ConnectionPaused, true))),
                    _ => return Ok(Err((ErrorCode::GrantRevoked, true))),
                }
                let visible = match (store::get_resource(&tx, &rid)?, &conn) {
                    (Some(r), Some(cr)) => store::visible(&cr.conn, &r.resource.project_id) && r.resource.status != ResourceStatus::Disabled,
                    _ => false,
                };
                if !visible {
                    return Ok(Err((ErrorCode::ScopeDenied, true)));
                }
                match g.grant.status {
                    GrantStatus::Active => {}
                    GrantStatus::Revoked | GrantStatus::Released => return Ok(Err((ErrorCode::GrantRevoked, true))),
                    GrantStatus::Expired => return Ok(Err((ErrorCode::GrantExpired, false))),
                    GrantStatus::Exhausted => return Ok(Err((ErrorCode::BudgetExhausted, false))),
                }
                if g.grant.expires_at <= now {
                    return Ok(Err((ErrorCode::GrantExpired, false)));
                }
                let rem = g.remaining();
                if rem.max_requests_per_grant == 0 || rem.max_rows_per_operation == 0 {
                    return Ok(Err((ErrorCode::BudgetExhausted, false)));
                }
                let rows = rem.max_rows_per_operation;
                let n = tx.execute(
                    "UPDATE grants SET used_requests = used_requests + 1, reserved_rows = reserved_rows + ?2
                     WHERE grant_id = ?1 AND status = 'active'",
                    rusqlite::params![gid.as_str(), i(rows)],
                )?;
                if n != 1 {
                    return Ok(Err((ErrorCode::GrantRevoked, true)));
                }
                if !store::transition(&tx, &oid, &[OperationStatus::Authorized], OperationStatus::Running, &now, OpUpdate::default())? {
                    return Ok(Err((ErrorCode::GrantRevoked, true)));
                }
                tx.commit()?;
                Ok(Ok(Reservation {
                    rows,
                    remaining: Limits {
                        max_rows_per_operation: rows,
                        max_rows_per_grant: rows,
                        max_requests_per_grant: rem.max_requests_per_grant,
                        max_result_bytes: rem.max_result_bytes,
                    },
                }))
            })
            .await
    }

    /// Execute with cancellation, a broker-side timeout and the retry rule.
    async fn execute_guarded(&self, plan: &RunPlan, f: &Inflight, res: &Reservation) -> Settlement {
        let interrupted_side = side_effects_if_interrupted(&plan.spec);
        let mut attempts = 0u32;
        loop {
            attempts += 1;
            let req = ExecutionRequest {
                operation_id: plan.op_id.clone(),
                grant_id: plan.grant_id.clone(),
                resource: plan.resource.clone(),
                normalized: plan.normalized.clone(),
                remaining: res.remaining,
                cancel: f.token.clone(),
            };
            let backend = plan.slot.backend.clone();
            // A panicking connector must not leave the operation stuck in `running`.
            let fut = std::panic::AssertUnwindSafe(backend.execute(req))
                .catch_unwind()
                .map(|r| {
                    r.unwrap_or_else(|_| {
                        tracing::error!("executor panicked during execute");
                        Err(ApiError::internal())
                    })
                });
            tokio::pin!(fut);
            let deadline = tokio::time::sleep(self.cfg.operation_timeout);
            tokio::pin!(deadline);
            let raced = tokio::select! {
                biased;
                r = &mut fut => Raced::Done(r),
                _ = f.token.cancelled() => Raced::Cancelled,
                _ = &mut deadline => Raced::TimedOut,
            };
            let (outcome, cancelled, timed_out) = match raced {
                Raced::Done(r) => (Some(r), f.token.is_cancelled(), false),
                other => {
                    let timed_out = matches!(other, Raced::TimedOut);
                    if timed_out {
                        f.token.cancel();
                    }
                    let _ = tokio::time::timeout(self.cfg.revoke_step_timeout, plan.slot.backend.cancel(plan.op_id.as_str())).await;
                    let late = tokio::time::timeout(self.cfg.cancel_grace, &mut fut).await.ok();
                    (late, !timed_out, timed_out)
                }
            };
            let reason = f.cancel_reason();
            match outcome {
                Some(Ok(out)) => {
                    // Completed. A revocation/pause that raced it withholds the result
                    // (data not yet handed to the model is not handed over).
                    if cancelled && reason.is_some() {
                        let rows = out.rows.unwrap_or(0);
                        return Settlement {
                            status: OperationStatus::Cancelled,
                            result: None,
                            error: reason.map(ApiError::new),
                            side_effects: out.side_effects,
                            rows_used: rows,
                            bytes_used: 0,
                            attempts,
                        };
                    }
                    return self.classify_success(out, res, attempts);
                }
                Some(Err(e)) => {
                    if timed_out {
                        return timeout_settlement(&plan.spec, res, attempts);
                    }
                    if cancelled {
                        return Settlement {
                            status: OperationStatus::Cancelled,
                            result: None,
                            error: reason.map(ApiError::new),
                            side_effects: interrupted_side,
                            rows_used: 0,
                            bytes_used: 0,
                            attempts,
                        };
                    }
                    if e.code == ErrorCode::UpstreamOutcomeUnknown {
                        if plan.spec.retry_safe && attempts < 2 && !f.token.is_cancelled() {
                            continue;
                        }
                        return Settlement {
                            status: OperationStatus::Unknown,
                            result: None,
                            error: Some(e),
                            side_effects: SideEffects::Possible,
                            rows_used: res.rows,
                            bytes_used: 0,
                            attempts,
                        };
                    }
                    return Settlement {
                        status: OperationStatus::Failed,
                        result: None,
                        error: Some(e),
                        side_effects: SideEffects::None,
                        rows_used: 0,
                        bytes_used: 0,
                        attempts,
                    };
                }
                None => {
                    if timed_out {
                        return timeout_settlement(&plan.spec, res, attempts);
                    }
                    return Settlement {
                        status: OperationStatus::Cancelled,
                        result: None,
                        error: reason.map(ApiError::new),
                        side_effects: interrupted_side,
                        rows_used: if interrupted_side == SideEffects::None { 0 } else { res.rows },
                        bytes_used: 0,
                        attempts,
                    };
                }
            }
        }
    }

    fn classify_success(&self, out: ExecutionOutcome, res: &Reservation, attempts: u32) -> Settlement {
        let computed = serde_json::to_vec(&out.data).map(|v| v.len() as u64).unwrap_or(u64::MAX);
        let bytes = out.bytes.max(computed);
        let rows = out.rows.unwrap_or(0);
        if rows > res.rows {
            return Settlement {
                status: OperationStatus::Failed,
                result: None,
                error: Some(
                    ApiError::new(ErrorCode::ResultRestricted)
                        .with_message("执行设备返回的行数超出本次额度，结果未返回", "The executor returned more rows than the remaining budget; the result was withheld.")
                        .with_detail("rows", rows)
                        .with_detail("allowed_rows", res.rows),
                ),
                side_effects: out.side_effects,
                rows_used: rows,
                bytes_used: 0,
                attempts,
            };
        }
        if bytes > res.remaining.max_result_bytes {
            return Settlement {
                status: OperationStatus::Failed,
                result: None,
                error: Some(
                    ApiError::new(ErrorCode::ResultRestricted)
                        .with_message("结果超出允许的大小上限，未返回", "The result exceeds the allowed size and was withheld.")
                        .with_detail("bytes", bytes)
                        .with_detail("max_result_bytes", res.remaining.max_result_bytes),
                ),
                side_effects: out.side_effects,
                rows_used: rows,
                bytes_used: 0,
                attempts,
            };
        }
        let restricted = !out.restricted_fields.is_empty();
        Settlement {
            status: OperationStatus::Succeeded,
            result: Some(OperationResult {
                data: out.data,
                rows: out.rows,
                truncated: out.truncated,
                restricted,
                restricted_fields: out.restricted_fields,
            }),
            error: None,
            side_effects: out.side_effects,
            rows_used: rows,
            bytes_used: bytes,
            attempts,
        }
    }

    /// `running → terminal`, budget settled, audit appended — one transaction.
    async fn settle(&self, plan: &RunPlan, res: &Reservation, mut s: Settlement) -> Result<OpRow, ApiError> {
        let now = self.now();
        let (gid, oid, cid, rid) = (
            plan.grant_id.clone(),
            plan.op_id.clone(),
            plan.connection_id.clone(),
            plan.resource.resource_id.clone(),
        );
        let reserved = res.rows;
        let op_name = plan.normalized.operation.clone();
        let pdigest = plan.normalized.parameters_digest.clone();
        let mark_secret_missing = s.error.as_ref().is_some_and(|e| e.code == ErrorCode::SecretUnavailable);
        let needs_login = s.error.as_ref().is_some_and(|e| e.code == ErrorCode::InteractiveAuthRequired);
        let row = self
            .db
            .call(move |c| {
                let tx = c.transaction()?;
                let g = store::get_grant(&tx, &gid)?;
                if s.status == OperationStatus::Succeeded
                    && g.as_ref().is_some_and(|g| matches!(g.grant.status, GrantStatus::Revoked | GrantStatus::Released))
                {
                    s.status = OperationStatus::Cancelled;
                    s.result = None;
                    s.error = Some(ApiError::new(ErrorCode::GrantRevoked));
                    s.bytes_used = 0;
                }
                tx.execute(
                    "UPDATE grants SET used_rows = used_rows + ?2, used_bytes = used_bytes + ?3,
                        reserved_rows = MAX(reserved_rows - ?4, 0) WHERE grant_id = ?1",
                    rusqlite::params![gid.as_str(), i(s.rows_used), i(s.bytes_used), i(reserved)],
                )?;
                if mark_secret_missing {
                    store::set_cred_state(&tx, &gid, CredState::None)?;
                }
                if needs_login
                    && let Some(mut r) = store::get_resource(&tx, &rid)?
                        && r.resource.status == ResourceStatus::Available {
                            r.resource.status = ResourceStatus::NeedsLogin;
                            store::upsert_resource(&tx, &r.resource)?;
                        }
                if let Some(g) = store::get_grant(&tx, &gid)?
                    && g.grant.status == GrantStatus::Active && g.is_exhausted() {
                        store::set_grant_status(&tx, &gid, &[GrantStatus::Active], GrantStatus::Exhausted)?;
                        audit::append(
                            &tx,
                            now,
                            Audit::new("system", "grant.exhausted")
                                .grant(&gid)
                                .resource(&rid)
                                .detail(json!({
                                    "requests": g.grant.usage.requests,
                                    "rows": g.grant.usage.rows,
                                })),
                        )?;
                    }
                let stored = s.error.as_ref().map(StoredError::from_api);
                store::transition(
                    &tx,
                    &oid,
                    &[OperationStatus::Running],
                    s.status,
                    &now,
                    OpUpdate {
                        result: s.result.as_ref(),
                        error: stored.as_ref(),
                        side_effects: Some(s.side_effects),
                        ..Default::default()
                    },
                )?;
                let action = match s.status {
                    OperationStatus::Succeeded => "operation.succeeded",
                    OperationStatus::Unknown => "operation.unknown",
                    OperationStatus::Cancelled => "operation.cancelled",
                    _ => "operation.failed",
                };
                let mut a = Audit::new(cid.as_str(), action)
                    .operation(&oid)
                    .resource(&rid)
                    .grant(&gid)
                    .outcome(match s.status {
                        OperationStatus::Succeeded => "ok",
                        OperationStatus::Unknown => "unknown",
                        OperationStatus::Cancelled => "cancelled",
                        _ => "error",
                    })
                    .detail(json!({
                        "operation": op_name,
                        "parameters_digest": pdigest,
                        "rows": s.rows_used,
                        "bytes": s.bytes_used,
                        "truncated": s.result.as_ref().is_some_and(|r| r.truncated),
                        "restricted_fields": s.result.as_ref().map(|r| r.restricted_fields.clone()).unwrap_or_default(),
                        "side_effects": enum_str(&s.side_effects),
                        "attempts": s.attempts,
                    }));
                if let Some(e) = &s.error {
                    a.error_code = Some(e.code);
                }
                audit::append(&tx, now, a)?;
                tx.commit()?;
                store::get_op(c, &oid)
            })
            .await?;
        row.ok_or_else(ApiError::internal)
    }

    async fn finish_unstarted(&self, plan: &RunPlan, reason: Option<ErrorCode>, cancelled: bool) -> Result<OpRow, ApiError> {
        let to = if cancelled { OperationStatus::Cancelled } else { OperationStatus::Failed };
        self.finish_unstarted_with(plan, to, reason.map(ApiError::new)).await
    }

    async fn finish_unstarted_err(&self, plan: &RunPlan, e: ApiError) -> Result<OpRow, ApiError> {
        self.finish_unstarted_with(plan, OperationStatus::Failed, Some(e)).await
    }

    async fn finish_unstarted_with(&self, plan: &RunPlan, to: OperationStatus, e: Option<ApiError>) -> Result<OpRow, ApiError> {
        let now = self.now();
        let (oid, cid, rid, gid) = (
            plan.op_id.clone(),
            plan.connection_id.clone(),
            plan.resource.resource_id.clone(),
            plan.grant_id.clone(),
        );
        let row = self
            .db
            .call(move |c| {
                let tx = c.transaction()?;
                let stored = e.as_ref().map(StoredError::from_api);
                store::transition(
                    &tx,
                    &oid,
                    &[OperationStatus::Authorized],
                    to,
                    &now,
                    OpUpdate {
                        error: stored.as_ref(),
                        side_effects: Some(SideEffects::None),
                        ..Default::default()
                    },
                )?;
                let mut a = Audit::new(cid.as_str(), if to == OperationStatus::Cancelled { "operation.cancelled" } else { "operation.failed" })
                    .operation(&oid)
                    .resource(&rid)
                    .grant(&gid)
                    .outcome(if to == OperationStatus::Cancelled { "cancelled" } else { "error" })
                    .detail(json!({ "started": false }));
                if let Some(e) = &e {
                    a.error_code = Some(e.code);
                }
                audit::append(&tx, now, a)?;
                tx.commit()?;
                store::get_op(c, &oid)
            })
            .await?;
        row.ok_or_else(ApiError::internal)
    }

    // ------------------------------------------------------------- status / cancel

    /// Build the API view of an operation (lazy approval expiry included).
    pub(crate) async fn op_response(&self, mut row: OpRow, lang: Lang) -> Result<OperationResponse, ApiError> {
        if row.op.status == OperationStatus::AwaitingApproval
            && let Some(apr) = row.op.approval_request_id.clone() {
                let a2 = apr.clone();
                let approval = self.db.call(move |c| store::get_approval(c, &a2)).await?;
                let now = self.now();
                if let Some(a) = approval {
                    if a.req.status == ApprovalStatus::Pending && now >= a.req.expires_at {
                        self.expire_approval(&apr).await?;
                        let oid = row.op.operation_id.clone();
                        if let Some(r) = self.db.call(move |c| store::get_op(c, &oid)).await? {
                            row = r;
                        }
                    } else if row.op.status == OperationStatus::AwaitingApproval {
                        let left = (unix(&a.req.expires_at) - unix(&now)).max(0);
                        return Ok(OperationResponse {
                            status: OperationStatus::AwaitingApproval,
                            operation_id: row.op.operation_id,
                            approval_request_id: Some(apr),
                            expires_in_seconds: Some(left as u64),
                            message: Some(match lang {
                                Lang::ZhCn => APPROVAL_REQUIRED_MESSAGE.to_owned(),
                                Lang::En => APPROVAL_REQUIRED_MESSAGE_EN.to_owned(),
                            }),
                            result: None,
                            error: None,
                        });
                    }
                }
            }
        let message = match row.op.status {
            OperationStatus::Received | OperationStatus::PolicyChecked | OperationStatus::Authorized | OperationStatus::Running => Some(match lang {
                Lang::ZhCn => "操作正在执行，请稍后用 operations_status 查询结果。".to_owned(),
                Lang::En => "The operation is running; check operations_status for the result.".to_owned(),
            }),
            OperationStatus::Unknown => Some(match lang {
                Lang::ZhCn => "外部服务可能已执行，请先核实再决定是否重试（需使用新的幂等标识）。".to_owned(),
                Lang::En => "The external service may have executed this; verify before retrying (with a new idempotency key).".to_owned(),
            }),
            _ => None,
        };
        Ok(OperationResponse {
            status: row.op.status,
            operation_id: row.op.operation_id,
            approval_request_id: row.op.approval_request_id,
            expires_in_seconds: None,
            message,
            result: row.op.result,
            error: row.error.map(|e| e.to_object(lang)),
        })
    }

    async fn own_operation(&self, conn: &ConnectionId, id: &OperationId) -> Result<OpRow, ApiError> {
        let (oid, cid) = (id.clone(), conn.clone());
        self.db
            .call(move |c| Ok(store::get_op(c, &oid)?.filter(|r| r.op.connection_id == cid)))
            .await?
            .ok_or_else(ApiError::not_found)
    }

    /// `GET /v1/operations/{id}` — own operations only (`NOT_FOUND` otherwise).
    pub async fn get_operation(&self, p: &ConnectionPrincipal, id: &OperationId, lang: Lang) -> Result<OperationResponse, ApiError> {
        let conn = self.active_connection(p).await?;
        let row = self.own_operation(&conn.connection_id, id).await?;
        self.op_response(row, lang).await
    }

    /// `POST /v1/operations/{id}/cancel`. Allowed for active and paused connections
    /// (cancelling only reduces activity).
    pub async fn cancel_operation(&self, p: &ConnectionPrincipal, id: &OperationId, lang: Lang) -> Result<CancelResponse, ApiError> {
        let cid = p.connection_id().clone();
        let c2 = cid.clone();
        let conn = self
            .db
            .call(move |c| store::get_connection(c, &c2))
            .await?
            .ok_or_else(ApiError::identity_unverified)?;
        if !matches!(conn.conn.status, ConnectionStatus::Active | ConnectionStatus::Paused) {
            return Err(ApiError::identity_unverified());
        }
        let row = self.own_operation(&cid, id).await?;
        let msg = |zh: &str, en: &str| match lang {
            Lang::ZhCn => zh.to_owned(),
            Lang::En => en.to_owned(),
        };
        match row.op.status {
            OperationStatus::AwaitingApproval => {
                let now = self.now();
                let (oid, apr) = (id.clone(), row.op.approval_request_id.clone());
                let actor = cid.as_str().to_owned();
                let changed = self
                    .db
                    .call(move |c| {
                        let tx = c.transaction()?;
                        let ok = store::transition(&tx, &oid, &[OperationStatus::AwaitingApproval], OperationStatus::Cancelled, &now, OpUpdate::default())?;
                        if ok {
                            if let Some(a) = &apr {
                                store::resolve_approval(&tx, a, ApprovalStatus::Cancelled, &now, Some(&actor), None)?;
                            }
                            audit::append(&tx, now, Audit::new(actor.clone(), "operation.cancelled").operation(&oid).outcome("cancelled"))?;
                        }
                        tx.commit()?;
                        Ok(ok)
                    })
                    .await?;
                if changed {
                    if let Some(a) = &row.op.approval_request_id {
                        self.approval_gone(a, ApprovalStatus::Cancelled, "cancelled_by_requester", None).await;
                    }
                    return Ok(CancelResponse {
                        operation_id: id.clone(),
                        status: OperationStatus::Cancelled,
                        cancelled: true,
                        side_effects: SideEffects::None,
                        message: msg("已取消，未执行任何外部操作。", "Cancelled; nothing was sent to the external service."),
                    });
                }
            }
            OperationStatus::Authorized | OperationStatus::Running | OperationStatus::Received | OperationStatus::PolicyChecked => {
                if let Some(f) = self.inflight_get(id) {
                    f.cancel_with(None);
                    if f.started.load(Ordering::SeqCst)
                        && let Some(slot) = self.executor_slot(&f.executor_id) {
                            let _ = tokio::time::timeout(self.cfg.revoke_step_timeout, slot.backend.cancel(id.as_str())).await;
                        }
                    f.wait_done(self.cfg.cancel_wait).await;
                }
            }
            _ => {}
        }
        let row = self.own_operation(&cid, id).await?;
        let st = row.op.status;
        let (cancelled, message) = match st {
            OperationStatus::Cancelled => (
                true,
                if row.op.side_effects == SideEffects::None {
                    msg("已取消，未对外部服务产生影响。", "Cancelled; the external service was not affected.")
                } else {
                    msg("已取消；外部服务可能已执行部分操作，请核实。", "Cancelled; the external service may already have acted — please verify.")
                },
            ),
            s if s.is_terminal() => (false, msg("操作已结束，无法取消。", "The operation already finished and cannot be cancelled.")),
            _ => (false, msg("已请求取消，操作仍在停止中。", "Cancellation requested; the operation is still stopping.")),
        };
        Ok(CancelResponse {
            operation_id: id.clone(),
            status: st,
            cancelled,
            side_effects: row.op.side_effects,
            message,
        })
    }

    /// `GET /v1/operations?limit=` (D, A) — metadata only; results are stripped.
    pub async fn list_operations(&self, limit: u64) -> Result<OperationsResponse, ApiError> {
        let limit = limit.clamp(1, 500);
        let rows = self
            .db
            .call(move |c| store::query_ops(c, "1 = 1 ORDER BY created_at DESC, operation_id DESC LIMIT ?1", &[&i(limit)]))
            .await?;
        Ok(OperationsResponse {
            operations: rows.into_iter().map(|r| operation_metadata(r, Lang::ZhCn)).collect(),
        })
    }

    /// Notify devices / listeners that an approval left the pending state.
    pub(crate) async fn approval_gone(&self, id: &ApprovalRequestId, status: ApprovalStatus, reason: &str, except: Option<aipass_types::ids::DeviceId>) {
        self.emit(BrokerEvent::ApprovalResolved {
            approval_request_id: id.clone(),
            status,
        });
        self.notify_devices(
            RelayMessage::ApprovalCancelled(ApprovalCancelled {
                approval_request_id: id.clone(),
                reason: reason.to_owned(),
            }),
            except,
        )
        .await;
    }
}

/// An operation record without its result body (admin listings, snapshots).
pub(crate) fn operation_metadata(r: OpRow, lang: Lang) -> Operation {
    let mut op = r.op;
    op.result = None;
    op.error = r.error.map(|e| e.to_object(lang));
    op
}

fn new_operation(conn: &AppConnection, resource: &Resource, n: &NormalizedRequest, req: &OperationRequest, now: aipass_types::Timestamp) -> Operation {
    Operation {
        operation_id: OperationId::generate(),
        connection_id: conn.connection_id.clone(),
        resource_id: resource.resource_id.clone(),
        operation: n.operation.clone(),
        parameters_digest: n.parameters_digest.clone(),
        idempotency_key: req.idempotency_key.clone(),
        status: OperationStatus::Received,
        grant_id: None,
        approval_request_id: None,
        result: None,
        error: None,
        side_effects: SideEffects::None,
        created_at: now,
        updated_at: now,
    }
}

fn timeout_settlement(spec: &OperationSpec, res: &Reservation, attempts: u32) -> Settlement {
    if spec.side_effect == SideEffectClass::Read {
        Settlement {
            status: OperationStatus::Failed,
            result: None,
            error: Some(
                ApiError::new(ErrorCode::UpstreamError)
                    .with_message("外部服务响应超时", "The external service timed out.")
                    .with_detail("reason", "timeout"),
            ),
            side_effects: SideEffects::None,
            rows_used: 0,
            bytes_used: 0,
            attempts,
        }
    } else {
        Settlement {
            status: OperationStatus::Unknown,
            result: None,
            error: Some(ApiError::new(ErrorCode::UpstreamOutcomeUnknown).with_detail("reason", "timeout")),
            side_effects: SideEffects::Possible,
            rows_used: res.rows,
            bytes_used: 0,
            attempts,
        }
    }
}

/// Throttle rules (§6.2 rule 5): a denial of the same connection + resource + operation
/// in the last 10 minutes, or more than 5 pending approvals → `RATE_LIMITED`.
pub(crate) fn check_throttle(
    c: &rusqlite::Connection,
    conn: &ConnectionId,
    res: &ResourceId,
    operations: &[String],
    now: &aipass_types::Timestamp,
) -> SResult<()> {
    let since = aipass_types::time::add_secs(now, -DENIAL_THROTTLE_SECS);
    for op in operations {
        if store::recently_denied(c, conn, res, op, &since)? {
            return Err(err(
                ErrorCode::RateLimited,
                "同类请求刚被拒绝，请稍后再试（约 10 分钟内不再提醒）",
                "A similar request was just denied; try again later (no new prompts for about 10 minutes).",
            )
            .with_detail("reason", "recently_denied")
            .with_detail("retry_after_seconds", DENIAL_THROTTLE_SECS)
            .into());
        }
    }
    if store::pending_approvals_for_connection(c, conn, now)? >= MAX_PENDING_APPROVALS_PER_CONNECTION {
        return Err(err(
            ErrorCode::RateLimited,
            "待批准的请求过多，请先在可信设备上处理",
            "Too many requests are waiting for approval; handle them on a trusted device first.",
        )
        .with_detail("reason", "too_many_pending_approvals")
        .into());
    }
    Ok(())
}

fn truncate(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}
