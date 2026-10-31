// SPDX-License-Identifier: Apache-2.0
//! PostgreSQL connector: `postgres.query_view` (V1) and, with the `experimental` feature,
//! `credentials.rotate` (scheme `postgres.password`) and `lease_mode: "temporary_role"`.
//!
//! Execution of `postgres.query_view`:
//!
//! 1. parameters re-validated against the resource allowlist (exact names only);
//! 2. a per-grant session (TLS per `sslmode`) authenticated with the grant's credential —
//!    new sessions are refused when the role is superuser / BYPASSRLS / a server-file role,
//!    unless `allow_superuser` is set;
//! 3. `BEGIN READ ONLY` (sessions also default to read-only), `SET LOCAL statement_timeout`,
//!    `SET LOCAL search_path TO pg_catalog, pg_temp`;
//! 4. column types from `information_schema.columns` (cached 5 min per role and view);
//! 5. `SELECT row_to_json(t)::text FROM (SELECT "f", … FROM "s"."v" WHERE … LIMIT cap+1) t`
//!    with every value a text parameter cast to the column type;
//! 6. row cap = min(`limit`, config cap, grant per-op limit, remaining grant rows); byte cap
//!    = remaining `max_result_bytes`;
//! 7. rows pass the output filter; the transaction is rolled back.
//!
//! Cancellation (`operations.cancel`, `end_sessions`) sends a PostgreSQL cancel request for
//! the running statement and discards the session.

pub mod config;
#[cfg(feature = "experimental")]
pub(crate) mod lease;
pub mod query;
#[cfg(feature = "experimental")]
pub(crate) mod rotate;
pub(crate) mod session;

use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use aipass_types::exec::{ExecutionOutcome, LevelReport, NormalizedRequest, OperationSpec, Stage};
use aipass_types::models::{Connector, Resource, SideEffectClass, SideEffects};
use aipass_types::vault::EntryKind;
use aipass_types::{ApiError, GrantId};
use async_trait::async_trait;
use futures::TryStreamExt;
use serde_json::{Value, json};

use self::config::{LeaseMode, PgConfig, split_view};
use self::query::{ColumnType, QUERY_VIEW, QueryView};
use self::session::{PgTarget, Session, SessionKind, SessionPool};
use crate::connectors::{ConnectorDriver, ExecContext, SessionsClosed};
use crate::errors;

/// Column-type cache lifetime.
pub const TYPE_CACHE_TTL: Duration = Duration::from_secs(300);

type TypeKey = (String, String, String);
type ColumnTypes = Arc<HashMap<String, ColumnType>>;

/// The PostgreSQL driver.
#[derive(Default)]
pub struct PostgresDriver {
    pool: SessionPool,
    types: Mutex<HashMap<TypeKey, (Instant, ColumnTypes)>>,
    #[cfg(feature = "experimental")]
    pub(crate) leases: lease::LeaseManager,
    #[cfg(feature = "experimental")]
    pub(crate) rotations: rotate::RotationStore,
}

impl std::fmt::Debug for PostgresDriver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PostgresDriver")
    }
}

/// Spec of `postgres.query_view`.
pub fn query_view_spec() -> OperationSpec {
    OperationSpec {
        name: QUERY_VIEW.to_owned(),
        connector: Connector::Postgres,
        description_zh: "只读查询资源允许的视图：选择允许的字段，可按条件过滤、排序并限制行数；不能执行任意 SQL。".to_owned(),
        description_en: "Read-only query of an allowlisted view: select allowed fields, filter, sort and limit rows. Arbitrary SQL is not possible.".to_owned(),
        side_effect: SideEffectClass::Read,
        retry_safe: true,
        parameters_schema: query::parameters_schema(),
        stage: Stage::V1,
    }
}

/// Spec of `credentials.rotate` (experimental).
#[cfg(feature = "experimental")]
pub fn rotate_spec() -> OperationSpec {
    OperationSpec {
        name: rotate::ROTATE.to_owned(),
        connector: Connector::Postgres,
        description_zh: "实验性：为该数据库账号生成新的随机密码并验证可用；新密码只加密送达批准的可信设备，AI 不会得到它。不能保证所有外部使用方都已更新。".to_owned(),
        description_en: "Experimental: set a new random password for this database role and verify it; the new password is delivered, encrypted, only to the approving trusted device and never to the AI. Other consumers of the old password are not updated automatically.".to_owned(),
        side_effect: SideEffectClass::Irreversible,
        retry_safe: false,
        parameters_schema: json!({
            "type": "object", "additionalProperties": false, "required": ["scheme"],
            "properties": {"scheme": {"type": "string", "enum": [rotate::SCHEME_POSTGRES_PASSWORD]}}
        }),
        stage: Stage::V1_1,
    }
}

impl PostgresDriver {
    /// New driver.
    pub fn new() -> Self {
        Self::default()
    }

    /// Open sessions of a grant (tests / diagnostics).
    pub fn open_sessions(&self, grant_id: &GrantId) -> usize {
        self.pool.open_sessions(grant_id)
    }

    fn cached_types(&self, key: &TypeKey) -> Option<Arc<HashMap<String, ColumnType>>> {
        let g = self.types.lock().unwrap_or_else(|p| p.into_inner());
        g.get(key)
            .filter(|(at, _)| at.elapsed() < TYPE_CACHE_TTL)
            .map(|(_, t)| t.clone())
    }

    fn store_types(&self, key: TypeKey, t: Arc<HashMap<String, ColumnType>>) {
        let mut g = self.types.lock().unwrap_or_else(|p| p.into_inner());
        g.retain(|_, (at, _)| at.elapsed() < TYPE_CACHE_TTL);
        g.insert(key, (Instant::now(), t));
    }

    fn check_credential_target(ctx: &ExecContext, cfg: &PgConfig) -> Result<(), ApiError> {
        let m = ctx.credential.material();
        if !matches!(m.kind, EntryKind::Database | EntryKind::Login) {
            return Err(errors::secret_unavailable(
                "该凭证类型不能用于数据库",
                "This credential type cannot be used for a database.",
            ));
        }
        if m.username.as_deref().is_none_or(str::is_empty) {
            return Err(errors::secret_unavailable(
                "数据库凭证缺少用户名",
                "The database credential has no username.",
            ));
        }
        if let Some(db) = &m.database
            && (!db.host.eq_ignore_ascii_case(&cfg.host) || db.port != cfg.port)
        {
            // Never send a credential to a server other than the one it was saved for.
            return Err(errors::scope_denied(
                "凭证所属的数据库地址与资源配置不一致，已拒绝连接",
                "The credential belongs to a different database server than the resource; connection refused.",
            )
            .with_detail("reason", "credential_target_mismatch"));
        }
        Ok(())
    }

    async fn login_for(
        &self,
        ctx: &ExecContext,
        cfg: &PgConfig,
        target: &PgTarget,
    ) -> Result<(String, aipass_crypto::SecretString, u64), ApiError> {
        match cfg.lease_mode {
            LeaseMode::Static => {
                let m = ctx.credential.material();
                Ok((
                    m.username.clone().unwrap_or_default(),
                    m.secret.clone(),
                    ctx.credential.install_id(),
                ))
            }
            LeaseMode::TemporaryRole => {
                #[cfg(feature = "experimental")]
                {
                    let l = self
                        .leases
                        .ensure(&ctx.grant_id, cfg, target, ctx.credential.clone())
                        .await?;
                    Ok((l.role, l.password, l.cred_key))
                }
                #[cfg(not(feature = "experimental"))]
                {
                    let _ = target;
                    Err(errors::not_supported(
                        "临时数据库角色是实验性功能，此版本未启用",
                        "Temporary database roles are experimental and not enabled in this build.",
                    ))
                }
            }
        }
    }

    async fn query_view(&self, ctx: ExecContext) -> Result<ExecutionOutcome, ApiError> {
        let cfg = PgConfig::parse(&ctx.resource.config)?;
        Self::check_credential_target(&ctx, &cfg)?;
        let q: QueryView = serde_json::from_value(ctx.normalized.params.clone())
            .map_err(|_| errors::invalid("参数无效", "Invalid parameters."))?;
        let view_cfg = cfg
            .view(&q.view)
            .ok_or_else(|| errors::scope_denied("该视图不在允许范围内", "View not allowlisted."))?
            .clone();
        let cap = crate::connectors::row_cap(q.limit, cfg.max_rows_per_operation, &ctx.remaining)?;
        let byte_cap = crate::connectors::byte_cap(&ctx.remaining);
        let target = PgTarget::from_config(&cfg)?;
        let (user, password, cred_key) = self.login_for(&ctx, &cfg, &target).await?;

        let lease = tokio::select! {
            l = self.pool.acquire(&ctx.grant_id) => l?,
            _ = ctx.cancel.cancelled() => return Err(errors::cancelled()),
        };
        let mut session = match self.pool.take_idle(&ctx.grant_id, cred_key) {
            Some(s) => s,
            None => {
                let s = tokio::select! {
                    s = session::connect(&target, &user, password.expose(), SessionKind::Query, cred_key) => s?,
                    _ = ctx.cancel.cancelled() => return Err(errors::cancelled()),
                };
                match session::role_privileges(&s.client).await {
                    Ok(p) if p.is_privileged() && !cfg.allow_superuser => {
                        s.close();
                        return Err(session::privileged_role_error());
                    }
                    Ok(_) => s,
                    Err(e) => {
                        s.close();
                        return Err(e);
                    }
                }
            }
        };
        drop(password);
        self.pool.mark_active(&lease, &session);

        let (schema, view) =
            split_view(&q.view).ok_or_else(|| errors::bad_config("allowed_views"))?;
        let type_key: TypeKey = (
            format!(
                "{}|{}:{}/{}",
                ctx.resource.resource_id, cfg.host, cfg.port, cfg.dbname
            ),
            user.clone(),
            q.view.clone(),
        );
        let cached = self.cached_types(&type_key);
        let cancel_token = session.cancel_token.clone();
        let tls = session.tls.clone();
        let timeout_ms = cfg.statement_timeout_ms;

        let outcome = {
            let run = run_query(
                &mut session,
                schema,
                view,
                &q,
                &view_cfg,
                cached,
                cap,
                byte_cap,
                timeout_ms,
            );
            tokio::pin!(run);
            tokio::select! {
                r = &mut run => r,
                _ = ctx.cancel.cancelled() => {
                    Session::send_cancel(&cancel_token, &tls).await;
                    // Let the server abort the statement before the session is discarded.
                    let _ = tokio::time::timeout(Duration::from_secs(2), &mut run).await;
                    Err(errors::cancelled())
                }
            }
        };
        let reuse = outcome.is_ok();
        self.pool.release(lease, session, reuse);
        let (rows, types, truncated_by_fetch) = outcome?;
        if let Some(t) = types {
            self.store_types(type_key, t);
        }

        // Output filter (fields are already restricted by the SELECT list).
        let mut restricted = BTreeSet::new();
        let mut rows = rows;
        for r in rows.iter_mut() {
            ctx.filter.redact(r, "", &mut restricted);
        }
        let mut truncated = truncated_by_fetch;
        let fields = q.fields.clone();
        let view_name = q.view.clone();
        let wrap = |items: &[Value]| json!({"view": view_name, "fields": fields, "rows": items});
        if crate::connectors::fit_items(&mut rows, byte_cap, wrap) {
            truncated = true;
        }
        let n = rows.len() as u64;
        let data = wrap(&rows);
        crate::connectors::finish(
            &ctx.filter,
            data,
            Some(n),
            truncated,
            restricted,
            SideEffects::None,
            byte_cap,
        )
    }
}

type QueryOutput = (Vec<Value>, Option<Arc<HashMap<String, ColumnType>>>, bool);

#[allow(clippy::too_many_arguments)]
async fn run_query(
    session: &mut Session,
    schema: &str,
    view: &str,
    q: &QueryView,
    view_cfg: &config::ViewConfig,
    cached: Option<Arc<HashMap<String, ColumnType>>>,
    cap: u64,
    byte_cap: u64,
    timeout_ms: u64,
) -> Result<QueryOutput, ApiError> {
    let map = |e: tokio_postgres::Error| session::map_pg_error(&e);
    let txn = session
        .client
        .build_transaction()
        .read_only(true)
        .start()
        .await
        .map_err(map)?;
    // Integer literal from validated config; identifiers are fixed.
    txn.batch_execute(&format!(
        "SET LOCAL statement_timeout = {timeout_ms}; SET LOCAL lock_timeout = 2000; \
         SET LOCAL search_path TO pg_catalog, pg_temp"
    ))
    .await
    .map_err(map)?;
    let (types, fresh) = match cached {
        Some(t) => (t, None),
        None => {
            let rows = txn
                .query(query::COLUMNS_SQL, &[&schema, &view])
                .await
                .map_err(map)?;
            let t: HashMap<String, ColumnType> = rows
                .iter()
                .map(|r| {
                    (
                        r.get::<_, String>(0),
                        ColumnType {
                            udt_schema: r.get(1),
                            udt_name: r.get(2),
                        },
                    )
                })
                .collect();
            let t = Arc::new(t);
            (t.clone(), Some(t))
        }
    };
    if types.is_empty() {
        return Err(errors::scope_denied(
            "数据库账号无法读取该视图",
            "The database role cannot read this view.",
        )
        .with_detail("reason", "not_visible_to_role"));
    }
    let built = query::build(q, view_cfg, &types, cap + 1)?;
    let params: Vec<&(dyn tokio_postgres::types::ToSql + Sync)> = built
        .params
        .iter()
        .map(|p| p as &(dyn tokio_postgres::types::ToSql + Sync))
        .collect();
    let (out, truncated) = {
        let stream = txn.query_raw(&built.sql, params).await.map_err(map)?;
        tokio::pin!(stream);
        let mut out = Vec::new();
        let mut total: u64 = 0;
        let mut truncated = false;
        while let Some(row) = stream.try_next().await.map_err(map)? {
            if out.len() as u64 >= cap {
                truncated = true;
                break;
            }
            let text: Option<String> = row.get(0);
            let text = text.unwrap_or_else(|| "null".to_owned());
            total += text.len() as u64 + 1;
            if total > byte_cap.saturating_add(1024) {
                truncated = true;
                break;
            }
            let v: Value = serde_json::from_str(&text).map_err(|_| ApiError::internal())?;
            out.push(v);
        }
        (out, truncated)
    };
    txn.rollback().await.map_err(map)?;
    Ok((out, fresh, truncated))
}

#[async_trait]
impl ConnectorDriver for PostgresDriver {
    fn connector(&self) -> Connector {
        Connector::Postgres
    }

    fn operation_specs(&self) -> Vec<OperationSpec> {
        #[allow(unused_mut)]
        let mut v = vec![query_view_spec()];
        #[cfg(feature = "experimental")]
        v.push(rotate_spec());
        v
    }

    fn validate_config(&self, config: &Value) -> Result<(), ApiError> {
        PgConfig::parse(config).map(|_| ())
    }

    fn normalize(
        &self,
        resource: &Resource,
        operation: &str,
        params: &Value,
    ) -> Result<NormalizedRequest, ApiError> {
        crate::connectors::require_offered(resource, operation)?;
        let cfg = PgConfig::parse(&resource.config)?;
        match operation {
            QUERY_VIEW => {
                let (q, scope) = query::normalize(&cfg, params)?;
                let p = serde_json::to_value(&q).map_err(|_| ApiError::internal())?;
                crate::connectors::normalized(operation, p, scope)
            }
            #[cfg(feature = "experimental")]
            rotate::ROTATE => {
                let scheme = params
                    .as_object()
                    .filter(|o| o.len() == 1)
                    .and_then(|o| o.get("scheme"))
                    .and_then(Value::as_str);
                if scheme != Some(rotate::SCHEME_POSTGRES_PASSWORD) {
                    return Err(errors::invalid_param(
                        "scheme",
                        "仅支持轮换方案 postgres.password",
                        "Only the postgres.password rotation scheme is supported.",
                    ));
                }
                crate::connectors::normalized(
                    operation,
                    json!({"scheme": rotate::SCHEME_POSTGRES_PASSWORD}),
                    aipass_types::models::GrantScope {
                        operations: vec![rotate::ROTATE.to_owned()],
                        ..Default::default()
                    },
                )
            }
            _ => Err(errors::scope_denied(
                "PostgreSQL 连接器不提供此操作",
                "The PostgreSQL connector does not offer this operation.",
            )),
        }
    }

    async fn execute(&self, ctx: ExecContext) -> Result<ExecutionOutcome, ApiError> {
        match ctx.normalized.operation.as_str() {
            QUERY_VIEW => self.query_view(ctx).await,
            #[cfg(feature = "experimental")]
            rotate::ROTATE => {
                let cfg = PgConfig::parse(&ctx.resource.config)?;
                Self::check_credential_target(&ctx, &cfg)?;
                let target = PgTarget::from_config(&cfg)?;
                let out = rotate::rotate(&ctx, &cfg, &target, &self.rotations).await;
                if out.is_ok() {
                    // Sessions authenticated with the old password are closed.
                    let _ = self.pool.close_grant(&ctx.grant_id).await;
                }
                out
            }
            _ => Err(errors::scope_denied(
                "PostgreSQL 连接器不提供此操作",
                "The PostgreSQL connector does not offer this operation.",
            )),
        }
    }

    async fn end_sessions(&self, grant_id: &GrantId) -> SessionsClosed {
        self.pool.close_grant(grant_id).await
    }

    async fn revoke_upstream(&self, grant_id: &GrantId) -> LevelReport {
        #[cfg(feature = "experimental")]
        {
            self.leases.revoke(grant_id).await
        }
        #[cfg(not(feature = "experimental"))]
        {
            let _ = grant_id;
            LevelReport::not_applicable()
        }
    }

    async fn sweep(&self) {
        self.pool.sweep_idle();
        #[cfg(feature = "experimental")]
        self.leases.sweep().await;
    }
}
