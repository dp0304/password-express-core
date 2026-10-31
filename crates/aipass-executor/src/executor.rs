// SPDX-License-Identifier: Apache-2.0
//! The [`Executor`]: credential custody + connector registry behind
//! [`aipass_types::exec::ExecutorBackend`].

use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use aipass_crypto::{DeviceIdentity, IdentityPublic, SealedBox};
use aipass_types::exec::{
    CredentialAad, CredentialMaterial, ExecutionOutcome, ExecutionRequest, ExecutorBackend,
    LevelReport, NormalizedRequest, OperationSpec,
};
use aipass_types::models::{
    Connector, ExecutorInfo, GrantScope, Limits, ProtectionLevel, Resource,
};
use aipass_types::{ApiError, ErrorCode, ExecutorId, GrantId, OperationId};
use async_trait::async_trait;
use rustls::pki_types::CertificateDer;
use serde_json::Value;
use tokio_util::sync::CancellationToken;

use crate::connectors::github::GithubDriver;
use crate::connectors::http_api::HttpApiDriver;
use crate::connectors::postgres::PostgresDriver;
use crate::connectors::{ConnectorDriver, ExecContext, SessionsClosed};
use crate::custody::CredentialCustody;
use crate::egress::{DefaultResolver, EgressGuard, EgressResolver};
use crate::errors;
use crate::filter::OutputFilter;

/// Default maximum time a credential stays installed (the contract's max task TTL, 24 h,
/// plus the approval grace).
pub const DEFAULT_MAX_CREDENTIAL_TTL: Duration = Duration::from_secs(86_400 + 60);
/// How long `end_sessions` waits for running operations to stop.
pub const END_SESSIONS_WAIT: Duration = Duration::from_secs(3);

fn bi(zh: impl AsRef<str>, en: impl AsRef<str>) -> String {
    format!("{} / {}", zh.as_ref(), en.as_ref())
}

/// Builder for [`Executor`].
pub struct ExecutorBuilder {
    executor_id: ExecutorId,
    name: String,
    identity: DeviceIdentity,
    protection_level: ProtectionLevel,
    max_credential_ttl: Duration,
    resolver: Option<Arc<dyn EgressResolver>>,
    extra_roots: Vec<CertificateDer<'static>>,
    webpki_roots: bool,
    #[cfg(feature = "test-util")]
    github_base_override: Option<url::Url>,
}

impl fmt::Debug for ExecutorBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExecutorBuilder")
            .field("executor_id", &self.executor_id)
            .field("name", &self.name)
            .field("protection_level", &self.protection_level)
            .finish_non_exhaustive()
    }
}

impl ExecutorBuilder {
    /// Protection level reported in [`ExecutorInfo`]. Default `compatible`; set `isolated`
    /// only when the node operator attests a separate host / VM (§9.3).
    pub fn protection_level(mut self, level: ProtectionLevel) -> Self {
        self.protection_level = level;
        self
    }

    /// Upper bound for how long any credential stays installed.
    pub fn max_credential_ttl(mut self, ttl: Duration) -> Self {
        self.max_credential_ttl = ttl;
        self
    }

    /// DNS resolver used by the egress guard (default: hickory with system config, OS
    /// resolver fallback).
    pub fn resolver(mut self, resolver: Arc<dyn EgressResolver>) -> Self {
        self.resolver = Some(resolver);
        self
    }

    /// Trust extra root certificates for outbound HTTPS (enterprise CA for GHES / private
    /// APIs). Trusted-client configuration only.
    pub fn add_root_certificates_pem(mut self, pem: &str) -> Result<Self, ApiError> {
        let certs = crate::tls::parse_pem_certs(pem)
            .map_err(|_| errors::invalid("根证书无效", "Invalid root certificate."))?;
        self.extra_roots.extend(certs);
        Ok(self)
    }

    /// Include the Mozilla root store (default true).
    pub fn webpki_roots(mut self, include: bool) -> Self {
        self.webpki_roots = include;
        self
    }

    /// **Test only**: send GitHub requests to `base` (e.g. a local mock over plain HTTP).
    /// Not reachable from resource configuration.
    #[cfg(feature = "test-util")]
    pub fn github_api_base_override_for_tests(mut self, base: url::Url) -> Self {
        self.github_base_override = Some(base);
        self
    }

    /// Build the executor.
    pub fn build(self) -> Result<Executor, ApiError> {
        let tls = crate::tls::webpki_config(self.webpki_roots, &self.extra_roots, true)
            .map_err(|_| ApiError::internal())?;
        let resolver: Arc<dyn EgressResolver> = self
            .resolver
            .unwrap_or_else(|| Arc::new(DefaultResolver::default()));
        let guard = EgressGuard::new(resolver, tls);
        #[allow(unused_mut)]
        let mut github = GithubDriver::new(guard.clone());
        #[cfg(feature = "test-util")]
        if let Some(b) = self.github_base_override {
            github = github.with_test_base_override(b);
        }
        Ok(Executor {
            executor_id: self.executor_id,
            name: self.name,
            identity: self.identity,
            protection_level: self.protection_level,
            online: AtomicBool::new(true),
            control_channel_ok: AtomicBool::new(true),
            custody: Arc::new(CredentialCustody::new(self.max_credential_ttl)),
            postgres: Arc::new(PostgresDriver::new()),
            github: Arc::new(github),
            http_api: Arc::new(HttpApiDriver::new(guard)),
            running: Mutex::new(HashMap::new()),
            grant_connectors: Mutex::new(HashMap::new()),
            #[cfg(test)]
            exec_gate: Mutex::new(None),
        })
    }
}

struct RunningOp {
    grant_id: GrantId,
    token: CancellationToken,
}

/// The executor. Thread-safe; share it as `Arc<Executor>` (it is also usable as
/// `Arc<dyn ExecutorBackend>`).
pub struct Executor {
    executor_id: ExecutorId,
    name: String,
    identity: DeviceIdentity,
    protection_level: ProtectionLevel,
    online: AtomicBool,
    control_channel_ok: AtomicBool,
    custody: Arc<CredentialCustody>,
    postgres: Arc<PostgresDriver>,
    github: Arc<GithubDriver>,
    http_api: Arc<HttpApiDriver>,
    running: Mutex<HashMap<OperationId, RunningOp>>,
    grant_connectors: Mutex<HashMap<GrantId, Connector>>,
    /// Unit-test hook: pause `execute` of one grant at its registration point.
    #[cfg(test)]
    exec_gate: Mutex<Option<ExecGate>>,
}

#[cfg(test)]
type ExecGate = (GrantId, Arc<tokio::sync::Notify>, Arc<tokio::sync::Notify>);

impl fmt::Debug for Executor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Executor")
            .field("executor_id", &self.executor_id)
            .field("name", &self.name)
            .field("protection_level", &self.protection_level)
            .field("credentials", &self.custody)
            .finish_non_exhaustive()
    }
}

/// Guard that removes a running-operation registration.
struct RunningGuard<'a> {
    exec: &'a Executor,
    op: OperationId,
}

impl Drop for RunningGuard<'_> {
    fn drop(&mut self) {
        self.exec.running_lock().remove(&self.op);
    }
}

impl Executor {
    /// Start building an executor with its identity (Ed25519 + X25519; the X25519 key opens
    /// credential envelopes).
    pub fn builder(
        executor_id: ExecutorId,
        name: impl Into<String>,
        identity: DeviceIdentity,
    ) -> ExecutorBuilder {
        ExecutorBuilder {
            executor_id,
            name: name.into(),
            identity,
            protection_level: ProtectionLevel::Compatible,
            max_credential_ttl: DEFAULT_MAX_CREDENTIAL_TTL,
            resolver: None,
            extra_roots: Vec::new(),
            webpki_roots: true,
            #[cfg(feature = "test-util")]
            github_base_override: None,
        }
    }

    /// Unit-test hook: when armed for `grant`, signal "reached" and wait for "release".
    #[cfg(test)]
    async fn test_gate(&self, grant: &GrantId) {
        let gate = self
            .exec_gate
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        if let Some((g, reached, release)) = gate
            && &g == grant
        {
            reached.notify_one();
            release.notified().await;
        }
    }

    fn running_lock(&self) -> std::sync::MutexGuard<'_, HashMap<OperationId, RunningOp>> {
        self.running.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Executor id.
    pub fn executor_id(&self) -> &ExecutorId {
        &self.executor_id
    }

    /// Public keys (sign + KEM).
    pub fn public_identity(&self) -> IdentityPublic {
        self.identity.public()
    }

    /// Mark online / offline (offline → `EXECUTOR_OFFLINE` for new operations).
    pub fn set_online(&self, online: bool) {
        self.online.store(online, Ordering::SeqCst);
    }

    /// Mark the control channel as lost / restored. While lost, new operations are denied
    /// with `CONTROL_CHANNEL_LOST` (`on_control_channel_lost: deny_new_operations`).
    pub fn set_control_channel_ok(&self, ok: bool) {
        self.control_channel_ok.store(ok, Ordering::SeqCst);
    }

    fn driver(&self, connector: Connector) -> &dyn ConnectorDriver {
        match connector {
            Connector::Postgres => self.postgres.as_ref(),
            Connector::Github => self.github.as_ref(),
            Connector::HttpApi => self.http_api.as_ref(),
        }
    }

    fn drivers(&self) -> [&dyn ConnectorDriver; 3] {
        [
            self.postgres.as_ref(),
            self.github.as_ref(),
            self.http_api.as_ref(),
        ]
    }

    /// Validate a (trusted) resource configuration before saving it
    /// (`/admin/resources`). Errors name the offending key, never echo values.
    pub fn validate_resource_config(
        &self,
        connector: Connector,
        config: &Value,
    ) -> Result<(), ApiError> {
        self.driver(connector).validate_config(config)
    }

    /// Operation specs as offered by `resource` (for `ResourceView`): filtered by
    /// `resource.operations`; for `http_api` the declared operations are listed inside the
    /// `http_api.call` schema (`enum` + `x-operations`).
    pub fn resource_operation_specs(&self, resource: &Resource) -> Vec<OperationSpec> {
        self.driver(resource.connector)
            .resource_operation_specs(resource)
    }

    /// Whether a live credential is installed for `grant_id`.
    pub fn has_credential(&self, grant_id: &str) -> bool {
        GrantId::parse(grant_id).is_ok_and(|g| self.custody.contains(&g))
    }

    /// Number of running operations.
    pub fn running_operations(&self) -> usize {
        self.running_lock().len()
    }

    /// Open PostgreSQL sessions of a grant (diagnostics / tests).
    pub fn postgres_open_sessions(&self, grant_id: &str) -> usize {
        GrantId::parse(grant_id)
            .map(|g| self.postgres.open_sessions(&g))
            .unwrap_or(0)
    }

    /// Periodic maintenance: drop expired credentials (closing their sessions), close idle
    /// sessions, revoke expired temporary roles.
    pub async fn sweep(&self) {
        for g in self.custody.sweep_expired() {
            tracing::info!(grant_id = %g, "credential expired; dropped");
            for d in self.drivers() {
                let _ = d.end_sessions(&g).await;
            }
        }
        for d in self.drivers() {
            d.sweep().await;
        }
        #[cfg(feature = "experimental")]
        self.postgres.rotations_sweep();
    }

    /// Run [`Executor::sweep`] every `interval` until the returned handle is aborted.
    pub fn spawn_maintenance(self: &Arc<Self>, interval: Duration) -> tokio::task::JoinHandle<()> {
        let me = Arc::downgrade(self);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(interval);
            tick.tick().await;
            loop {
                tick.tick().await;
                let Some(exec) = me.upgrade() else { break };
                exec.sweep().await;
            }
        })
    }

    /// Drop every credential and close every session (process shutdown).
    pub async fn shutdown(&self) {
        let ops: Vec<CancellationToken> = self
            .running_lock()
            .values()
            .map(|r| r.token.clone())
            .collect();
        for t in ops {
            t.cancel();
        }
        let grants: Vec<GrantId> = self
            .grant_connectors
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .keys()
            .cloned()
            .collect();
        for g in grants {
            for d in self.drivers() {
                let _ = d.end_sessions(&g).await;
            }
        }
        self.custody.clear();
    }

    fn parse_grant(grant_id: &str) -> Result<GrantId, ApiError> {
        GrantId::parse(grant_id)
            .map_err(|_| errors::invalid_param("grant_id", "授权 ID 无效", "Invalid grant id."))
    }

    fn check_operation_allowed(&self) -> Result<(), ApiError> {
        if !self.online.load(Ordering::SeqCst) {
            return Err(ApiError::new(ErrorCode::ExecutorOffline));
        }
        if !self.control_channel_ok.load(Ordering::SeqCst) {
            return Err(ApiError::new(ErrorCode::ControlChannelLost));
        }
        Ok(())
    }

    async fn end_sessions_inner(&self, grant: &GrantId) -> LevelReport {
        // Drop the credential FIRST, then snapshot the running operations. `execute`
        // registers in `running` before it looks the credential up, so every operation of
        // the grant is either in this snapshot (and cancelled) or finds no credential.
        let had_credential = self.custody.remove(grant);
        let tokens: Vec<(OperationId, CancellationToken)> = self
            .running_lock()
            .iter()
            .filter(|(_, r)| &r.grant_id == grant)
            .map(|(id, r)| (id.clone(), r.token.clone()))
            .collect();
        for (_, t) in &tokens {
            t.cancel();
        }
        let mut closed = SessionsClosed::default();
        for d in self.drivers() {
            let r = d.end_sessions(grant).await;
            closed.closed += r.closed;
            closed.cancelled += r.cancelled;
            closed.cancel_failures += r.cancel_failures;
        }
        // Wait (bounded) until the cancelled operations have actually stopped.
        let deadline = Instant::now() + END_SESSIONS_WAIT;
        let still_running = loop {
            let n = self
                .running_lock()
                .values()
                .filter(|r| &r.grant_id == grant)
                .count();
            if n == 0 || Instant::now() >= deadline {
                break n;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        };
        tracing::info!(
            grant_id = %grant,
            cancelled_operations = tokens.len(),
            closed_sessions = closed.closed,
            credential_dropped = had_credential,
            "end_sessions"
        );
        if still_running > 0 || closed.cancel_failures > 0 {
            return LevelReport::pending(bi(
                format!(
                    "已清除凭证并断开连接；{still_running} 个操作仍在结束中，{} 个数据库查询的取消请求未能确认送达",
                    closed.cancel_failures
                ),
                format!(
                    "Credential dropped and connections closed; {still_running} operation(s) still stopping, {} database cancel request(s) not confirmed",
                    closed.cancel_failures
                ),
            ));
        }
        if tokens.is_empty() && closed.closed == 0 && !had_credential {
            return LevelReport {
                status: aipass_types::models::LevelStatus::Done,
                detail: Some(bi(
                    "执行器上没有该授权的会话或凭证",
                    "No sessions or credential for this grant on the executor",
                )),
            };
        }
        LevelReport {
            status: aipass_types::models::LevelStatus::Done,
            detail: Some(bi(
                format!(
                    "已取消 {} 个运行中的操作，关闭 {} 个会话，并从内存清除凭证",
                    tokens.len(),
                    closed.closed
                ),
                format!(
                    "Cancelled {} running operation(s), closed {} session(s) and wiped the credential from memory",
                    tokens.len(),
                    closed.closed
                ),
            )),
        }
    }
}

#[async_trait]
impl ExecutorBackend for Executor {
    fn info(&self) -> ExecutorInfo {
        let public = self.identity.public();
        ExecutorInfo {
            executor_id: self.executor_id.clone(),
            name: self.name.clone(),
            protection_level: self.protection_level,
            capabilities: vec![Connector::Postgres, Connector::Github, Connector::HttpApi],
            online: self.online.load(Ordering::SeqCst)
                && self.control_channel_ok.load(Ordering::SeqCst),
            last_heartbeat_at: Some(aipass_types::time::now()),
            sign_pk: public.sign_pk,
            kem_pk: public.kem_pk,
        }
    }

    fn operation_specs(&self, connector: &str) -> Vec<OperationSpec> {
        match connector {
            "postgres" => self.postgres.operation_specs(),
            "github" => self.github.operation_specs(),
            "http_api" => self.http_api.operation_specs(),
            _ => Vec::new(),
        }
    }

    fn normalize(
        &self,
        resource: &Resource,
        operation: &str,
        params: &Value,
    ) -> Result<NormalizedRequest, ApiError> {
        if !params.is_object() {
            return Err(errors::invalid(
                "parameters 必须是对象",
                "parameters must be an object.",
            ));
        }
        self.driver(resource.connector)
            .normalize(resource, operation, params)
    }

    fn scope_covers(&self, scope: &GrantScope, limits: &Limits, req: &NormalizedRequest) -> bool {
        if !aipass_types::approval::scope_is_subset(&req.required_scope, scope) {
            return false;
        }
        if limits.max_requests_per_grant == 0 || limits.max_result_bytes == 0 {
            return false;
        }
        let returns_rows = req.operation != "credentials.rotate";
        !(returns_rows && (limits.max_rows_per_operation == 0 || limits.max_rows_per_grant == 0))
    }

    async fn install_credential(
        &self,
        grant_id: &str,
        envelope: &SealedBox,
        aad: &CredentialAad,
    ) -> Result<(), ApiError> {
        let grant = Self::parse_grant(grant_id)?;
        if aad.executor_id != self.executor_id {
            return Err(ApiError::integrity_failed().with_detail("reason", "wrong_executor"));
        }
        let aad_bytes = aad.to_bytes().map_err(|_| ApiError::integrity_failed())?;
        let material =
            aipass_types::exec::open_credential(self.identity.kem_keypair(), &aad_bytes, envelope)?;
        let installed = self.custody.install(grant.clone(), material)?;
        tracing::info!(
            grant_id = %grant,
            entry_id = %installed.material().entry_id,
            expires_at = %aipass_types::time::format_rfc3339(&installed.expires_at()),
            "credential installed (sealed envelope)"
        );
        Ok(())
    }

    async fn install_plain_credential(
        &self,
        grant_id: &str,
        material: CredentialMaterial,
    ) -> Result<(), ApiError> {
        let grant = Self::parse_grant(grant_id)?;
        let installed = self.custody.install(grant.clone(), material)?;
        tracing::info!(
            grant_id = %grant,
            entry_id = %installed.material().entry_id,
            "credential installed (in-process trusted client)"
        );
        Ok(())
    }

    async fn drop_credential(&self, grant_id: &str) {
        if let Ok(g) = GrantId::parse(grant_id) {
            // Without its credential nothing of the grant may keep running: same teardown
            // as end_sessions (cancel running operations, close sessions, wipe).
            let report = self.end_sessions_inner(&g).await;
            tracing::info!(grant_id = %g, status = ?report.status, "credential dropped");
        }
    }

    async fn execute(&self, req: ExecutionRequest) -> Result<ExecutionOutcome, ApiError> {
        self.check_operation_allowed()?;
        let started = Instant::now();
        if req.resource.executor_id != self.executor_id {
            return Err(errors::scope_denied(
                "该资源绑定在其他执行设备上",
                "This resource is bound to a different executor.",
            )
            .with_detail("reason", "wrong_executor"));
        }
        let driver = self.driver(req.resource.connector);
        // Defence in depth: re-validate against the resource config and require the same
        // digest, so a normalized request can never smuggle unvetted parameters.
        let renormalized = driver.normalize(
            &req.resource,
            &req.normalized.operation,
            &req.normalized.params,
        )?;
        if renormalized.parameters_digest != req.normalized.parameters_digest {
            return Err(
                ApiError::integrity_failed().with_detail("reason", "parameters_digest_mismatch")
            );
        }
        // Register BEFORE the credential lookup (see `end_sessions_inner`): an operation
        // that registers after the teardown snapshot is guaranteed to find no credential.
        let token = req.cancel.child_token();
        {
            let mut running = self.running_lock();
            if running.contains_key(&req.operation_id) {
                return Err(errors::invalid(
                    "该操作已在执行中",
                    "This operation is already running.",
                ));
            }
            running.insert(
                req.operation_id.clone(),
                RunningOp {
                    grant_id: req.grant_id.clone(),
                    token: token.clone(),
                },
            );
        }
        let _guard = RunningGuard {
            exec: self,
            op: req.operation_id.clone(),
        };
        #[cfg(test)]
        self.test_gate(&req.grant_id).await;
        let credential = match self.custody.get(&req.grant_id) {
            Ok(c) => c,
            Err(e) => {
                // Close sessions that belonged to a credential that just expired.
                for g in self.custody.sweep_expired() {
                    for d in self.drivers() {
                        let _ = d.end_sessions(&g).await;
                    }
                }
                return Err(e);
            }
        };
        if credential.material().entry_id != req.resource.credential_entry_id {
            return Err(errors::scope_denied(
                "已安装的凭证不属于该资源",
                "The installed credential does not belong to this resource.",
            )
            .with_detail("reason", "credential_entry_mismatch"));
        }
        if token.is_cancelled() {
            // Cancelled (operation cancel / end_sessions) before anything was sent.
            return Err(errors::cancelled());
        }
        self.grant_connectors
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(req.grant_id.clone(), req.resource.connector);
        let filter = Arc::new(OutputFilter::for_credential(credential.material()));
        let operation = renormalized.operation.clone();
        let resource_id = req.resource.resource_id.clone();
        let ctx = ExecContext {
            operation_id: req.operation_id.clone(),
            grant_id: req.grant_id.clone(),
            resource: req.resource,
            normalized: renormalized,
            remaining: req.remaining,
            cancel: token,
            credential,
            filter,
            custody: self.custody.clone(),
        };
        let out = driver.execute(ctx).await;
        let ms = started.elapsed().as_millis() as u64;
        match &out {
            Ok(o) => tracing::info!(
                operation_id = %req.operation_id, grant_id = %req.grant_id, resource_id = %resource_id,
                operation = %operation, rows = ?o.rows, bytes = o.bytes, truncated = o.truncated,
                restricted = o.restricted_fields.len(), duration_ms = ms, "operation succeeded"
            ),
            Err(e) => tracing::info!(
                operation_id = %req.operation_id, grant_id = %req.grant_id, resource_id = %resource_id,
                operation = %operation, code = %e.code, duration_ms = ms, "operation failed"
            ),
        }
        out
    }

    async fn cancel(&self, operation_id: &str) -> bool {
        let Ok(op) = OperationId::parse(operation_id) else {
            return false;
        };
        let token = self.running_lock().get(&op).map(|r| r.token.clone());
        match token {
            Some(t) => {
                t.cancel();
                tracing::info!(operation_id = %op, "operation cancel requested");
                true
            }
            None => false,
        }
    }

    async fn end_sessions(&self, grant_id: &str) -> LevelReport {
        match GrantId::parse(grant_id) {
            Ok(g) => self.end_sessions_inner(&g).await,
            Err(_) => LevelReport::failed(bi("授权 ID 无效", "Invalid grant id")),
        }
    }

    async fn revoke_upstream(&self, grant_id: &str) -> LevelReport {
        let Ok(g) = GrantId::parse(grant_id) else {
            return LevelReport::failed(bi("授权 ID 无效", "Invalid grant id"));
        };
        // Each higher level includes the lower ones.
        let _ = self.end_sessions_inner(&g).await;
        let connector = self
            .grant_connectors
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&g)
            .copied();
        let report = match connector {
            Some(c) => self.driver(c).revoke_upstream(&g).await,
            None => {
                // Unknown connector (never executed here): check every driver for leases.
                let pg = self.postgres.revoke_upstream(&g).await;
                if pg.status == aipass_types::models::LevelStatus::NotApplicable {
                    LevelReport {
                        status: aipass_types::models::LevelStatus::NotApplicable,
                        detail: Some(bi(
                            "执行器没有为该授权创建上游临时凭证",
                            "The executor created no upstream temporary credential for this grant",
                        )),
                    }
                } else {
                    pg
                }
            }
        };
        if report.is_settled() {
            self.grant_connectors
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .remove(&g);
        }
        tracing::info!(grant_id = %g, status = ?report.status, "revoke_upstream");
        report
    }
}

// ======================================================================================
// Experimental: rotation result delivery and leases
// ======================================================================================

/// AAD of a rotation result envelope:
/// `JCS({purpose:"credentials.rotate", rotation_id, entry_id, executor_id})`.
#[cfg(feature = "experimental")]
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RotationAad {
    /// Always `"credentials.rotate"`.
    pub purpose: String,
    /// The rotation operation id.
    pub rotation_id: OperationId,
    /// Rotated entry.
    pub entry_id: aipass_types::EntryId,
    /// Executor that rotated it.
    pub executor_id: ExecutorId,
}

#[cfg(feature = "experimental")]
impl RotationAad {
    /// Canonical bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, aipass_types::CanonicalError> {
        aipass_types::to_jcs_bytes(self)
    }
}

/// Device-side helper: open a rotation result envelope (HPKE, `info=aipass/v1/credential`).
#[cfg(feature = "experimental")]
pub fn open_rotation_result(
    device_kem: &aipass_crypto::KemKeypair,
    aad: &RotationAad,
    sealed: &SealedBox,
) -> Result<CredentialMaterial, ApiError> {
    let bytes = aad.to_bytes().map_err(|_| ApiError::integrity_failed())?;
    aipass_types::exec::open_credential(device_kem, &bytes, sealed)
}

#[cfg(feature = "experimental")]
impl Executor {
    /// Seal the new credential of a completed (or unknown-state) rotation to the approving
    /// device's KEM key. The broker relays the envelope to that device only; the AI never
    /// sees it. Returns `NOT_FOUND` when nothing is held for `rotation_id`.
    pub fn seal_rotation_result(
        &self,
        rotation_id: &OperationId,
        device_kem_pk: &[u8; 32],
    ) -> Result<(SealedBox, RotationAad), ApiError> {
        self.postgres
            .rotations
            .with(rotation_id, |p| {
                let aad = RotationAad {
                    purpose: crate::connectors::postgres::rotate::ROTATE.to_owned(),
                    rotation_id: rotation_id.clone(),
                    entry_id: p.material.entry_id.clone(),
                    executor_id: self.executor_id.clone(),
                };
                let bytes = aad.to_bytes().map_err(|_| ApiError::internal())?;
                let sealed =
                    aipass_types::exec::seal_credential(device_kem_pk, &bytes, &p.material)?;
                Ok((sealed, aad))
            })
            .unwrap_or_else(|| Err(ApiError::not_found()))
    }

    /// State of a held rotation result.
    pub fn rotation_state(
        &self,
        rotation_id: &OperationId,
    ) -> Option<crate::connectors::postgres::rotate::RotationState> {
        self.postgres.rotations.with(rotation_id, |p| p.state)
    }

    /// The trusted device persisted the new credential: forget the executor's copy.
    pub fn confirm_rotation_persisted(&self, rotation_id: &OperationId) -> bool {
        self.postgres.rotations.remove(rotation_id)
    }

    /// Upstream leases (temporary roles) of a grant — metadata only.
    pub fn leases(&self, grant_id: &str) -> Vec<aipass_types::models::Lease> {
        GrantId::parse(grant_id)
            .map(|g| self.postgres.leases.leases(&g))
            .unwrap_or_default()
    }

    /// **Test only**: make the next rotations fail verification (exercises restore).
    #[cfg(feature = "test-util")]
    pub fn force_rotation_verify_failure_for_tests(&self, fail: bool) {
        self.postgres
            .rotations
            .force_verify_failure
            .store(fail, Ordering::SeqCst);
    }
}

#[cfg(feature = "experimental")]
impl PostgresDriver {
    pub(crate) fn rotations_sweep(&self) {
        self.rotations
            .sweep(crate::connectors::postgres::rotate::HOLD_TTL);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aipass_types::models::{Environment, ResourceStatus};
    use aipass_types::vault::EntryKind;
    use aipass_types::{EntryId, ProjectId, ResourceId};
    use serde_json::json;
    use tokio::sync::Notify;

    /// EGR-04: an `execute` that races `end_sessions` (it passed the credential lookup
    /// before the credential was dropped but registers only afterwards) must not run its
    /// driver: once level 2 began, nothing of the grant may reach the upstream.
    #[tokio::test(flavor = "current_thread")]
    async fn execute_racing_end_sessions_never_runs_the_driver() {
        let exec = Arc::new(
            Executor::builder(ExecutorId::generate(), "t", DeviceIdentity::generate())
                .build()
                .unwrap(),
        );
        // A closed loopback port: if the driver ran, the call would fail with a connect
        // error instead of the custody error asserted below.
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let resource = Resource {
            resource_id: ResourceId::generate(),
            alias: "race".into(),
            service: "http_api".into(),
            connector: Connector::HttpApi,
            project_id: ProjectId::generate(),
            environment: Environment::Test,
            config: json!({
                "base_url": format!("https://127.0.0.1:{port}/v1"),
                "auth": {"type": "bearer"},
                "allow_private_network": true,
                "operations": {"create": {"method": "POST", "path": "/things",
                    "side_effect": "write", "body_schema": {"type": "object"},
                    "response": {"allowed_fields": ["id"]}}}
            }),
            credential_entry_id: EntryId::generate(),
            executor_id: exec.executor_id().clone(),
            operations: vec!["http_api.call".into()],
            status: ResourceStatus::Available,
            created_at: aipass_types::time::now(),
        };
        let grant = GrantId::generate();
        exec.install_plain_credential(
            grant.as_str(),
            CredentialMaterial {
                entry_id: resource.credential_entry_id.clone(),
                version: 1,
                kind: EntryKind::ApiKey,
                username: None,
                secret: aipass_crypto::SecretString::from("race-secret-value-123456"),
                database: None,
                expires_at: chrono::Utc::now() + chrono::Duration::seconds(600),
            },
        )
        .await
        .unwrap();
        let normalized = exec
            .normalize(
                &resource,
                "http_api.call",
                &json!({"operation": "create", "body": {}}),
            )
            .unwrap();
        let (reached, release) = (Arc::new(Notify::new()), Arc::new(Notify::new()));
        *exec.exec_gate.lock().unwrap() = Some((grant.clone(), reached.clone(), release.clone()));

        let e2 = exec.clone();
        let req = ExecutionRequest {
            operation_id: OperationId::generate(),
            grant_id: grant.clone(),
            resource,
            normalized,
            remaining: Limits::default(),
            cancel: CancellationToken::new(),
        };
        let run = tokio::spawn(async move { e2.execute(req).await });
        reached.notified().await;

        let e3 = exec.clone();
        let g3 = grant.clone();
        let teardown = tokio::spawn(async move { e3.end_sessions(g3.as_str()).await });
        // Let end_sessions get going until the credential is gone.
        while exec.custody.contains(&grant) {
            tokio::task::yield_now().await;
        }
        release.notify_one();

        let out = run.await.unwrap();
        let report = teardown.await.unwrap();
        let err = out.expect_err("the racing execute must not succeed");
        assert_eq!(
            err.code,
            ErrorCode::SecretUnavailable,
            "the driver must never run once the credential is dropped: {err:?}"
        );
        assert_eq!(report.status, aipass_types::models::LevelStatus::Done);
        assert!(exec.running_lock().is_empty());
    }
}
