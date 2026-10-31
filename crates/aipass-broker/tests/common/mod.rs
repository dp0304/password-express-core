// SPDX-License-Identifier: Apache-2.0
//! Test fixtures: a fake `ExecutorBackend` with controllable behaviour, and a harness that
//! wires a broker, a trusted device, a project, a test resource and an active connection.
#![allow(dead_code)]

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use aipass_broker::{Actor, Broker, BrokerConfig, ConnectionPrincipal, ManualClock, NewConnection};
use aipass_crypto::{DeviceIdentity, Ed25519Keypair, KemKeypair, SealedBox, SecretString};
use aipass_types::approval;
use aipass_types::error::{ApiError, ErrorCode};
use aipass_types::exec::{
    CredentialAad, CredentialMaterial, ExecutionOutcome, ExecutionRequest, ExecutorBackend,
    NormalizedRequest, OperationSpec, Stage, parameters_digest, seal_credential,
};
use aipass_types::ids::{DeviceId, EntryId, ExecutorId, ProjectId, ResourceId};
use aipass_types::models::{
    AccessSpec, AllowedProjects, ApprovalDecision, ApprovalRequest, Connector, CreateProjectRequest,
    Decision, DecisionResponse, Environment, ExecutorInfo, GithubScope, GrantScope, HostType,
    HttpApiScope, LevelReport, Limits, OperationRequest, PostgresScope, ProtectionLevel, Resource,
    ResourceInput, SideEffectClass, SideEffects, Transport,
};
use aipass_types::vault::{DevicePublic, EntryKind, MemberRole, Platform};
use async_trait::async_trait;
use serde_json::{Value, json};

/// The fake credential. Tests assert it never appears in outputs, audit or the database.
pub const SECRET: &str = "pg-SECRET-DO-NOT-LEAK-7f3a9c";
pub const SECRET_USER: &str = "readonly_user_7f3a9c";

/// Start time used by most tests (the CONTRACTS §1.6 vector timestamp).
pub const T0: i64 = 1_793_318_400;

#[derive(Debug, Clone)]
pub struct Behavior {
    /// Rows the fake table holds (each query returns up to this many).
    pub rows_available: u64,
    /// Execution latency.
    pub delay: Duration,
    /// Stop early when the cancellation token fires.
    pub honor_cancel: bool,
    /// Fail every execution with this code.
    pub fail_with: Option<ErrorCode>,
    /// Return `UPSTREAM_OUTCOME_UNKNOWN` this many times first.
    pub unknown_times: u32,
    /// Ignore the remaining-row cap (a buggy executor).
    pub overreport_rows: bool,
    /// Pad each row with this many bytes.
    pub row_padding: usize,
    /// Report from `revoke_upstream`.
    pub upstream: LevelReport,
    /// Make `end_sessions` hang (to test honest `pending`).
    pub end_sessions_hang: bool,
    /// Panic inside `execute` (a buggy connector).
    pub panic_on_execute: bool,
    /// Latency of `install_credential` (widens the approve → resume window).
    pub install_delay: Duration,
    /// Latency of `revoke_upstream` (a slow upstream token revocation).
    pub upstream_delay: Duration,
}

impl Default for Behavior {
    fn default() -> Self {
        Self {
            rows_available: 3,
            delay: Duration::ZERO,
            honor_cancel: true,
            fail_with: None,
            unknown_times: 0,
            overreport_rows: false,
            row_padding: 0,
            upstream: LevelReport::not_applicable(),
            end_sessions_hang: false,
            panic_on_execute: false,
            install_delay: Duration::ZERO,
            upstream_delay: Duration::ZERO,
        }
    }
}

pub struct FakeExecutor {
    pub id: ExecutorId,
    pub kem: KemKeypair,
    pub sign: Ed25519Keypair,
    pub online: AtomicBool,
    pub protection: ProtectionLevel,
    pub creds: Mutex<HashMap<String, CredentialMaterial>>,
    pub behavior: Mutex<Behavior>,
    pub executions: AtomicUsize,
    pub running: AtomicUsize,
    pub max_running: AtomicUsize,
    pub cancels: Mutex<Vec<String>>,
    pub end_sessions_calls: Mutex<Vec<String>>,
    pub dropped: Mutex<Vec<String>>,
    pub seen_remaining: Mutex<Vec<Limits>>,
}

impl FakeExecutor {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            id: ExecutorId::generate(),
            kem: KemKeypair::generate(),
            sign: Ed25519Keypair::generate(),
            online: AtomicBool::new(true),
            protection: ProtectionLevel::Compatible,
            creds: Mutex::new(HashMap::new()),
            behavior: Mutex::new(Behavior::default()),
            executions: AtomicUsize::new(0),
            running: AtomicUsize::new(0),
            max_running: AtomicUsize::new(0),
            cancels: Mutex::new(Vec::new()),
            end_sessions_calls: Mutex::new(Vec::new()),
            dropped: Mutex::new(Vec::new()),
            seen_remaining: Mutex::new(Vec::new()),
        })
    }

    pub fn set(&self, f: impl FnOnce(&mut Behavior)) {
        f(&mut self.behavior.lock().unwrap());
    }

    pub fn has_cred(&self, grant: &str) -> bool {
        self.creds.lock().unwrap().contains_key(grant)
    }

    pub fn executions(&self) -> usize {
        self.executions.load(Ordering::SeqCst)
    }
}

fn spec(name: &str, connector: Connector, side: SideEffectClass, retry_safe: bool, stage: Stage) -> OperationSpec {
    OperationSpec {
        name: name.into(),
        connector,
        description_zh: format!("测试操作 {name}"),
        description_en: format!("Test operation {name}"),
        side_effect: side,
        retry_safe,
        parameters_schema: json!({"type": "object"}),
        stage,
    }
}

#[async_trait]
impl ExecutorBackend for FakeExecutor {
    fn info(&self) -> ExecutorInfo {
        ExecutorInfo {
            executor_id: self.id.clone(),
            name: "测试执行器 / test executor".into(),
            protection_level: self.protection,
            capabilities: vec![Connector::Postgres, Connector::HttpApi, Connector::Github],
            online: self.online.load(Ordering::SeqCst),
            last_heartbeat_at: None,
            sign_pk: self.sign.public_key(),
            kem_pk: self.kem.public_key(),
        }
    }

    fn operation_specs(&self, connector: &str) -> Vec<OperationSpec> {
        match connector {
            "postgres" => vec![
                spec("postgres.query_view", Connector::Postgres, SideEffectClass::Read, true, Stage::V1),
                spec("postgres.experimental_rotate", Connector::Postgres, SideEffectClass::Write, false, Stage::V1_1),
            ],
            "http_api" => vec![
                spec("demo.create_order", Connector::HttpApi, SideEffectClass::Write, false, Stage::V1),
                spec("demo.get_status", Connector::HttpApi, SideEffectClass::Read, true, Stage::V1),
            ],
            "github" => vec![spec("github.repo.get", Connector::Github, SideEffectClass::Read, true, Stage::V1)],
            _ => vec![],
        }
    }

    fn normalize(&self, resource: &Resource, operation: &str, params: &Value) -> Result<NormalizedRequest, ApiError> {
        let obj = params
            .as_object()
            .ok_or_else(|| ApiError::invalid_request("参数必须是对象", "parameters must be an object"))?;
        match operation {
            "postgres.query_view" => {
                let view = obj
                    .get("view")
                    .and_then(Value::as_str)
                    .ok_or_else(|| ApiError::invalid_request("缺少 view", "missing view"))?;
                let allowed = resource
                    .config
                    .get("allowed_views")
                    .and_then(|v| v.get(view))
                    .and_then(|v| v.get("fields"))
                    .and_then(Value::as_array)
                    .ok_or_else(ApiError::scope_denied)?;
                let mut fields: Vec<String> = obj
                    .get("fields")
                    .and_then(Value::as_array)
                    .ok_or_else(|| ApiError::invalid_request("缺少 fields", "missing fields"))?
                    .iter()
                    .map(|f| f.as_str().map(str::to_owned).ok_or_else(|| ApiError::invalid_request("字段无效", "bad field")))
                    .collect::<Result<_, _>>()?;
                fields.sort();
                fields.dedup();
                if fields.is_empty() || fields.iter().any(|f| !allowed.iter().any(|a| a.as_str() == Some(f))) {
                    return Err(ApiError::scope_denied());
                }
                let mut np = serde_json::Map::new();
                np.insert("view".into(), json!(view));
                np.insert("fields".into(), json!(fields));
                if let Some(l) = obj.get("limit") {
                    np.insert("limit".into(), json!(l.as_u64().ok_or_else(|| ApiError::invalid_request("limit 无效", "bad limit"))?));
                }
                if let Some(p) = obj.get("page") {
                    np.insert("page".into(), json!(p.as_u64().unwrap_or(0)));
                }
                let params = Value::Object(np);
                Ok(NormalizedRequest {
                    operation: operation.into(),
                    parameters_digest: parameters_digest(operation, &params).unwrap(),
                    params,
                    required_scope: GrantScope {
                        operations: vec![operation.into()],
                        postgres: Some(PostgresScope {
                            views: BTreeMap::from([(view.to_owned(), fields)]),
                        }),
                        github: None,
                        http_api: None,
                    },
                })
            }
            "demo.create_order" | "demo.get_status" => {
                let params = Value::Object(obj.clone());
                Ok(NormalizedRequest {
                    operation: operation.into(),
                    parameters_digest: parameters_digest(operation, &params).unwrap(),
                    params,
                    required_scope: GrantScope {
                        operations: vec![operation.into()],
                        postgres: None,
                        github: None,
                        http_api: Some(HttpApiScope {
                            operations: vec![operation.into()],
                        }),
                    },
                })
            }
            "github.repo.get" => {
                let repo = obj.get("repo").and_then(Value::as_str).unwrap_or_default().to_ascii_lowercase();
                let params = json!({ "repo": repo });
                Ok(NormalizedRequest {
                    operation: operation.into(),
                    parameters_digest: parameters_digest(operation, &params).unwrap(),
                    params,
                    required_scope: GrantScope {
                        operations: vec![operation.into()],
                        postgres: None,
                        github: Some(GithubScope { repos: vec![repo] }),
                        http_api: None,
                    },
                })
            }
            _ => Err(ApiError::scope_denied()),
        }
    }

    fn scope_covers(&self, scope: &GrantScope, limits: &Limits, req: &NormalizedRequest) -> bool {
        if limits.max_rows_per_operation == 0 || !scope.operations.contains(&req.operation) {
            return false;
        }
        match &req.required_scope {
            GrantScope { postgres: Some(need), .. } => {
                let Some(have) = &scope.postgres else { return false };
                need.views.iter().all(|(v, fs)| have.views.get(v).is_some_and(|hf| fs.iter().all(|f| hf.contains(f))))
            }
            GrantScope { http_api: Some(need), .. } => {
                let Some(have) = &scope.http_api else { return false };
                need.operations.iter().all(|o| have.operations.contains(o))
            }
            GrantScope { github: Some(need), .. } => {
                let Some(have) = &scope.github else { return false };
                need.repos.iter().all(|r| have.repos.contains(r))
            }
            _ => true,
        }
    }

    async fn install_credential(&self, grant_id: &str, envelope: &SealedBox, aad: &CredentialAad) -> Result<(), ApiError> {
        let delay = self.behavior.lock().unwrap().install_delay;
        if !delay.is_zero() {
            tokio::time::sleep(delay).await;
        }
        let m = aipass_types::exec::open_credential(&self.kem, &aad.to_bytes().unwrap(), envelope)?;
        self.creds.lock().unwrap().insert(grant_id.to_owned(), m);
        Ok(())
    }

    async fn install_plain_credential(&self, grant_id: &str, material: CredentialMaterial) -> Result<(), ApiError> {
        self.creds.lock().unwrap().insert(grant_id.to_owned(), material);
        Ok(())
    }

    async fn drop_credential(&self, grant_id: &str) {
        self.creds.lock().unwrap().remove(grant_id);
        self.dropped.lock().unwrap().push(grant_id.to_owned());
    }

    async fn execute(&self, req: ExecutionRequest) -> Result<ExecutionOutcome, ApiError> {
        self.executions.fetch_add(1, Ordering::SeqCst);
        let now_running = self.running.fetch_add(1, Ordering::SeqCst) + 1;
        self.max_running.fetch_max(now_running, Ordering::SeqCst);
        struct Dec<'a>(&'a AtomicUsize);
        impl Drop for Dec<'_> {
            fn drop(&mut self) {
                self.0.fetch_sub(1, Ordering::SeqCst);
            }
        }
        let _dec = Dec(&self.running);
        self.seen_remaining.lock().unwrap().push(req.remaining);
        let b = self.behavior.lock().unwrap().clone();
        if !self.creds.lock().unwrap().contains_key(req.grant_id.as_str()) {
            return Err(ApiError::new(ErrorCode::SecretUnavailable));
        }
        if !b.delay.is_zero() {
            if b.honor_cancel {
                tokio::select! {
                    _ = tokio::time::sleep(b.delay) => {}
                    _ = req.cancel.cancelled() => {
                        return Err(ApiError::new(ErrorCode::UpstreamError).with_detail("reason", "cancelled"));
                    }
                }
            } else {
                tokio::time::sleep(b.delay).await;
            }
        }
        if b.panic_on_execute {
            panic!("connector bug");
        }
        if let Some(code) = b.fail_with {
            // never echo the credential, even in errors
            return Err(ApiError::new(code));
        }
        if b.unknown_times > 0 {
            self.set(|x| x.unknown_times -= 1);
            return Err(ApiError::new(ErrorCode::UpstreamOutcomeUnknown));
        }
        let write = req.normalized.operation == "demo.create_order";
        let mut rows = b.rows_available;
        if !b.overreport_rows {
            rows = rows.min(req.remaining.max_rows_per_operation);
        }
        if let Some(l) = req.normalized.params.get("limit").and_then(Value::as_u64) {
            rows = rows.min(l);
        }
        let pad = "x".repeat(b.row_padding);
        let data: Vec<Value> = (0..rows).map(|i| json!({"n": i, "pad": pad})).collect();
        let data = Value::Array(data);
        let bytes = serde_json::to_vec(&data).unwrap().len() as u64;
        Ok(ExecutionOutcome {
            data,
            rows: Some(rows),
            bytes,
            truncated: rows < b.rows_available,
            restricted_fields: vec![],
            side_effects: if write { SideEffects::Applied } else { SideEffects::None },
        })
    }

    async fn cancel(&self, operation_id: &str) -> bool {
        self.cancels.lock().unwrap().push(operation_id.to_owned());
        true
    }

    async fn end_sessions(&self, grant_id: &str) -> LevelReport {
        self.end_sessions_calls.lock().unwrap().push(grant_id.to_owned());
        if self.behavior.lock().unwrap().end_sessions_hang {
            tokio::time::sleep(Duration::from_secs(30)).await;
        }
        self.creds.lock().unwrap().remove(grant_id);
        LevelReport::done()
    }

    async fn revoke_upstream(&self, _grant_id: &str) -> LevelReport {
        let (delay, report) = {
            let b = self.behavior.lock().unwrap();
            (b.upstream_delay, b.upstream.clone())
        };
        if !delay.is_zero() {
            tokio::time::sleep(delay).await;
        }
        report
    }
}

/// A wired-up broker for tests.
pub struct Harness {
    pub broker: Arc<Broker>,
    pub clock: Arc<ManualClock>,
    pub exe: Arc<FakeExecutor>,
    pub device: DeviceIdentity,
    pub device_id: DeviceId,
    pub project: ProjectId,
    pub resource: Resource,
    pub conn: ConnectionPrincipal,
    pub dir: Option<tempfile::TempDir>,
}

pub fn test_config() -> BrokerConfig {
    let mut cfg = BrokerConfig::in_memory();
    cfg.decision_wait = Duration::from_secs(10);
    cfg.cancel_wait = Duration::from_secs(3);
    cfg.revoke_step_timeout = Duration::from_millis(800);
    cfg.cancel_grace = Duration::from_millis(500);
    cfg
}

impl Harness {
    pub async fn new() -> Self {
        Self::build(test_config(), false).await
    }

    pub async fn persistent() -> Self {
        Self::build(test_config(), true).await
    }

    pub async fn with_config(cfg: BrokerConfig) -> Self {
        Self::build(cfg, false).await
    }

    pub async fn build(mut cfg: BrokerConfig, persistent: bool) -> Self {
        let dir = if persistent {
            let d = tempfile::tempdir().unwrap();
            cfg.data_dir = Some(d.path().join("data"));
            Some(d)
        } else {
            None
        };
        let clock = Arc::new(ManualClock::at_unix(T0));
        let broker = Broker::open_with_clock(cfg, clock.clone()).unwrap();
        let exe = FakeExecutor::new();
        broker.register_executor(exe.clone()).await.unwrap();
        let device = DeviceIdentity::generate();
        let device_id = DeviceId::generate();
        broker
            .add_trusted_device(
                &Actor::Admin,
                DevicePublic {
                    device_id: device_id.clone(),
                    name: "我的手机".into(),
                    platform: Platform::Ios,
                    role: MemberRole::Owner,
                    sign_pk: device.public().sign_pk,
                    kem_pk: device.public().kem_pk,
                },
            )
            .await
            .unwrap();
        let project = broker
            .create_project(&Actor::Admin, CreateProjectRequest { name: "路亚站".into() })
            .await
            .unwrap()
            .project_id;
        let mut h = Self {
            broker,
            clock,
            exe,
            device,
            device_id,
            project,
            resource: placeholder_resource(),
            conn: ConnectionPrincipal::in_process(aipass_types::ids::ConnectionId::generate()),
            dir,
        };
        h.resource = h.add_resource(Environment::Test).await;
        h.conn = h.new_connection("Claude Code").await;
        h
    }

    pub async fn add_resource(&self, env: Environment) -> Resource {
        self.broker
            .create_resource(
                &Actor::Admin,
                ResourceInput {
                    alias: "路亚站测试库".into(),
                    service: "postgres".into(),
                    connector: Connector::Postgres,
                    project_id: self.project.clone(),
                    environment: env,
                    config: json!({
                        "host": "db.internal", "port": 5432, "dbname": "lure",
                        "allowed_views": {
                            "analytics.subscription_daily": {"fields": ["day", "plan", "subscriptions", "email"]},
                        }
                    }),
                    credential_entry_id: EntryId::generate(),
                    executor_id: self.exe.id.clone(),
                    operations: None,
                },
            )
            .await
            .unwrap()
    }

    pub async fn add_api_resource(&self, env: Environment) -> Resource {
        self.broker
            .create_resource(
                &Actor::Admin,
                ResourceInput {
                    alias: "订单 API".into(),
                    service: "orders".into(),
                    connector: Connector::HttpApi,
                    project_id: self.project.clone(),
                    environment: env,
                    config: json!({"base_url": "https://api.example.com", "auth": {"type": "bearer"}}),
                    credential_entry_id: EntryId::generate(),
                    executor_id: self.exe.id.clone(),
                    operations: None,
                },
            )
            .await
            .unwrap()
    }

    pub async fn new_connection(&self, name: &str) -> ConnectionPrincipal {
        let created = self
            .broker
            .create_connection(
                &Actor::Admin,
                NewConnection {
                    host_type: HostType::ClaudeCode,
                    display_name: name.into(),
                    transport: Transport::Stdio,
                    allowed_projects: AllowedProjects::Only([self.project.clone()].into()),
                    public_key: Some(Ed25519Keypair::generate().public_key_b64u()),
                },
            )
            .await
            .unwrap();
        ConnectionPrincipal::in_process(created.connection.connection_id)
    }

    pub fn query(&self, key: &str, fields: &[&str]) -> OperationRequest {
        self.query_on(&self.resource.resource_id, key, fields)
    }

    pub fn query_on(&self, res: &ResourceId, key: &str, fields: &[&str]) -> OperationRequest {
        OperationRequest {
            resource_id: res.clone(),
            operation: "postgres.query_view".into(),
            parameters: json!({"view": "analytics.subscription_daily", "fields": fields}),
            idempotency_key: key.into(),
            task_id: None,
        }
    }

    pub fn material(&self, resource: &Resource) -> CredentialMaterial {
        CredentialMaterial {
            entry_id: resource.credential_entry_id.clone(),
            version: 1,
            kind: EntryKind::Database,
            username: Some(SECRET_USER.into()),
            secret: SecretString::from(SECRET),
            database: None,
            expires_at: aipass_types::time::add_secs(&self.clock.now_ts(), 3600),
        }
    }

    pub async fn request(&self, apr: &aipass_types::ids::ApprovalRequestId) -> ApprovalRequest {
        self.broker.get_approval(apr).await.unwrap()
    }

    /// Build a signed decision on the trusted device, with a credential envelope.
    pub async fn decision(&self, apr: &aipass_types::ids::ApprovalRequestId, decision: Decision, narrowed: Option<AccessSpec>) -> ApprovalDecision {
        let req = self.request(apr).await;
        let now = self.clock.now_ts();
        let mut d = approval::build_decision(&self.device, &self.device_id, &req, decision, narrowed, &now).unwrap();
        if decision == Decision::Approve {
            let rid = req.resource.resource_id.clone();
            let res = self.broker.get_resource(&rid).await.unwrap();
            let aad = CredentialAad {
                approval_request_id: req.approval_request_id.clone(),
                digest: d.digest.clone(),
                executor_id: req.executor.executor_id.clone(),
            };
            d.credential_envelope = Some(seal_credential(&self.exe.kem.public_key(), &aad.to_bytes().unwrap(), &self.material(&res)).unwrap());
        }
        d
    }

    pub async fn approve(&self, apr: &aipass_types::ids::ApprovalRequestId) -> DecisionResponse {
        let d = self.decision(apr, Decision::Approve, None).await;
        self.broker.submit_decision(d).await.unwrap()
    }

    pub async fn deny(&self, apr: &aipass_types::ids::ApprovalRequestId) -> DecisionResponse {
        let d = self.decision(apr, Decision::Deny, None).await;
        self.broker.submit_decision(d).await.unwrap()
    }
}

fn placeholder_resource() -> Resource {
    Resource {
        resource_id: ResourceId::generate(),
        alias: String::new(),
        service: String::new(),
        connector: Connector::Postgres,
        project_id: ProjectId::generate(),
        environment: Environment::Test,
        config: json!({}),
        credential_entry_id: EntryId::generate(),
        executor_id: ExecutorId::generate(),
        operations: vec![],
        status: aipass_types::models::ResourceStatus::Available,
        created_at: aipass_types::time::now(),
    }
}

pub trait ClockExt {
    fn now_ts(&self) -> aipass_types::Timestamp;
}

impl ClockExt for ManualClock {
    fn now_ts(&self) -> aipass_types::Timestamp {
        aipass_broker::Clock::now(self)
    }
}

/// Assert that `text` contains no fake credential material.
pub fn assert_no_secret(text: &str) {
    assert!(!text.contains(SECRET), "credential leaked");
    assert!(!text.contains(SECRET_USER), "credential username leaked");
}
