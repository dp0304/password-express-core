// SPDX-License-Identifier: Apache-2.0
//! `TestExecutor` — a minimal broker / executor used by host tests (feature
//! `test-support`, never shipped). It pairs as an executor through a [`LocalRelay`],
//! sends sealed `approval.request`s to a device, verifies the returned decision exactly
//! like the broker does (`aipass_types::approval::verify_decision`), opens the credential
//! envelope, and answers `state.request` / `grant.revoke`.
//!
//! It only ever reports *whether* a credential arrived and its username — never the
//! secret itself.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use aipass_crypto::DeviceIdentity;
use aipass_types::ids::{ApprovalRequestId, DeviceId, ExecutorId, GrantId, MailboxId, MessageId};
use aipass_types::models::{ApprovalRequest, LevelReport, RevocationReport};
use aipass_types::pairing::PairingRole;
use aipass_types::relay::{DeviceSigned, RelayMessage, StateSnapshot};
use aipass_types::vault::{DevicePublic, MemberRole, Platform};
use aipass_vault::RelayTransport;
use aipass_vault::pairing::NewDeviceSession;
use aipass_vault::relay::MemoryRelay;
use tokio::sync::Mutex;

use crate::error::{CoreError, CoreResult};
use crate::relay::{LOCAL_RELAY_URL, LocalRelay};

/// Outcome of a decision verified by the test executor.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct TestDecisionFfi {
    pub approval_request_id: String,
    pub decision: String,
    /// `verify_decision` passed (signer is a trusted device, digest, subset, expiry).
    pub verified: bool,
    pub verify_error: Option<String>,
    /// A credential envelope was present and opened with the executor's key.
    pub credential_opened: bool,
    pub credential_username: Option<String>,
    pub credential_secret_len: u32,
}

struct State {
    session: Option<NewDeviceSession>,
    trusted: Vec<DevicePublic>,
    requests: BTreeMap<String, ApprovalRequest>,
    cursor: Option<MessageId>,
    control_log: Vec<String>,
}

/// Fake executor / broker for tests.
#[derive(uniffi::Object)]
pub struct TestExecutor {
    relay: Arc<MemoryRelay>,
    identity: DeviceIdentity,
    exe: ExecutorId,
    pairing_relay: Arc<MemoryRelay>,
    qr: String,
    state: Mutex<State>,
}

fn err(msg: &str) -> CoreError {
    CoreError::new(aipass_types::ErrorCode::Internal, msg, msg)
}

impl TestExecutor {
    fn trusted_key(&self, st: &State, dev: &DeviceId) -> Option<[u8; 32]> {
        st.trusted
            .iter()
            .find(|d| &d.device_id == dev)
            .map(|d| d.sign_pk)
    }

    /// Fetch and open messages addressed to this executor from trusted devices.
    async fn inbox(&self, wait: Duration) -> CoreResult<Vec<(DeviceId, RelayMessage)>> {
        let me = MailboxId::Executor(self.exe.clone());
        let mut st = self.state.lock().await;
        let msgs = self
            .relay
            .fetch(&me, st.cursor.as_ref(), wait.as_secs().min(25), None)
            .await?;
        let mut out = Vec::new();
        for m in msgs {
            st.cursor = Some(m.message_id.clone());
            let MailboxId::Device(dev) = &m.envelope.from else {
                continue;
            };
            let Some(pk) = self.trusted_key(&st, dev) else {
                continue;
            };
            if let Ok(msg) =
                aipass_vault::relay::open_message(self.identity.kem_keypair(), &pk, &m.envelope)
            {
                out.push((dev.clone(), msg));
            }
        }
        Ok(out)
    }

    async fn send_to(&self, dev: &DevicePublic, msg: &RelayMessage) -> CoreResult<String> {
        let env = aipass_vault::relay::seal_message(
            &self.identity,
            MailboxId::Executor(self.exe.clone()),
            MailboxId::Device(dev.device_id.clone()),
            &dev.kem_pk,
            msg,
            aipass_types::time::now(),
        )?;
        Ok(self
            .relay
            .post(&MailboxId::Device(dev.device_id.clone()), &env, None)
            .await?
            .to_string())
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl TestExecutor {
    /// New executor that will pair through `relay`.
    #[uniffi::constructor]
    pub fn new(relay: Arc<LocalRelay>, name: String) -> CoreResult<Arc<Self>> {
        let identity = DeviceIdentity::generate();
        let device_id = DeviceId::generate();
        let dp = aipass_vault::member::device_public(
            &device_id,
            &identity,
            &name,
            Platform::Node,
            MemberRole::Executor,
        );
        let session =
            NewDeviceSession::start(dp, identity.clone(), PairingRole::Executor, LOCAL_RELAY_URL)?;
        let exe = aipass_vault::member::member_executor_id(&device_id);
        Ok(Arc::new(Self {
            relay: relay.inner.clone(),
            identity,
            exe,
            pairing_relay: relay.inner.clone(),
            qr: session.qr_payload(),
            state: Mutex::new(State {
                session: Some(session),
                trusted: Vec::new(),
                requests: BTreeMap::new(),
                cursor: None,
                control_log: Vec::new(),
            }),
        }))
    }

    /// Pairing link to give to `pairing_scan`.
    pub fn qr_payload(&self) -> String {
        self.qr.clone()
    }

    /// `exe_…` principal.
    pub fn executor_id(&self) -> String {
        self.exe.to_string()
    }

    /// Wait for `pairing.hello`, answer `pairing.join`; returns the SAS.
    pub async fn wait_for_hello(&self, timeout_secs: u32) -> CoreResult<String> {
        let mut st = self.state.lock().await;
        let s = st.session.as_mut().ok_or_else(|| err("already paired"))?;
        let h = s
            .wait_for_hello(&*self.pairing_relay, Duration::from_secs(timeout_secs.into()))
            .await?;
        Ok(h.sas)
    }

    /// Wait for `pairing.welcome`; stores the trusted approver set. Returns its size.
    pub async fn wait_for_welcome(&self, timeout_secs: u32) -> CoreResult<u32> {
        let mut st = self.state.lock().await;
        let mut s = st.session.take().ok_or_else(|| err("already paired"))?;
        let w = s
            .wait_for_welcome(&*self.pairing_relay, Duration::from_secs(timeout_secs.into()))
            .await?;
        if w.storage_secret.is_some() {
            return Err(err("executor received a storage secret"));
        }
        st.trusted = w.trusted_devices;
        Ok(u32::try_from(st.trusted.len()).unwrap_or(u32::MAX))
    }

    /// Send a sealed `approval.request` (access, test environment) to `device_id`.
    /// Returns the `apr_…` id.
    pub async fn send_approval_request(
        &self,
        device_id: String,
        resource_id: String,
        operations: Vec<String>,
    ) -> CoreResult<String> {
        self.send_approval_request_variant(device_id, resource_id, operations, "access".into(), None, None, None)
            .await
    }

    /// Test variants of [`Self::send_approval_request`]: `kind` `"access"` | `"operation"`
    /// (an operation request carries `operation_id` + `parameters_digest`); `reuse_id`
    /// re-sends an existing id (the executor keeps verifying against its first copy);
    /// `summary_en` changes a displayed field; `claimed_executor_id` names another executor
    /// in the request. Returns the `apr_…` id.
    #[allow(clippy::too_many_arguments)]
    pub async fn send_approval_request_variant(
        &self,
        device_id: String,
        resource_id: String,
        operations: Vec<String>,
        kind: String,
        reuse_id: Option<String>,
        summary_en: Option<String>,
        claimed_executor_id: Option<String>,
    ) -> CoreResult<String> {
        let dev = {
            let st = self.state.lock().await;
            st.trusted
                .iter()
                .find(|d| d.device_id.as_str() == device_id)
                .cloned()
                .ok_or_else(|| err("device is not a trusted approver of this executor"))?
        };
        let now = aipass_types::time::now();
        let apr = match &reuse_id {
            Some(id) => ApprovalRequestId::parse(id).map_err(|_| err("bad approval_request_id"))?,
            None => ApprovalRequestId::generate(),
        };
        let conn = aipass_types::ids::ConnectionId::generate();
        let executor = claimed_executor_id.unwrap_or_else(|| self.exe.to_string());
        let mut body = serde_json::json!({
            "approval_request_id": apr,
            "kind": "access",
            "connection": {"connection_id": conn, "display_name": "Test agent", "host_type": "claude_code", "verified": false},
            "resource": {"resource_id": resource_id, "alias": "test-db", "service": "postgres", "environment": "test"},
            "summary": {"zh": "读取测试数据库", "en": summary_en.unwrap_or_else(|| "Read the test database".into())},
            "requested": {
                "operations": operations,
                "scope": {"operations": operations, "postgres": {"views": {"public.orders_summary": ["id", "total"]}}},
                "limits": {"max_rows_per_operation": 100, "max_rows_per_grant": 500, "max_requests_per_grant": 10, "max_result_bytes": 65536},
                "duration_seconds": 900,
                "mode": "task"
            },
            "excluded_fields": {"public.orders_summary": ["customer_email"]},
            "executor": {"executor_id": executor, "name": "Test executor", "protection_level": "isolated"},
            "recipients": [{"connection_id": conn, "display_name": "Test agent"}],
            "status": "pending",
            "created_at": aipass_types::time::format_rfc3339(&now),
            "expires_at": aipass_types::time::format_rfc3339(&aipass_types::time::add_secs(&now, 600)),
        });
        if kind == "operation" {
            let op = operations.first().cloned().unwrap_or_default();
            let pd = aipass_types::exec::parameters_digest(&op, &serde_json::json!({"view": "public.orders_summary", "limit": 10}))
                .map_err(|_| err("bad parameters"))?;
            body["kind"] = "operation".into();
            body["operation_id"] = serde_json::json!(aipass_types::ids::OperationId::generate());
            body["parameters_digest"] = pd.into();
        }
        let req: ApprovalRequest = serde_json::from_value(body).map_err(|_| err("bad test request"))?;
        self.send_to(&dev, &RelayMessage::ApprovalRequest(Box::new(req.clone())))
            .await?;
        self.state
            .lock()
            .await
            .requests
            .entry(apr.to_string())
            .or_insert(req);
        Ok(apr.to_string())
    }

    /// Send a sealed `connection.pair_request` for a pending AI connection. `reuse_id`
    /// re-sends an existing `conn_…` id (e.g. with another `pairing_code`). Returns the id.
    pub async fn send_connection_pair_request(
        &self,
        device_id: String,
        reuse_id: Option<String>,
        pairing_code: String,
    ) -> CoreResult<String> {
        let dev = {
            let st = self.state.lock().await;
            st.trusted
                .iter()
                .find(|d| d.device_id.as_str() == device_id)
                .cloned()
                .ok_or_else(|| err("device is not a trusted approver of this executor"))?
        };
        let conn = match &reuse_id {
            Some(id) => aipass_types::ids::ConnectionId::parse(id).map_err(|_| err("bad connection_id"))?,
            None => aipass_types::ids::ConnectionId::generate(),
        };
        let body = serde_json::json!({
            "connection": {
                "connection_id": conn,
                "host_type": "claude_code",
                "display_name": "Test agent",
                "transport": "stdio",
                "status": "pending",
                "allowed_projects": [],
                "created_at": aipass_types::time::format_rfc3339(&aipass_types::time::now()),
            },
            "pairing_code": pairing_code,
        });
        let req = serde_json::from_value(body).map_err(|_| err("bad test pair request"))?;
        self.send_to(&dev, &RelayMessage::ConnectionPairRequest(Box::new(req)))
            .await?;
        Ok(conn.to_string())
    }

    /// Wait for an `approval.decision`, verify it like the broker, open the credential.
    pub async fn receive_decision(&self, timeout_secs: u32) -> CoreResult<TestDecisionFfi> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(timeout_secs.into());
        loop {
            let left = deadline.saturating_duration_since(tokio::time::Instant::now());
            for (dev, msg) in self.inbox(left.min(Duration::from_secs(5))).await? {
                let RelayMessage::ApprovalDecision(d) = msg else {
                    continue;
                };
                let st = self.state.lock().await;
                let req = st
                    .requests
                    .get(d.approval_request_id.as_str())
                    .ok_or_else(|| err("decision for an unknown request"))?;
                let pk = self.trusted_key(&st, &dev).ok_or_else(|| err("unknown signer"))?;
                let verdict = if d.signer_device_id == dev {
                    aipass_types::approval::verify_decision(&d, req, &pk, &aipass_types::time::now())
                        .map_err(|e| e.code.as_str().to_owned())
                } else {
                    Err("SIGNER_MISMATCH".to_owned())
                };
                let mut out = TestDecisionFfi {
                    approval_request_id: d.approval_request_id.to_string(),
                    decision: crate::types::enum_str(&d.decision),
                    verified: verdict.is_ok(),
                    verify_error: verdict.err(),
                    credential_opened: false,
                    credential_username: None,
                    credential_secret_len: 0,
                };
                if let Some(env) = &d.credential_envelope {
                    let aad = aipass_types::approval::credential_aad_bytes(
                        &d.approval_request_id,
                        &d.digest,
                        &self.exe,
                    )
                    .map_err(|_| err("aad"))?;
                    if let Ok(m) =
                        aipass_types::exec::open_credential(self.identity.kem_keypair(), &aad, env)
                    {
                        out.credential_opened = true;
                        out.credential_username = m.username.clone();
                        out.credential_secret_len =
                            u32::try_from(m.secret.expose().len()).unwrap_or(u32::MAX);
                    }
                }
                return Ok(out);
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(err("no decision received"));
            }
        }
    }

    /// Serve one control message: `state.request` → empty `state.snapshot`;
    /// `grant.revoke` (signature checked) → fully completed `revoke.report`;
    /// `connection.decision` / `connection.control` (signature checked) → logged.
    /// Returns the handled message type.
    pub async fn serve_once(&self, timeout_secs: u32) -> CoreResult<String> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(timeout_secs.into());
        loop {
            let left = deadline.saturating_duration_since(tokio::time::Instant::now());
            for (dev, msg) in self.inbox(left.min(Duration::from_secs(5))).await? {
                let (pk, target) = {
                    let st = self.state.lock().await;
                    let pk = self.trusted_key(&st, &dev).ok_or_else(|| err("unknown signer"))?;
                    let t = st.trusted.iter().find(|d| d.device_id == dev).cloned();
                    (pk, t.ok_or_else(|| err("unknown device"))?)
                };
                let kind = msg.message_type();
                match msg {
                    RelayMessage::StateRequest(_) => {
                        let snap = StateSnapshot {
                            connections: Vec::new(),
                            grants: Vec::new(),
                            executors: Vec::new(),
                            pending_approvals: Vec::new(),
                            recent_operations: Vec::new(),
                            activity_summary: Default::default(),
                        };
                        self.send_to(&target, &RelayMessage::StateSnapshot(Box::new(snap)))
                            .await?;
                    }
                    RelayMessage::GrantRevoke(r) => {
                        r.verify_control(&pk).map_err(|_| err("bad revoke signature"))?;
                        let report = RevocationReport {
                            grant_id: GrantId::parse(r.grant_id.as_str())
                                .map_err(|_| err("grant id"))?,
                            stop_access: LevelReport::done(),
                            end_sessions: LevelReport::done(),
                            revoke_upstream: LevelReport::not_applicable(),
                            completed_at: Some(aipass_types::time::now()),
                        };
                        self.send_to(&target, &RelayMessage::RevokeReport(report))
                            .await?;
                    }
                    RelayMessage::ConnectionDecision(d) => {
                        d.verify_control(&pk)
                            .map_err(|_| err("bad decision signature"))?;
                    }
                    RelayMessage::ConnectionControl(c) => {
                        c.verify_control(&pk)
                            .map_err(|_| err("bad control signature"))?;
                    }
                    _ => continue,
                }
                let name = serde_json::to_value(kind)
                    .ok()
                    .and_then(|v| v.as_str().map(str::to_owned))
                    .unwrap_or_default();
                self.state.lock().await.control_log.push(name.clone());
                return Ok(name);
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(err("no control message received"));
            }
        }
    }
}
