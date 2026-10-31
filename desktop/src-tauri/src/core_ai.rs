// SPDX-License-Identifier: Apache-2.0
//! AI side of the desktop core: embedded node status, AI connections and the host-config
//! wizard, projects and resources, approvals (§5.3), grants with 3-level revocation,
//! operations and the audit log. All results are metadata; the broker never returns
//! secrets or operation results through these admin views.

use std::sync::Arc;

use aipass_broker::{Actor, ApprovalNotifier, BrokerEvent, CredentialSource, NewConnection};
use aipass_client::{AipassHome, ConnectionKey, ConnectionKeyMeta, KeyStore};
use aipass_crypto::{Ed25519Keypair, SecretString};
use aipass_hostconfig::{ConfigPlan, Host, HostEnv, McpEntry, RemoteTarget, Scope};
use aipass_sync::VaultClient;
use aipass_types::ApiError;
use aipass_types::exec::CredentialMaterial;
use aipass_types::ids::{ApprovalRequestId, ConnectionId, EntryId, GrantId, ProjectId, ResourceId};
use aipass_types::models::{
    AccessSpec, AllowedProjects, ApprovalRequest, ApprovalStatus, Connector, CreateProjectRequest, Environment,
    Grant, Resource, ResourceInput, RevocationLevel, Transport,
};
use aipass_types::relay::ControlAction;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::core::{AppCore, EventSink};
use crate::error::{UiError, UiResult};

/// Forwards broker events to the UI. Broker events never carry secrets or results.
pub struct UiNotifier {
    /// Sink.
    pub sink: Arc<dyn EventSink>,
}

impl ApprovalNotifier for UiNotifier {
    fn notify(&self, event: &BrokerEvent) {
        if let Ok(v) = serde_json::to_value(event) {
            self.sink.emit("broker-event", v);
        }
    }
}

/// Re-delivers an approved grant's credential from the unlocked vault (used by the broker
/// after a restart, when the in-memory executor lost the envelope it had installed).
pub struct VaultCredentialSource {
    /// Vault.
    pub vault: Arc<VaultClient>,
}

#[async_trait::async_trait]
impl CredentialSource for VaultCredentialSource {
    async fn material_for_grant(&self, grant: &Grant, resource: &Resource) -> Result<Option<CredentialMaterial>, ApiError> {
        if !self.vault.is_unlocked() {
            return Ok(None);
        }
        let entry = &resource.credential_entry_id;
        let detail = self.vault.get_item(entry).map_err(ApiError::from)?;
        if detail.summary.has_conflict {
            return Err(ApiError::new(aipass_types::ErrorCode::SyncConflict));
        }
        let cred = self.vault.autofill_credential(entry).map_err(ApiError::from)?;
        Ok(Some(CredentialMaterial {
            entry_id: entry.clone(),
            version: detail.version.unwrap_or(1),
            kind: detail.summary.kind,
            username: cred.username.clone(),
            secret: cred.password.clone(),
            database: detail.database.clone(),
            expires_at: grant.expires_at,
        }))
    }
}

/// A host-config plan waiting for the user to confirm.
pub struct PendingPlan {
    /// The plan (contains file contents; never sent to the UI).
    pub plan: ConfigPlan,
    /// Connection created for it.
    pub connection_id: ConnectionId,
}

/// What the UI sees of a plan.
#[derive(Debug, Clone, Serialize)]
pub struct PlanView {
    /// Opaque id.
    pub plan_id: String,
    /// Host.
    pub host: Host,
    /// Scope.
    pub scope: Scope,
    /// File to change.
    pub path: String,
    /// create | update | remove | unchanged.
    pub action: String,
    /// Secret-redacted unified diff.
    pub unified_diff: String,
    /// Connection the entry uses.
    pub connection_id: ConnectionId,
}

/// Host plan request.
#[derive(Debug, Clone, Deserialize)]
pub struct HostPlanInput {
    /// Host.
    pub host: Host,
    /// Scope.
    pub scope: Scope,
    /// Project directory for project-scoped hosts.
    #[serde(default)]
    pub project_dir: Option<String>,
    /// Projects the new connection may see.
    pub allowed_projects: AllowedProjects,
}

/// Resource creation from the UI.
#[derive(Debug, Clone, Deserialize)]
pub struct ResourceForm {
    /// Alias shown to AI.
    pub alias: String,
    /// Service label.
    pub service: String,
    /// Connector.
    pub connector: Connector,
    /// Project.
    pub project_id: ProjectId,
    /// test | production.
    pub environment: Environment,
    /// Connector config (no secrets; validated by the executor).
    pub config: Value,
    /// Vault entry holding the credential.
    pub credential_entry_id: EntryId,
    /// Operations (default: connector v1 operations).
    #[serde(default)]
    pub operations: Option<Vec<String>>,
}

fn host_env(scope: Scope, project_dir: Option<&str>) -> UiResult<HostEnv> {
    let env = HostEnv::from_system()?;
    match (scope, project_dir) {
        (Scope::Project, Some(d)) if !d.trim().is_empty() => {
            let p = std::path::PathBuf::from(d);
            if !p.is_absolute() || !p.is_dir() {
                return Err(UiError::invalid("项目目录必须是已存在的绝对路径", "The project directory must be an existing absolute path"));
            }
            Ok(env.project(p))
        }
        (Scope::Project, _) => Err(UiError::invalid("请选择项目目录", "Choose a project directory")),
        _ => Ok(env),
    }
}

/// Absolute path of the bundled `aipass-mcp` sidecar.
pub fn mcp_binary_path() -> UiResult<std::path::PathBuf> {
    if let Some(p) = std::env::var_os("AIPASS_MCP_PATH") {
        let p = std::path::PathBuf::from(p);
        if p.is_absolute() && p.is_file() {
            return Ok(p);
        }
    }
    let exe = std::env::current_exe()?;
    let dir = exe.parent().ok_or_else(|| UiError::internal("exe dir"))?;
    let name = if cfg!(windows) { "aipass-mcp.exe" } else { "aipass-mcp" };
    let p = dir.join(name);
    if p.is_file() {
        return Ok(p);
    }
    Err(UiError::new(
        "NOT_FOUND",
        "找不到随附的 aipass-mcp 接入桥，请重新安装桌面 App。",
        "The bundled aipass-mcp bridge was not found. Reinstall the desktop app.",
    ))
}

impl AppCore {
    pub(crate) async fn actor(&self) -> Actor {
        match self.vault.device_id() {
            Some(d) => Actor::Device(d),
            None => Actor::System,
        }
    }

    /// Embedded node status and protection-level explanation.
    pub async fn node_status(&self) -> UiResult<Value> {
        let node = self.node.lock().await.clone();
        let Some(n) = node else {
            return Ok(json!({"running": false}));
        };
        let executors = n.broker.list_executors().await?;
        Ok(json!({
            "running": true,
            "executor_id": n.executor_id,
            "protection_level": "compatible",
            "broker_socket": n.broker_socket.as_ref().map(|p| p.display().to_string()),
            "executors": executors,
            "health": n.broker.health(),
        }))
    }

    // ---------------- connections ----------------

    /// All AI connections, with the pairing code of pending ones.
    pub async fn list_connections(&self) -> UiResult<Value> {
        let n = self.node().await?;
        let list = n.broker.list_connections().await?;
        let mut out = Vec::new();
        for c in list.connections {
            let pairing = n.broker.connection_pairing(&c.connection_id).await?;
            let mut v = serde_json::to_value(&c).map_err(|_| UiError::internal("encode"))?;
            if let Some((pid, code, st)) = pairing {
                v["pairing"] = json!({"pairing_id": pid, "code": code, "status": st});
            }
            out.push(v);
        }
        Ok(Value::Array(out))
    }

    /// Approve a pending bridge connection (user compared the pairing code). Needs fresh
    /// presence (`password`), see [`AppCore::confirm_presence`].
    pub async fn approve_connection(&self, id: &ConnectionId, allowed: AllowedProjects, password: Option<&SecretString>) -> UiResult<Value> {
        self.confirm_presence(password).await?;
        let n = self.node().await?;
        let c = n.broker.approve_connection(&self.actor().await, id, allowed).await?;
        Ok(serde_json::to_value(c).unwrap_or(Value::Null))
    }

    /// Deny a pending connection.
    pub async fn deny_connection(&self, id: &ConnectionId) -> UiResult<Value> {
        let n = self.node().await?;
        let c = n.broker.deny_connection(&self.actor().await, id).await?;
        Ok(serde_json::to_value(c).unwrap_or(Value::Null))
    }

    /// Pause / resume / remove / revoke_all.
    pub async fn control_connection(&self, id: &ConnectionId, action: ControlAction) -> UiResult<Value> {
        let n = self.node().await?;
        let r = n.broker.control_connection(&self.actor().await, id, action).await?;
        if action == ControlAction::Remove {
            let ks = KeyStore::new(&AipassHome::new(self.paths.home.clone()));
            let _ = ks.delete(id);
        }
        Ok(serde_json::to_value(r).unwrap_or(Value::Null))
    }

    // ---------------- host config wizard ----------------

    /// Detect installed AI hosts and their existing configuration.
    pub fn host_detect(&self) -> UiResult<Value> {
        let hosts = aipass_hostconfig::detect()?;
        let out: Vec<Value> = hosts
            .iter()
            .map(|h| {
                let mut v = serde_json::to_value(h).unwrap_or(Value::Null);
                v["label_text"] = serde_json::to_value(h.label.label()).unwrap_or(Value::Null);
                v["display_name"] = Value::String(h.host.display_name().to_owned());
                v["is_remote"] = Value::Bool(h.host.is_remote());
                v
            })
            .collect();
        Ok(Value::Array(out))
    }

    /// Create a connection for `host` and plan the config change (nothing written yet).
    pub async fn host_plan(&self, input: HostPlanInput) -> UiResult<PlanView> {
        self.require_unlocked()?;
        if input.host.is_remote() {
            return Err(UiError::invalid("远程宿主请使用远程接入说明", "Remote hosts use the remote setup instructions"));
        }
        let env = host_env(input.scope, input.project_dir.as_deref())?;
        let mcp = mcp_binary_path()?;
        let n = self.node().await?;
        let keypair = Ed25519Keypair::generate();
        let created = n
            .broker
            .create_connection(
                &self.actor().await,
                NewConnection {
                    host_type: input.host.host_type(),
                    display_name: input.host.display_name().to_owned(),
                    transport: Transport::Stdio,
                    allowed_projects: input.allowed_projects,
                    public_key: Some(keypair.public_key_b64u()),
                },
            )
            .await?;
        let conn = created.connection.connection_id.clone();
        let home = AipassHome::new(self.paths.home.clone());
        let key = ConnectionKey::new(
            conn.clone(),
            keypair,
            ConnectionKeyMeta {
                host_type: input.host.host_type(),
                display_name: input.host.display_name().to_owned(),
                broker_url: None,
                created_at: aipass_types::time::now(),
            },
        );
        let cleanup = |n: &Arc<crate::node::EmbeddedNode>, conn: ConnectionId| {
            let n = n.clone();
            async move {
                let _ = n.broker.control_connection(&Actor::System, &conn, ControlAction::Remove).await;
            }
        };
        if let Err(e) = KeyStore::new(&home).save(&key) {
            cleanup(&n, conn.clone()).await;
            return Err(e.into());
        }
        let plan = match McpEntry::stdio(mcp, &conn).and_then(|entry| aipass_hostconfig::plan_in(&env, input.host, input.scope, &entry)) {
            Ok(p) => p,
            Err(e) => {
                let _ = KeyStore::new(&home).delete(&conn);
                cleanup(&n, conn.clone()).await;
                return Err(e.into());
            }
        };
        let plan_id = format!("plan_{}", hex::encode(aipass_crypto::rng::random_array::<12>()));
        let view = PlanView {
            plan_id: plan_id.clone(),
            host: plan.host,
            scope: plan.scope,
            path: plan.path.display().to_string(),
            action: serde_json::to_value(plan.action).ok().and_then(|v| v.as_str().map(str::to_owned)).unwrap_or_default(),
            unified_diff: plan.unified_diff.clone(),
            connection_id: conn.clone(),
        };
        self.host_plans
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(plan_id, PendingPlan { plan, connection_id: conn });
        Ok(view)
    }

    /// Write a planned change (backup + atomic write, only our entry touched).
    pub fn host_apply(&self, plan_id: &str) -> UiResult<Value> {
        let pending = self
            .host_plans
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(plan_id)
            .ok_or_else(|| UiError::invalid("配置预览已失效，请重新生成", "The plan expired; create it again"))?;
        let out = aipass_hostconfig::apply(&pending.plan)?;
        Ok(json!({"outcome": out, "connection_id": pending.connection_id}))
    }

    /// Discard a plan and the connection created for it.
    pub async fn host_cancel(&self, plan_id: &str) -> UiResult<()> {
        let pending = self.host_plans.lock().unwrap_or_else(|e| e.into_inner()).remove(plan_id);
        if let Some(p) = pending {
            self.control_connection(&p.connection_id, ControlAction::Remove).await?;
        }
        Ok(())
    }

    /// Remove our entry from a host's configuration.
    pub fn host_remove(&self, host: Host, scope: Scope, project_dir: Option<String>) -> UiResult<Value> {
        let env = host_env(scope, project_dir.as_deref())?;
        let out = aipass_hostconfig::remove_in(&env, host, scope)?;
        Ok(serde_json::to_value(out).unwrap_or(Value::Null))
    }

    /// Setup instructions for remote hosts (ChatGPT, Claude connector) via the official gateway.
    pub fn remote_instructions(&self, host: Host) -> UiResult<Value> {
        let base = self.settings().cloud_url;
        let r = aipass_hostconfig::remote_instructions(host, &RemoteTarget::OfficialGateway(base))?;
        Ok(serde_json::to_value(r).unwrap_or(Value::Null))
    }

    // ---------------- projects & resources ----------------

    /// Projects.
    pub async fn list_projects(&self) -> UiResult<Value> {
        let n = self.node().await?;
        Ok(serde_json::to_value(n.broker.list_projects().await?).unwrap_or(Value::Null))
    }

    /// Create a project.
    pub async fn create_project(&self, name: &str) -> UiResult<Value> {
        self.require_unlocked()?;
        let name = name.trim();
        if name.is_empty() || name.chars().count() > 80 {
            return Err(UiError::invalid("项目名称需为 1–80 个字符", "Project name must be 1–80 characters"));
        }
        let n = self.node().await?;
        let p = n
            .broker
            .create_project(&self.actor().await, CreateProjectRequest { name: name.to_owned() })
            .await?;
        Ok(serde_json::to_value(p).unwrap_or(Value::Null))
    }

    /// Resources (admin view).
    pub async fn list_resources(&self) -> UiResult<Value> {
        let n = self.node().await?;
        Ok(serde_json::to_value(n.broker.admin_list_resources().await?).unwrap_or(Value::Null))
    }

    /// Create a resource bound to a vault entry on the embedded executor.
    pub async fn create_resource(&self, form: ResourceForm) -> UiResult<Resource> {
        self.require_unlocked()?;
        let n = self.node().await?;
        let detail = self.vault.get_item(&form.credential_entry_id)?;
        if !detail.has_secret {
            return Err(UiError::invalid("所选账号没有可用的密码或 Key", "The chosen entry has no password or key"));
        }
        n.executor.validate_resource_config(form.connector, &form.config)?;
        let r = n
            .broker
            .create_resource(
                &self.actor().await,
                ResourceInput {
                    alias: form.alias.trim().to_owned(),
                    service: form.service.trim().to_owned(),
                    connector: form.connector,
                    project_id: form.project_id,
                    environment: form.environment,
                    config: form.config,
                    credential_entry_id: form.credential_entry_id.clone(),
                    executor_id: n.executor_id.clone(),
                    operations: form.operations,
                },
            )
            .await?;
        self.vault.bind_resource(&r.resource_id, &form.credential_entry_id)?;
        Ok(r)
    }

    /// Delete a resource (revokes its grants).
    pub async fn delete_resource(&self, id: &ResourceId) -> UiResult<()> {
        let n = self.node().await?;
        n.broker.delete_resource(&self.actor().await, id).await?;
        Ok(())
    }

    // ---------------- approvals ----------------

    /// Pending approvals. Each row carries `request_digest`
    /// (`aipass_types::approval::request_digest`) — the UI passes it back with the decision
    /// so the desktop signs exactly the request it displayed.
    pub async fn list_approvals(&self) -> UiResult<Value> {
        let n = self.node().await?;
        let list = n.broker.list_approvals(Some(ApprovalStatus::Pending)).await?;
        let mut approvals = Vec::with_capacity(list.approvals.len());
        for r in &list.approvals {
            let mut v = serde_json::to_value(r).unwrap_or(Value::Null);
            if let (Value::Object(m), Ok(d)) = (&mut v, aipass_types::approval::request_digest(r)) {
                m.insert("request_digest".into(), Value::String(d));
            }
            approvals.push(v);
        }
        Ok(json!({ "approvals": approvals }))
    }

    /// The request fetched for a decision must be exactly the one the UI displayed
    /// (`request_digest` from [`Self::list_approvals`]); `INTEGRITY_FAILED` otherwise.
    fn check_displayed(req: &ApprovalRequest, request_digest: &str) -> UiResult<()> {
        let stored = aipass_types::approval::request_digest(req).map_err(|_| UiError::from(ApiError::internal()))?;
        if aipass_crypto::ct_eq(stored.as_bytes(), request_digest.trim().as_bytes()) {
            Ok(())
        } else {
            Err(UiError::from(
                ApiError::integrity_failed().with_message("该请求的内容与显示的不一致，请重新查看", "This request no longer matches what was displayed; review it again."),
            ))
        }
    }

    /// Approve on this trusted desktop: the vault recomputes the digest, signs it and seals
    /// the bound credential to the embedded executor; the broker verifies everything again.
    /// `narrowed` must be a subset of the request (选择较小权限). Every decision needs fresh
    /// presence (`password`, verified for this call only), so a desktop-driving agent cannot
    /// approve its own request with a click (CLI-01).
    pub async fn approve(&self, id: &ApprovalRequestId, request_digest: &str, narrowed: Option<AccessSpec>, password: Option<&SecretString>) -> UiResult<Value> {
        self.confirm_presence(password).await?;
        let n = self.node().await?;
        let req = n.broker.get_approval(id).await?;
        Self::check_displayed(&req, request_digest)?;
        let decision = self.vault.approve(&req, narrowed).await?;
        let r = n.broker.submit_decision(decision).await?;
        Ok(serde_json::to_value(r).unwrap_or(Value::Null))
    }

    /// Deny (signed), for the request the UI displayed (`request_digest`).
    pub async fn deny(&self, id: &ApprovalRequestId, request_digest: &str) -> UiResult<Value> {
        self.require_unlocked()?;
        let n = self.node().await?;
        let req = n.broker.get_approval(id).await?;
        Self::check_displayed(&req, request_digest)?;
        let decision = self.vault.deny(&req)?;
        let r = n.broker.submit_decision(decision).await?;
        Ok(serde_json::to_value(r).unwrap_or(Value::Null))
    }

    // ---------------- activity ----------------

    /// Recent operations (no results).
    pub async fn list_operations(&self, limit: u64) -> UiResult<Value> {
        let n = self.node().await?;
        Ok(serde_json::to_value(n.broker.list_operations(limit.clamp(1, 500)).await?).unwrap_or(Value::Null))
    }

    /// Grants.
    pub async fn list_grants(&self) -> UiResult<Value> {
        let n = self.node().await?;
        Ok(serde_json::to_value(n.broker.list_grants(None).await?).unwrap_or(Value::Null))
    }

    /// Revoke a grant at one of the three levels; the report states what really happened.
    pub async fn revoke_grant(&self, id: &GrantId, level: RevocationLevel) -> UiResult<Value> {
        let n = self.node().await?;
        let r = n.broker.revoke_grant(&self.actor().await, id, level).await?;
        Ok(json!({"report": r, "fully_revoked": r.fully_revoked(), "label": r.summary_label()}))
    }

    /// Audit events.
    pub async fn audit_events(&self, after: u64, limit: u64) -> UiResult<Value> {
        let n = self.node().await?;
        Ok(serde_json::to_value(n.broker.audit_events(after, limit.clamp(1, 1000)).await?).unwrap_or(Value::Null))
    }

    /// Verify the audit hash chain.
    pub async fn verify_audit(&self) -> UiResult<Value> {
        let n = self.node().await?;
        Ok(serde_json::to_value(n.broker.verify_audit().await?).unwrap_or(Value::Null))
    }

    /// Activity summary with anomalies.
    pub async fn activity_summary(&self) -> UiResult<Value> {
        let n = self.node().await?;
        Ok(serde_json::to_value(n.broker.activity_summary(None).await?).unwrap_or(Value::Null))
    }
}
