// SPDX-License-Identifier: Apache-2.0
//! Access Broker models (CONTRACTS §6.1) and HTTP API request/response shapes (§6.3).
//!
//! All JSON is snake_case; enums serialize as exactly the strings in the contract.
//! Optional contract fields (`field?`) are omitted when absent; `X|null` fields are always
//! present. None of these types carries secrets — credential material lives only in
//! [`crate::exec::CredentialMaterial`] and inside sealed envelopes.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;

use crate::error::{ErrorObject, Localized};
use crate::ids::{
    ApprovalRequestId, ConnectionId, DeviceId, EntryId, EventId, ExecutorId, GrantId, LeaseId,
    OperationId, PairingId, PolicyId, ProjectId, ResourceId,
};
use crate::time::{Timestamp, rfc3339, rfc3339_option};

// ======================================================================================
// Enums
// ======================================================================================

/// AI host type of an [`AppConnection`]. A label — never identity (§7.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostType {
    /// OpenAI Codex (CLI / IDE).
    Codex,
    /// Claude Code.
    ClaudeCode,
    /// Cursor.
    Cursor,
    /// ChatGPT (remote MCP).
    Chatgpt,
    /// Claude custom connector (remote MCP).
    ClaudeConnector,
    /// SDK client.
    Sdk,
    /// Anything else speaking standard MCP.
    Custom,
}

/// Transport of an [`AppConnection`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Transport {
    /// Local stdio MCP bridge.
    Stdio,
    /// Streamable HTTP MCP.
    Http,
    /// SDK over the broker API.
    Sdk,
    /// Through the official remote MCP gateway.
    RemoteGateway,
}

/// Lifecycle of an [`AppConnection`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionStatus {
    /// Waiting for approval on a trusted device.
    Pending,
    /// Approved and usable.
    Active,
    /// Paused by the user (`CONNECTION_PAUSED`).
    Paused,
    /// Removed.
    Removed,
}

/// Which projects a connection may see: `["*"]` or a list of `proj_…` ids.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum AllowedProjects {
    /// `["*"]` — every project.
    All,
    /// Explicit project list (may be empty = nothing visible).
    Only(BTreeSet<ProjectId>),
}

impl Default for AllowedProjects {
    fn default() -> Self {
        Self::Only(BTreeSet::new())
    }
}

impl AllowedProjects {
    /// Whether `project` is visible.
    pub fn allows(&self, project: &ProjectId) -> bool {
        match self {
            Self::All => true,
            Self::Only(s) => s.contains(project),
        }
    }
}

impl Serialize for AllowedProjects {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::All => ["*"].serialize(s),
            Self::Only(set) => set.serialize(s),
        }
    }
}

impl<'de> Deserialize<'de> for AllowedProjects {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let items = Vec::<String>::deserialize(d)?;
        if items.iter().any(|i| i == "*") {
            if items.len() != 1 {
                return Err(serde::de::Error::custom(
                    "\"*\" must be the only element of allowed_projects",
                ));
            }
            return Ok(Self::All);
        }
        let mut set = BTreeSet::new();
        for i in items {
            set.insert(ProjectId::try_from(i).map_err(serde::de::Error::custom)?);
        }
        Ok(Self::Only(set))
    }
}

/// Connector kinds offered in V1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Connector {
    /// PostgreSQL restricted view queries.
    Postgres,
    /// GitHub repository reads.
    Github,
    /// Declarative HTTPS API connector.
    HttpApi,
}

impl Connector {
    /// Wire name.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Postgres => "postgres",
            Self::Github => "github",
            Self::HttpApi => "http_api",
        }
    }
}

/// Resource environment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Environment {
    /// Test / staging data.
    Test,
    /// Production data.
    Production,
}

/// Resource availability (UI: 可用 · 需要重新登录 · 同步冲突 · 执行设备离线 · 已停用).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceStatus {
    /// Usable.
    Available,
    /// Upstream needs re-login.
    NeedsLogin,
    /// Credential entry has an unresolved sync conflict.
    SyncConflict,
    /// Executor offline.
    ExecutorOffline,
    /// Disabled by the user.
    Disabled,
}

/// Approval / grant mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalMode {
    /// Serves exactly one operation.
    Once,
    /// Same connection + scope until expiry (default 900 s, max 24 h).
    Task,
    /// Standing signed rule (policy).
    Rule,
}

impl ApprovalMode {
    /// Breadth rank: once (0) < task (1) < rule (2). A narrowed approval may only lower it.
    pub fn rank(&self) -> u8 {
        match self {
            Self::Once => 0,
            Self::Task => 1,
            Self::Rule => 2,
        }
    }
}

/// Executor protection level (UI: 隔离执行 / 兼容连接, §9.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtectionLevel {
    /// Separate host/VM attested by the node operator.
    Isolated,
    /// Shares an unrestricted user environment with the AI host.
    Compatible,
}

impl ProtectionLevel {
    /// UI label.
    pub fn label(&self) -> Localized {
        match self {
            Self::Isolated => Localized::new("隔离执行", "Isolated execution"),
            Self::Compatible => Localized::new("兼容连接", "Compatible connection"),
        }
    }
}

/// Side-effect class of an operation spec.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SideEffectClass {
    /// Read-only.
    Read,
    /// Writes, reversible.
    Write,
    /// Irreversible (delete, pay, submit).
    Irreversible,
}

/// Actual side-effect status of an operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SideEffects {
    /// Nothing was sent upstream / read-only.
    #[default]
    None,
    /// May have been applied upstream (outcome unknown).
    Possible,
    /// Applied.
    Applied,
}

/// Status of an [`ApprovalRequest`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalStatus {
    /// Waiting for a trusted device.
    Pending,
    /// Approved.
    Approved,
    /// Denied.
    Denied,
    /// Expired — never auto-approved.
    Expired,
    /// Cancelled.
    Cancelled,
}

/// Kind of approval request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalKind {
    /// Triggered by a concrete operation (TTL 120 s).
    Operation,
    /// Explicit `access.request` (TTL 600 s).
    Access,
}

/// A decision on an approval request or connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    /// Allow.
    Approve,
    /// Refuse.
    Deny,
}

impl Decision {
    /// Wire name (`approve` / `deny`).
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Approve => "approve",
            Self::Deny => "deny",
        }
    }
}

/// Grant status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantStatus {
    /// Usable.
    Active,
    /// Past `expires_at`.
    Expired,
    /// Revoked by the user.
    Revoked,
    /// Budget used up.
    Exhausted,
    /// Released by the connection (`access.release`).
    Released,
}

/// Policy status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyStatus {
    /// In force.
    Active,
    /// Disabled (`POST /policies/{id}/disable`).
    Disabled,
}

/// What an executor does when it loses its control channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlChannelLostAction {
    /// The only V1 behaviour.
    #[default]
    DenyNewOperations,
}

/// Revocation level (§8.4). Each higher level includes the lower ones.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevocationLevel {
    /// Reject new and queued operations.
    StopAccess,
    /// Also cancel running operations, close sessions, drop credentials.
    EndSessions,
    /// Also revoke upstream leases/tokens where supported.
    RevokeUpstream,
}

/// Outcome of one revocation level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LevelStatus {
    /// Completed.
    Done,
    /// In progress / waiting on upstream (UI: 待处理).
    Pending,
    /// Failed (UI: 部分撤销失败).
    Failed,
    /// Nothing to do at this level.
    NotApplicable,
}

/// Executor online indicator in [`ResourceView`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutorStatus {
    /// Online.
    Online,
    /// Offline (UI: 执行设备离线).
    Offline,
}

// ======================================================================================
// §6.1 objects
// ======================================================================================

/// An AI host registered with the broker. `display_name` is a label, never identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppConnection {
    /// `conn_…`.
    pub connection_id: ConnectionId,
    /// Host type label.
    pub host_type: HostType,
    /// Display label (self-declared).
    pub display_name: String,
    /// Transport.
    pub transport: Transport,
    /// Status.
    pub status: ConnectionStatus,
    /// Ed25519 connection key (b64u) used for `AIPass-Sig`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
    /// `["*"]` or `proj_…` list.
    pub allowed_projects: AllowedProjects,
    /// Created.
    #[serde(with = "rfc3339")]
    pub created_at: Timestamp,
    /// When approved.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "rfc3339_option"
    )]
    pub approved_at: Option<Timestamp>,
    /// Approving device.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approved_by: Option<DeviceId>,
    /// Last authenticated request.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "rfc3339_option"
    )]
    pub last_seen_at: Option<Timestamp>,
}

/// A project grouping resources.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Project {
    /// `proj_…`.
    pub project_id: ProjectId,
    /// Name.
    pub name: String,
}

/// A business resource an AI may operate on through a connector. `config` never contains
/// secrets; the credential is referenced by vault entry id.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Resource {
    /// `res_…`.
    pub resource_id: ResourceId,
    /// Human alias shown to AI hosts (hosts are shown only as alias).
    pub alias: String,
    /// Service label, e.g. `"postgres"`, `"github"`, `"stripe"`.
    pub service: String,
    /// Connector.
    pub connector: Connector,
    /// Owning project.
    pub project_id: ProjectId,
    /// Environment.
    pub environment: Environment,
    /// Connector configuration (no secrets).
    pub config: Value,
    /// Vault entry holding the credential.
    pub credential_entry_id: EntryId,
    /// Executor that runs operations for this resource.
    pub executor_id: ExecutorId,
    /// Operation names offered.
    pub operations: Vec<String>,
    /// Availability.
    pub status: ResourceStatus,
    /// Created.
    #[serde(with = "rfc3339")]
    pub created_at: Timestamp,
}

/// PostgreSQL part of a grant scope: `{"schema.view": [field, …]}`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct PostgresScope {
    /// Allowed views → allowed fields.
    pub views: BTreeMap<String, Vec<String>>,
}

/// GitHub part of a grant scope.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct GithubScope {
    /// `owner/name` repositories.
    pub repos: Vec<String>,
}

/// Declarative HTTP API part of a grant scope.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct HttpApiScope {
    /// Declared operation names.
    pub operations: Vec<String>,
}

/// What a grant allows. See [`crate::approval::normalize_scope`] for the canonical form.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct GrantScope {
    /// Operation names.
    pub operations: Vec<String>,
    /// PostgreSQL views/fields.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub postgres: Option<PostgresScope>,
    /// GitHub repositories.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub github: Option<GithubScope>,
    /// HTTP API operations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_api: Option<HttpApiScope>,
}

/// Budget limits (integers). Defaults 1000 / 5000 / 20 / 262144.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Limits {
    /// Rows per operation.
    pub max_rows_per_operation: u64,
    /// Rows across the grant (cumulative; defeats pagination bypass, A08).
    pub max_rows_per_grant: u64,
    /// Requests across the grant.
    pub max_requests_per_grant: u64,
    /// Result bytes per operation.
    pub max_result_bytes: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_rows_per_operation: 1000,
            max_rows_per_grant: 5000,
            max_requests_per_grant: 20,
            max_result_bytes: 262_144,
        }
    }
}

impl Limits {
    /// True when every limit is ≤ the corresponding limit of `other`.
    pub fn within(&self, other: &Limits) -> bool {
        self.max_rows_per_operation <= other.max_rows_per_operation
            && self.max_rows_per_grant <= other.max_rows_per_grant
            && self.max_requests_per_grant <= other.max_requests_per_grant
            && self.max_result_bytes <= other.max_result_bytes
    }
}

/// A signed standing policy (superset of the design doc §8.2 example).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Policy {
    /// `pol_…`.
    pub policy_id: PolicyId,
    /// Monotonic version.
    pub version: u64,
    /// Connection the policy applies to.
    pub subject_connection_id: ConnectionId,
    /// Project.
    pub project_id: ProjectId,
    /// Resource.
    pub resource_id: ResourceId,
    /// Executor.
    pub executor_id: ExecutorId,
    /// Flat compatibility field (§8.2).
    pub allowed_operations: Vec<String>,
    /// Flat compatibility field (§8.2).
    pub allowed_views: Vec<String>,
    /// Flat compatibility field (§8.2).
    pub allowed_fields: Vec<String>,
    /// Structured scope (authoritative).
    pub scope: GrantScope,
    /// Limits.
    pub limits: Limits,
    /// TTL of grants created from this policy.
    pub grant_ttl_seconds: u64,
    /// Mode.
    pub approval_mode: ApprovalMode,
    /// Auto-approve — only valid for `rule` + `environment:"test"` + read-only operations.
    pub auto_approve: bool,
    /// Always `deny_new_operations`.
    pub on_control_channel_lost: ControlChannelLostAction,
    /// Connections allowed to receive results.
    pub output_recipients: Vec<ConnectionId>,
    /// Status.
    pub status: PolicyStatus,
    /// Created.
    #[serde(with = "rfc3339")]
    pub created_at: Timestamp,
    /// Signing device.
    pub signed_by: DeviceId,
    /// b64u Ed25519 over [`crate::policy::signing_message`].
    pub signature: String,
}

/// Connection summary inside an [`ApprovalRequest`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalConnection {
    /// Connection.
    pub connection_id: ConnectionId,
    /// Label.
    pub display_name: String,
    /// Host type.
    pub host_type: HostType,
    /// Always `true` — only authenticated connections can create requests.
    pub verified: bool,
}

/// Resource summary inside an [`ApprovalRequest`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalResource {
    /// Resource.
    pub resource_id: ResourceId,
    /// Alias.
    pub alias: String,
    /// Service.
    pub service: String,
    /// Environment.
    pub environment: Environment,
}

/// Requested or approved access (`requested` / `approved` of §6.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessSpec {
    /// Operations.
    pub operations: Vec<String>,
    /// Scope.
    pub scope: GrantScope,
    /// Limits.
    pub limits: Limits,
    /// Grant duration.
    pub duration_seconds: u64,
    /// Mode.
    pub mode: ApprovalMode,
}

/// Executor summary inside an [`ApprovalRequest`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalExecutor {
    /// Executor.
    pub executor_id: ExecutorId,
    /// Name (UI: 执行位置).
    pub name: String,
    /// Protection level.
    pub protection_level: ProtectionLevel,
}

/// A result recipient (UI: 结果接收方).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Recipient {
    /// Connection.
    pub connection_id: ConnectionId,
    /// Label.
    pub display_name: String,
}

/// An approval request shown on a trusted device. Field order of design doc §5.3:
/// requester, resource, operation, data fields (and excluded fields), scope/limits/duration,
/// execution location, result recipients.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ApprovalRequest {
    /// `apr_…`.
    pub approval_request_id: ApprovalRequestId,
    /// Kind.
    pub kind: ApprovalKind,
    /// Requester.
    pub connection: ApprovalConnection,
    /// Resource.
    pub resource: ApprovalResource,
    /// Human summary.
    pub summary: Localized,
    /// What is requested.
    pub requested: AccessSpec,
    /// Additive extension: per-view fields that exist but are **not** requested (UI:
    /// "不含客户邮箱"). Display only; not part of the digest.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub excluded_fields: BTreeMap<String, Vec<String>>,
    /// Execution location.
    pub executor: ApprovalExecutor,
    /// Result recipients.
    pub recipients: Vec<Recipient>,
    /// Status.
    pub status: ApprovalStatus,
    /// Created.
    #[serde(with = "rfc3339")]
    pub created_at: Timestamp,
    /// Approval window end (never approved after).
    #[serde(with = "rfc3339")]
    pub expires_at: Timestamp,
    /// Operation that triggered it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<OperationId>,
    /// `parameters_digest` of the triggering operation's normalized parameters
    /// (`kind:"operation"` only). Part of the §7 v2 digest, so a decision binds to the
    /// exact request the user saw.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parameters_digest: Option<String>,
}

/// A signed decision from a trusted device (§7).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ApprovalDecision {
    /// Request.
    pub approval_request_id: ApprovalRequestId,
    /// Decision.
    pub decision: Decision,
    /// Approved access (⊆ requested); present for `approve`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approved: Option<AccessSpec>,
    /// Grant expiry.
    #[serde(with = "rfc3339")]
    pub expires_at: Timestamp,
    /// b64u digest ([`crate::approval::compute_digest`]).
    pub digest: String,
    /// Signing device.
    pub signer_device_id: DeviceId,
    /// Signing time.
    #[serde(with = "rfc3339")]
    pub signed_at: Timestamp,
    /// b64u Ed25519 over [`crate::approval::signing_message`].
    pub signature: String,
    /// Credential sealed to the executor (`info=aipass/v1/credential`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_envelope: Option<aipass_crypto::SealedBox>,
}

/// Usage counters of a grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct GrantUsage {
    /// Requests.
    pub requests: u64,
    /// Rows.
    pub rows: u64,
    /// Bytes.
    pub bytes: u64,
}

/// A grant: the authorization record bound to an approval digest or policy.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Grant {
    /// `grt_…`.
    pub grant_id: GrantId,
    /// Source approval.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_request_id: Option<ApprovalRequestId>,
    /// Source policy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_id: Option<PolicyId>,
    /// Policy version.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_version: Option<u64>,
    /// Connection.
    pub connection_id: ConnectionId,
    /// Resource.
    pub resource_id: ResourceId,
    /// Executor.
    pub executor_id: ExecutorId,
    /// Scope.
    pub scope: GrantScope,
    /// Limits.
    pub limits: Limits,
    /// Mode.
    pub mode: ApprovalMode,
    /// Approval digest this grant is bound to.
    pub digest: String,
    /// Status.
    pub status: GrantStatus,
    /// Usage.
    pub usage: GrantUsage,
    /// Created.
    #[serde(with = "rfc3339")]
    pub created_at: Timestamp,
    /// Expiry.
    #[serde(with = "rfc3339")]
    pub expires_at: Timestamp,
    /// Revocation time.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "rfc3339_option"
    )]
    pub revoked_at: Option<Timestamp>,
    /// Revocation report.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revocation: Option<RevocationReport>,
}

/// Operation status (§6.2 state machine). The API shows `awaiting_approval` as
/// `"approval_required"`; `"awaiting_approval"` is accepted on input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationStatus {
    /// Received.
    Received,
    /// Policy checked.
    PolicyChecked,
    /// Waiting for approval.
    #[serde(rename = "approval_required", alias = "awaiting_approval")]
    AwaitingApproval,
    /// Authorized, about to run.
    Authorized,
    /// Running.
    Running,
    /// Succeeded (terminal).
    Succeeded,
    /// Failed (terminal).
    Failed,
    /// Outcome unknown — upstream may have executed (terminal).
    Unknown,
    /// Denied (terminal).
    Denied,
    /// Approval expired (terminal).
    Expired,
    /// Cancelled (terminal).
    Cancelled,
}

impl OperationStatus {
    /// API wire string (`approval_required` for [`OperationStatus::AwaitingApproval`]).
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Received => "received",
            Self::PolicyChecked => "policy_checked",
            Self::AwaitingApproval => "approval_required",
            Self::Authorized => "authorized",
            Self::Running => "running",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Unknown => "unknown",
            Self::Denied => "denied",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
        }
    }

    /// Internal state-machine name (`awaiting_approval`), e.g. for database columns.
    pub fn state_name(&self) -> &'static str {
        match self {
            Self::AwaitingApproval => "awaiting_approval",
            other => other.as_str(),
        }
    }

    /// Parse either the API or the internal name.
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "received" => Self::Received,
            "policy_checked" => Self::PolicyChecked,
            "approval_required" | "awaiting_approval" => Self::AwaitingApproval,
            "authorized" => Self::Authorized,
            "running" => Self::Running,
            "succeeded" => Self::Succeeded,
            "failed" => Self::Failed,
            "unknown" => Self::Unknown,
            "denied" => Self::Denied,
            "expired" => Self::Expired,
            "cancelled" => Self::Cancelled,
            _ => return None,
        })
    }

    /// Terminal states: `succeeded failed unknown denied expired cancelled`.
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            Self::Succeeded
                | Self::Failed
                | Self::Unknown
                | Self::Denied
                | Self::Expired
                | Self::Cancelled
        )
    }

    /// Whether `self → next` is a legal transition (CONTRACTS §6.2):
    /// `received → policy_checked → (awaiting_approval | authorized | denied)`;
    /// `awaiting_approval → authorized | denied | expired | cancelled`;
    /// `authorized → running | cancelled | failed`;
    /// `running → succeeded | failed | unknown | cancelled`.
    pub fn can_transition(&self, next: OperationStatus) -> bool {
        use OperationStatus::*;
        matches!(
            (self, next),
            (Received, PolicyChecked)
                | (PolicyChecked, AwaitingApproval | Authorized | Denied)
                | (AwaitingApproval, Authorized | Denied | Expired | Cancelled)
                | (Authorized, Running | Cancelled | Failed)
                | (Running, Succeeded | Failed | Unknown | Cancelled)
        )
    }
}

/// The result returned to the AI host after the output filter.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OperationResult {
    /// Filtered data.
    pub data: Value,
    /// Rows returned.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rows: Option<u64>,
    /// Truncated by limits.
    pub truncated: bool,
    /// Some fields were redacted (`[REDACTED]`).
    pub restricted: bool,
    /// Names of redacted fields.
    pub restricted_fields: Vec<String>,
}

/// An operation record.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Operation {
    /// `op_…`.
    pub operation_id: OperationId,
    /// Connection.
    pub connection_id: ConnectionId,
    /// Resource.
    pub resource_id: ResourceId,
    /// Operation name, e.g. `postgres.query_view`.
    pub operation: String,
    /// Digest of the normalized parameters.
    pub parameters_digest: String,
    /// Idempotency key (1..=128).
    pub idempotency_key: String,
    /// Status.
    pub status: OperationStatus,
    /// Grant used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_id: Option<GrantId>,
    /// Approval request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_request_id: Option<ApprovalRequestId>,
    /// Result.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<OperationResult>,
    /// Error.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<ErrorObject>,
    /// Side effects.
    pub side_effects: SideEffects,
    /// Created.
    #[serde(with = "rfc3339")]
    pub created_at: Timestamp,
    /// Updated.
    #[serde(with = "rfc3339")]
    pub updated_at: Timestamp,
}

/// Outcome of one revocation level (`{status, detail?}`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LevelReport {
    /// Status.
    pub status: LevelStatus,
    /// Non-sensitive detail.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl LevelReport {
    /// `{status:"done"}`.
    pub fn done() -> Self {
        Self {
            status: LevelStatus::Done,
            detail: None,
        }
    }
    /// `{status:"not_applicable"}`.
    pub fn not_applicable() -> Self {
        Self {
            status: LevelStatus::NotApplicable,
            detail: None,
        }
    }
    /// `{status:"pending", detail}`.
    pub fn pending(detail: impl Into<String>) -> Self {
        Self {
            status: LevelStatus::Pending,
            detail: Some(detail.into()),
        }
    }
    /// `{status:"failed", detail}`.
    pub fn failed(detail: impl Into<String>) -> Self {
        Self {
            status: LevelStatus::Failed,
            detail: Some(detail.into()),
        }
    }
    /// Done or not applicable.
    pub fn is_settled(&self) -> bool {
        matches!(self.status, LevelStatus::Done | LevelStatus::NotApplicable)
    }
}

/// Three-level revocation report (§8.4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevocationReport {
    /// Grant.
    pub grant_id: GrantId,
    /// Level 1.
    pub stop_access: LevelReport,
    /// Level 2.
    pub end_sessions: LevelReport,
    /// Level 3.
    pub revoke_upstream: LevelReport,
    /// When all levels settled.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "rfc3339_option"
    )]
    pub completed_at: Option<Timestamp>,
}

impl RevocationReport {
    /// UI may say "全部已收回" only when every level is `done` / `not_applicable`.
    pub fn fully_revoked(&self) -> bool {
        self.stop_access.is_settled()
            && self.end_sessions.is_settled()
            && self.revoke_upstream.is_settled()
    }

    /// Status label: 全部已收回 / 部分撤销失败 / 待处理.
    pub fn summary_label(&self) -> Localized {
        let levels = [&self.stop_access, &self.end_sessions, &self.revoke_upstream];
        if self.fully_revoked() {
            Localized::new("全部已收回", "Fully revoked")
        } else if levels.iter().any(|l| l.status == LevelStatus::Failed) {
            Localized::new("部分撤销失败", "Partially failed")
        } else {
            Localized::new("待处理", "Pending")
        }
    }
}

/// An upstream lease (temporary role, token).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Lease {
    /// `lse_…`.
    pub lease_id: LeaseId,
    /// Grant.
    pub grant_id: GrantId,
    /// Kind, e.g. `postgres.temporary_role`.
    pub kind: String,
    /// Upstream reference (role name, token id — never the secret).
    pub upstream_ref: String,
    /// Expiry.
    #[serde(with = "rfc3339")]
    pub expires_at: Timestamp,
    /// Revocation progress.
    pub revoke_status: LevelStatus,
}

/// A hash-chained audit event. `detail` holds no secrets and no result bodies.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Sequence number (1-based).
    pub seq: u64,
    /// `evt_…`.
    pub event_id: EventId,
    /// Time.
    #[serde(with = "rfc3339")]
    pub ts: Timestamp,
    /// Actor principal id or `"system"`.
    pub actor: String,
    /// Action, e.g. `operation.succeeded`, `rule.auto_approved`.
    pub action: String,
    /// Resource.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_id: Option<ResourceId>,
    /// Operation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<OperationId>,
    /// Grant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_id: Option<GrantId>,
    /// Outcome, e.g. `ok`, `denied`, `error`.
    pub outcome: String,
    /// Error code.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_code: Option<crate::error::ErrorCode>,
    /// Non-sensitive detail object.
    pub detail: Value,
    /// Previous event hash (b64u; `""` for the first event).
    pub prev_hash: String,
    /// `b64u(SHA-256(prev_hash_bytes ‖ JCS(event minus hash)))`.
    pub hash: String,
}

impl AuditEvent {
    /// Compute the chained hash. `prev_hash_bytes` = b64u-decoded `prev_hash` (empty for the
    /// first event).
    pub fn compute_hash(&self) -> Result<String, crate::canonical::CanonicalError> {
        let prev = if self.prev_hash.is_empty() {
            Vec::new()
        } else {
            aipass_crypto::b64u::decode(&self.prev_hash)
                .map_err(|_| crate::canonical::CanonicalError::NotAnObject)?
        };
        let body = crate::canonical::jcs_without_field(self, "hash")?;
        Ok(aipass_crypto::b64u::encode(
            aipass_crypto::hash::sha256_concat(&[&prev, &body]),
        ))
    }

    /// Set `hash` from the current contents.
    pub fn seal(&mut self) -> Result<(), crate::canonical::CanonicalError> {
        self.hash = self.compute_hash()?;
        Ok(())
    }

    /// Verify `hash` and (optionally) the link to the previous event.
    pub fn verify(&self, expected_prev_hash: &str) -> bool {
        self.prev_hash == expected_prev_hash && self.compute_hash().is_ok_and(|h| h == self.hash)
    }
}

/// Executor node info. Desktop-embedded executors are always `compatible`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutorInfo {
    /// `exe_…`.
    pub executor_id: ExecutorId,
    /// Name.
    pub name: String,
    /// Protection level.
    pub protection_level: ProtectionLevel,
    /// Connectors offered.
    pub capabilities: Vec<Connector>,
    /// Online.
    pub online: bool,
    /// Last heartbeat.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "rfc3339_option"
    )]
    pub last_heartbeat_at: Option<Timestamp>,
    /// Ed25519 public key (b64u).
    #[serde(with = "aipass_crypto::b64u::array")]
    pub sign_pk: [u8; 32],
    /// X25519 KEM public key (b64u) — credential envelopes are sealed to it.
    #[serde(with = "aipass_crypto::b64u::array")]
    pub kem_pk: [u8; 32],
}

// ======================================================================================
// §6.3 HTTP API shapes
// ======================================================================================

/// The exact approval-required message of design doc §12.2.
pub const APPROVAL_REQUIRED_MESSAGE: &str = "请在已配对的手机或可信客户端批准本次访问。";
/// English equivalent.
pub const APPROVAL_REQUIRED_MESSAGE_EN: &str =
    "Please approve this access on your paired phone or trusted client.";

/// `POST /connections/pair` body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairConnectionRequest {
    /// Host type.
    pub host_type: HostType,
    /// Label.
    pub display_name: String,
    /// Transport.
    pub transport: Transport,
    /// Ed25519 connection public key (b64u).
    pub public_key: String,
}

/// `POST /connections/pair` response (201).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairConnectionResponse {
    /// Pairing request (`pair_…`).
    pub pairing_request_id: PairingId,
    /// The pending connection.
    pub connection_id: ConnectionId,
    /// Short code shown on both sides.
    pub pairing_code: String,
    /// Expiry.
    #[serde(with = "rfc3339")]
    pub expires_at: Timestamp,
}

/// Status of a connection pairing request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PairStatus {
    /// Waiting.
    Pending,
    /// Approved.
    Approved,
    /// Denied.
    Denied,
    /// Expired.
    Expired,
}

/// `GET /connections/pair/{id}` response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairStatusResponse {
    /// Status.
    pub status: PairStatus,
    /// Connection.
    pub connection_id: ConnectionId,
}

/// One operation offered by a resource.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OperationView {
    /// Name.
    pub name: String,
    /// Description (language per `Accept-Language`).
    pub description: String,
    /// Side-effect class.
    pub side_effect: SideEffectClass,
    /// JSON Schema of `parameters`.
    pub parameters_schema: Value,
}

/// A resource as shown to an AI principal — never contains config secrets; hosts only as alias.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResourceView {
    /// Resource.
    pub resource_id: ResourceId,
    /// Alias.
    pub alias: String,
    /// Service.
    pub service: String,
    /// Project.
    pub project_id: ProjectId,
    /// Environment.
    pub environment: Environment,
    /// Operations.
    pub operations: Vec<OperationView>,
    /// Status.
    pub status: ResourceStatus,
    /// Protection level of its executor.
    pub protection_level: ProtectionLevel,
    /// Executor online/offline.
    pub executor_status: ExecutorStatus,
}

/// `GET /resources` response.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResourcesResponse {
    /// Resources.
    pub resources: Vec<ResourceView>,
}

/// Maximum idempotency key length.
pub const MAX_IDEMPOTENCY_KEY_LEN: usize = 128;

/// `POST /operations` body.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OperationRequest {
    /// Resource.
    pub resource_id: ResourceId,
    /// Operation name.
    pub operation: String,
    /// Structured parameters (object).
    #[serde(default = "empty_object")]
    pub parameters: Value,
    /// Idempotency key (1..=128 printable characters).
    pub idempotency_key: String,
    /// Optional task id (label only — not identity).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_id: Option<String>,
}

fn empty_object() -> Value {
    Value::Object(serde_json::Map::new())
}

impl OperationRequest {
    /// Shape validation (not authorization).
    pub fn validate(&self) -> Result<(), crate::error::ApiError> {
        let k = &self.idempotency_key;
        if k.is_empty()
            || k.chars().count() > MAX_IDEMPOTENCY_KEY_LEN
            || k.chars().any(char::is_control)
        {
            return Err(crate::error::ApiError::invalid_request(
                "idempotency_key 必须为 1 到 128 个可打印字符",
                "idempotency_key must be 1 to 128 printable characters",
            )
            .with_detail("field", "idempotency_key"));
        }
        if !self.parameters.is_object() {
            return Err(crate::error::ApiError::invalid_request(
                "parameters 必须是对象",
                "parameters must be an object",
            )
            .with_detail("field", "parameters"));
        }
        if self.operation.is_empty() || self.operation.len() > 128 {
            return Err(crate::error::ApiError::invalid_request(
                "operation 无效",
                "invalid operation",
            )
            .with_detail("field", "operation"));
        }
        Ok(())
    }
}

/// `POST /operations` / `GET /operations/{id}` response (200 done / 202 pending).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OperationResponse {
    /// Status (`approval_required` while waiting).
    pub status: OperationStatus,
    /// Operation.
    pub operation_id: OperationId,
    /// Approval request (when waiting).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_request_id: Option<ApprovalRequestId>,
    /// Seconds until the approval window closes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_in_seconds: Option<u64>,
    /// Human hint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// Result.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<OperationResult>,
    /// Error.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<ErrorObject>,
}

impl OperationResponse {
    /// The approval-required response exactly as design doc §12.2.
    pub fn approval_required(
        operation_id: OperationId,
        approval_request_id: ApprovalRequestId,
        expires_in_seconds: u64,
    ) -> Self {
        Self {
            status: OperationStatus::AwaitingApproval,
            operation_id,
            approval_request_id: Some(approval_request_id),
            expires_in_seconds: Some(expires_in_seconds),
            message: Some(APPROVAL_REQUIRED_MESSAGE.to_owned()),
            result: None,
            error: None,
        }
    }

    /// HTTP status: 202 while not terminal, 200 otherwise.
    pub fn http_status(&self) -> u16 {
        if self.status.is_terminal() { 200 } else { 202 }
    }
}

/// `POST /operations/{id}/cancel` response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CancelResponse {
    /// Operation.
    pub operation_id: OperationId,
    /// Status after the cancel attempt.
    pub status: OperationStatus,
    /// Whether it was cancelled.
    pub cancelled: bool,
    /// Side effects that may already have happened.
    pub side_effects: SideEffects,
    /// Human message.
    pub message: String,
}

/// `POST /access/requests` body.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AccessRequest {
    /// Resource.
    pub resource_id: ResourceId,
    /// Operations.
    pub operations: Vec<String>,
    /// Requested scope.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<GrantScope>,
    /// Requested limits.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limits: Option<Limits>,
    /// Requested duration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_seconds: Option<u64>,
    /// Reason (shown to the user; never used to widen permissions).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// `POST /access/requests` (202) and `GET /access/requests/{id}` response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessRequestResponse {
    /// Approval request.
    pub approval_request_id: ApprovalRequestId,
    /// Status.
    pub status: ApprovalStatus,
    /// Grant once approved.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_id: Option<GrantId>,
}

/// `POST /access/grants/{id}/release` response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseResponse {
    /// Grant.
    pub grant_id: GrantId,
    /// Always `released`.
    pub status: GrantStatus,
}

/// `GET /approvals` response.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ApprovalsResponse {
    /// Approvals.
    pub approvals: Vec<ApprovalRequest>,
}

/// `POST /approvals/{id}/decision` response.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DecisionResponse {
    /// Resulting approval status.
    pub status: ApprovalStatus,
    /// Grant created.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_id: Option<GrantId>,
    /// Operation outcome, when the approval resumed an operation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation: Option<OperationResponse>,
}

/// `GET /connections` response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectionsResponse {
    /// Connections.
    pub connections: Vec<AppConnection>,
}

/// A connection as shown to trusted devices / local admins (`GET /v1/connections/{id}`
/// and the rows of `GET /v1/connections`, D/A only). While the connection is `pending`
/// and its pairing is still open, it also carries the 6-digit `pairing_code` the AI host
/// displayed, so the approving user can compare the two before approving. Never sent to
/// AI connections (`C` principals cannot call these endpoints).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectionView {
    /// The connection (flattened: the JSON is an `AppConnection` plus the fields below).
    #[serde(flatten)]
    pub connection: AppConnection,
    /// Pairing code of a pending, unexpired pairing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pairing_code: Option<String>,
    /// When that pairing expires.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "rfc3339_option"
    )]
    pub pairing_expires_at: Option<Timestamp>,
}

/// `GET /connections` response for trusted devices / admins (rows are [`ConnectionView`];
/// compatible with [`ConnectionsResponse`] readers, which ignore the extra fields).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectionViewsResponse {
    /// Connections.
    pub connections: Vec<ConnectionView>,
}

/// `POST /connections/{id}/approve` body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApproveConnectionRequest {
    /// Allowed projects.
    pub allowed_projects: AllowedProjects,
}

/// `GET /projects` response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectsResponse {
    /// Projects.
    pub projects: Vec<Project>,
}

/// `POST /projects` body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateProjectRequest {
    /// Name.
    pub name: String,
}

/// `POST /admin/resources` body (no secrets — the credential is a vault entry reference).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResourceInput {
    /// Alias.
    pub alias: String,
    /// Service.
    pub service: String,
    /// Connector.
    pub connector: Connector,
    /// Project.
    pub project_id: ProjectId,
    /// Environment.
    pub environment: Environment,
    /// Connector configuration (no secrets).
    pub config: Value,
    /// Credential entry.
    pub credential_entry_id: EntryId,
    /// Executor.
    pub executor_id: ExecutorId,
    /// Operations offered (default: every V1 operation of the connector).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operations: Option<Vec<String>>,
}

/// `PATCH /admin/resources/{id}` body — every field optional.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct ResourcePatch {
    /// Alias.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alias: Option<String>,
    /// Environment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment: Option<Environment>,
    /// Config.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config: Option<Value>,
    /// Credential entry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_entry_id: Option<EntryId>,
    /// Executor.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub executor_id: Option<ExecutorId>,
    /// Operations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operations: Option<Vec<String>>,
    /// Status (e.g. `disabled`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<ResourceStatus>,
}

/// `GET /admin/resources` response.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AdminResourcesResponse {
    /// Resources.
    pub resources: Vec<Resource>,
}

/// `GET /policies` response.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PoliciesResponse {
    /// Policies.
    pub policies: Vec<Policy>,
}

/// `GET /grants` response.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GrantsResponse {
    /// Grants.
    pub grants: Vec<Grant>,
}

/// `POST /grants/{id}/revoke` body.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevokeRequest {
    /// Level.
    pub level: RevocationLevel,
}

/// `GET /operations` (admin) response.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OperationsResponse {
    /// Operations.
    pub operations: Vec<Operation>,
}

/// `GET /audit` response.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditResponse {
    /// Events.
    pub events: Vec<AuditEvent>,
    /// Hash of the newest event.
    pub head_hash: String,
}

/// `GET /audit/verify` response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditVerifyResponse {
    /// Chain valid.
    pub valid: bool,
    /// Events checked.
    pub events_checked: u64,
    /// Head hash.
    pub head_hash: String,
}

/// An anomaly in the activity summary (e.g. repeated denials, budget exhaustion).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Anomaly {
    /// Machine kind, e.g. `repeated_denials`, `budget_exhausted`, `executor_offline`.
    pub kind: String,
    /// Human summary.
    pub summary: Localized,
    /// When.
    #[serde(with = "rfc3339")]
    pub at: Timestamp,
    /// Connection involved.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connection_id: Option<ConnectionId>,
    /// Resource involved.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_id: Option<ResourceId>,
}

/// `GET /activity/summary` response (counts since `since`).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ActivitySummary {
    /// Pending approvals.
    pub pending_approvals: u64,
    /// Active grants.
    pub active_grants: u64,
    /// Operations in the window.
    pub recent_operations: u64,
    /// Rule auto-approvals in the window (activity digest, §5.3).
    pub auto_approved_count: u64,
    /// Anomalies.
    pub anomalies: Vec<Anomaly>,
}

/// `GET /executors` response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutorsResponse {
    /// Executors.
    pub executors: Vec<ExecutorInfo>,
}

/// `POST /credentials/delegate` body (experimental unattended rules).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelegateCredentialRequest {
    /// Policy.
    pub policy_id: PolicyId,
    /// Credential sealed to the executor.
    pub credential_envelope: aipass_crypto::SealedBox,
}

/// `GET /health` response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthResponse {
    /// Always `"ok"`.
    pub status: String,
    /// Version.
    pub version: String,
    /// Executor online.
    pub executor_online: bool,
    /// Protection level.
    pub protection_level: ProtectionLevel,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn operation_status_transitions() {
        use OperationStatus::*;
        let all = [
            Received,
            PolicyChecked,
            AwaitingApproval,
            Authorized,
            Running,
            Succeeded,
            Failed,
            Unknown,
            Denied,
            Expired,
            Cancelled,
        ];
        let legal = [
            (Received, PolicyChecked),
            (PolicyChecked, AwaitingApproval),
            (PolicyChecked, Authorized),
            (PolicyChecked, Denied),
            (AwaitingApproval, Authorized),
            (AwaitingApproval, Denied),
            (AwaitingApproval, Expired),
            (AwaitingApproval, Cancelled),
            (Authorized, Running),
            (Authorized, Cancelled),
            (Authorized, Failed),
            (Running, Succeeded),
            (Running, Failed),
            (Running, Unknown),
            (Running, Cancelled),
        ];
        for a in all {
            for b in all {
                assert_eq!(
                    a.can_transition(b),
                    legal.contains(&(a, b)),
                    "{a:?} -> {b:?}"
                );
            }
            if a.is_terminal() {
                assert!(all.iter().all(|b| !a.can_transition(*b)));
            }
            assert_eq!(OperationStatus::parse(a.as_str()), Some(a));
            assert_eq!(OperationStatus::parse(a.state_name()), Some(a));
            assert_eq!(serde_json::to_value(a).unwrap(), json!(a.as_str()));
        }
        // never "approve on timeout": expired cannot become authorized
        assert!(!Expired.can_transition(Authorized));
        assert_eq!(
            serde_json::from_value::<OperationStatus>(json!("awaiting_approval")).unwrap(),
            AwaitingApproval
        );
    }

    #[test]
    fn approval_required_matches_design_doc() {
        let r = OperationResponse::approval_required(
            OperationId::parse("op_01jbz3k6w8a7m2q4t5v9x0y1z2").unwrap(),
            ApprovalRequestId::parse("apr_01jbz3k6w8a7m2q4t5v9x0y1z2").unwrap(),
            120,
        );
        assert_eq!(
            serde_json::to_value(&r).unwrap(),
            json!({
                "status": "approval_required",
                "operation_id": "op_01jbz3k6w8a7m2q4t5v9x0y1z2",
                "approval_request_id": "apr_01jbz3k6w8a7m2q4t5v9x0y1z2",
                "expires_in_seconds": 120,
                "message": "请在已配对的手机或可信客户端批准本次访问。"
            })
        );
        assert_eq!(r.http_status(), 202);
    }

    #[test]
    fn allowed_projects_serde() {
        let all: AllowedProjects = serde_json::from_value(json!(["*"])).unwrap();
        assert_eq!(all, AllowedProjects::All);
        assert_eq!(serde_json::to_value(&all).unwrap(), json!(["*"]));
        let some: AllowedProjects =
            serde_json::from_value(json!(["proj_01jbz3k6w8a7m2q4t5v9x0y1z3"])).unwrap();
        assert!(some.allows(&ProjectId::parse("proj_01jbz3k6w8a7m2q4t5v9x0y1z3").unwrap()));
        assert!(!some.allows(&ProjectId::generate()));
        assert!(
            serde_json::from_value::<AllowedProjects>(json!([
                "*",
                "proj_01jbz3k6w8a7m2q4t5v9x0y1z3"
            ]))
            .is_err()
        );
        assert!(
            serde_json::from_value::<AllowedProjects>(json!(["res_01jbz3k6w8a7m2q4t5v9x0y1z3"]))
                .is_err()
        );
    }

    #[test]
    fn operation_request_from_design_doc() {
        let body = r#"{"resource_id":"res_01jbz3k6w8a7m2q4t5v9x0y1z2","operation":"postgres.query_view","parameters":{"view":"analytics.subscription_daily","fields":["day","plan","subscriptions"],"period_days":30},"idempotency_key":"subscription-summary-request-001"}"#;
        let r: OperationRequest = serde_json::from_str(body).unwrap();
        r.validate().unwrap();
        let mut bad = r.clone();
        bad.idempotency_key = "x".repeat(129);
        assert!(bad.validate().is_err());
        bad.idempotency_key = String::new();
        assert!(bad.validate().is_err());
    }

    #[test]
    fn revocation_report_labels() {
        let g = GrantId::generate();
        let mut r = RevocationReport {
            grant_id: g,
            stop_access: LevelReport::done(),
            end_sessions: LevelReport::done(),
            revoke_upstream: LevelReport::not_applicable(),
            completed_at: None,
        };
        assert!(r.fully_revoked());
        assert_eq!(r.summary_label().zh, "全部已收回");
        r.revoke_upstream = LevelReport::pending("upstream busy");
        assert!(!r.fully_revoked());
        assert_eq!(r.summary_label().zh, "待处理");
        r.end_sessions = LevelReport::failed("connector did not close");
        assert_eq!(r.summary_label().zh, "部分撤销失败");
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["stop_access"], json!({"status":"done"}));
        assert_eq!(v["revoke_upstream"]["status"], "pending");
    }

    #[test]
    fn audit_chain() {
        let mut e1 = AuditEvent {
            seq: 1,
            event_id: EventId::generate(),
            ts: crate::time::now(),
            actor: "conn_01jbz3k6w8a7m2q4t5v9x0y1z4".into(),
            action: "operation.succeeded".into(),
            resource_id: None,
            operation_id: None,
            grant_id: None,
            outcome: "ok".into(),
            error_code: None,
            detail: json!({"rows": 3}),
            prev_hash: String::new(),
            hash: String::new(),
        };
        e1.seal().unwrap();
        assert!(e1.verify(""));
        let mut e2 = AuditEvent {
            seq: 2,
            event_id: EventId::generate(),
            prev_hash: e1.hash.clone(),
            ..e1.clone()
        };
        e2.seal().unwrap();
        assert!(e2.verify(&e1.hash));
        let mut tampered = e2.clone();
        tampered.detail = json!({"rows": 4});
        assert!(!tampered.verify(&e1.hash));
        assert!(!e2.verify("other"));
    }

    #[test]
    fn enums_serialize_as_contract_strings() {
        assert_eq!(
            serde_json::to_value(HostType::ClaudeCode).unwrap(),
            json!("claude_code")
        );
        assert_eq!(
            serde_json::to_value(HostType::ClaudeConnector).unwrap(),
            json!("claude_connector")
        );
        assert_eq!(
            serde_json::to_value(Transport::RemoteGateway).unwrap(),
            json!("remote_gateway")
        );
        assert_eq!(
            serde_json::to_value(Connector::HttpApi).unwrap(),
            json!("http_api")
        );
        assert_eq!(
            serde_json::to_value(ResourceStatus::NeedsLogin).unwrap(),
            json!("needs_login")
        );
        assert_eq!(
            serde_json::to_value(LevelStatus::NotApplicable).unwrap(),
            json!("not_applicable")
        );
        assert_eq!(
            serde_json::to_value(RevocationLevel::RevokeUpstream).unwrap(),
            json!("revoke_upstream")
        );
        assert_eq!(
            serde_json::to_value(ControlChannelLostAction::DenyNewOperations).unwrap(),
            json!("deny_new_operations")
        );
        assert_eq!(
            serde_json::to_value(SideEffectClass::Irreversible).unwrap(),
            json!("irreversible")
        );
        assert_eq!(Limits::default().max_result_bytes, 262_144);
    }
}
