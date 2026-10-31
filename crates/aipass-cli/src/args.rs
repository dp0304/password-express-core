// SPDX-License-Identifier: Apache-2.0
//! Command-line grammar of `aipass`.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

/// `aipass` — AI 通行证参考 CLI / AI Pass reference CLI (trusted client).
#[derive(Parser, Debug)]
#[command(name = "aipass", version, about = "AI 通行证参考 CLI（可信客户端） / AI Pass reference CLI (trusted client)")]
pub struct Cli {
    /// AI Pass home (default `~/.aipass`, env AIPASS_HOME).
    #[arg(long, global = true, env = "AIPASS_HOME")]
    pub home: Option<PathBuf>,
    /// Broker URL (`unix:///…sock` or `http(s)://…`; env AIPASS_BROKER_URL).
    #[arg(long, global = true, env = "AIPASS_BROKER_URL")]
    pub broker: Option<String>,
    /// Output JSON instead of text.
    #[arg(long, global = true)]
    pub json: bool,
    /// Language for messages (`zh-CN` or `en`, env AIPASS_LANG).
    #[arg(long, global = true, env = "AIPASS_LANG", default_value = "zh-CN")]
    pub lang: String,
    /// Subcommand.
    #[command(subcommand)]
    pub cmd: Cmd,
}

/// Top-level commands.
#[derive(Subcommand, Debug)]
pub enum Cmd {
    /// Vault lifecycle.
    #[command(subcommand)]
    Vault(VaultCmd),
    /// Where the encrypted vault is stored.
    #[command(subcommand)]
    Storage(StorageCmd),
    /// Passwords, API keys, database credentials.
    #[command(subcommand)]
    Item(ItemCmd),
    /// Import a CSV export from another password manager.
    Import {
        /// chrome | firefox | safari | bitwarden | 1password | lastpass | generic
        #[arg(long)]
        format: String,
        /// CSV file.
        file: PathBuf,
    },
    /// Export the vault.
    Export {
        /// Encrypted `.aipassx` (asks for an export password).
        #[arg(long, conflicts_with = "csv")]
        encrypted: Option<PathBuf>,
        /// Plain CSV (dangerous; shows a warning and asks to confirm).
        #[arg(long)]
        csv: Option<PathBuf>,
        /// Accepted for compatibility; has no effect: export is human-only (interactive
        /// terminal, passphrase re-entered) and plaintext CSV is always confirmed there.
        #[arg(long)]
        yes: bool,
    },
    /// Synchronise with storage.
    Sync,
    /// Sync conflicts.
    #[command(subcommand)]
    Conflicts(ConflictsCmd),
    /// Recovery key and kit.
    #[command(subcommand)]
    Recovery(RecoveryCmd),
    /// Devices of this vault.
    #[command(subcommand)]
    Device(DeviceCmd),
    /// Credentials to rotate after a device was revoked (design §10.4).
    #[command(subcommand)]
    Rotation(RotationCmd),
    /// Embedded local broker + executor (like the desktop app).
    #[command(subcommand)]
    Node(NodeCmd),
    /// Configure an AI host (Codex, Claude Code, Cursor, …) to use `aipass-mcp`.
    Connect(ConnectArgs),
    /// AI connections known to the broker.
    #[command(subcommand)]
    Connections(ConnectionsCmd),
    /// Projects.
    #[command(subcommand)]
    Projects(ProjectsCmd),
    /// Resources (a database / API the AI may use through the executor).
    #[command(subcommand)]
    Resource(ResourceCmd),
    /// Signed policies (rules).
    #[command(subcommand)]
    Policy(PolicyCmd),
    /// Pending approval requests.
    #[command(subcommand)]
    Approvals(ApprovalsCmd),
    /// Grants.
    #[command(subcommand)]
    Grants(GrantsCmd),
    /// Activity summary.
    Activity {
        /// RFC 3339 start time.
        #[arg(long)]
        since: Option<String>,
    },
    /// Audit log.
    #[command(subcommand)]
    Audit(AuditCmd),
    /// Read this device's relay inbox (what a phone receives: approval requests, reports).
    Inbox {
        /// Long-poll up to this many seconds (0..25).
        #[arg(long, default_value_t = 0)]
        wait: u64,
        /// Executor whose relay to read (default: the only paired one).
        #[arg(long)]
        executor: Option<String>,
    },
    /// Remember the broker URL for later commands.
    UseBroker {
        /// URL.
        url: String,
    },
}

/// Storage profile flags.
#[derive(Args, Debug, Clone)]
pub struct StorageArgs {
    /// local | s3 | selfhost | official | webdav (experimental)
    #[arg(long, default_value = "local")]
    pub storage: String,
    /// Directory (local).
    #[arg(long)]
    pub path: Option<PathBuf>,
    /// Endpoint URL (s3 / webdav).
    #[arg(long)]
    pub endpoint: Option<String>,
    /// Region (s3).
    #[arg(long)]
    pub region: Option<String>,
    /// Bucket (s3).
    #[arg(long)]
    pub bucket: Option<String>,
    /// Key prefix (s3).
    #[arg(long)]
    pub prefix: Option<String>,
    /// Virtual-host addressing instead of path style (s3).
    #[arg(long)]
    pub virtual_host: bool,
    /// Base URL (selfhost / official).
    #[arg(long)]
    pub base_url: Option<String>,
    /// Access key id (s3) / user name (webdav).
    #[arg(long)]
    pub username: Option<String>,
    /// Name of an environment variable holding the storage secret (S3 secret key, WebDAV
    /// password, or the enroll token / session for selfhost/official).
    #[arg(long)]
    pub secret_env: Option<String>,
    /// Prompt for the storage secret.
    #[arg(long)]
    pub secret_prompt: bool,
}

/// `vault …`
#[derive(Subcommand, Debug)]
#[allow(clippy::large_enum_variant)]
pub enum VaultCmd {
    /// Create a new vault on this device.
    Init {
        /// Name of this device.
        #[arg(long, default_value = "cli")]
        device_name: String,
        /// Storage.
        #[command(flatten)]
        storage: StorageArgs,
        /// Also protect the vault with a master password (asked interactively).
        #[arg(long)]
        master_password: bool,
        /// Write the recovery kit to this file (0600) instead of printing it.
        #[arg(long)]
        kit_out: Option<PathBuf>,
    },
    /// Show status.
    Status,
    /// Check that this device can unlock the vault.
    UnlockCheck,
    /// Recover the vault on this (fresh) device with the recovery key — no other device
    /// needed: the vault is verified from storage, this device joins as a new owner member
    /// and nothing is revoked automatically (review `aipass device list` afterwards).
    Recover {
        /// Vault id (`vlt_…`, printed on the recovery kit).
        #[arg(long)]
        vault_id: String,
        /// Name of this device.
        #[arg(long, default_value = "cli-recovered")]
        device_name: String,
        /// Storage holding the encrypted vault.
        #[command(flatten)]
        storage: StorageArgs,
        /// Name of an environment variable holding the recovery key. Without it (and
        /// without `--recovery-key-file`) the key is asked for on the terminal; it is never
        /// taken as a command-line value, which other local processes could read.
        #[arg(long, conflicts_with = "recovery_key_file")]
        recovery_key_env: Option<String>,
        /// File with the recovery key or the whole recovery kit (the `AIPR-…` key is
        /// taken from it).
        #[arg(long)]
        recovery_key_file: Option<PathBuf>,
    },
}

/// `rotation …`
#[derive(Subcommand, Debug)]
pub enum RotationCmd {
    /// Open rotation tasks of this device (created when it revoked a device).
    List,
    /// Mark a credential as rotated.
    Done {
        /// Entry id.
        entry_id: String,
    },
}

/// `storage …`
#[derive(Subcommand, Debug)]
pub enum StorageCmd {
    /// Test a storage location (capability test, no switch).
    Test(StorageArgs),
    /// Move the vault to another storage location (verified before switching).
    Migrate(StorageArgs),
    /// Alias of `migrate` for first-time configuration of an existing vault.
    Configure(StorageArgs),
}

/// Item fields.
#[derive(Args, Debug, Clone, Default)]
pub struct ItemFields {
    /// login | api_key | database | oauth_token | ssh_key | secure_note
    #[arg(long)]
    pub kind: Option<String>,
    /// Title.
    #[arg(long)]
    pub title: Option<String>,
    /// User name.
    #[arg(long)]
    pub username: Option<String>,
    /// Read the secret from stdin (first line).
    #[arg(long)]
    pub secret_stdin: bool,
    /// Read the secret from this environment variable.
    #[arg(long)]
    pub secret_env: Option<String>,
    /// Prompt for the secret.
    #[arg(long)]
    pub secret_prompt: bool,
    /// Generate a password (length).
    #[arg(long)]
    pub generate: Option<u32>,
    /// URL (repeatable).
    #[arg(long = "url")]
    pub urls: Vec<String>,
    /// Notes.
    #[arg(long)]
    pub notes: Option<String>,
    /// TOTP (otpauth:// URI or base32 seed) from this environment variable.
    #[arg(long)]
    pub totp_env: Option<String>,
    /// Database host.
    #[arg(long)]
    pub db_host: Option<String>,
    /// Database port.
    #[arg(long)]
    pub db_port: Option<u16>,
    /// Database name.
    #[arg(long)]
    pub db_name: Option<String>,
    /// Database sslmode (disable | prefer | require | verify-full).
    #[arg(long)]
    pub db_sslmode: Option<String>,
    /// Project id.
    #[arg(long)]
    pub project: Option<String>,
}

/// `item …`
#[derive(Subcommand, Debug)]
pub enum ItemCmd {
    /// Add an item.
    Add(ItemFields),
    /// List items.
    List {
        /// Search text.
        #[arg(long)]
        query: Option<String>,
    },
    /// Show an item (secrets masked).
    Show {
        /// Entry id.
        id: String,
    },
    /// Edit an item (only given fields change).
    Edit {
        /// Entry id.
        id: String,
        /// New values.
        #[command(flatten)]
        fields: ItemFields,
    },
    /// Delete an item.
    Rm {
        /// Entry id.
        id: String,
    },
    /// Reveal a secret (re-enter the passphrase on the terminal; never for AI tools).
    Reveal {
        /// Entry id.
        id: String,
        /// `secret`, `totp` or a custom field name.
        #[arg(long, default_value = "secret")]
        field: String,
    },
    /// Generate a password.
    Generate {
        /// Length.
        #[arg(long, default_value_t = 20)]
        length: u32,
        /// No symbols.
        #[arg(long)]
        no_symbols: bool,
    },
    /// Current TOTP code.
    Totp {
        /// Entry id.
        id: String,
    },
}

/// `conflicts …`
#[derive(Subcommand, Debug)]
pub enum ConflictsCmd {
    /// List conflicts.
    List,
    /// Keep one version.
    Resolve {
        /// Entry id.
        id: String,
        /// Version to keep.
        #[arg(long)]
        keep: u64,
    },
}

/// `recovery …`
#[derive(Subcommand, Debug)]
pub enum RecoveryCmd {
    /// Print the recovery kit (contains the key only until it was verified).
    Kit {
        /// Include the storage secret.
        #[arg(long)]
        include_storage_secret: bool,
    },
    /// Verify you saved the recovery key (asked interactively or from AIPASS_RECOVERY_KEY).
    Verify,
}

/// `device …`
#[derive(Subcommand, Debug)]
pub enum DeviceCmd {
    /// Pair a new device / executor node by its `aipass://pair?…` link.
    Pair {
        /// The pairing link shown by the new device.
        #[arg(long)]
        uri: String,
        /// Share the storage secret with a new trusted device (never with executors).
        #[arg(long)]
        share_storage_secret: bool,
        /// Seconds to wait for the new device.
        #[arg(long, default_value_t = 300)]
        timeout_secs: u64,
    },
    /// Join an existing vault as a new trusted device: shows a pairing link to open with
    /// `aipass device pair` (or the phone app) on a device that already has the vault.
    Join {
        /// Name of this device.
        #[arg(long)]
        device_name: String,
        /// Relay used for pairing (the node / self-host URL or the official relay).
        #[arg(long)]
        relay: String,
        /// Seconds to wait for the trusted device.
        #[arg(long, default_value_t = 600)]
        timeout_secs: u64,
        /// Name of an environment variable holding the storage secret, when the trusted
        /// device does not share it (not needed for selfhost / official storage).
        #[arg(long)]
        storage_secret_env: Option<String>,
    },
    /// List devices.
    List,
    /// Revoke a device (rotates the vault key).
    Revoke {
        /// Device id.
        id: String,
    },
}

/// `node …`
#[derive(Subcommand, Debug)]
pub enum NodeCmd {
    /// Run the embedded broker + executor on `<AIPASS_HOME>/run/broker.sock`.
    Run {
        /// Also listen on TCP (e.g. 127.0.0.1:7878).
        #[arg(long)]
        tcp: Option<String>,
        /// Executor name on approval cards.
        #[arg(long, default_value = "this-computer")]
        name: String,
    },
}

/// `connect <host>`
#[derive(Args, Debug)]
pub struct ConnectArgs {
    /// codex | claude_code | cursor | claude_desktop | vscode | windsurf
    pub host: String,
    /// Paired AI connection id (from `aipass-mcp pair`).
    #[arg(long)]
    pub connection: Option<String>,
    /// user | project
    #[arg(long)]
    pub scope: Option<String>,
    /// Project directory (project scope).
    #[arg(long)]
    pub project_dir: Option<PathBuf>,
    /// Path of the `aipass-mcp` binary (default: next to `aipass`).
    #[arg(long)]
    pub mcp_bin: Option<PathBuf>,
    /// Remove our entry instead.
    #[arg(long)]
    pub remove: bool,
    /// Apply without asking.
    #[arg(long)]
    pub yes: bool,
}

/// `connections …`
#[derive(Subcommand, Debug)]
pub enum ConnectionsCmd {
    /// List connections.
    List,
    /// Approve a pending connection.
    Approve {
        /// Connection id.
        id: String,
        /// Comma-separated project ids, or `*` for every project (required: no implicit
        /// all-projects grant).
        #[arg(long)]
        projects: String,
        /// The 6-digit pairing code shown by the AI host (`aipass-mcp pair` / the SDK). It
        /// must equal the code the broker holds for this pending connection; without the
        /// flag it is asked for on the terminal.
        #[arg(long)]
        code: Option<String>,
        /// Send the device-signed control message through the end-to-end relay (the phone
        /// path, CONTRACTS §4) instead of calling the broker's HTTP API.
        #[arg(long)]
        via_relay: bool,
    },
    /// Deny a pending connection.
    Deny {
        /// Connection id.
        id: String,
        /// Send the device-signed control message through the end-to-end relay (the phone
        /// path, CONTRACTS §4) instead of calling the broker's HTTP API.
        #[arg(long)]
        via_relay: bool,
    },
    /// Pause.
    Pause {
        /// Connection id.
        id: String,
        /// Send the device-signed control message through the end-to-end relay (the phone
        /// path, CONTRACTS §4) instead of calling the broker's HTTP API.
        #[arg(long)]
        via_relay: bool,
    },
    /// Resume.
    Resume {
        /// Connection id.
        id: String,
        /// Send the device-signed control message through the end-to-end relay (the phone
        /// path, CONTRACTS §4) instead of calling the broker's HTTP API.
        #[arg(long)]
        via_relay: bool,
    },
    /// Remove (revokes everything).
    Remove {
        /// Connection id.
        id: String,
        /// Send the device-signed control message through the end-to-end relay (the phone
        /// path, CONTRACTS §4) instead of calling the broker's HTTP API.
        #[arg(long)]
        via_relay: bool,
    },
}

/// `projects …`
#[derive(Subcommand, Debug)]
pub enum ProjectsCmd {
    /// List.
    List,
    /// Create.
    Add {
        /// Name.
        name: String,
    },
}

/// `resource …`
#[derive(Subcommand, Debug)]
pub enum ResourceCmd {
    /// Register a resource. Only a reference to the vault entry is sent; the secret stays
    /// in the vault until a trusted device approves and seals it to the executor.
    Add {
        /// Alias the AI sees.
        #[arg(long)]
        alias: String,
        /// Service label (e.g. "PostgreSQL").
        #[arg(long)]
        service: Option<String>,
        /// postgres | github | http_api
        #[arg(long)]
        connector: String,
        /// Project id or name (created if missing).
        #[arg(long)]
        project: String,
        /// test | production
        #[arg(long, default_value = "test")]
        environment: String,
        /// Vault entry holding the credential.
        #[arg(long)]
        entry: String,
        /// Connector config JSON file (no secrets).
        #[arg(long)]
        config: PathBuf,
        /// Executor id (default: the only paired executor).
        #[arg(long)]
        executor: Option<String>,
    },
    /// List resources.
    List,
}

/// `policy …`
#[derive(Subcommand, Debug)]
pub enum PolicyCmd {
    /// Add a signed rule.
    Add {
        /// Resource id.
        #[arg(long)]
        resource: String,
        /// Connection id.
        #[arg(long)]
        connection: String,
        /// Operations (comma-separated).
        #[arg(long, default_value = "postgres.query_view")]
        operations: String,
        /// `schema.view:field1,field2` (repeatable, postgres).
        #[arg(long = "view")]
        views: Vec<String>,
        /// `owner/name` (repeatable, github).
        #[arg(long = "repo")]
        repos: Vec<String>,
        /// once | task | rule
        #[arg(long, default_value = "rule")]
        mode: String,
        /// Auto-approve (rule + test environment + read-only only).
        #[arg(long)]
        auto_approve: bool,
        /// Grant lifetime in seconds.
        #[arg(long, default_value_t = 900)]
        ttl: u64,
    },
    /// List policies.
    List,
    /// Disable a policy.
    Disable {
        /// Policy id.
        id: String,
    },
}

/// `approvals …`
#[derive(Subcommand, Debug)]
pub enum ApprovalsCmd {
    /// List pending requests (approval cards).
    List,
    /// Show one card.
    Show {
        /// Approval request id.
        id: String,
    },
    /// Approve (optionally narrowed).
    Approve {
        /// Approval request id.
        id: String,
        /// Narrow the fields of one view: `schema.view:f1,f2` (repeatable).
        #[arg(long = "narrow")]
        narrow: Vec<String>,
        /// Shorter duration (seconds).
        #[arg(long)]
        duration: Option<u64>,
        /// Lower row limit per operation.
        #[arg(long)]
        max_rows: Option<u64>,
        /// Approve without the interactive confirmation.
        #[arg(long)]
        yes: bool,
        /// Take the request from the relay inbox and send the signed decision through the
        /// end-to-end relay (the phone path) instead of calling the broker directly.
        #[arg(long)]
        via_relay: bool,
    },
    /// Deny.
    Deny {
        /// Approval request id.
        id: String,
    },
}

/// `grants …`
#[derive(Subcommand, Debug)]
pub enum GrantsCmd {
    /// List grants.
    List {
        /// active | expired | revoked | exhausted | released
        #[arg(long)]
        status: Option<String>,
    },
    /// Revoke a grant.
    Revoke {
        /// Grant id.
        id: String,
        /// stop_access | end_sessions | revoke_upstream
        #[arg(long, default_value = "end_sessions")]
        level: String,
        /// Send the device-signed control message through the end-to-end relay (the phone
        /// path, CONTRACTS §4) instead of calling the broker's HTTP API.
        #[arg(long)]
        via_relay: bool,
    },
}

/// `audit …`
#[derive(Subcommand, Debug)]
pub enum AuditCmd {
    /// Verify the hash chain.
    Verify,
    /// List events.
    List {
        /// After this sequence number.
        #[arg(long, default_value_t = 0)]
        after: u64,
        /// Max events.
        #[arg(long, default_value_t = 100)]
        limit: u32,
    },
}
