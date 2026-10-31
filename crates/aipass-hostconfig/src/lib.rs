// SPDX-License-Identifier: Apache-2.0
//! # aipass-hostconfig — AI host configuration wizard
//!
//! Responsibilities (CONTRACTS §10; design doc §5.2, §7.1):
//!
//! * [`detect()`] installed AI hosts, their version (`<tool> --version` with a timeout, or the
//!   macOS app bundle), the config path and whether it already has an `aipass` MCP entry;
//! * [`plan()`] a change with before/after and a (secret-redacted) unified diff, [`apply()`]
//!   it atomically after a timestamped backup (`<file>.aipass-backup-<yyyymmddHHMMSS>`),
//!   touching **only our key**, and [`remove()`] it again (removing what we inserted restores
//!   the original bytes);
//! * Codex `config.toml` is edited with `toml_edit` (comments and formatting preserved);
//!   JSON / JSONC files are edited with a span-preserving editor ([`jsonc`]), so comments,
//!   key order and whitespace of everything else stay byte-identical;
//! * never writes secrets: an entry is the absolute path of `aipass-mcp` plus
//!   `["stdio", "--connection", "conn_…"]` (and a few safe flags), validated against a strict
//!   grammar and a secret-pattern scan;
//! * labels per design doc §7.1 — the verified list is **empty in this build**, so local hosts
//!   report `standard_protocol` ([`CompatLabel`]);
//! * remote hosts (ChatGPT, Claude connectors) get instructions as data ([`remote`]).

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::path::{Path, PathBuf};

pub mod codex;
pub mod detect;
pub mod jsonc;
pub mod model;
pub mod plan;
pub mod remote;
pub mod secrets;

pub use detect::{DetectOptions, detect_in};
pub use model::{
    ApplyOutcome, CompatLabel, ConfigPlan, Host, HostEnv, HostStatus, McpEntry, Os, PlanAction,
    SERVER_KEY, Scope, VERIFIED_HOST_VERSIONS, label_for,
};
pub use plan::{apply, claude_mcp_add_command, config_location, plan_in, plan_remove_in};
pub use remote::{RemoteInstructions, RemoteTarget, remote_instructions};

/// Wizard errors. Messages never contain file contents (which may hold the user's secrets).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HostConfigError {
    /// The home directory could not be determined.
    #[error("cannot determine the home directory")]
    NoHome,
    /// Remote hosts have no local config.
    #[error("{0} is a remote host; use remote_instructions()")]
    RemoteHost(Host),
    /// Scope not supported by the host.
    #[error("{host} does not support the {scope} scope")]
    UnsupportedScope {
        /// Host.
        host: Host,
        /// Scope.
        scope: Scope,
    },
    /// Not available on this platform.
    #[error("{host} is not supported here: {reason}")]
    Unsupported {
        /// Host.
        host: Host,
        /// Reason.
        reason: String,
    },
    /// Project scope without a project directory.
    #[error("a project directory is required for the project scope")]
    NoProjectDir,
    /// The entry does not follow the allowed grammar.
    #[error("invalid MCP entry: {0}")]
    InvalidEntry(String),
    /// The entry looks like it contains a secret — refused (host configs never hold secrets).
    #[error("refusing to write something that looks like a secret into a host config")]
    SecretInEntry,
    /// The existing config does not parse; it is left untouched.
    #[error("{path}: cannot parse (line {line}, column {column}): {message}", path = .path.display())]
    Parse {
        /// File.
        path: PathBuf,
        /// 1-based line (0 when unknown).
        line: usize,
        /// 1-based column (0 when unknown).
        column: usize,
        /// Parser message.
        message: String,
    },
    /// The root or the servers container is not an object/table; left untouched.
    #[error("{path}: {what} is not an object", path = .path.display())]
    NotAnObject {
        /// File.
        path: PathBuf,
        /// What.
        what: String,
    },
    /// The file changed between plan and apply; nothing was written.
    #[error("{path} changed since the plan was made; plan again", path = .path.display())]
    ConcurrentModification {
        /// File.
        path: PathBuf,
    },
    /// I/O error.
    #[error("{path}: {message}", path = .path.display())]
    Io {
        /// File.
        path: PathBuf,
        /// Message.
        message: String,
    },
}

impl HostConfigError {
    pub(crate) fn io(path: &Path, e: std::io::Error) -> Self {
        HostConfigError::Io {
            path: path.to_owned(),
            message: e.to_string(),
        }
    }
}

/// Detect hosts using the process environment (versions probed with a 3 s timeout each).
pub fn detect() -> Result<Vec<HostStatus>, HostConfigError> {
    Ok(detect_in(&HostEnv::from_system()?, &DetectOptions::default()))
}

/// Plan adding the `aipass` entry for `host` at `scope` using the process environment
/// (project scope uses the current directory).
pub fn plan(host: Host, scope: Scope, entry: &McpEntry) -> Result<ConfigPlan, HostConfigError> {
    plan_in(&HostEnv::from_system()?, host, scope, entry)
}

/// Remove the `aipass` entry for `host` at `scope` (plan + apply; backup kept).
pub fn remove(host: Host, scope: Scope) -> Result<ApplyOutcome, HostConfigError> {
    remove_in(&HostEnv::from_system()?, host, scope)
}

/// [`remove`] in an explicit environment.
pub fn remove_in(env: &HostEnv, host: Host, scope: Scope) -> Result<ApplyOutcome, HostConfigError> {
    apply(&plan_remove_in(env, host, scope)?)
}
