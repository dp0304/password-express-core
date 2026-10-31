// SPDX-License-Identifier: Apache-2.0
//! SQLite persistence (`<data>/broker.db`, WAL) with forward-only migrations.
//!
//! One connection guarded by a mutex; every call runs on the blocking pool so the async
//! runtime never stalls on disk I/O. Because all statements are serialized through this
//! connection, read-modify-write sequences inside one closure (budget reservation,
//! audit chaining, idempotency) are atomic — the budget tests run concurrent requests
//! against exactly this property (A08).
//!
//! The database never stores credentials: only IDs, scopes, digests, sealed envelopes
//! (which the broker cannot open) and filtered operation results (purged after the
//! retention period).

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use aipass_types::Timestamp;
use aipass_types::error::ApiError;
use rusqlite::Connection;
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::error::{OpenError, SResult, StoreError};

/// Database handle.
#[derive(Clone)]
pub(crate) struct Db {
    conn: Arc<Mutex<Connection>>,
    path: Option<PathBuf>,
}

impl std::fmt::Debug for Db {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Db").field("path", &self.path).finish()
    }
}

impl Db {
    /// Open (creating with mode 0600 when missing) and migrate.
    pub(crate) fn open(path: Option<&Path>) -> Result<Self, OpenError> {
        let conn = match path {
            Some(p) => {
                create_private_file(p)?;
                Connection::open(p)?
            }
            None => Connection::open_in_memory()?,
        };
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        if path.is_some() {
            // WAL for crash safety + concurrent readers of the file (backups).
            let mode: String = conn.query_row("PRAGMA journal_mode=WAL", [], |r| r.get(0))?;
            if !mode.eq_ignore_ascii_case("wal") {
                return Err(OpenError::Database(format!(
                    "could not enable WAL (journal_mode={mode})"
                )));
            }
            conn.pragma_update(None, "synchronous", "NORMAL")?;
        }
        migrate(&conn)?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
            path: path.map(Path::to_path_buf),
        })
    }

    /// Database file path (None for in-memory).
    pub(crate) fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// Run `f` with exclusive access on the blocking pool.
    pub(crate) async fn call<R, F>(&self, f: F) -> Result<R, ApiError>
    where
        F: FnOnce(&mut Connection) -> SResult<R> + Send + 'static,
        R: Send + 'static,
    {
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || {
            let mut guard = match conn.lock() {
                Ok(g) => g,
                // A panic inside a previous closure rolled its transaction back on drop;
                // the connection itself is still consistent.
                Err(poisoned) => poisoned.into_inner(),
            };
            f(&mut guard)
        })
        .await
        .map_err(|_| ApiError::internal())?
        .map_err(StoreError::into_api)
    }

    /// Synchronous access (startup only, before any async work is scheduled).
    pub(crate) fn call_sync<R>(&self, f: impl FnOnce(&mut Connection) -> SResult<R>) -> SResult<R> {
        let mut guard = match self.conn.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        f(&mut guard)
    }
}

#[cfg(unix)]
fn create_private_file(p: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    if p.exists() {
        let meta = std::fs::metadata(p)?;
        if meta.permissions().mode() & 0o077 != 0 {
            std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o600))?;
        }
        return Ok(());
    }
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(p)
        .map(|_| ())
}

#[cfg(not(unix))]
fn create_private_file(p: &Path) -> std::io::Result<()> {
    if !p.exists() {
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(p)?;
    }
    Ok(())
}

// ------------------------------------------------------------------------------------
// Schema
// ------------------------------------------------------------------------------------

const MIGRATIONS: &[&str] = &[r#"
CREATE TABLE connections (
    connection_id    TEXT PRIMARY KEY,
    host_type        TEXT NOT NULL,
    display_name     TEXT NOT NULL,
    transport        TEXT NOT NULL,
    status           TEXT NOT NULL,
    public_key       TEXT,
    allowed_projects TEXT NOT NULL,
    created_at       INTEGER NOT NULL,
    approved_at      INTEGER,
    approved_by      TEXT,
    last_seen_at     INTEGER,
    last_control_at  INTEGER
);

CREATE TABLE connection_tokens (
    token_hash    TEXT PRIMARY KEY,
    connection_id TEXT NOT NULL REFERENCES connections(connection_id),
    created_at    INTEGER NOT NULL,
    revoked_at    INTEGER
);
CREATE INDEX connection_tokens_conn ON connection_tokens(connection_id);

CREATE TABLE pairings (
    pairing_id    TEXT PRIMARY KEY,
    connection_id TEXT NOT NULL UNIQUE REFERENCES connections(connection_id),
    pairing_code  TEXT NOT NULL,
    status        TEXT NOT NULL,
    created_at    INTEGER NOT NULL,
    expires_at    INTEGER NOT NULL
);
CREATE INDEX pairings_status ON pairings(status, expires_at);

CREATE TABLE projects (
    project_id TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE TABLE resources (
    resource_id         TEXT PRIMARY KEY,
    project_id          TEXT NOT NULL,
    executor_id         TEXT NOT NULL,
    credential_entry_id TEXT NOT NULL,
    entry_conflict      INTEGER NOT NULL DEFAULT 0,
    body                TEXT NOT NULL,
    created_at          INTEGER NOT NULL,
    deleted_at          INTEGER
);
CREATE INDEX resources_entry ON resources(credential_entry_id);

CREATE TABLE devices (
    device_id  TEXT PRIMARY KEY,
    body       TEXT NOT NULL,
    role       TEXT NOT NULL,
    status     TEXT NOT NULL,
    added_at   INTEGER NOT NULL,
    added_by   TEXT NOT NULL,
    revoked_at INTEGER
);

CREATE TABLE executors (
    executor_id TEXT PRIMARY KEY,
    body        TEXT NOT NULL,
    updated_at  INTEGER NOT NULL
);

CREATE TABLE policies (
    policy_id             TEXT PRIMARY KEY,
    version               INTEGER NOT NULL,
    subject_connection_id TEXT NOT NULL,
    resource_id           TEXT NOT NULL,
    body                  TEXT NOT NULL,
    created_at            INTEGER NOT NULL,
    disabled_at           INTEGER
);
CREATE INDEX policies_subject ON policies(subject_connection_id, resource_id);

CREATE TABLE policy_credentials (
    policy_id      TEXT NOT NULL,
    policy_version INTEGER NOT NULL,
    envelope       TEXT NOT NULL,
    delegated_by   TEXT NOT NULL,
    created_at     INTEGER NOT NULL,
    PRIMARY KEY (policy_id, policy_version)
);

CREATE TABLE approvals (
    approval_request_id TEXT PRIMARY KEY,
    kind                TEXT NOT NULL,
    connection_id       TEXT NOT NULL,
    resource_id         TEXT NOT NULL,
    operation_id        TEXT,
    status              TEXT NOT NULL,
    body                TEXT NOT NULL,
    created_at          INTEGER NOT NULL,
    expires_at          INTEGER NOT NULL,
    decided_at          INTEGER,
    decided_by          TEXT,
    grant_id            TEXT
);
CREATE INDEX approvals_status ON approvals(status, expires_at);
CREATE INDEX approvals_conn ON approvals(connection_id, status);

CREATE TABLE grants (
    grant_id               TEXT PRIMARY KEY,
    approval_request_id    TEXT,
    policy_id              TEXT,
    policy_version         INTEGER,
    connection_id          TEXT NOT NULL,
    resource_id            TEXT NOT NULL,
    executor_id            TEXT NOT NULL,
    scope                  TEXT NOT NULL,
    mode                   TEXT NOT NULL,
    digest                 TEXT NOT NULL,
    status                 TEXT NOT NULL,
    max_rows_per_operation INTEGER NOT NULL,
    max_rows_per_grant     INTEGER NOT NULL,
    max_requests_per_grant INTEGER NOT NULL,
    max_result_bytes       INTEGER NOT NULL,
    used_requests          INTEGER NOT NULL DEFAULT 0,
    used_rows              INTEGER NOT NULL DEFAULT 0,
    used_bytes             INTEGER NOT NULL DEFAULT 0,
    reserved_rows          INTEGER NOT NULL DEFAULT 0,
    credential_state       TEXT NOT NULL DEFAULT 'none',
    approved_by            TEXT,
    created_at             INTEGER NOT NULL,
    expires_at             INTEGER NOT NULL,
    revoked_at             INTEGER,
    revocation             TEXT
);
CREATE INDEX grants_match ON grants(connection_id, resource_id, status, expires_at);
CREATE INDEX grants_status ON grants(status, expires_at);

CREATE TABLE operations (
    operation_id        TEXT PRIMARY KEY,
    connection_id       TEXT NOT NULL,
    resource_id         TEXT NOT NULL,
    operation           TEXT NOT NULL,
    parameters_digest   TEXT NOT NULL,
    request_digest      TEXT NOT NULL,
    idempotency_key     TEXT NOT NULL,
    status              TEXT NOT NULL,
    grant_id            TEXT,
    approval_request_id TEXT,
    result              TEXT,
    error               TEXT,
    side_effects        TEXT NOT NULL,
    normalized          TEXT,
    task_id             TEXT,
    created_at          INTEGER NOT NULL,
    updated_at          INTEGER NOT NULL,
    UNIQUE (connection_id, idempotency_key)
);
CREATE INDEX operations_grant ON operations(grant_id, status);
CREATE INDEX operations_created ON operations(created_at);

CREATE TABLE leases (
    lease_id      TEXT PRIMARY KEY,
    grant_id      TEXT NOT NULL,
    kind          TEXT NOT NULL,
    upstream_ref  TEXT NOT NULL,
    expires_at    INTEGER NOT NULL,
    revoke_status TEXT NOT NULL
);
CREATE INDEX leases_grant ON leases(grant_id);

CREATE TABLE audit (
    seq      INTEGER PRIMARY KEY,
    event_id TEXT NOT NULL UNIQUE,
    ts       INTEGER NOT NULL,
    action   TEXT NOT NULL,
    body     TEXT NOT NULL,
    hash     TEXT NOT NULL
);
CREATE INDEX audit_action ON audit(action, ts);

CREATE TABLE denials (
    connection_id TEXT NOT NULL,
    resource_id   TEXT NOT NULL,
    operation     TEXT NOT NULL,
    denied_at     INTEGER NOT NULL
);
CREATE INDEX denials_key ON denials(connection_id, resource_id, operation, denied_at);

CREATE TABLE nonces (
    kid        TEXT NOT NULL,
    nonce      TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    PRIMARY KEY (kid, nonce)
);
CREATE INDEX nonces_exp ON nonces(expires_at);

CREATE TABLE relay_seen (
    sig_hash TEXT PRIMARY KEY,
    seen_at  INTEGER NOT NULL
);
"#,
// v2: a `once` operation approval binds its grant to the operation the user saw (BRK-01);
// per-key nonce quota lookups (BRK-04); per-peer pending-pairing cap (BRK-06).
r#"
ALTER TABLE grants ADD COLUMN bound_operation_id TEXT;
CREATE INDEX nonces_kid_exp ON nonces(kid, expires_at);
ALTER TABLE pairings ADD COLUMN peer TEXT;
CREATE INDEX pairings_peer ON pairings(peer, status, expires_at);
"#];

fn migrate(conn: &Connection) -> Result<(), OpenError> {
    let current: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    let target = MIGRATIONS.len() as i64;
    if current > target {
        return Err(OpenError::Database(format!(
            "database schema version {current} is newer than this build supports ({target})"
        )));
    }
    for (i, sql) in MIGRATIONS.iter().enumerate().skip(current as usize) {
        conn.execute_batch(&format!(
            "BEGIN IMMEDIATE;\n{sql}\nPRAGMA user_version = {};\nCOMMIT;",
            i + 1
        ))?;
    }
    Ok(())
}

// ------------------------------------------------------------------------------------
// Value helpers
// ------------------------------------------------------------------------------------

/// Unix seconds of a timestamp.
pub(crate) fn unix(t: &Timestamp) -> i64 {
    t.timestamp()
}

/// Timestamp from unix seconds stored in the database.
pub(crate) fn ts(secs: i64) -> Timestamp {
    aipass_types::time::from_unix(secs).unwrap_or_default()
}

/// Optional timestamp.
pub(crate) fn ts_opt(secs: Option<i64>) -> Option<Timestamp> {
    secs.map(ts)
}

/// JSON-encode a record.
pub(crate) fn enc<T: Serialize + ?Sized>(v: &T) -> SResult<String> {
    Ok(serde_json::to_string(v)?)
}

/// JSON-decode a record.
pub(crate) fn dec<T: DeserializeOwned>(s: &str) -> SResult<T> {
    Ok(serde_json::from_str(s)?)
}

/// Wire string of a unit enum (`"active"`, `"stop_access"`, …).
pub(crate) fn enum_str<T: Serialize>(v: &T) -> String {
    match serde_json::to_value(v) {
        Ok(Value::String(s)) => s,
        _ => String::new(),
    }
}

/// Parse a unit enum from its wire string.
pub(crate) fn enum_parse<T: DeserializeOwned>(s: &str) -> SResult<T> {
    Ok(serde_json::from_value(Value::String(s.to_owned()))?)
}

/// u64 → i64 for storage (saturating; all broker counters are far below 2^63).
pub(crate) fn i(v: u64) -> i64 {
    i64::try_from(v).unwrap_or(i64::MAX)
}

/// i64 → u64 from storage (negative values clamp to 0).
pub(crate) fn u(v: i64) -> u64 {
    u64::try_from(v).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migrates_in_memory_and_file() {
        let db = Db::open(None).unwrap();
        let v: i64 = db
            .call_sync(|c| Ok(c.query_row("PRAGMA user_version", [], |r| r.get(0))?))
            .unwrap();
        assert_eq!(v, MIGRATIONS.len() as i64);

        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("broker.db");
        drop(Db::open(Some(&p)).unwrap());
        // reopening is a no-op migration
        let db = Db::open(Some(&p)).unwrap();
        let mode: String = db
            .call_sync(|c| Ok(c.query_row("PRAGMA journal_mode", [], |r| r.get(0))?))
            .unwrap();
        assert_eq!(mode.to_ascii_lowercase(), "wal");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let m = std::fs::metadata(&p).unwrap().permissions().mode();
            assert_eq!(m & 0o777, 0o600);
        }
    }

    #[test]
    fn enum_roundtrip() {
        use aipass_types::models::GrantStatus;
        assert_eq!(enum_str(&GrantStatus::Exhausted), "exhausted");
        let g: GrantStatus = enum_parse("revoked").unwrap();
        assert_eq!(g, GrantStatus::Revoked);
        assert!(enum_parse::<GrantStatus>("nope").is_err());
    }
}
