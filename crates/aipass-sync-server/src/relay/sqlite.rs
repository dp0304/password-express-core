// SPDX-License-Identifier: Apache-2.0
//! SQLite relay store (rusqlite, bundled SQLite). Survives restarts; WAL journal; the
//! database file is created `0600`. Envelopes are stored as the JSON the relay received
//! (sealed payloads only — the relay never has keys to open them).

use std::path::Path;
use std::sync::{Arc, Mutex};

use aipass_types::ids::{MailboxId, MessageId, PairingId};
use aipass_types::relay::{MailboxMessage, RelayEnvelope};
use aipass_types::{ApiError, ErrorCode, Timestamp};
use async_trait::async_trait;
use rusqlite::{Connection, OptionalExtension, params};

use super::store::{GcStats, InsertOutcome, MessageIdGen, PairingCheck, RelayStore};

const SCHEMA_VERSION: i64 = 1;

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS relay_messages (
    message_id  TEXT PRIMARY KEY,
    mailbox     TEXT NOT NULL,
    received_at INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL,
    envelope    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS relay_messages_mailbox ON relay_messages (mailbox, message_id);
CREATE INDEX IF NOT EXISTS relay_messages_expiry ON relay_messages (expires_at);
CREATE TABLE IF NOT EXISTS relay_pairing (
    pairing_id  TEXT PRIMARY KEY,
    secret_hash BLOB NOT NULL,
    expires_at  INTEGER NOT NULL
);
"#;

/// SQLite-backed relay store.
pub struct SqliteRelayStore {
    conn: Arc<Mutex<Connection>>,
    ids: Arc<MessageIdGen>,
}

impl core::fmt::Debug for SqliteRelayStore {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SqliteRelayStore").finish_non_exhaustive()
    }
}

fn db_err(e: rusqlite::Error) -> ApiError {
    tracing::warn!(error = %e, "relay database error");
    ApiError::new(ErrorCode::Internal)
}

fn ts(t: &Timestamp) -> i64 {
    t.timestamp()
}

fn from_ts(s: i64) -> Timestamp {
    aipass_types::time::from_unix(s).unwrap_or_default()
}

impl SqliteRelayStore {
    /// Open (or create) the database at `path`.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ApiError> {
        let path = path.as_ref();
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent).map_err(|_| ApiError::new(ErrorCode::Internal))?;
        }
        #[cfg(unix)]
        if !path.exists() {
            use std::os::unix::fs::OpenOptionsExt;
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)
                .map_err(|_| ApiError::new(ErrorCode::Internal))?;
        }
        let conn = Connection::open(path).map_err(db_err)?;
        Self::init(conn)
    }

    /// In-memory database (tests).
    pub fn open_in_memory() -> Result<Self, ApiError> {
        Self::init(Connection::open_in_memory().map_err(db_err)?)
    }

    fn init(conn: Connection) -> Result<Self, ApiError> {
        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(db_err)?;
        conn.pragma_update(None, "synchronous", "NORMAL")
            .map_err(db_err)?;
        conn.busy_timeout(std::time::Duration::from_secs(5))
            .map_err(db_err)?;
        let v: i64 = conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .map_err(db_err)?;
        if v > SCHEMA_VERSION {
            return Err(ApiError::new(ErrorCode::Internal).with_message(
                "中继数据库版本过新",
                "The relay database was created by a newer version.",
            ));
        }
        conn.execute_batch(SCHEMA).map_err(db_err)?;
        conn.pragma_update(None, "user_version", SCHEMA_VERSION)
            .map_err(db_err)?;
        let newest: Option<String> = conn
            .query_row("SELECT max(message_id) FROM relay_messages", [], |r| {
                r.get(0)
            })
            .optional()
            .map_err(db_err)?
            .flatten();
        let floor = newest.and_then(|s| MessageId::parse(&s).ok());
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
            ids: Arc::new(MessageIdGen::with_floor(floor.as_ref())),
        })
    }

    async fn run<T: Send + 'static>(
        &self,
        f: impl FnOnce(&mut Connection, &MessageIdGen) -> Result<T, ApiError> + Send + 'static,
    ) -> Result<T, ApiError> {
        let conn = self.conn.clone();
        let ids = self.ids.clone();
        tokio::task::spawn_blocking(move || {
            let mut c = conn.lock().unwrap_or_else(|p| p.into_inner());
            f(&mut c, &ids)
        })
        .await
        .map_err(|_| ApiError::new(ErrorCode::Internal))?
    }
}

#[async_trait]
impl RelayStore for SqliteRelayStore {
    async fn insert(
        &self,
        mailbox: &MailboxId,
        envelope: &RelayEnvelope,
        received_at: Timestamp,
        expires_at: Timestamp,
        max_messages: usize,
    ) -> Result<InsertOutcome, ApiError> {
        let mailbox = mailbox.as_str().to_owned();
        let json =
            serde_json::to_string(envelope).map_err(|_| ApiError::new(ErrorCode::Internal))?;
        self.run(move |c, ids| {
            let tx = c.transaction().map_err(db_err)?;
            let live: i64 = tx
                .query_row(
                    "SELECT count(*) FROM relay_messages WHERE mailbox = ?1 AND expires_at > ?2",
                    params![mailbox, ts(&received_at)],
                    |r| r.get(0),
                )
                .map_err(db_err)?;
            if live as usize >= max_messages {
                return Ok(InsertOutcome::MailboxFull);
            }
            let id = ids.next();
            tx.execute(
                "INSERT INTO relay_messages (message_id, mailbox, received_at, expires_at, envelope) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![id.as_str(), mailbox, ts(&received_at), ts(&expires_at), json],
            )
            .map_err(db_err)?;
            tx.commit().map_err(db_err)?;
            Ok(InsertOutcome::Inserted(id))
        })
        .await
    }

    async fn fetch(
        &self,
        mailbox: &MailboxId,
        after: Option<&MessageId>,
        now: Timestamp,
        limit: usize,
    ) -> Result<Vec<MailboxMessage>, ApiError> {
        let mailbox = mailbox.as_str().to_owned();
        let after = after.map(|a| a.as_str().to_owned()).unwrap_or_default();
        self.run(move |c, _| {
            let mut st = c
                .prepare_cached(
                    "SELECT message_id, received_at, envelope FROM relay_messages
                     WHERE mailbox = ?1 AND message_id > ?2 AND expires_at > ?3
                     ORDER BY message_id LIMIT ?4",
                )
                .map_err(db_err)?;
            let rows = st
                .query_map(params![mailbox, after, ts(&now), limit as i64], |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, i64>(1)?,
                        r.get::<_, String>(2)?,
                    ))
                })
                .map_err(db_err)?;
            let mut out = Vec::new();
            for row in rows {
                let (id, received, env) = row.map_err(db_err)?;
                let (Ok(message_id), Ok(envelope)) = (
                    MessageId::parse(&id),
                    serde_json::from_str::<RelayEnvelope>(&env),
                ) else {
                    tracing::warn!("skipping undecodable relay row");
                    continue;
                };
                out.push(MailboxMessage {
                    message_id,
                    received_at: from_ts(received),
                    envelope,
                });
            }
            Ok(out)
        })
        .await
    }

    async fn delete(&self, mailbox: &MailboxId, message_id: &MessageId) -> Result<bool, ApiError> {
        let mailbox = mailbox.as_str().to_owned();
        let id = message_id.as_str().to_owned();
        self.run(move |c, _| {
            let n = c
                .execute(
                    "DELETE FROM relay_messages WHERE mailbox = ?1 AND message_id = ?2",
                    params![mailbox, id],
                )
                .map_err(db_err)?;
            Ok(n > 0)
        })
        .await
    }

    async fn pairing_secret(
        &self,
        pairing: &PairingId,
        secret_hash: &[u8; 32],
        expires_at: Timestamp,
        now: Timestamp,
    ) -> Result<PairingCheck, ApiError> {
        let pid = pairing.as_str().to_owned();
        let hash = *secret_hash;
        self.run(move |c, _| {
            let tx = c.transaction().map_err(db_err)?;
            let row: Option<(Vec<u8>, i64)> = tx
                .query_row(
                    "SELECT secret_hash, expires_at FROM relay_pairing WHERE pairing_id = ?1",
                    params![pid],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()
                .map_err(db_err)?;
            let out = match row {
                Some((h, exp)) if exp > ts(&now) => {
                    if aipass_crypto::ct_eq(&h, &hash) {
                        PairingCheck::Matched { expires_at: from_ts(exp) }
                    } else {
                        PairingCheck::Mismatch
                    }
                }
                _ => {
                    tx.execute("DELETE FROM relay_messages WHERE mailbox = ?1", params![pid])
                        .map_err(db_err)?;
                    tx.execute(
                        "INSERT OR REPLACE INTO relay_pairing (pairing_id, secret_hash, expires_at) VALUES (?1, ?2, ?3)",
                        params![pid, hash.to_vec(), ts(&expires_at)],
                    )
                    .map_err(db_err)?;
                    PairingCheck::Registered { expires_at }
                }
            };
            tx.commit().map_err(db_err)?;
            Ok(out)
        })
        .await
    }

    async fn gc(&self, now: Timestamp) -> Result<GcStats, ApiError> {
        self.run(move |c, _| {
            let tx = c.transaction().map_err(db_err)?;
            let pair_msgs = tx
                .execute(
                    "DELETE FROM relay_messages WHERE mailbox IN (SELECT pairing_id FROM relay_pairing WHERE expires_at <= ?1)",
                    params![ts(&now)],
                )
                .map_err(db_err)?;
            let pairings = tx
                .execute("DELETE FROM relay_pairing WHERE expires_at <= ?1", params![ts(&now)])
                .map_err(db_err)?;
            let msgs = tx
                .execute("DELETE FROM relay_messages WHERE expires_at <= ?1", params![ts(&now)])
                .map_err(db_err)?;
            tx.commit().map_err(db_err)?;
            Ok(GcStats {
                messages: (pair_msgs + msgs) as u64,
                pairings: pairings as u64,
            })
        })
        .await
    }
}
