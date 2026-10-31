// SPDX-License-Identifier: Apache-2.0
//! Relay mailbox storage: the [`RelayStore`] trait, the in-memory implementation and the
//! monotonic message-id generator shared by all implementations.
//!
//! Message ids are ULIDs issued in strictly increasing order per process, so the `after`
//! cursor works by lexicographic comparison even after the cursor message was deleted.

use std::collections::{BTreeMap, HashMap};
use std::sync::Mutex;

use aipass_types::ids::{MailboxId, MessageId, PairingId};
use aipass_types::relay::{MailboxMessage, RelayEnvelope};
use aipass_types::{ApiError, Timestamp};
use async_trait::async_trait;

/// Result of inserting a message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InsertOutcome {
    /// Stored with this id.
    Inserted(MessageId),
    /// The mailbox already holds the maximum number of live messages.
    MailboxFull,
}

/// Result of presenting a pairing-mailbox secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PairingCheck {
    /// First use: the secret (hash) is now bound to the mailbox until `expires_at`.
    Registered {
        /// Mailbox expiry.
        expires_at: Timestamp,
    },
    /// Matches the bound secret.
    Matched {
        /// Mailbox expiry.
        expires_at: Timestamp,
    },
    /// Does not match.
    Mismatch,
}

/// Garbage-collection statistics.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct GcStats {
    /// Expired messages removed.
    pub messages: u64,
    /// Expired pairing mailboxes removed.
    pub pairings: u64,
}

/// Mailbox storage backend.
#[async_trait]
pub trait RelayStore: Send + Sync {
    /// Store an envelope unless the mailbox holds `max_messages` live messages.
    async fn insert(
        &self,
        mailbox: &MailboxId,
        envelope: &RelayEnvelope,
        received_at: Timestamp,
        expires_at: Timestamp,
        max_messages: usize,
    ) -> Result<InsertOutcome, ApiError>;
    /// Live messages with id > `after`, oldest first, at most `limit`.
    async fn fetch(
        &self,
        mailbox: &MailboxId,
        after: Option<&MessageId>,
        now: Timestamp,
        limit: usize,
    ) -> Result<Vec<MailboxMessage>, ApiError>;
    /// Delete one message; `true` if it existed.
    async fn delete(&self, mailbox: &MailboxId, message_id: &MessageId) -> Result<bool, ApiError>;
    /// Bind (first use) or check the SHA-256 of a pairing mailbox secret.
    async fn pairing_secret(
        &self,
        pairing: &PairingId,
        secret_hash: &[u8; 32],
        expires_at: Timestamp,
        now: Timestamp,
    ) -> Result<PairingCheck, ApiError>;
    /// Remove expired messages and pairing mailboxes (with their messages).
    async fn gc(&self, now: Timestamp) -> Result<GcStats, ApiError>;
}

/// Strictly increasing ULID message ids.
#[derive(Debug, Default)]
pub struct MessageIdGen {
    last: Mutex<u128>,
}

impl MessageIdGen {
    /// Generator that will only issue ids greater than `floor` (e.g. the newest stored id).
    pub fn with_floor(floor: Option<&MessageId>) -> Self {
        let v = floor.and_then(|m| decode(m.as_str())).unwrap_or(0);
        Self {
            last: Mutex::new(v),
        }
    }

    /// Next id.
    pub fn next(&self) -> MessageId {
        let ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
            & ((1u64 << 48) - 1);
        let rnd = aipass_crypto::rng::random_array::<10>()
            .iter()
            .fold(0u128, |acc, b| (acc << 8) | u128::from(*b));
        let candidate = ulid::Ulid::from_parts(ms, rnd).0;
        let mut last = self.last.lock().unwrap_or_else(|p| p.into_inner());
        let v = if candidate > *last {
            candidate
        } else {
            last.saturating_add(1)
        };
        *last = v;
        let s = format!("msg_{}", ulid::Ulid(v).to_string().to_ascii_lowercase());
        MessageId::parse(&s).unwrap_or_else(|_| MessageId::generate())
    }
}

fn decode(id: &str) -> Option<u128> {
    let (_, u) = aipass_types::ids::split(id)?;
    ulid::Ulid::from_string(&u.to_ascii_uppercase())
        .ok()
        .map(|u| u.0)
}

#[derive(Debug, Clone)]
struct Stored {
    received_at: Timestamp,
    expires_at: Timestamp,
    envelope: RelayEnvelope,
}

#[derive(Debug, Default)]
struct MemState {
    mailboxes: HashMap<String, BTreeMap<String, Stored>>,
    pairings: HashMap<String, ([u8; 32], Timestamp)>,
}

/// In-memory relay store (single process; lost on restart).
#[derive(Debug, Default)]
pub struct MemoryRelayStore {
    state: Mutex<MemState>,
    ids: MessageIdGen,
}

impl MemoryRelayStore {
    /// Empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Total stored messages (incl. expired, until GC).
    pub fn len(&self) -> usize {
        self.state
            .lock()
            .map(|s| s.mailboxes.values().map(BTreeMap::len).sum())
            .unwrap_or(0)
    }

    /// True when empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[async_trait]
impl RelayStore for MemoryRelayStore {
    async fn insert(
        &self,
        mailbox: &MailboxId,
        envelope: &RelayEnvelope,
        received_at: Timestamp,
        expires_at: Timestamp,
        max_messages: usize,
    ) -> Result<InsertOutcome, ApiError> {
        let mut st = self.state.lock().unwrap_or_else(|p| p.into_inner());
        let mb = st.mailboxes.entry(mailbox.as_str().to_owned()).or_default();
        mb.retain(|_, m| m.expires_at > received_at);
        if mb.len() >= max_messages {
            return Ok(InsertOutcome::MailboxFull);
        }
        let id = self.ids.next();
        mb.insert(
            id.as_str().to_owned(),
            Stored {
                received_at,
                expires_at,
                envelope: envelope.clone(),
            },
        );
        Ok(InsertOutcome::Inserted(id))
    }

    async fn fetch(
        &self,
        mailbox: &MailboxId,
        after: Option<&MessageId>,
        now: Timestamp,
        limit: usize,
    ) -> Result<Vec<MailboxMessage>, ApiError> {
        let st = self.state.lock().unwrap_or_else(|p| p.into_inner());
        let Some(mb) = st.mailboxes.get(mailbox.as_str()) else {
            return Ok(Vec::new());
        };
        let lower = match after {
            Some(a) => std::ops::Bound::Excluded(a.as_str().to_owned()),
            None => std::ops::Bound::Unbounded,
        };
        Ok(mb
            .range((lower, std::ops::Bound::Unbounded))
            .filter(|(_, m)| m.expires_at > now)
            .take(limit)
            .filter_map(|(id, m)| {
                Some(MailboxMessage {
                    message_id: MessageId::parse(id).ok()?,
                    received_at: m.received_at,
                    envelope: m.envelope.clone(),
                })
            })
            .collect())
    }

    async fn delete(&self, mailbox: &MailboxId, message_id: &MessageId) -> Result<bool, ApiError> {
        let mut st = self.state.lock().unwrap_or_else(|p| p.into_inner());
        Ok(st
            .mailboxes
            .get_mut(mailbox.as_str())
            .and_then(|mb| mb.remove(message_id.as_str()))
            .is_some())
    }

    async fn pairing_secret(
        &self,
        pairing: &PairingId,
        secret_hash: &[u8; 32],
        expires_at: Timestamp,
        now: Timestamp,
    ) -> Result<PairingCheck, ApiError> {
        let mut st = self.state.lock().unwrap_or_else(|p| p.into_inner());
        match st.pairings.get(pairing.as_str()) {
            Some((h, exp)) if *exp > now => {
                if aipass_crypto::ct_eq(h, secret_hash) {
                    Ok(PairingCheck::Matched { expires_at: *exp })
                } else {
                    Ok(PairingCheck::Mismatch)
                }
            }
            _ => {
                // first use (or the previous binding expired: start over clean)
                st.mailboxes.remove(pairing.as_str());
                st.pairings
                    .insert(pairing.as_str().to_owned(), (*secret_hash, expires_at));
                Ok(PairingCheck::Registered { expires_at })
            }
        }
    }

    async fn gc(&self, now: Timestamp) -> Result<GcStats, ApiError> {
        let mut st = self.state.lock().unwrap_or_else(|p| p.into_inner());
        let mut stats = GcStats::default();
        let expired_pairings: Vec<String> = st
            .pairings
            .iter()
            .filter(|(_, (_, e))| *e <= now)
            .map(|(k, _)| k.clone())
            .collect();
        for p in expired_pairings {
            st.pairings.remove(&p);
            if let Some(mb) = st.mailboxes.remove(&p) {
                stats.messages += mb.len() as u64;
            }
            stats.pairings += 1;
        }
        for mb in st.mailboxes.values_mut() {
            let before = mb.len();
            mb.retain(|_, m| m.expires_at > now);
            stats.messages += (before - mb.len()) as u64;
        }
        st.mailboxes.retain(|_, mb| !mb.is_empty());
        Ok(stats)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_strictly_increase() {
        let g = MessageIdGen::default();
        let mut prev = g.next();
        for _ in 0..10_000 {
            let n = g.next();
            assert!(n.as_str() > prev.as_str());
            prev = n;
        }
        let g2 = MessageIdGen::with_floor(Some(&prev));
        assert!(g2.next().as_str() > prev.as_str());
    }
}
