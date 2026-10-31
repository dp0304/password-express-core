// SPDX-License-Identifier: Apache-2.0
//! Encrypted local outbox for offline edits (CONTRACTS §3.2, design doc §10.6).
//!
//! Pending changes are kept on disk as `XChaCha20-Poly1305(local_key, nonce, JCS(outbox),
//! aad = "aipass:v1:outbox:{vault_id}:{device_id}")`. The 32-byte local key lives in the
//! platform secret store, never next to the file.
//!
//! Multiple offline edits of one entry are coalesced into one change that keeps the
//! **original** base version, so the later 3-way merge compares against what the user
//! started from.

use std::path::Path;

use aipass_crypto::{Key32, aead};
use aipass_types::ids::{DeviceId, EntryId, VaultId};
use aipass_types::time::{Timestamp, rfc3339};
use aipass_types::vault::EntryPayload;
use aipass_vault::{Result, VaultError};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// Outbox file format tag.
pub const OUTBOX_FORMAT: &str = "aipass-outbox-1";

/// Operation of a pending change.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum ChangeOp {
    /// Create or update an entry.
    Upsert {
        /// New payload.
        payload: EntryPayload,
    },
    /// Delete (tombstone) an entry.
    Delete,
    /// Explicitly restore a deleted entry with a new version above its tombstone.
    Restore {
        /// Payload to restore.
        payload: EntryPayload,
    },
}

impl core::fmt::Debug for ChangeOp {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Upsert { .. } => "Upsert",
            Self::Delete => "Delete",
            Self::Restore { .. } => "Restore",
        })
    }
}

/// A pending local change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingChange {
    /// Entry.
    pub entry_id: EntryId,
    /// Version the edit was based on (`None` for a new entry).
    pub base_version: Option<u64>,
    /// Operation.
    pub op: ChangeOp,
    /// When the change was made.
    #[serde(with = "rfc3339")]
    pub created_at: Timestamp,
}

/// A change the sync engine refused (edit of an entry deleted elsewhere). Kept until the
/// user restores or discards it — never silently resurrected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RejectedChange {
    /// Entry.
    pub entry_id: EntryId,
    /// The edit that could not be applied.
    pub op: ChangeOp,
    /// Tombstone version on storage.
    pub tombstone_version: u64,
    /// Rejected at.
    #[serde(with = "rfc3339")]
    pub rejected_at: Timestamp,
}

/// The outbox.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Outbox {
    /// Changes waiting to be pushed.
    pub changes: Vec<PendingChange>,
    /// Changes refused because the entry was deleted elsewhere.
    #[serde(default)]
    pub rejected: Vec<RejectedChange>,
}

impl Outbox {
    /// Number of pending changes.
    pub fn len(&self) -> usize {
        self.changes.len()
    }

    /// Whether nothing is pending.
    pub fn is_empty(&self) -> bool {
        self.changes.is_empty()
    }

    /// The pending change for `entry`, if any.
    pub fn get(&self, entry: &EntryId) -> Option<&PendingChange> {
        self.changes.iter().find(|c| &c.entry_id == entry)
    }

    /// Record a change, coalescing with an earlier pending change of the same entry.
    pub fn push(&mut self, change: PendingChange) {
        if let Some(i) = self
            .changes
            .iter()
            .position(|c| c.entry_id == change.entry_id)
        {
            let prev = self.changes.remove(i);
            let merged = match (&prev.op, change.op) {
                // created offline and deleted offline: nothing to push
                (ChangeOp::Upsert { .. }, ChangeOp::Delete) if prev.base_version.is_none() => {
                    return;
                }
                (_, op) => PendingChange {
                    entry_id: prev.entry_id,
                    base_version: prev.base_version,
                    op: match (&prev.op, op) {
                        (ChangeOp::Restore { .. }, ChangeOp::Upsert { payload }) => {
                            ChangeOp::Restore { payload }
                        }
                        (_, op) => op,
                    },
                    created_at: change.created_at,
                },
            };
            self.changes.push(merged);
        } else {
            self.changes.push(change);
        }
    }
}

#[derive(Serialize, Deserialize)]
struct OutboxFile {
    format: String,
    #[serde(with = "aipass_crypto::b64u::array")]
    nonce: [u8; 24],
    #[serde(with = "aipass_crypto::b64u::bytes")]
    ciphertext: Vec<u8>,
}

fn aad(vault: &VaultId, device: &DeviceId) -> String {
    format!("aipass:v1:outbox:{vault}:{device}")
}

/// Load the outbox (empty when the file does not exist).
pub fn load(path: &Path, key: &Key32, vault: &VaultId, device: &DeviceId) -> Result<Outbox> {
    let Some(bytes) = aipass_vault::fsutil::read_optional(path)? else {
        return Ok(Outbox::default());
    };
    let f: OutboxFile = serde_json::from_slice(&bytes)
        .map_err(|_| VaultError::Integrity("outbox file is not valid"))?;
    if f.format != OUTBOX_FORMAT {
        return Err(VaultError::Unsupported("outbox format"));
    }
    let pt = aead::open(key, &f.nonce, aad(vault, device).as_bytes(), &f.ciphertext)
        .map_err(|_| VaultError::Integrity("outbox could not be decrypted"))?;
    serde_json::from_slice(pt.expose())
        .map_err(|_| VaultError::Integrity("outbox content is not valid"))
}

/// Persist the outbox atomically (mode 0600).
pub fn save(
    path: &Path,
    key: &Key32,
    vault: &VaultId,
    device: &DeviceId,
    outbox: &Outbox,
) -> Result<()> {
    let pt = Zeroizing::new(aipass_types::canonical::to_jcs_bytes(outbox)?);
    let (nonce, ciphertext) = aead::seal(key, aad(vault, device).as_bytes(), &pt)?;
    let f = OutboxFile {
        format: OUTBOX_FORMAT.into(),
        nonce,
        ciphertext,
    };
    let bytes = serde_json::to_vec(&f).map_err(|_| VaultError::Internal("outbox encode"))?;
    aipass_vault::fsutil::write_private_atomic(path, &bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aipass_types::vault::EntryKind;

    #[test]
    fn coalesce_and_persist() {
        let e = EntryId::generate();
        let now = aipass_types::time::now();
        let p = EntryPayload::new(EntryKind::Login, "x");
        let mut o = Outbox::default();
        o.push(PendingChange {
            entry_id: e.clone(),
            base_version: Some(3),
            op: ChangeOp::Upsert { payload: p.clone() },
            created_at: now,
        });
        o.push(PendingChange {
            entry_id: e.clone(),
            base_version: Some(4),
            op: ChangeOp::Upsert { payload: p.clone() },
            created_at: now,
        });
        assert_eq!(o.len(), 1);
        assert_eq!(o.changes[0].base_version, Some(3));
        let n = EntryId::generate();
        o.push(PendingChange {
            entry_id: n.clone(),
            base_version: None,
            op: ChangeOp::Upsert { payload: p.clone() },
            created_at: now,
        });
        o.push(PendingChange {
            entry_id: n,
            base_version: None,
            op: ChangeOp::Delete,
            created_at: now,
        });
        assert_eq!(o.len(), 1);

        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("outbox.json");
        let key = Key32::generate().unwrap();
        let v = VaultId::generate();
        let dev = DeviceId::generate();
        save(&path, &key, &v, &dev, &o).unwrap();
        assert_eq!(load(&path, &key, &v, &dev).unwrap(), o);
        assert!(load(&path, &Key32::generate().unwrap(), &v, &dev).is_err());
        assert!(load(&path, &key, &v, &DeviceId::generate()).is_err());
        assert!(!String::from_utf8_lossy(&std::fs::read(&path).unwrap()).contains("\"x\""));
    }
}
