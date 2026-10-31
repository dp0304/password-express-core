// SPDX-License-Identifier: Apache-2.0
//! Credential custody: per-grant, in-memory, zeroizing credential store.
//!
//! * Credentials arrive either as an HPKE envelope sealed to the executor's X25519 key
//!   (opened by [`crate::Executor`]) or, for the in-process desktop case, as plaintext
//!   [`CredentialMaterial`] from the trusted client.
//! * Each grant has at most one installed credential. It is dropped on expiry, on
//!   `drop_credential`, on `end_sessions` and on revocation. [`CredentialMaterial`] is
//!   `ZeroizeOnDrop`, so the bytes are wiped when the last [`Arc`] goes away.
//! * Nothing here implements `Serialize`, and every `Debug` impl is redacted.

use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use aipass_types::exec::CredentialMaterial;
use aipass_types::{ApiError, GrantId, Timestamp};
use chrono::Utc;

use crate::errors;

/// A credential installed for one grant.
pub struct InstalledCredential {
    install_id: u64,
    grant_id: GrantId,
    material: CredentialMaterial,
    installed_at: Timestamp,
    expires_at: Timestamp,
}

impl InstalledCredential {
    /// Process-unique installation id (changes when a credential is re-installed or rotated;
    /// connector sessions opened with an older installation are closed).
    pub fn install_id(&self) -> u64 {
        self.install_id
    }

    /// Grant this credential belongs to.
    pub fn grant_id(&self) -> &GrantId {
        &self.grant_id
    }

    /// The credential material. Keep borrows short; never log or return it.
    pub fn material(&self) -> &CredentialMaterial {
        &self.material
    }

    /// When it was installed.
    pub fn installed_at(&self) -> Timestamp {
        self.installed_at
    }

    /// Effective expiry (the material's `expires_at`, clamped to the custody maximum TTL).
    pub fn expires_at(&self) -> Timestamp {
        self.expires_at
    }

    /// True once `expires_at` has passed.
    pub fn is_expired(&self) -> bool {
        Utc::now() >= self.expires_at
    }
}

impl fmt::Debug for InstalledCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InstalledCredential")
            .field("install_id", &self.install_id)
            .field("grant_id", &self.grant_id)
            .field("entry_id", &self.material.entry_id)
            .field("kind", &self.material.kind)
            .field("material", &"[REDACTED]")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// Per-grant credential store.
pub struct CredentialCustody {
    inner: Mutex<HashMap<GrantId, Arc<InstalledCredential>>>,
    /// Grants whose credential expired on access; their sessions still need closing.
    expired: Mutex<Vec<GrantId>>,
    next_id: AtomicU64,
    max_ttl: Duration,
}

impl fmt::Debug for CredentialCustody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CredentialCustody")
            .field("installed", &self.len())
            .field("max_ttl", &self.max_ttl)
            .finish()
    }
}

impl CredentialCustody {
    /// New store; credentials are never kept longer than `max_ttl` after installation.
    pub fn new(max_ttl: Duration) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            expired: Mutex::new(Vec::new()),
            next_id: AtomicU64::new(1),
            max_ttl,
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<GrantId, Arc<InstalledCredential>>> {
        // A poisoned lock only means another thread panicked while holding it; the map is
        // still structurally valid, so keep serving (fail-closed checks happen per entry).
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Install (or replace) the credential of `grant_id`.
    pub fn install(
        &self,
        grant_id: GrantId,
        material: CredentialMaterial,
    ) -> Result<Arc<InstalledCredential>, ApiError> {
        let installed = self.prepare(grant_id.clone(), material)?;
        self.lock().insert(grant_id, installed.clone());
        Ok(installed)
    }

    /// Replace the credential of `grant_id` only while the installed one is still
    /// `expected_install_id` (compare-and-swap). `Ok(None)` when it was dropped or
    /// replaced meanwhile: a credential removed by `end_sessions` is never resurrected by
    /// an operation that was still finishing (e.g. a rotation).
    pub fn replace_if_current(
        &self,
        grant_id: &GrantId,
        expected_install_id: u64,
        material: CredentialMaterial,
    ) -> Result<Option<Arc<InstalledCredential>>, ApiError> {
        let installed = self.prepare(grant_id.clone(), material)?;
        let mut map = self.lock();
        match map.get(grant_id) {
            Some(c) if c.install_id == expected_install_id => {
                map.insert(grant_id.clone(), installed.clone());
                Ok(Some(installed))
            }
            _ => Ok(None),
        }
    }

    fn prepare(
        &self,
        grant_id: GrantId,
        material: CredentialMaterial,
    ) -> Result<Arc<InstalledCredential>, ApiError> {
        let now = Utc::now();
        if material.expires_at <= now {
            return Err(errors::secret_unavailable(
                "凭证已过期，未安装",
                "The credential has already expired and was not installed.",
            ));
        }
        if material.secret.is_empty() {
            return Err(errors::invalid(
                "凭证内容为空",
                "The credential material is empty.",
            ));
        }
        let max = chrono::Duration::from_std(self.max_ttl).unwrap_or(chrono::Duration::hours(24));
        let expires_at = material.expires_at.min(now + max);
        let installed = Arc::new(InstalledCredential {
            install_id: self.next_id.fetch_add(1, Ordering::Relaxed),
            grant_id: grant_id.clone(),
            material,
            installed_at: now,
            expires_at,
        });
        Ok(installed)
    }

    /// The live credential of `grant_id`. An expired credential is dropped and reported as
    /// `SECRET_UNAVAILABLE`.
    pub fn get(&self, grant_id: &GrantId) -> Result<Arc<InstalledCredential>, ApiError> {
        let mut map = self.lock();
        match map.get(grant_id) {
            Some(c) if !c.is_expired() => Ok(c.clone()),
            Some(_) => {
                map.remove(grant_id);
                self.expired
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .push(grant_id.clone());
                Err(errors::secret_unavailable(
                    "凭证已到期并已从执行设备清除",
                    "The credential expired and was removed from the executor.",
                ))
            }
            None => Err(errors::secret_unavailable(
                "执行设备上没有本次授权的凭证（未送达、已过期或已撤销）",
                "No credential for this grant on the executor (not delivered, expired or revoked).",
            )),
        }
    }

    /// Whether a live credential is installed.
    pub fn contains(&self, grant_id: &GrantId) -> bool {
        self.lock().get(grant_id).is_some_and(|c| !c.is_expired())
    }

    /// Drop the credential of `grant_id`; true when one was installed.
    pub fn remove(&self, grant_id: &GrantId) -> bool {
        self.lock().remove(grant_id).is_some()
    }

    /// Drop every expired credential; returns the affected grants (including grants whose
    /// credential was found expired on access since the last sweep).
    pub fn sweep_expired(&self) -> Vec<GrantId> {
        let mut expired: Vec<GrantId> =
            std::mem::take(&mut *self.expired.lock().unwrap_or_else(|p| p.into_inner()));
        let mut map = self.lock();
        let now_expired: Vec<GrantId> = map
            .iter()
            .filter(|(_, c)| c.is_expired())
            .map(|(g, _)| g.clone())
            .collect();
        for g in &now_expired {
            map.remove(g);
        }
        expired.extend(now_expired);
        expired.sort_by(|a, b| a.as_str().cmp(b.as_str()));
        expired.dedup();
        expired
    }

    /// Number of installed credentials (including not-yet-swept expired ones).
    pub fn len(&self) -> usize {
        self.lock().len()
    }

    /// True when nothing is installed.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Drop everything (executor shutdown).
    pub fn clear(&self) {
        self.lock().clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aipass_crypto::SecretString;
    use aipass_types::EntryId;
    use aipass_types::vault::EntryKind;

    fn material(secs: i64) -> CredentialMaterial {
        CredentialMaterial {
            entry_id: EntryId::generate(),
            version: 1,
            kind: EntryKind::ApiKey,
            username: Some("svc-user".into()),
            secret: SecretString::from("custody-secret-DO-NOT-LEAK"),
            database: None,
            expires_at: Utc::now() + chrono::Duration::seconds(secs),
        }
    }

    #[test]
    fn replace_if_current_never_resurrects() {
        let c = CredentialCustody::new(Duration::from_secs(3600));
        let g = GrantId::generate();
        let a = c.install(g.clone(), material(60)).unwrap();
        let b = c
            .replace_if_current(&g, a.install_id(), material(60))
            .unwrap()
            .expect("swapped while current");
        assert_eq!(c.get(&g).unwrap().install_id(), b.install_id());
        // Stale expectation: not swapped.
        assert!(
            c.replace_if_current(&g, a.install_id(), material(60))
                .unwrap()
                .is_none()
        );
        assert_eq!(c.get(&g).unwrap().install_id(), b.install_id());
        // Dropped (end_sessions): stays dropped.
        assert!(c.remove(&g));
        assert!(
            c.replace_if_current(&g, b.install_id(), material(60))
                .unwrap()
                .is_none()
        );
        assert!(!c.contains(&g));
    }

    #[test]
    fn install_get_remove() {
        let c = CredentialCustody::new(Duration::from_secs(3600));
        let g = GrantId::generate();
        assert!(c.get(&g).is_err());
        let a = c.install(g.clone(), material(60)).unwrap();
        let b = c.get(&g).unwrap();
        assert_eq!(a.install_id(), b.install_id());
        assert!(c.contains(&g));
        assert!(c.remove(&g));
        assert_eq!(
            c.get(&g).unwrap_err().code,
            aipass_types::ErrorCode::SecretUnavailable
        );
    }

    #[test]
    fn expired_refused_and_clamped() {
        let c = CredentialCustody::new(Duration::from_secs(10));
        let g = GrantId::generate();
        assert!(c.install(g.clone(), material(-1)).is_err());
        let i = c.install(g.clone(), material(100_000)).unwrap();
        assert!(i.expires_at() <= Utc::now() + chrono::Duration::seconds(11));
    }

    #[test]
    fn debug_is_redacted() {
        let c = CredentialCustody::new(Duration::from_secs(3600));
        let g = GrantId::generate();
        let i = c.install(g, material(60)).unwrap();
        let s = format!("{i:?} {c:?}");
        assert!(
            !s.contains("custody-secret") && !s.contains("svc-user"),
            "{s}"
        );
    }
}
