// SPDX-License-Identifier: Apache-2.0
//! Desktop secret store: an [`aipass_vault::FileSecretStore`] (Argon2id-derived key,
//! XChaCha20-Poly1305, file 0600) that is only open while the app is unlocked.
//!
//! The `VaultClient` is opened once at start-up with this wrapper; while it is closed
//! every access fails with `LOCKED`, so nothing can read the device key without the
//! local unlock password. This works identically on macOS, Windows and Linux; OS keychain
//! integration (Touch ID / Windows Hello) is a documented future option, not claimed here.

use std::path::PathBuf;
use std::sync::RwLock;

use aipass_crypto::{SecretBytes, SecretString, password::Argon2Params};
use aipass_vault::{FileSecretStore, SecretStore, VaultError};

/// Minimum unlock-password length.
pub const MIN_PASSWORD_CHARS: usize = 8;

/// Lockable wrapper around the encrypted file store.
pub struct LockableSecretStore {
    path: PathBuf,
    params: Argon2Params,
    inner: RwLock<Option<FileSecretStore>>,
}

impl std::fmt::Debug for LockableSecretStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LockableSecretStore").field("path", &self.path).finish_non_exhaustive()
    }
}

impl LockableSecretStore {
    /// Store at `path` (not opened).
    pub fn new(path: PathBuf, params: Argon2Params) -> Self {
        Self { path, params, inner: RwLock::new(None) }
    }

    /// Whether the encrypted file exists (i.e. an unlock password was set).
    pub fn exists(&self) -> bool {
        self.path.exists()
    }

    /// Whether it is currently open.
    pub fn is_open(&self) -> bool {
        self.inner.read().map(|g| g.is_some()).unwrap_or(false)
    }

    /// Create the store with a new password. Fails if it already exists.
    pub fn create(&self, password: &SecretString) -> Result<(), VaultError> {
        if password.expose().chars().count() < MIN_PASSWORD_CHARS {
            return Err(VaultError::Invalid(aipass_types::Localized::new(
                "本机解锁密码至少需要 8 个字符",
                "The local unlock password needs at least 8 characters",
            )));
        }
        if self.exists() {
            return Err(VaultError::AlreadyExists);
        }
        let s = FileSecretStore::open_or_create(&self.path, password, self.params)?;
        *self.inner.write().map_err(|_| VaultError::SecretStore("lock poisoned"))? = Some(s);
        Ok(())
    }

    /// Open with the password (wrong password → error, file untouched).
    pub fn open(&self, password: &SecretString) -> Result<(), VaultError> {
        if !self.exists() {
            return Err(VaultError::NoVault);
        }
        let s = FileSecretStore::open_or_create(&self.path, password, self.params)?;
        *self.inner.write().map_err(|_| VaultError::SecretStore("lock poisoned"))? = Some(s);
        Ok(())
    }

    /// Check a password without changing the open state (re-authentication).
    pub fn verify_password(&self, password: &SecretString) -> bool {
        self.exists() && FileSecretStore::open_or_create(&self.path, password, self.params).is_ok()
    }

    /// Close (drops the derived key, which zeroizes).
    pub fn close(&self) {
        if let Ok(mut g) = self.inner.write() {
            *g = None;
        }
    }
}

impl SecretStore for LockableSecretStore {
    fn get(&self, key: &str) -> Result<Option<SecretBytes>, VaultError> {
        let g = self.inner.read().map_err(|_| VaultError::SecretStore("lock poisoned"))?;
        g.as_ref().ok_or(VaultError::Locked)?.get(key)
    }
    fn set(&self, key: &str, value: &[u8], require_user_presence: bool) -> Result<(), VaultError> {
        let g = self.inner.read().map_err(|_| VaultError::SecretStore("lock poisoned"))?;
        g.as_ref().ok_or(VaultError::Locked)?.set(key, value, require_user_presence)
    }
    fn delete(&self, key: &str) -> Result<(), VaultError> {
        let g = self.inner.read().map_err(|_| VaultError::SecretStore("lock poisoned"))?;
        g.as_ref().ok_or(VaultError::Locked)?.delete(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lock_cycle() {
        let dir = tempfile::tempdir().unwrap();
        let s = LockableSecretStore::new(dir.path().join("s.json"), Argon2Params::INSECURE_FAST_FOR_TESTS_ONLY);
        assert!(matches!(s.get("k"), Err(VaultError::Locked)));
        assert!(s.create(&SecretString::from("short")).is_err());
        s.create(&SecretString::from("correct horse")).unwrap();
        s.set("k", b"v", true).unwrap();
        s.close();
        assert!(matches!(s.get("k"), Err(VaultError::Locked)));
        assert!(s.open(&SecretString::from("wrong password")).is_err());
        assert!(!s.verify_password(&SecretString::from("wrong password")));
        assert!(s.verify_password(&SecretString::from("correct horse")));
        s.open(&SecretString::from("correct horse")).unwrap();
        assert_eq!(s.get("k").unwrap().unwrap().expose(), b"v");
        assert!(s.create(&SecretString::from("another pass")).is_err());
    }
}
