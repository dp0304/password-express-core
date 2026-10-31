// SPDX-License-Identifier: Apache-2.0
//! Platform secret stores (CONTRACTS §12): where a device keeps its identity secret, the
//! local outbox key and storage access secrets.
//!
//! * [`SecretStore`] — the trait (implemented natively on iOS/Android through FFI).
//! * [`MemorySecretStore`] — tests / ephemeral sessions.
//! * [`FileSecretStore`] — a single Argon2id-passphrase-encrypted file (mode 0600), for the
//!   CLI and headless hosts.
//! * `OsKeyringStore` (cargo feature `os-keyring`) — macOS Keychain, Windows Credential
//!   Manager or the Secret Service through the `keyring` crate.
//!
//! `require_user_presence` asks the store to gate reads behind biometrics / device
//! passcode. Only native stores can enforce it; the file and keyring stores record the
//! flag but cannot enforce presence (the file store's passphrase is the presence check).
//! Storing a secret in Keychain / Keystore is **not** advertised as hardware-protected.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use aipass_crypto::{Argon2Params, Argon2idDescriptor, Key32, SecretBytes, SecretString, aead};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::{Result, VaultError};

/// A key → secret bytes store.
pub trait SecretStore: Send + Sync {
    /// Read a secret.
    fn get(&self, key: &str) -> Result<Option<SecretBytes>>;
    /// Write a secret; `require_user_presence` asks native stores to gate reads.
    fn set(&self, key: &str, value: &[u8], require_user_presence: bool) -> Result<()>;
    /// Delete a secret (no error when absent).
    fn delete(&self, key: &str) -> Result<()>;
}

/// In-memory store.
#[derive(Default)]
pub struct MemorySecretStore {
    map: Mutex<BTreeMap<String, (SecretBytes, bool)>>,
}

impl core::fmt::Debug for MemorySecretStore {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("MemorySecretStore")
    }
}

impl MemorySecretStore {
    /// New empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether `key` was stored with `require_user_presence`.
    pub fn requires_presence(&self, key: &str) -> Option<bool> {
        self.map.lock().ok()?.get(key).map(|(_, p)| *p)
    }

    /// Stored keys (names only).
    pub fn keys(&self) -> Vec<String> {
        self.map
            .lock()
            .map(|m| m.keys().cloned().collect())
            .unwrap_or_default()
    }
}

impl SecretStore for MemorySecretStore {
    fn get(&self, key: &str) -> Result<Option<SecretBytes>> {
        let m = self
            .map
            .lock()
            .map_err(|_| VaultError::SecretStore("lock poisoned"))?;
        Ok(m.get(key).map(|(v, _)| v.clone()))
    }
    fn set(&self, key: &str, value: &[u8], require_user_presence: bool) -> Result<()> {
        let mut m = self
            .map
            .lock()
            .map_err(|_| VaultError::SecretStore("lock poisoned"))?;
        m.insert(
            key.to_owned(),
            (SecretBytes::from_slice(value), require_user_presence),
        );
        Ok(())
    }
    fn delete(&self, key: &str) -> Result<()> {
        let mut m = self
            .map
            .lock()
            .map_err(|_| VaultError::SecretStore("lock poisoned"))?;
        m.remove(key);
        Ok(())
    }
}

/// Format tag of the encrypted secret file.
pub const SECRET_FILE_FORMAT: &str = "aipass-secrets-1";
const SECRET_FILE_AAD: &[u8] = b"aipass:v1:secret-store";

#[derive(Serialize, Deserialize)]
struct SecretFile {
    format: String,
    kdf: Argon2idDescriptor,
    #[serde(with = "aipass_crypto::b64u::array")]
    nonce: [u8; 24],
    #[serde(with = "aipass_crypto::b64u::bytes")]
    ciphertext: Vec<u8>,
}

#[derive(Default, Serialize, Deserialize)]
struct SecretMap {
    entries: BTreeMap<String, SecretEntry>,
}

#[derive(Serialize, Deserialize)]
struct SecretEntry {
    value: SecretBytes,
    presence: bool,
}

/// A secret store in one file encrypted with XChaCha20-Poly1305 under an Argon2id key
/// derived from a passphrase. The file is rewritten atomically with mode 0600.
pub struct FileSecretStore {
    path: PathBuf,
    kdf: Argon2idDescriptor,
    key: Key32,
    map: Mutex<SecretMap>,
}

impl core::fmt::Debug for FileSecretStore {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FileSecretStore")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl FileSecretStore {
    /// Open `path` with `passphrase`, creating an empty store (with `params`) if the file
    /// does not exist. A wrong passphrase is an error; the file is never overwritten then.
    pub fn open_or_create(
        path: impl AsRef<Path>,
        passphrase: &SecretString,
        params: Argon2Params,
    ) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        if passphrase.is_empty() {
            return Err(VaultError::InvalidInput("passphrase must not be empty"));
        }
        match crate::fsutil::read_optional(&path)? {
            Some(bytes) => {
                let file: SecretFile = serde_json::from_slice(&bytes)
                    .map_err(|_| VaultError::Integrity("secret store file is not valid"))?;
                if file.format != SECRET_FILE_FORMAT {
                    return Err(VaultError::Unsupported("secret store format"));
                }
                let key = file.kdf.derive(passphrase.expose().as_bytes())?;
                let pt = aead::open(&key, &file.nonce, SECRET_FILE_AAD, &file.ciphertext).map_err(
                    |_| {
                        VaultError::Invalid(aipass_types::Localized::new(
                            "本地密钥库的口令不正确",
                            "Wrong passphrase for the local secret store.",
                        ))
                    },
                )?;
                let map: SecretMap = serde_json::from_slice(pt.expose())
                    .map_err(|_| VaultError::Integrity("secret store content is not valid"))?;
                Ok(Self {
                    path,
                    kdf: file.kdf,
                    key,
                    map: Mutex::new(map),
                })
            }
            None => {
                let kdf = Argon2idDescriptor::generate(params)?;
                let key = kdf.derive(passphrase.expose().as_bytes())?;
                let s = Self {
                    path,
                    kdf,
                    key,
                    map: Mutex::new(SecretMap::default()),
                };
                s.persist(&SecretMap::default())?;
                Ok(s)
            }
        }
    }

    fn persist(&self, map: &SecretMap) -> Result<()> {
        let pt =
            Zeroizing::new(serde_json::to_vec(map).map_err(|_| VaultError::Internal("encode"))?);
        let (nonce, ciphertext) = aead::seal(&self.key, SECRET_FILE_AAD, &pt)?;
        let file = SecretFile {
            format: SECRET_FILE_FORMAT.into(),
            kdf: self.kdf.clone(),
            nonce,
            ciphertext,
        };
        let bytes = serde_json::to_vec(&file).map_err(|_| VaultError::Internal("encode"))?;
        crate::fsutil::write_private_atomic(&self.path, &bytes)
    }

    /// Path of the file.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl SecretStore for FileSecretStore {
    fn get(&self, key: &str) -> Result<Option<SecretBytes>> {
        let m = self
            .map
            .lock()
            .map_err(|_| VaultError::SecretStore("lock poisoned"))?;
        Ok(m.entries.get(key).map(|e| e.value.clone()))
    }
    fn set(&self, key: &str, value: &[u8], require_user_presence: bool) -> Result<()> {
        let mut m = self
            .map
            .lock()
            .map_err(|_| VaultError::SecretStore("lock poisoned"))?;
        m.entries.insert(
            key.to_owned(),
            SecretEntry {
                value: SecretBytes::from_slice(value),
                presence: require_user_presence,
            },
        );
        self.persist(&m)
    }
    fn delete(&self, key: &str) -> Result<()> {
        let mut m = self
            .map
            .lock()
            .map_err(|_| VaultError::SecretStore("lock poisoned"))?;
        if m.entries.remove(key).is_some() {
            self.persist(&m)?;
        }
        Ok(())
    }
}

/// OS keychain store (macOS Keychain, Windows Credential Manager, Secret Service).
#[cfg(feature = "os-keyring")]
pub struct OsKeyringStore {
    service: String,
}

#[cfg(feature = "os-keyring")]
impl OsKeyringStore {
    /// Store secrets under keychain service `service` (e.g. `"com.aipass.desktop"`).
    pub fn new(service: impl Into<String>) -> Result<Self> {
        if keyring::Entry::store_status().is_err() {
            return Err(VaultError::SecretStore("the OS keychain is not available"));
        }
        Ok(Self {
            service: service.into(),
        })
    }

    fn entry(&self, key: &str) -> Result<keyring::Entry> {
        // never surface keyring errors verbatim: some variants carry the stored bytes
        keyring::Entry::new(&self.service, key)
            .map_err(|_| VaultError::SecretStore("keychain entry could not be opened"))
    }
}

#[cfg(feature = "os-keyring")]
impl SecretStore for OsKeyringStore {
    fn get(&self, key: &str) -> Result<Option<SecretBytes>> {
        match self.entry(key)?.get_secret() {
            Ok(v) => Ok(Some(SecretBytes::new(v))),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(_) => Err(VaultError::SecretStore("keychain read failed")),
        }
    }
    fn set(&self, key: &str, value: &[u8], _require_user_presence: bool) -> Result<()> {
        self.entry(key)?
            .set_secret(value)
            .map_err(|_| VaultError::SecretStore("keychain write failed"))
    }
    fn delete(&self, key: &str) -> Result<()> {
        match self.entry(key)?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(_) => Err(VaultError::SecretStore("keychain delete failed")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_store() {
        let s = MemorySecretStore::new();
        s.set("a", b"1", true).unwrap();
        assert_eq!(s.get("a").unwrap().unwrap().expose(), b"1");
        assert_eq!(s.requires_presence("a"), Some(true));
        s.delete("a").unwrap();
        assert!(s.get("a").unwrap().is_none());
        s.delete("a").unwrap();
    }

    #[test]
    fn file_store_roundtrip_and_wrong_passphrase() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("secrets.bin");
        let pw = SecretString::from("local passphrase");
        {
            let s = FileSecretStore::open_or_create(
                &p,
                &pw,
                Argon2Params::INSECURE_FAST_FOR_TESTS_ONLY,
            )
            .unwrap();
            s.set("device", b"top-secret-bytes", true).unwrap();
            s.set("other", b"x", false).unwrap();
            s.delete("other").unwrap();
        }
        let raw = std::fs::read(&p).unwrap();
        assert!(!String::from_utf8_lossy(&raw).contains("top-secret"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        let s =
            FileSecretStore::open_or_create(&p, &pw, Argon2Params::INSECURE_FAST_FOR_TESTS_ONLY)
                .unwrap();
        assert_eq!(
            s.get("device").unwrap().unwrap().expose(),
            b"top-secret-bytes"
        );
        assert!(s.get("other").unwrap().is_none());
        let bad = FileSecretStore::open_or_create(
            &p,
            &SecretString::from("wrong"),
            Argon2Params::INSECURE_FAST_FOR_TESTS_ONLY,
        );
        assert!(bad.is_err());
        assert_eq!(std::fs::read(&p).unwrap(), raw);
    }

    /// Touches the real OS keychain of the machine running the tests (may prompt), so it
    /// only runs on request: `cargo test -p aipass-vault --features os-keyring -- --ignored`.
    #[cfg(feature = "os-keyring")]
    #[test]
    #[ignore = "uses the real OS keychain"]
    fn os_keyring_roundtrip() {
        let s = OsKeyringStore::new("com.aipass.test").unwrap();
        let key = format!(
            "test-{}",
            aipass_crypto::b64u::encode(aipass_crypto::rng::random_array::<6>())
        );
        s.set(&key, b"keyring-secret", false).unwrap();
        assert_eq!(s.get(&key).unwrap().unwrap().expose(), b"keyring-secret");
        s.delete(&key).unwrap();
        assert!(s.get(&key).unwrap().is_none());
        s.delete(&key).unwrap();
    }
}
