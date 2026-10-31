// SPDX-License-Identifier: Apache-2.0
//! The native `SecretStore` callback interface (iOS Keychain / Android Keystore) and its
//! adapter to [`aipass_vault::SecretStore`].
//!
//! Keys written by the core (see `aipass_sync` docs):
//! `aipass.device.<dev>` (64 bytes, `require_user_presence = true`), `aipass.local.<vault>`,
//! `aipass.storage.<vault>`, `aipass.recovery-pending.<vault>`.
//!
//! The adapter remembers the device key it handed to the core while the vault is
//! unlocked, so the relay client can sign requests (`AIPass-Sig`) without a second
//! biometric prompt. The copy is zeroized on `lock()`.

use std::sync::{Arc, Mutex};

use aipass_crypto::{DeviceIdentity, SecretBytes};
use aipass_vault::VaultError;
use zeroize::Zeroize;

use crate::error::SecretStoreError;

/// Implemented natively. `require_user_presence = true` means the item must be protected
/// by biometrics / device passcode (iOS: `.userPresence` access control; Android:
/// `setUserAuthenticationRequired(true)`). Values must never be logged by the native side.
#[uniffi::export(with_foreign)]
pub trait SecretStore: Send + Sync {
    /// Return the stored bytes, or `None` when the key does not exist.
    fn get(&self, key: String) -> Result<Option<Vec<u8>>, SecretStoreError>;
    /// Create or replace a value.
    fn set(
        &self,
        key: String,
        value: Vec<u8>,
        require_user_presence: bool,
    ) -> Result<(), SecretStoreError>;
    /// Delete a value (deleting a missing key is not an error).
    fn delete(&self, key: String) -> Result<(), SecretStoreError>;
}

const DEVICE_KEY_PREFIX: &str = "aipass.device.";

/// Adapter used by the core.
pub(crate) struct NativeSecretStore {
    inner: Arc<dyn SecretStore>,
    device_key: Mutex<Option<(String, SecretBytes)>>,
}

impl NativeSecretStore {
    pub(crate) fn new(inner: Arc<dyn SecretStore>) -> Self {
        Self {
            inner,
            device_key: Mutex::new(None),
        }
    }

    fn remember(&self, key: &str, value: &[u8]) {
        if key.starts_with(DEVICE_KEY_PREFIX)
            && let Ok(mut g) = self.device_key.lock()
        {
            *g = Some((key.to_owned(), SecretBytes::from_slice(value)));
        }
    }

    /// Device identity remembered from the last unlock / create, if it belongs to `device_id`.
    pub(crate) fn device_identity(&self, device_id: &str) -> Option<DeviceIdentity> {
        let want = format!("{DEVICE_KEY_PREFIX}{device_id}");
        let g = self.device_key.lock().ok()?;
        match g.as_ref() {
            Some((k, v)) if *k == want => DeviceIdentity::from_secret_bytes(v.expose()).ok(),
            _ => None,
        }
    }

    /// Forget the remembered device key (zeroized on drop).
    pub(crate) fn forget(&self) {
        if let Ok(mut g) = self.device_key.lock() {
            *g = None;
        }
    }
}

impl aipass_vault::SecretStore for NativeSecretStore {
    fn get(&self, key: &str) -> aipass_vault::Result<Option<SecretBytes>> {
        match self.inner.get(key.to_owned()) {
            Ok(Some(mut v)) => {
                self.remember(key, &v);
                let s = SecretBytes::from_slice(&v);
                v.zeroize();
                Ok(Some(s))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(VaultError::from(e)),
        }
    }

    fn set(&self, key: &str, value: &[u8], require_user_presence: bool) -> aipass_vault::Result<()> {
        self.inner
            .set(key.to_owned(), value.to_vec(), require_user_presence)
            .map_err(VaultError::from)?;
        self.remember(key, value);
        Ok(())
    }

    fn delete(&self, key: &str) -> aipass_vault::Result<()> {
        if key.starts_with(DEVICE_KEY_PREFIX) {
            self.forget();
        }
        self.inner.delete(key.to_owned()).map_err(VaultError::from)
    }
}
