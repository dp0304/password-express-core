// SPDX-License-Identifier: Apache-2.0
//! Relay transport selection: the HTTPS relay (`aipass_storage::RelayClient`, signed with
//! this device's key or the pairing secret) or an in-process [`LocalRelay`] shared by
//! several cores (tests, demos, single-process setups).

use std::sync::Arc;

use aipass_storage::RelayClient;
use aipass_storage::relay_client::RelayAuth;
use aipass_types::ids::{MailboxId, PrincipalId};
use aipass_vault::RelayTransport;
use aipass_vault::relay::MemoryRelay;
use url::Url;

use crate::error::{CoreError, CoreResult};

/// URL placed in pairing links when a [`LocalRelay`] is used (loopback, never contacted).
pub(crate) const LOCAL_RELAY_URL: &str = "http://127.0.0.1/aipass-local-relay";

/// In-process relay mailbox store with the same semantics as the relay server
/// (long-poll, pairing secrets, per-mailbox cap). For tests and single-process demos;
/// messages live in memory only.
#[derive(uniffi::Object, Default)]
pub struct LocalRelay {
    pub(crate) inner: Arc<MemoryRelay>,
}

#[uniffi::export]
impl LocalRelay {
    /// New empty in-process relay.
    #[uniffi::constructor]
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Number of undelivered messages stored for `mailbox` (`dev_…`, `exe_…`, `pair_…`).
    pub fn pending_messages(&self, mailbox: String) -> u32 {
        match MailboxId::parse(&mailbox) {
            Ok(m) => u32::try_from(self.inner.len(&m)).unwrap_or(u32::MAX),
            Err(_) => 0,
        }
    }
}

/// Configured relay.
#[derive(Clone, Default)]
pub(crate) enum RelaySetting {
    #[default]
    None,
    Http(Url),
    Local(Arc<MemoryRelay>),
}

impl RelaySetting {
    pub(crate) fn is_configured(&self) -> bool {
        !matches!(self, RelaySetting::None)
    }

    /// Base URL to advertise in pairing links.
    pub(crate) fn advertised_url(&self) -> CoreResult<String> {
        match self {
            RelaySetting::None => Err(not_configured()),
            RelaySetting::Http(u) => Ok(u.as_str().trim_end_matches('/').to_owned()),
            RelaySetting::Local(_) => Ok(LOCAL_RELAY_URL.to_owned()),
        }
    }

    /// Transport for this device's own mailbox, signed as `dev_…`.
    pub(crate) fn own(
        &self,
        kid: PrincipalId,
        identity: Option<aipass_crypto::DeviceIdentity>,
    ) -> CoreResult<Arc<dyn RelayTransport>> {
        match self {
            RelaySetting::None => Err(not_configured()),
            RelaySetting::Local(m) => Ok(m.clone() as Arc<dyn RelayTransport>),
            RelaySetting::Http(u) => {
                let identity = identity.ok_or_else(|| {
                    CoreError::from(aipass_vault::VaultError::Locked)
                })?;
                let client = RelayClient::new(
                    u.clone(),
                    RelayAuth::Signed {
                        kid,
                        signer: Arc::new(identity),
                    },
                )
                .map_err(|e| CoreError::from(aipass_types::ApiError::from(e)))?;
                Ok(Arc::new(client))
            }
        }
    }

    /// Transport for a `pair_…` mailbox (pairing secret auth). For the HTTP relay the
    /// URL comes from the pairing link (`relay_url`).
    pub(crate) fn pairing(
        &self,
        relay_url: &str,
        secret: [u8; 16],
    ) -> CoreResult<Arc<dyn RelayTransport>> {
        match self {
            RelaySetting::Local(m) => Ok(m.clone() as Arc<dyn RelayTransport>),
            _ => {
                let url = Url::parse(relay_url).map_err(|_| {
                    CoreError::invalid("配对链接中的中继地址无效", "invalid relay URL in pairing link")
                })?;
                let client = RelayClient::for_pairing(url, secret)
                    .map_err(|e| CoreError::from(aipass_types::ApiError::from(e)))?;
                Ok(Arc::new(client))
            }
        }
    }
}

fn not_configured() -> CoreError {
    CoreError::new(
        aipass_types::ErrorCode::InvalidRequest,
        "尚未配置中继服务（set_relay）",
        "relay is not configured (call set_relay first)",
    )
}
