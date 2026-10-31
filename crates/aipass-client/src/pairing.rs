// SPDX-License-Identifier: Apache-2.0
//! Connection pairing helper (CONTRACTS §6.3 `POST /connections/pair`, `GET /connections/pair/{id}`;
//! design doc §5.2 step 5).
//!
//! 1. Generate a fresh Ed25519 connection key from the OS CSPRNG.
//! 2. `POST /v1/connections/pair {host_type, display_name, transport, public_key}` → pairing
//!    code. The user compares the code and approves **on a trusted device**; nothing on this
//!    machine can approve the connection.
//! 3. Poll `GET /v1/connections/pair/{pairing_request_id}` signed by the pending key until
//!    `approved` / `denied` / `expired`. Polling never approves anything and never times out
//!    into approval.
//! 4. On approval the key is stored at `<AIPASS_HOME>/connections/<conn_id>.key` (0600).

use std::time::Duration;

use aipass_crypto::Ed25519Keypair;
use aipass_types::models::{HostType, PairConnectionRequest, PairConnectionResponse, PairStatus, Transport};
use aipass_types::{ConnectionId, ErrorCode};

use crate::auth::Auth;
use crate::client::BrokerClient;
use crate::endpoint::BrokerEndpoint;
use crate::error::ClientError;
use crate::keys::{ConnectionKey, ConnectionKeyMeta, KeyStore};

/// Maximum display label length (characters).
pub const MAX_DISPLAY_NAME: usize = 64;
/// Default poll interval.
pub const DEFAULT_POLL_INTERVAL: Duration = Duration::from_secs(2);

/// What to register.
#[derive(Debug, Clone)]
pub struct PairingRequest {
    /// Host type label.
    pub host_type: HostType,
    /// Display label (self-declared; shown on the trusted device marked as such).
    pub display_name: String,
    /// Transport.
    pub transport: Transport,
    /// Record the broker URL in the key file (set when the user explicitly chose the broker).
    pub record_broker_url: bool,
}

/// Outcome of a pairing.
#[derive(Debug)]
pub enum PairingOutcome {
    /// Approved; the key has been stored.
    Approved {
        /// The key.
        key: ConnectionKey,
        /// Where it was stored.
        path: std::path::PathBuf,
    },
    /// Denied on the trusted device.
    Denied,
    /// The pairing window passed without approval (never auto-approved).
    Expired,
}

/// A pairing in progress.
pub struct PendingPairing {
    client: BrokerClient,
    keypair: Ed25519Keypair,
    request: PairingRequest,
    response: PairConnectionResponse,
}

impl std::fmt::Debug for PendingPairing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingPairing")
            .field("connection_id", &self.response.connection_id)
            .field("pairing_request_id", &self.response.pairing_request_id)
            .field("expires_at", &self.response.expires_at)
            .finish()
    }
}

/// Validate a display label: 1..=64 characters, no control characters.
pub fn validate_display_name(name: &str) -> Result<(), ClientError> {
    let n = name.trim();
    if n.is_empty() || n.chars().count() > MAX_DISPLAY_NAME || n.chars().any(char::is_control) {
        return Err(ClientError::Config(format!(
            "--name must be 1 to {MAX_DISPLAY_NAME} printable characters"
        )));
    }
    Ok(())
}

/// Register a new pending connection. `client` should be unauthenticated (public endpoint).
pub async fn start_pairing(
    client: &BrokerClient,
    request: PairingRequest,
) -> Result<PendingPairing, ClientError> {
    validate_display_name(&request.display_name)?;
    let keypair = Ed25519Keypair::generate();
    let body = PairConnectionRequest {
        host_type: request.host_type,
        display_name: request.display_name.trim().to_owned(),
        transport: request.transport,
        public_key: keypair.public_key_b64u(),
    };
    let response = client.with_auth(Auth::None).pair_connection(&body).await?;
    let signer: std::sync::Arc<dyn aipass_crypto::Ed25519Signer + Send + Sync> =
        std::sync::Arc::new(keypair.clone());
    let client = client.with_auth(Auth::signed(response.connection_id.as_str(), signer));
    Ok(PendingPairing {
        client,
        keypair,
        request,
        response,
    })
}

impl PendingPairing {
    /// The broker's response (pairing code, ids, expiry).
    pub fn response(&self) -> &PairConnectionResponse {
        &self.response
    }

    /// Pairing code to compare on the trusted device.
    pub fn pairing_code(&self) -> &str {
        &self.response.pairing_code
    }

    /// Pending connection id.
    pub fn connection_id(&self) -> &ConnectionId {
        &self.response.connection_id
    }

    /// Endpoint.
    pub fn endpoint(&self) -> &BrokerEndpoint {
        self.client.endpoint()
    }

    /// One status poll (signed by the pending key).
    pub async fn poll_once(&self) -> Result<PairStatus, ClientError> {
        let status = self
            .client
            .pair_status(&self.response.pairing_request_id)
            .await?;
        if status.connection_id != self.response.connection_id {
            return Err(ClientError::Protocol(
                "pairing status refers to a different connection".into(),
            ));
        }
        Ok(status.status)
    }

    /// Poll until a final status; store the key in `store` on approval.
    ///
    /// Transient transport errors are retried until the pairing's `expires_at`; API errors
    /// other than `RATE_LIMITED` end the wait. Passing the expiry yields
    /// [`PairingOutcome::Expired`] — never approval.
    pub async fn wait(
        self,
        store: &KeyStore,
        poll_interval: Duration,
    ) -> Result<PairingOutcome, ClientError> {
        let expires = self.response.expires_at;
        loop {
            match self.poll_once().await {
                Ok(PairStatus::Approved) => return self.finish(store),
                Ok(PairStatus::Denied) => return Ok(PairingOutcome::Denied),
                Ok(PairStatus::Expired) => return Ok(PairingOutcome::Expired),
                Ok(PairStatus::Pending) => {}
                Err(ClientError::Api(e)) if e.code == ErrorCode::RateLimited => {}
                Err(ClientError::Api(e)) if e.code == ErrorCode::ApprovalExpired => {
                    return Ok(PairingOutcome::Expired);
                }
                Err(e @ ClientError::Api(_)) => return Err(e),
                Err(e) => {
                    tracing::warn!(error = %e, "pairing status poll failed; retrying");
                }
            }
            if aipass_types::time::now() > expires {
                // one last check so an approval at the boundary is not lost
                return match self.poll_once().await {
                    Ok(PairStatus::Approved) => self.finish(store),
                    Ok(PairStatus::Denied) => Ok(PairingOutcome::Denied),
                    _ => Ok(PairingOutcome::Expired),
                };
            }
            tokio::time::sleep(poll_interval).await;
        }
    }

    fn finish(self, store: &KeyStore) -> Result<PairingOutcome, ClientError> {
        let meta = ConnectionKeyMeta {
            host_type: self.request.host_type,
            display_name: self.request.display_name.trim().to_owned(),
            broker_url: self
                .request
                .record_broker_url
                .then(|| self.client.endpoint().to_string()),
            created_at: aipass_types::time::now(),
        };
        let key = ConnectionKey::new(self.response.connection_id.clone(), self.keypair, meta);
        let path = store.save(&key)?;
        Ok(PairingOutcome::Approved { key, path })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_names() {
        assert!(validate_display_name("Codex on laptop").is_ok());
        assert!(validate_display_name("").is_err());
        assert!(validate_display_name("   ").is_err());
        assert!(validate_display_name("a\nb").is_err());
        assert!(validate_display_name(&"x".repeat(65)).is_err());
        assert!(validate_display_name(&"码".repeat(64)).is_ok());
    }
}
