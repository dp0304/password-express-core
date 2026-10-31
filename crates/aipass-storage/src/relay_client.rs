// SPDX-License-Identifier: Apache-2.0
//! Relay mailbox client (CONTRACTS §4) shared by trusted clients, brokers and executors.
//!
//! * `POST /v1/relay/{mailbox}` — deliver a sealed [`RelayEnvelope`] → `message_id`;
//! * `GET /v1/relay/{mailbox}?after=&wait=` — long-poll (≤ 25 s) for new messages;
//! * `DELETE /v1/relay/{mailbox}/{message_id}` — acknowledge.
//!
//! Authentication is either `AIPass-Sig` with a device / executor key
//! ([`RelayAuth::Signed`]; the relay checks the sender shares a vault with the recipient,
//! and only the mailbox owner may read) or, for `pair_…` mailboxes, the 16-byte pairing
//! secret from the QR code ([`RelayAuth::PairingSecret`]).
//!
//! The relay only sees envelopes: `{v, from, to, type, created_at}` metadata plus the
//! HPKE-sealed payload. Sealing / opening is done by the caller with
//! `aipass_types::relay::{seal_envelope, open_envelope}`.

use std::time::Duration;

use aipass_crypto::b64u;
use aipass_types::ids::{MailboxId, MessageId, PrincipalId};
use aipass_types::pairing::PAIRING_SECRET_HEADER;
use aipass_types::relay::{
    MAX_WAIT_SECS, MailboxMessage, MailboxResponse, PostMessageResponse, RelayEnvelope,
};
use aipass_types::{ApiError, ErrorBody, ErrorCode};
use reqwest::Method;
use reqwest::header::HeaderValue;
use thiserror::Error;
use url::Url;
use zeroize::Zeroizing;

use crate::http::DeviceSigner;
use crate::httputil::{self, transport_error};

/// How the client authenticates to the relay.
#[derive(Clone)]
pub enum RelayAuth {
    /// `AIPass-Sig` as a device (`dev_…`) or executor (`exe_…`).
    Signed {
        /// Principal id used as `kid` (and as the owned mailbox id).
        kid: PrincipalId,
        /// Its Ed25519 key.
        signer: DeviceSigner,
    },
    /// `X-AIPass-Pairing-Secret` for one `pair_…` mailbox.
    PairingSecret(Zeroizing<[u8; 16]>),
}

impl core::fmt::Debug for RelayAuth {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Signed { kid, .. } => f.debug_struct("Signed").field("kid", kid).finish(),
            Self::PairingSecret(_) => f.write_str("PairingSecret([REDACTED])"),
        }
    }
}

/// Relay client failure.
#[derive(Debug, Clone, PartialEq, Error)]
pub enum RelayClientError {
    /// The relay answered with an error envelope.
    #[error("relay error: {0}")]
    Api(ApiError),
    /// Network failure (relay unreachable — callers should fall back to "open the app to
    /// fetch pending requests", never to approval).
    #[error("relay unreachable: {0}")]
    Network(String),
    /// Timed out.
    #[error("relay request timed out")]
    Timeout,
    /// Unexpected response.
    #[error("unexpected relay response: {0}")]
    Protocol(String),
}

impl RelayClientError {
    /// Whether retrying later may help.
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Network(_) | Self::Timeout => true,
            Self::Api(e) => matches!(e.code, ErrorCode::RateLimited | ErrorCode::Internal),
            Self::Protocol(_) => false,
        }
    }
}

impl From<RelayClientError> for ApiError {
    fn from(e: RelayClientError) -> Self {
        match e {
            RelayClientError::Api(a) => a,
            RelayClientError::Network(_) | RelayClientError::Timeout => ApiError::new(
                ErrorCode::UpstreamError,
            )
            .with_message(
                "无法连接中继服务，请稍后重试或打开 App 拉取待处理请求",
                "The relay is unreachable; retry later or open the app to fetch pending requests.",
            ),
            RelayClientError::Protocol(_) => ApiError::new(ErrorCode::UpstreamError),
        }
    }
}

fn from_storage(e: crate::StorageError) -> RelayClientError {
    match e {
        crate::StorageError::Timeout => RelayClientError::Timeout,
        crate::StorageError::Network(m) => RelayClientError::Network(m),
        other => RelayClientError::Protocol(other.to_string()),
    }
}

/// Relay mailbox client.
#[derive(Clone)]
pub struct RelayClient {
    base: Url,
    auth: RelayAuth,
    http: reqwest::Client,
}

impl core::fmt::Debug for RelayClient {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RelayClient")
            .field("base", &self.base.as_str())
            .field("auth", &self.auth)
            .finish()
    }
}

impl RelayClient {
    /// Client with a default HTTP client (timeout covers the longest long-poll).
    pub fn new(base_url: Url, auth: RelayAuth) -> Result<Self, RelayClientError> {
        let http = httputil::build_client(Duration::from_secs(MAX_WAIT_SECS + 20))
            .map_err(from_storage)?;
        Self::with_client(base_url, auth, http, false)
    }

    /// Client with a caller-supplied HTTP client; its timeout must exceed 25 s + margin.
    pub fn with_client(
        base_url: Url,
        auth: RelayAuth,
        http: reqwest::Client,
        allow_http: bool,
    ) -> Result<Self, RelayClientError> {
        httputil::check_url(&base_url, allow_http).map_err(from_storage)?;
        if let RelayAuth::Signed { kid, .. } = &auth
            && matches!(kid, PrincipalId::Connection(_))
        {
            return Err(RelayClientError::Protocol(
                "AI connections cannot use the relay".into(),
            ));
        }
        let mut base = base_url;
        if !base.path().ends_with('/') {
            let p = format!("{}/", base.path());
            base.set_path(&p);
        }
        base.set_query(None);
        base.set_fragment(None);
        Ok(Self { base, auth, http })
    }

    /// Pairing-secret client for a `pair_` mailbox.
    pub fn for_pairing(base_url: Url, secret: [u8; 16]) -> Result<Self, RelayClientError> {
        Self::new(base_url, RelayAuth::PairingSecret(Zeroizing::new(secret)))
    }

    async fn send(
        &self,
        method: Method,
        rel: &str,
        body: Vec<u8>,
    ) -> Result<(u16, Vec<u8>), RelayClientError> {
        let url = self
            .base
            .join(rel)
            .map_err(|_| RelayClientError::Protocol("invalid relay path".into()))?;
        let pq = match url.query() {
            Some(q) => format!("{}?{q}", url.path()),
            None => url.path().to_owned(),
        };
        let mut req = self.http.request(method.clone(), url);
        match &self.auth {
            RelayAuth::Signed { kid, signer } => {
                let sig = aipass_types::signing::sign_request(
                    signer.as_ref(),
                    kid.as_str(),
                    method.as_str(),
                    &pq,
                    &body,
                );
                let mut v = HeaderValue::from_str(&sig.to_header_value())
                    .map_err(|_| RelayClientError::Protocol("bad signature header".into()))?;
                v.set_sensitive(true);
                req = req.header(reqwest::header::AUTHORIZATION, v);
            }
            RelayAuth::PairingSecret(s) => {
                let mut v = HeaderValue::from_str(&b64u::encode(s.as_slice()))
                    .map_err(|_| RelayClientError::Protocol("bad pairing secret".into()))?;
                v.set_sensitive(true);
                req = req.header(PAIRING_SECRET_HEADER, v);
            }
        }
        if !body.is_empty() {
            req = req.header(reqwest::header::CONTENT_TYPE, "application/json");
        }
        let resp = req
            .body(body)
            .send()
            .await
            .map_err(|e| from_storage(transport_error(&e)))?;
        let status = resp.status().as_u16();
        let bytes = resp
            .bytes()
            .await
            .map_err(|e| from_storage(transport_error(&e)))?;
        Ok((status, bytes.to_vec()))
    }

    fn api_error(status: u16, body: &[u8]) -> RelayClientError {
        match serde_json::from_slice::<ErrorBody>(body) {
            Ok(b) => RelayClientError::Api(ApiError::from_body(&b)),
            Err(_) => RelayClientError::Protocol(format!("HTTP {status}")),
        }
    }

    /// Deliver an envelope to `envelope.to`.
    pub async fn post(&self, envelope: &RelayEnvelope) -> Result<MessageId, RelayClientError> {
        envelope
            .check_size()
            .map_err(|e| RelayClientError::Protocol(e.to_string()))?;
        let body = serde_json::to_vec(envelope)
            .map_err(|_| RelayClientError::Protocol("envelope serialization".into()))?;
        let (status, resp) = self
            .send(Method::POST, &format!("v1/relay/{}", envelope.to), body)
            .await?;
        if status != 202 && status != 200 {
            return Err(Self::api_error(status, &resp));
        }
        serde_json::from_slice::<PostMessageResponse>(&resp)
            .map(|r| r.message_id)
            .map_err(|_| RelayClientError::Protocol("invalid post response".into()))
    }

    /// Fetch messages after `after`, waiting up to `wait_secs` (clamped to 25) for new ones.
    pub async fn fetch(
        &self,
        mailbox: &MailboxId,
        after: Option<&MessageId>,
        wait_secs: u64,
    ) -> Result<Vec<MailboxMessage>, RelayClientError> {
        let wait = wait_secs.min(MAX_WAIT_SECS);
        let mut rel = format!("v1/relay/{mailbox}?wait={wait}");
        if let Some(a) = after {
            rel = format!("v1/relay/{mailbox}?after={a}&wait={wait}");
        }
        let (status, resp) = self.send(Method::GET, &rel, Vec::new()).await?;
        if status != 200 {
            return Err(Self::api_error(status, &resp));
        }
        serde_json::from_slice::<MailboxResponse>(&resp)
            .map(|r| r.messages)
            .map_err(|_| RelayClientError::Protocol("invalid mailbox response".into()))
    }

    /// Acknowledge (delete) one message.
    pub async fn delete(
        &self,
        mailbox: &MailboxId,
        message_id: &MessageId,
    ) -> Result<(), RelayClientError> {
        let (status, resp) = self
            .send(
                Method::DELETE,
                &format!("v1/relay/{mailbox}/{message_id}"),
                Vec::new(),
            )
            .await?;
        match status {
            200 | 204 | 404 => Ok(()),
            _ => Err(Self::api_error(status, &resp)),
        }
    }
}
