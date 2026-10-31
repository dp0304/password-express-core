// SPDX-License-Identifier: Apache-2.0
//! Push hints (CONTRACTS §4, design doc §9.2 / §11.4 / §16.3).
//!
//! A [`PushNotifier`] receives **only** [`PushHint`] `{mailbox, message_id}` — never the
//! envelope, its type, sender, or anything sealed inside. The app wakes up, fetches the
//! mailbox over the authenticated relay API and decrypts locally. A missing push never
//! implies approval; approvals time out as denied (§11.5).
//!
//! Implementations here: [`NoopPushNotifier`] (node default), [`LogPushNotifier`] (dev),
//! [`WebhookPushNotifier`] (self-host: POST the hint to an operator-chosen HTTPS endpoint,
//! HMAC-signed). The commercial cloud implements APNs / FCM behind the same trait.

use std::time::Duration;

use aipass_crypto::SecretBytes;
use aipass_types::relay::PushHint;
use async_trait::async_trait;
use url::Url;

/// Delivers push hints.
#[async_trait]
pub trait PushNotifier: Send + Sync {
    /// Best effort; failures are logged by the implementation, never surfaced to senders.
    async fn notify(&self, hint: PushHint);
}

/// Does nothing.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopPushNotifier;

#[async_trait]
impl PushNotifier for NoopPushNotifier {
    async fn notify(&self, _hint: PushHint) {}
}

/// Logs the hint (mailbox + message id only) at info level.
#[derive(Debug, Default, Clone, Copy)]
pub struct LogPushNotifier;

#[async_trait]
impl PushNotifier for LogPushNotifier {
    async fn notify(&self, hint: PushHint) {
        tracing::info!(mailbox = %hint.mailbox, message_id = %hint.message_id, "push hint");
    }
}

/// Header carrying `v1=<hex HMAC-SHA256(secret, body)>` on webhook deliveries.
pub const WEBHOOK_SIGNATURE_HEADER: &str = "X-AIPass-Signature";

/// POSTs `{"mailbox","message_id"}` to an operator-configured endpoint.
pub struct WebhookPushNotifier {
    url: Url,
    secret: Option<SecretBytes>,
    http: reqwest::Client,
}

impl core::fmt::Debug for WebhookPushNotifier {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("WebhookPushNotifier")
            .field("host", &self.url.host_str())
            .finish_non_exhaustive()
    }
}

impl WebhookPushNotifier {
    /// `url` must be https (or loopback http). `secret` signs each delivery.
    pub fn new(url: Url, secret: Option<SecretBytes>) -> Result<Self, String> {
        let loopback = matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
        if url.scheme() != "https" && !(url.scheme() == "http" && loopback) {
            return Err("webhook URL must use https".into());
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err("webhook URL must not contain credentials".into());
        }
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(5))
            .build()
            .map_err(|_| "could not build HTTP client".to_owned())?;
        Ok(Self { url, secret, http })
    }
}

#[async_trait]
impl PushNotifier for WebhookPushNotifier {
    async fn notify(&self, hint: PushHint) {
        let Ok(body) = serde_json::to_vec(&hint) else {
            return;
        };
        let mut req = self
            .http
            .post(self.url.clone())
            .header(reqwest::header::CONTENT_TYPE, "application/json");
        if let Some(s) = &self.secret {
            let tag = aipass_crypto::hash::hmac_sha256(s.expose(), &body);
            req = req.header(WEBHOOK_SIGNATURE_HEADER, format!("v1={}", hex::encode(tag)));
        }
        match req.body(body).send().await {
            Ok(r) if r.status().is_success() => {}
            Ok(r) => tracing::warn!(
                status = r.status().as_u16(),
                "push webhook rejected the hint"
            ),
            Err(_) => tracing::warn!("push webhook unreachable"),
        }
    }
}
