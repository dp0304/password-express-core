// SPDX-License-Identifier: Apache-2.0
//! Broker ↔ trusted devices over the relay (CONTRACTS §4).
//!
//! * [`NodeDirectory`] lets the node's own relay accept traffic between this executor
//!   (`exe_X`) and the broker's active trusted devices, also when the vault itself lives on
//!   the user's S3 / local storage rather than on this node.
//! * [`RelayOutbox`] is the broker's `DeviceOutbox`: sealed envelopes are posted to the
//!   configured relay (this node, or e.g. the official cloud relay with push).
//! * [`run_consumer`] long-polls this executor's own mailbox and feeds every envelope to
//!   `Broker::handle_device_message`, posting the sealed replies. It also drives the
//!   control-channel flag: while the relay is unreachable new operations get
//!   `CONTROL_CHANNEL_LOST` (the user must always be able to reach the node to revoke).

use std::sync::Arc;
use std::time::Duration;

use aipass_broker::{Broker, DeviceOutbox};
use aipass_executor::Executor;
use aipass_storage::relay_client::{RelayAuth, RelayClient};
use aipass_sync_server::relay::RelayDirectory;
use aipass_types::error::{ApiError, ErrorCode};
use aipass_types::ids::{ExecutorId, MessageId, PrincipalId};
use aipass_types::ids::MailboxId;
use aipass_types::relay::RelayEnvelope;
use async_trait::async_trait;
use tokio::sync::watch;

/// Relay directory backed by the broker's trusted-device table.
pub struct NodeDirectory {
    broker: Arc<Broker>,
    executor_id: ExecutorId,
    sign_pk: [u8; 32],
}

impl NodeDirectory {
    /// Directory for this node's executor.
    pub fn new(broker: Arc<Broker>, executor_id: ExecutorId, sign_pk: [u8; 32]) -> Self {
        Self { broker, executor_id, sign_pk }
    }

    async fn active_device_key(&self, p: &PrincipalId) -> Result<Option<[u8; 32]>, ApiError> {
        let PrincipalId::Device(d) = p else { return Ok(None) };
        let devices = self.broker.list_devices().await?;
        Ok(devices
            .devices
            .iter()
            .find(|t| &t.device.device_id == d && t.is_active_approver())
            .map(|t| t.device.sign_pk))
    }

    fn is_self(&self, p: &PrincipalId) -> bool {
        matches!(p, PrincipalId::Executor(e) if e == &self.executor_id)
    }
}

#[async_trait]
impl RelayDirectory for NodeDirectory {
    async fn principal_key(&self, principal: &PrincipalId) -> Result<Option<[u8; 32]>, ApiError> {
        if self.is_self(principal) {
            return Ok(Some(self.sign_pk));
        }
        self.active_device_key(principal).await
    }

    async fn authorize_send(&self, sender: &PrincipalId, recipient: &PrincipalId) -> Result<(), ApiError> {
        let ok = (self.is_self(sender) && self.active_device_key(recipient).await?.is_some())
            || (self.is_self(recipient) && self.active_device_key(sender).await?.is_some());
        if ok {
            Ok(())
        } else {
            Err(ApiError::new(ErrorCode::Forbidden).with_message("发送方与接收方不属于同一保管库", "sender and recipient do not share a vault"))
        }
    }
}

/// Relay client for this executor's mailbox.
pub fn executor_relay_client(base: &str, node: &crate::identity::NodeIdentity) -> anyhow::Result<RelayClient> {
    let url = url::Url::parse(base)?;
    let allow_http = crate::config::is_loopback_url(&url);
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(40))
        .connect_timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    let signer: aipass_storage::http::DeviceSigner = node.identity.clone();
    let auth = RelayAuth::Signed { kid: PrincipalId::Executor(node.executor_id.clone()), signer };
    RelayClient::with_client(url, auth, http, allow_http).map_err(|e| anyhow::anyhow!("relay client: {e}"))
}

/// The broker's outbox to trusted devices.
pub struct RelayOutbox {
    client: Arc<RelayClient>,
}

impl RelayOutbox {
    /// Outbox posting through `client`.
    pub fn new(client: Arc<RelayClient>) -> Self {
        Self { client }
    }
}

#[async_trait]
impl DeviceOutbox for RelayOutbox {
    async fn deliver(&self, envelope: RelayEnvelope) -> Result<(), ApiError> {
        let mut last = None;
        for attempt in 0..3u64 {
            match self.client.post(&envelope).await {
                Ok(_) => return Ok(()),
                Err(e) if e.is_retryable() => {
                    last = Some(e);
                    tokio::time::sleep(Duration::from_millis(250 * (attempt + 1))).await;
                }
                Err(e) => return Err(e.into()),
            }
        }
        Err(last.map(Into::into).unwrap_or_else(ApiError::internal))
    }
}

/// Number of consecutive relay failures after which the control channel counts as lost.
pub const CONTROL_LOST_AFTER_FAILURES: u32 = 3;

/// Consume this executor's relay mailbox until `stop` flips to true.
pub async fn run_consumer(
    broker: Arc<Broker>,
    executor: Option<Arc<Executor>>,
    client: Arc<RelayClient>,
    executor_id: ExecutorId,
    mut stop: watch::Receiver<bool>,
) {
    let mailbox = MailboxId::Executor(executor_id.clone());
    let mut after: Option<MessageId> = None;
    let mut failures: u32 = 0;
    let mut connected = true;
    let mut backoff = Duration::from_millis(500);
    loop {
        if *stop.borrow() {
            return;
        }
        let fetch = client.fetch(&mailbox, after.as_ref(), 25);
        let res = tokio::select! {
            r = fetch => r,
            _ = stop.changed() => return,
        };
        match res {
            Ok(messages) => {
                failures = 0;
                backoff = Duration::from_millis(500);
                if !connected {
                    connected = true;
                    set_channel(&broker, executor.as_deref(), &executor_id, true).await;
                    tracing::info!("relay control channel restored");
                }
                for m in messages {
                    after = Some(m.message_id.clone());
                    match broker.handle_device_message(&m.envelope).await {
                        Ok(replies) => {
                            for r in replies {
                                if let Err(e) = client.post(&r).await {
                                    tracing::warn!(code = %ApiError::from(e).code.as_str(), "could not post relay reply");
                                }
                            }
                        }
                        Err(e) => tracing::warn!(code = %e.code.as_str(), kind = %m.envelope.message_type.as_str(), "relay message rejected"),
                    }
                    if let Err(e) = client.delete(&mailbox, &m.message_id).await {
                        tracing::debug!(code = %ApiError::from(e).code.as_str(), "could not delete relay message");
                    }
                }
            }
            Err(e) => {
                failures = failures.saturating_add(1);
                tracing::warn!(code = %ApiError::from(e).code.as_str(), failures, "relay fetch failed");
                if connected && failures >= CONTROL_LOST_AFTER_FAILURES {
                    connected = false;
                    set_channel(&broker, executor.as_deref(), &executor_id, false).await;
                    tracing::warn!("relay unreachable: control channel lost, new operations are refused until it recovers");
                }
                tokio::select! {
                    _ = tokio::time::sleep(backoff) => {},
                    _ = stop.changed() => return,
                }
                backoff = (backoff * 2).min(Duration::from_secs(30));
            }
        }
    }
}

async fn set_channel(broker: &Broker, executor: Option<&Executor>, id: &ExecutorId, ok: bool) {
    if let Some(e) = executor {
        e.set_control_channel_ok(ok);
    }
    if let Err(e) = broker.set_control_channel(id, ok).await {
        tracing::warn!(code = %e.code.as_str(), "could not update control channel state");
    }
}
