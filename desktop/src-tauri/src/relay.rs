// SPDX-License-Identifier: Apache-2.0
//! Relay wiring for the embedded node so a paired phone can approve (CONTRACTS §4):
//! the broker's [`DeviceOutbox`] posts sealed `approval.request` / `approval.cancelled` /
//! `connection.pair_request` envelopes to each approver's mailbox, and a consumer
//! long-polls the executor's own mailbox (`exe_…`) and feeds `approval.decision`,
//! `grant.revoke`, `connection.*` and `state.request` to
//! [`Broker::handle_device_message`], posting its sealed replies. The relay only sees
//! ciphertext plus routing metadata (from, to, type, time, size).

use std::sync::Arc;
use std::time::Duration;

use aipass_broker::{Broker, DeviceOutbox};
use aipass_storage::RelayClient;
use aipass_types::ApiError;
use aipass_types::ids::{MailboxId, MessageId};
use aipass_types::relay::RelayEnvelope;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

/// Posts broker envelopes to the relay.
pub struct RelayOutbox {
    /// Signed relay client (kid = the executor).
    pub client: Arc<RelayClient>,
}

#[async_trait::async_trait]
impl DeviceOutbox for RelayOutbox {
    async fn deliver(&self, env: RelayEnvelope) -> Result<(), ApiError> {
        self.client.post(&env).await.map(|_| ()).map_err(ApiError::from)
    }
}

/// Long-poll the executor mailbox until `token` is cancelled.
pub fn spawn_consumer(broker: Arc<Broker>, client: Arc<RelayClient>, mailbox: MailboxId, token: CancellationToken) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut after: Option<MessageId> = None;
        let mut backoff = Duration::from_secs(1);
        loop {
            let fetched = tokio::select! {
                _ = token.cancelled() => return,
                r = client.fetch(&mailbox, after.as_ref(), 25) => r,
            };
            match fetched {
                Ok(messages) => {
                    backoff = Duration::from_secs(1);
                    for m in messages {
                        match broker.handle_device_message(&m.envelope).await {
                            Ok(replies) => {
                                for r in replies {
                                    if let Err(e) = client.post(&r).await {
                                        tracing::warn!(error = %ApiError::from(e).code.as_str(), "relay reply not delivered");
                                    }
                                }
                            }
                            Err(e) => tracing::warn!(code = e.code.as_str(), "relay message rejected"),
                        }
                        let _ = client.delete(&mailbox, &m.message_id).await;
                        after = Some(m.message_id);
                    }
                }
                Err(e) => {
                    let retry = e.is_retryable();
                    tracing::warn!(retryable = retry, "relay fetch failed");
                    tokio::select! {
                        _ = token.cancelled() => return,
                        _ = tokio::time::sleep(backoff) => {}
                    }
                    backoff = (backoff * 2).min(Duration::from_secs(60));
                }
            }
        }
    })
}
