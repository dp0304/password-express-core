// SPDX-License-Identifier: Apache-2.0
//! Relay transport abstraction (CONTRACTS §4) and an in-memory implementation.
//!
//! The relay only ever stores sealed, signed [`RelayEnvelope`]s. [`RelayTransport`] is what
//! pairing and the approval inbox use; the HTTP implementation (device-signed
//! `AIPass-Sig` requests or the `X-AIPass-Pairing-Secret` header for `pair_` mailboxes)
//! lives in `aipass-storage::relay_client`, and [`MemoryRelay`] serves tests and in-process
//! deployments.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use aipass_crypto::{Ed25519Signer, KemKeypair};
use aipass_types::ids::{MailboxId, MessageId};
use aipass_types::relay::{
    MAX_MESSAGES_PER_MAILBOX, MailboxMessage, RelayEnvelope, RelayMessage, open_envelope,
    seal_envelope,
};
use aipass_types::time::Timestamp;
use async_trait::async_trait;
use tokio::sync::Notify;

use crate::error::{Result, VaultError};

/// A relay mailbox transport.
#[async_trait]
pub trait RelayTransport: Send + Sync {
    /// Post `envelope` to `mailbox`. `pairing_secret` authorizes `pair_` mailboxes.
    async fn post(
        &self,
        mailbox: &MailboxId,
        envelope: &RelayEnvelope,
        pairing_secret: Option<&[u8; 16]>,
    ) -> Result<MessageId>;

    /// Fetch messages of `mailbox` after `after`, long-polling up to `wait_secs` (≤ 25).
    async fn fetch(
        &self,
        mailbox: &MailboxId,
        after: Option<&MessageId>,
        wait_secs: u64,
        pairing_secret: Option<&[u8; 16]>,
    ) -> Result<Vec<MailboxMessage>>;

    /// Delete a message (mailbox owner).
    async fn delete(
        &self,
        mailbox: &MailboxId,
        message_id: &MessageId,
        pairing_secret: Option<&[u8; 16]>,
    ) -> Result<()>;
}

/// Seal and sign a message for `to` (thin wrapper over `aipass_types::relay::seal_envelope`).
pub fn seal_message(
    sender: &dyn Ed25519Signer,
    from: MailboxId,
    to: MailboxId,
    recipient_kem_pk: &[u8; 32],
    message: &RelayMessage,
    now: Timestamp,
) -> Result<RelayEnvelope> {
    Ok(seal_envelope(
        sender,
        from,
        to,
        recipient_kem_pk,
        message,
        now,
    )?)
}

/// Verify the sender signature and open a message addressed to us.
pub fn open_message(
    recipient: &KemKeypair,
    sender_sign_pk: &[u8; 32],
    envelope: &RelayEnvelope,
) -> Result<RelayMessage> {
    Ok(open_envelope(recipient, sender_sign_pk, envelope)?)
}

#[derive(Default)]
struct Mailbox {
    secret: Option<[u8; 16]>,
    messages: Vec<MailboxMessage>,
}

/// In-memory relay with long-poll semantics (tests, in-process use). Enforces the pairing
/// secret on `pair_` mailboxes (first poster sets it) and the per-mailbox message cap.
#[derive(Default)]
pub struct MemoryRelay {
    boxes: Mutex<HashMap<String, Mailbox>>,
    notify: Notify,
}

impl MemoryRelay {
    /// New empty relay.
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of stored messages in `mailbox`.
    pub fn len(&self, mailbox: &MailboxId) -> usize {
        self.boxes
            .lock()
            .map(|b| b.get(mailbox.as_str()).map_or(0, |m| m.messages.len()))
            .unwrap_or(0)
    }

    fn check_secret(
        mb: &mut Mailbox,
        mailbox: &MailboxId,
        secret: Option<&[u8; 16]>,
        create: bool,
    ) -> Result<()> {
        if !mailbox.is_pairing() {
            return Ok(());
        }
        let Some(s) = secret else {
            return Err(VaultError::Relay("pairing secret required".into()));
        };
        match &mb.secret {
            Some(existing) if aipass_crypto::ct_eq(existing, s) => Ok(()),
            Some(_) => Err(VaultError::Relay("pairing secret mismatch".into())),
            None if create => {
                mb.secret = Some(*s);
                Ok(())
            }
            None => Ok(()),
        }
    }

    fn collect(
        &self,
        mailbox: &MailboxId,
        after: Option<&MessageId>,
        secret: Option<&[u8; 16]>,
    ) -> Result<Vec<MailboxMessage>> {
        let mut boxes = self
            .boxes
            .lock()
            .map_err(|_| VaultError::Internal("relay lock poisoned"))?;
        let mb = boxes.entry(mailbox.as_str().to_owned()).or_default();
        Self::check_secret(mb, mailbox, secret, false)?;
        let start = match after {
            Some(a) => mb
                .messages
                .iter()
                .position(|m| &m.message_id == a)
                .map_or(0, |i| i + 1),
            None => 0,
        };
        Ok(mb.messages[start..].to_vec())
    }
}

#[async_trait]
impl RelayTransport for MemoryRelay {
    async fn post(
        &self,
        mailbox: &MailboxId,
        envelope: &RelayEnvelope,
        pairing_secret: Option<&[u8; 16]>,
    ) -> Result<MessageId> {
        envelope.check_size()?;
        if &envelope.to != mailbox {
            return Err(VaultError::InvalidInput(
                "envelope recipient does not match the mailbox",
            ));
        }
        let id = MessageId::generate();
        {
            let mut boxes = self
                .boxes
                .lock()
                .map_err(|_| VaultError::Internal("relay lock poisoned"))?;
            let mb = boxes.entry(mailbox.as_str().to_owned()).or_default();
            Self::check_secret(mb, mailbox, pairing_secret, true)?;
            if mb.messages.len() >= MAX_MESSAGES_PER_MAILBOX {
                return Err(VaultError::Relay("mailbox full".into()));
            }
            mb.messages.push(MailboxMessage {
                message_id: id.clone(),
                received_at: aipass_types::time::now(),
                envelope: envelope.clone(),
            });
        }
        self.notify.notify_waiters();
        Ok(id)
    }

    async fn fetch(
        &self,
        mailbox: &MailboxId,
        after: Option<&MessageId>,
        wait_secs: u64,
        pairing_secret: Option<&[u8; 16]>,
    ) -> Result<Vec<MailboxMessage>> {
        let wait = Duration::from_secs(wait_secs.min(aipass_types::relay::MAX_WAIT_SECS));
        let deadline = tokio::time::Instant::now() + wait;
        loop {
            let notified = self.notify.notified();
            let got = self.collect(mailbox, after, pairing_secret)?;
            if !got.is_empty() || tokio::time::Instant::now() >= deadline {
                return Ok(got);
            }
            let _ = tokio::time::timeout_at(deadline, notified).await;
        }
    }

    async fn delete(
        &self,
        mailbox: &MailboxId,
        message_id: &MessageId,
        pairing_secret: Option<&[u8; 16]>,
    ) -> Result<()> {
        let mut boxes = self
            .boxes
            .lock()
            .map_err(|_| VaultError::Internal("relay lock poisoned"))?;
        if let Some(mb) = boxes.get_mut(mailbox.as_str()) {
            Self::check_secret(mb, mailbox, pairing_secret, false)?;
            mb.messages.retain(|m| &m.message_id != message_id);
        }
        Ok(())
    }
}

fn relay_client_error(e: aipass_storage::relay_client::RelayClientError) -> VaultError {
    use aipass_storage::relay_client::RelayClientError as E;
    match e {
        E::Api(api) => VaultError::Api(Box::new(api)),
        E::Network(_) => VaultError::Relay("relay unreachable".into()),
        E::Timeout => VaultError::Relay("relay request timed out".into()),
        E::Protocol(m) => VaultError::Relay(m),
    }
}

/// The HTTP relay client of `aipass-storage` as a [`RelayTransport`]. Its authentication is
/// fixed when it is built: `RelayClient::for_pairing(url, secret)` for one `pair_` mailbox
/// (pairing sessions), or `RelayAuth::Signed` with the device / executor key for its own
/// mailbox. The per-call `pairing_secret` argument is therefore ignored.
#[async_trait]
impl RelayTransport for aipass_storage::RelayClient {
    async fn post(
        &self,
        mailbox: &MailboxId,
        envelope: &RelayEnvelope,
        _pairing_secret: Option<&[u8; 16]>,
    ) -> Result<MessageId> {
        if &envelope.to != mailbox {
            return Err(VaultError::InvalidInput(
                "envelope recipient does not match the mailbox",
            ));
        }
        aipass_storage::RelayClient::post(self, envelope)
            .await
            .map_err(relay_client_error)
    }

    async fn fetch(
        &self,
        mailbox: &MailboxId,
        after: Option<&MessageId>,
        wait_secs: u64,
        _pairing_secret: Option<&[u8; 16]>,
    ) -> Result<Vec<MailboxMessage>> {
        aipass_storage::RelayClient::fetch(self, mailbox, after, wait_secs)
            .await
            .map_err(relay_client_error)
    }

    async fn delete(
        &self,
        mailbox: &MailboxId,
        message_id: &MessageId,
        _pairing_secret: Option<&[u8; 16]>,
    ) -> Result<()> {
        aipass_storage::RelayClient::delete(self, mailbox, message_id)
            .await
            .map_err(relay_client_error)
    }
}
