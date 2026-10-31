// SPDX-License-Identifier: Apache-2.0
//! Relay mailbox envelopes and inner messages (CONTRACTS §4).
//!
//! `RelayEnvelope {v:1, from, to, type, created_at, sealed, sig}`:
//! * `sealed` = HPKE to the recipient `kem_pk`, `info=aipass/v1/relay`,
//!   `aad = JCS({v, from, to, type, created_at})`;
//! * `sig` = Ed25519(sender, JCS(envelope minus sig)).
//!
//! The relay server only ever sees envelopes. Device control messages
//! (`connection.decision`, `grant.revoke`, `connection.control`) are additionally signed
//! over `aipass:v1:control:<b64u sha256 JCS(payload minus signature)>` ([`DeviceSigned`]).

use aipass_crypto::{Ed25519Signer, KemKeypair, SealedBox, b64u};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::SignatureError;
use crate::canonical::{CanonicalError, jcs_without_field, to_jcs_bytes};
use crate::ids::{ApprovalRequestId, ConnectionId, GrantId, MailboxId, MessageId};
use crate::models::{
    ActivitySummary, AllowedProjects, AppConnection, ApprovalDecision, ApprovalRequest, Decision,
    ExecutorInfo, Grant, Operation, RevocationLevel, RevocationReport,
};
use crate::pairing::{PairingHello, PairingJoin, PairingWelcome};
use crate::time::{Timestamp, rfc3339};

/// Envelope version.
pub const RELAY_VERSION: u32 = 1;
/// Maximum envelope size (64 KiB).
pub const MAX_ENVELOPE_BYTES: usize = 64 * 1024;
/// Mailbox message TTL (24 h).
pub const MESSAGE_TTL_SECS: i64 = 24 * 3600;
/// Pairing mailbox TTL (10 min).
pub const PAIRING_MAILBOX_TTL_SECS: i64 = 600;
/// Maximum messages per mailbox.
pub const MAX_MESSAGES_PER_MAILBOX: usize = 500;
/// Maximum long-poll wait.
pub const MAX_WAIT_SECS: u64 = 25;

/// Relay failure.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum RelayError {
    /// Canonicalization failed.
    #[error(transparent)]
    Canonical(#[from] CanonicalError),
    /// HPKE seal/open failed.
    #[error("relay envelope could not be sealed or opened")]
    Crypto,
    /// Envelope signature invalid.
    #[error("relay envelope signature invalid")]
    Signature,
    /// Payload does not match the declared type.
    #[error("relay payload invalid for its type")]
    Payload,
    /// Envelope larger than 64 KiB.
    #[error("relay envelope too large")]
    TooLarge,
    /// Unsupported version.
    #[error("unsupported relay envelope version")]
    Version,
}

/// Inner message types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RelayMessageType {
    /// broker → device: [`ApprovalRequest`].
    #[serde(rename = "approval.request")]
    ApprovalRequest,
    /// device → broker: [`ApprovalDecision`].
    #[serde(rename = "approval.decision")]
    ApprovalDecision,
    /// broker → device: [`ApprovalCancelled`].
    #[serde(rename = "approval.cancelled")]
    ApprovalCancelled,
    /// broker → device: [`ConnectionPairRequest`].
    #[serde(rename = "connection.pair_request")]
    ConnectionPairRequest,
    /// device → broker: [`ConnectionDecision`].
    #[serde(rename = "connection.decision")]
    ConnectionDecision,
    /// device → broker: [`GrantRevoke`].
    #[serde(rename = "grant.revoke")]
    GrantRevoke,
    /// device → broker: [`ConnectionControl`].
    #[serde(rename = "connection.control")]
    ConnectionControl,
    /// device → broker: [`StateRequest`].
    #[serde(rename = "state.request")]
    StateRequest,
    /// broker → device: [`StateSnapshot`].
    #[serde(rename = "state.snapshot")]
    StateSnapshot,
    /// broker → device: [`RevocationReport`].
    #[serde(rename = "revoke.report")]
    RevokeReport,
    /// pairing step 3.
    #[serde(rename = "pairing.hello")]
    PairingHello,
    /// pairing step 4.
    #[serde(rename = "pairing.join")]
    PairingJoin,
    /// pairing step 6.
    #[serde(rename = "pairing.welcome")]
    PairingWelcome,
}

impl RelayMessageType {
    /// Wire string.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ApprovalRequest => "approval.request",
            Self::ApprovalDecision => "approval.decision",
            Self::ApprovalCancelled => "approval.cancelled",
            Self::ConnectionPairRequest => "connection.pair_request",
            Self::ConnectionDecision => "connection.decision",
            Self::GrantRevoke => "grant.revoke",
            Self::ConnectionControl => "connection.control",
            Self::StateRequest => "state.request",
            Self::StateSnapshot => "state.snapshot",
            Self::RevokeReport => "revoke.report",
            Self::PairingHello => "pairing.hello",
            Self::PairingJoin => "pairing.join",
            Self::PairingWelcome => "pairing.welcome",
        }
    }

    /// Types that trigger a push hint to a `dev_` mailbox (only `{mailbox, message_id}`).
    pub fn triggers_push(&self) -> bool {
        matches!(self, Self::ApprovalRequest | Self::ConnectionPairRequest)
    }
}

/// `approval.cancelled`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalCancelled {
    /// Request.
    pub approval_request_id: ApprovalRequestId,
    /// Reason (non-sensitive).
    pub reason: String,
}

/// `connection.pair_request`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectionPairRequest {
    /// The pending connection.
    pub connection: AppConnection,
    /// Code shown by the AI host side.
    pub pairing_code: String,
}

/// `connection.decision` (device-signed).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectionDecision {
    /// Connection.
    pub connection_id: ConnectionId,
    /// Decision.
    pub decision: Decision,
    /// Allowed projects.
    pub allowed_projects: AllowedProjects,
    /// Signing time.
    #[serde(with = "rfc3339")]
    pub signed_at: Timestamp,
    /// b64u control signature.
    pub signature: String,
}

/// `grant.revoke` (device-signed).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantRevoke {
    /// Grant.
    pub grant_id: GrantId,
    /// Level.
    pub level: RevocationLevel,
    /// Signing time.
    #[serde(with = "rfc3339")]
    pub signed_at: Timestamp,
    /// b64u control signature.
    pub signature: String,
}

/// Connection control action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlAction {
    /// Pause.
    Pause,
    /// Resume.
    Resume,
    /// Remove.
    Remove,
    /// Revoke all grants of the connection.
    RevokeAll,
}

/// `connection.control` (device-signed).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectionControl {
    /// Connection.
    pub connection_id: ConnectionId,
    /// Action.
    pub action: ControlAction,
    /// Signing time.
    #[serde(with = "rfc3339")]
    pub signed_at: Timestamp,
    /// b64u control signature.
    pub signature: String,
}

/// `state.request` (empty body).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct StateRequest {}

/// `state.snapshot`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StateSnapshot {
    /// Connections.
    pub connections: Vec<AppConnection>,
    /// Grants.
    pub grants: Vec<Grant>,
    /// Executors.
    pub executors: Vec<ExecutorInfo>,
    /// Pending approvals.
    pub pending_approvals: Vec<ApprovalRequest>,
    /// Recent operations (metadata; results filtered).
    pub recent_operations: Vec<Operation>,
    /// Activity summary.
    pub activity_summary: ActivitySummary,
}

/// `aipass:v1:control:<b64u sha256 JCS(payload minus signature)>`.
pub fn control_signing_message<T: Serialize + ?Sized>(
    payload: &T,
) -> Result<String, CanonicalError> {
    let bytes = jcs_without_field(payload, "signature")?;
    Ok(format!(
        "aipass:v1:control:{}",
        aipass_crypto::sha256_b64u(bytes)
    ))
}

/// Device control messages signed with [`control_signing_message`].
pub trait DeviceSigned: Serialize {
    /// The signature field.
    fn signature_field(&mut self) -> &mut String;
    /// Read the signature.
    fn signature_value(&self) -> &str;

    /// Sign in place.
    fn sign_control(&mut self, signer: &dyn Ed25519Signer) -> Result<(), CanonicalError>
    where
        Self: Sized,
    {
        let msg = control_signing_message(self)?;
        *self.signature_field() = b64u::encode(signer.sign(msg.as_bytes()));
        Ok(())
    }

    /// Verify against the signing device's key.
    fn verify_control(&self, sign_pk: &[u8; 32]) -> Result<(), SignatureError> {
        let msg = control_signing_message(self)?;
        let sig = b64u::decode_array::<64>(self.signature_value())
            .map_err(|_| SignatureError::Malformed)?;
        aipass_crypto::identity::verify(sign_pk, msg.as_bytes(), &sig)
            .map_err(|_| SignatureError::Invalid)
    }
}

macro_rules! device_signed {
    ($t:ty) => {
        impl DeviceSigned for $t {
            fn signature_field(&mut self) -> &mut String {
                &mut self.signature
            }
            fn signature_value(&self) -> &str {
                &self.signature
            }
        }
    };
}
device_signed!(ConnectionDecision);
device_signed!(GrantRevoke);
device_signed!(ConnectionControl);

/// A decoded inner message.
#[derive(Debug, Clone, PartialEq)]
pub enum RelayMessage {
    /// `approval.request`.
    ApprovalRequest(Box<ApprovalRequest>),
    /// `approval.decision`.
    ApprovalDecision(Box<ApprovalDecision>),
    /// `approval.cancelled`.
    ApprovalCancelled(ApprovalCancelled),
    /// `connection.pair_request`.
    ConnectionPairRequest(Box<ConnectionPairRequest>),
    /// `connection.decision`.
    ConnectionDecision(ConnectionDecision),
    /// `grant.revoke`.
    GrantRevoke(GrantRevoke),
    /// `connection.control`.
    ConnectionControl(ConnectionControl),
    /// `state.request`.
    StateRequest(StateRequest),
    /// `state.snapshot`.
    StateSnapshot(Box<StateSnapshot>),
    /// `revoke.report`.
    RevokeReport(RevocationReport),
    /// `pairing.hello`.
    PairingHello(Box<PairingHello>),
    /// `pairing.join`.
    PairingJoin(PairingJoin),
    /// `pairing.welcome`.
    PairingWelcome(PairingWelcome),
}

impl RelayMessage {
    /// The message type.
    pub fn message_type(&self) -> RelayMessageType {
        match self {
            Self::ApprovalRequest(_) => RelayMessageType::ApprovalRequest,
            Self::ApprovalDecision(_) => RelayMessageType::ApprovalDecision,
            Self::ApprovalCancelled(_) => RelayMessageType::ApprovalCancelled,
            Self::ConnectionPairRequest(_) => RelayMessageType::ConnectionPairRequest,
            Self::ConnectionDecision(_) => RelayMessageType::ConnectionDecision,
            Self::GrantRevoke(_) => RelayMessageType::GrantRevoke,
            Self::ConnectionControl(_) => RelayMessageType::ConnectionControl,
            Self::StateRequest(_) => RelayMessageType::StateRequest,
            Self::StateSnapshot(_) => RelayMessageType::StateSnapshot,
            Self::RevokeReport(_) => RelayMessageType::RevokeReport,
            Self::PairingHello(_) => RelayMessageType::PairingHello,
            Self::PairingJoin(_) => RelayMessageType::PairingJoin,
            Self::PairingWelcome(_) => RelayMessageType::PairingWelcome,
        }
    }

    /// Plaintext payload bytes (JSON of the inner struct).
    pub fn to_payload(&self) -> Result<Vec<u8>, RelayError> {
        let r = match self {
            Self::ApprovalRequest(m) => serde_json::to_vec(m),
            Self::ApprovalDecision(m) => serde_json::to_vec(m),
            Self::ApprovalCancelled(m) => serde_json::to_vec(m),
            Self::ConnectionPairRequest(m) => serde_json::to_vec(m),
            Self::ConnectionDecision(m) => serde_json::to_vec(m),
            Self::GrantRevoke(m) => serde_json::to_vec(m),
            Self::ConnectionControl(m) => serde_json::to_vec(m),
            Self::StateRequest(m) => serde_json::to_vec(m),
            Self::StateSnapshot(m) => serde_json::to_vec(m),
            Self::RevokeReport(m) => serde_json::to_vec(m),
            Self::PairingHello(m) => serde_json::to_vec(m),
            Self::PairingJoin(m) => serde_json::to_vec(m),
            Self::PairingWelcome(m) => serde_json::to_vec(m),
        };
        r.map_err(|_| RelayError::Payload)
    }

    /// Decode a payload of the given type.
    pub fn from_payload(t: RelayMessageType, bytes: &[u8]) -> Result<Self, RelayError> {
        use RelayMessageType as T;
        let p = |e: serde_json::Error| {
            let _ = e;
            RelayError::Payload
        };
        Ok(match t {
            T::ApprovalRequest => {
                Self::ApprovalRequest(Box::new(serde_json::from_slice(bytes).map_err(p)?))
            }
            T::ApprovalDecision => {
                Self::ApprovalDecision(Box::new(serde_json::from_slice(bytes).map_err(p)?))
            }
            T::ApprovalCancelled => {
                Self::ApprovalCancelled(serde_json::from_slice(bytes).map_err(p)?)
            }
            T::ConnectionPairRequest => {
                Self::ConnectionPairRequest(Box::new(serde_json::from_slice(bytes).map_err(p)?))
            }
            T::ConnectionDecision => {
                Self::ConnectionDecision(serde_json::from_slice(bytes).map_err(p)?)
            }
            T::GrantRevoke => Self::GrantRevoke(serde_json::from_slice(bytes).map_err(p)?),
            T::ConnectionControl => {
                Self::ConnectionControl(serde_json::from_slice(bytes).map_err(p)?)
            }
            T::StateRequest => Self::StateRequest(serde_json::from_slice(bytes).map_err(p)?),
            T::StateSnapshot => {
                Self::StateSnapshot(Box::new(serde_json::from_slice(bytes).map_err(p)?))
            }
            T::RevokeReport => Self::RevokeReport(serde_json::from_slice(bytes).map_err(p)?),
            T::PairingHello => {
                Self::PairingHello(Box::new(serde_json::from_slice(bytes).map_err(p)?))
            }
            T::PairingJoin => Self::PairingJoin(serde_json::from_slice(bytes).map_err(p)?),
            T::PairingWelcome => Self::PairingWelcome(serde_json::from_slice(bytes).map_err(p)?),
        })
    }
}

/// The relay envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayEnvelope {
    /// Always 1.
    pub v: u32,
    /// Sender mailbox / principal.
    pub from: MailboxId,
    /// Recipient mailbox.
    pub to: MailboxId,
    /// Inner message type.
    #[serde(rename = "type")]
    pub message_type: RelayMessageType,
    /// Creation time.
    #[serde(with = "rfc3339")]
    pub created_at: Timestamp,
    /// HPKE-sealed payload.
    pub sealed: SealedBox,
    /// b64u Ed25519 over `JCS(envelope minus sig)`.
    pub sig: String,
}

#[derive(Serialize)]
struct HeaderAad<'a> {
    v: u32,
    from: &'a MailboxId,
    to: &'a MailboxId,
    #[serde(rename = "type")]
    message_type: RelayMessageType,
    #[serde(with = "rfc3339")]
    created_at: Timestamp,
}

impl RelayEnvelope {
    /// `JCS({v, from, to, type, created_at})` — the HPKE AAD.
    pub fn header_aad(&self) -> Result<Vec<u8>, CanonicalError> {
        header_aad(
            self.v,
            &self.from,
            &self.to,
            self.message_type,
            self.created_at,
        )
    }

    /// `JCS(envelope minus sig)`.
    pub fn signing_bytes(&self) -> Result<Vec<u8>, CanonicalError> {
        jcs_without_field(self, "sig")
    }

    /// Verify the sender signature.
    pub fn verify(&self, sender_sign_pk: &[u8; 32]) -> Result<(), RelayError> {
        if self.v != RELAY_VERSION {
            return Err(RelayError::Version);
        }
        let bytes = self.signing_bytes()?;
        let sig = b64u::decode_array::<64>(&self.sig).map_err(|_| RelayError::Signature)?;
        aipass_crypto::identity::verify(sender_sign_pk, &bytes, &sig)
            .map_err(|_| RelayError::Signature)
    }

    /// Serialized size check (≤ 64 KiB).
    pub fn check_size(&self) -> Result<(), RelayError> {
        let n = serde_json::to_vec(self)
            .map_err(|_| RelayError::Payload)?
            .len();
        if n > MAX_ENVELOPE_BYTES {
            Err(RelayError::TooLarge)
        } else {
            Ok(())
        }
    }
}

fn header_aad(
    v: u32,
    from: &MailboxId,
    to: &MailboxId,
    message_type: RelayMessageType,
    created_at: Timestamp,
) -> Result<Vec<u8>, CanonicalError> {
    to_jcs_bytes(&HeaderAad {
        v,
        from,
        to,
        message_type,
        created_at,
    })
}

/// Seal and sign a message for `to`, whose X25519 KEM key is `recipient_kem_pk`.
pub fn seal_envelope(
    sender: &dyn Ed25519Signer,
    from: MailboxId,
    to: MailboxId,
    recipient_kem_pk: &[u8; 32],
    message: &RelayMessage,
    created_at: Timestamp,
) -> Result<RelayEnvelope, RelayError> {
    let created_at = crate::time::truncate(created_at);
    let t = message.message_type();
    let aad = header_aad(RELAY_VERSION, &from, &to, t, created_at)?;
    let payload = zeroize::Zeroizing::new(message.to_payload()?);
    let sealed =
        aipass_crypto::hpke::seal(recipient_kem_pk, aipass_crypto::info::RELAY, &aad, &payload)
            .map_err(|_| RelayError::Crypto)?;
    let mut env = RelayEnvelope {
        v: RELAY_VERSION,
        from,
        to,
        message_type: t,
        created_at,
        sealed,
        sig: String::new(),
    };
    let bytes = env.signing_bytes()?;
    env.sig = b64u::encode(sender.sign(&bytes));
    env.check_size()?;
    Ok(env)
}

/// Verify the sender signature, then open. Use when the sender key is known in advance.
pub fn open_envelope(
    recipient: &KemKeypair,
    sender_sign_pk: &[u8; 32],
    env: &RelayEnvelope,
) -> Result<RelayMessage, RelayError> {
    env.verify(sender_sign_pk)?;
    open_envelope_unverified(recipient, env)
}

/// Open **without** verifying `sig` — only for `pairing.join`, where the sender key arrives
/// inside the payload. The caller must call [`RelayEnvelope::verify`] with that key before
/// trusting anything in the message.
pub fn open_envelope_unverified(
    recipient: &KemKeypair,
    env: &RelayEnvelope,
) -> Result<RelayMessage, RelayError> {
    if env.v != RELAY_VERSION {
        return Err(RelayError::Version);
    }
    let aad = env.header_aad()?;
    let pt = aipass_crypto::hpke::open(recipient, aipass_crypto::info::RELAY, &aad, &env.sealed)
        .map_err(|_| RelayError::Crypto)?;
    RelayMessage::from_payload(env.message_type, pt.expose())
}

/// A stored mailbox message as returned by `GET /v1/relay/{mailbox}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MailboxMessage {
    /// Message.
    pub message_id: MessageId,
    /// Received by the relay.
    #[serde(with = "rfc3339")]
    pub received_at: Timestamp,
    /// Envelope.
    pub envelope: RelayEnvelope,
}

/// `GET /v1/relay/{mailbox}` response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MailboxResponse {
    /// Messages after the cursor.
    pub messages: Vec<MailboxMessage>,
}

/// `POST /v1/relay/{mailbox}` response (202).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PostMessageResponse {
    /// Assigned id.
    pub message_id: MessageId,
}

/// The only data a `PushNotifier` ever receives (§9.2, §11.4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushHint {
    /// Mailbox.
    pub mailbox: MailboxId,
    /// Message.
    pub message_id: MessageId,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::{DeviceId, ExecutorId};
    use aipass_crypto::DeviceIdentity;

    #[test]
    fn seal_open_verify() {
        let sender = DeviceIdentity::generate();
        let recipient = DeviceIdentity::generate();
        let from = MailboxId::Device(DeviceId::generate());
        let to = MailboxId::Executor(ExecutorId::generate());
        let mut ctl = GrantRevoke {
            grant_id: GrantId::generate(),
            level: RevocationLevel::EndSessions,
            signed_at: crate::time::now(),
            signature: String::new(),
        };
        ctl.sign_control(&sender).unwrap();
        ctl.verify_control(&sender.public().sign_pk).unwrap();
        let msg = RelayMessage::GrantRevoke(ctl.clone());
        let env = seal_envelope(
            &sender,
            from.clone(),
            to.clone(),
            &recipient.public().kem_pk,
            &msg,
            crate::time::now(),
        )
        .unwrap();
        let json = serde_json::to_value(&env).unwrap();
        assert_eq!(json["type"], "grant.revoke");
        assert_eq!(json["v"], 1);
        let back: RelayEnvelope = serde_json::from_value(json).unwrap();
        let opened =
            open_envelope(recipient.kem_keypair(), &sender.public().sign_pk, &back).unwrap();
        assert_eq!(opened, msg);

        // header tamper → signature fails; with signature bypassed → AAD fails
        let mut t = back.clone();
        t.to = MailboxId::Device(DeviceId::generate());
        assert_eq!(
            open_envelope(recipient.kem_keypair(), &sender.public().sign_pk, &t),
            Err(RelayError::Signature)
        );
        assert_eq!(
            open_envelope_unverified(recipient.kem_keypair(), &t),
            Err(RelayError::Crypto)
        );
        // wrong type relabel
        let mut t2 = back.clone();
        t2.message_type = RelayMessageType::ConnectionControl;
        assert!(open_envelope_unverified(recipient.kem_keypair(), &t2).is_err());
        // wrong recipient
        assert_eq!(
            open_envelope_unverified(DeviceIdentity::generate().kem_keypair(), &back),
            Err(RelayError::Crypto)
        );
        // control signature tamper
        let mut c2 = ctl.clone();
        c2.level = RevocationLevel::RevokeUpstream;
        assert!(c2.verify_control(&sender.public().sign_pk).is_err());
    }

    #[test]
    fn type_strings() {
        assert_eq!(
            serde_json::to_value(RelayMessageType::ConnectionPairRequest).unwrap(),
            "connection.pair_request"
        );
        assert!(RelayMessageType::ApprovalRequest.triggers_push());
        assert!(!RelayMessageType::ApprovalDecision.triggers_push());
        let all = [
            RelayMessageType::ApprovalRequest,
            RelayMessageType::ApprovalDecision,
            RelayMessageType::ApprovalCancelled,
            RelayMessageType::ConnectionPairRequest,
            RelayMessageType::ConnectionDecision,
            RelayMessageType::GrantRevoke,
            RelayMessageType::ConnectionControl,
            RelayMessageType::StateRequest,
            RelayMessageType::StateSnapshot,
            RelayMessageType::RevokeReport,
            RelayMessageType::PairingHello,
            RelayMessageType::PairingJoin,
            RelayMessageType::PairingWelcome,
        ];
        for t in all {
            assert_eq!(serde_json::to_value(t).unwrap(), t.as_str());
        }
    }
}
