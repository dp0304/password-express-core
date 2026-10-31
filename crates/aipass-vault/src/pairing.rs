// SPDX-License-Identifier: Apache-2.0
//! Device / executor pairing protocol (CONTRACTS §5, design doc §9.5) — state machines for
//! both roles over a [`RelayTransport`].
//!
//! 1. The **new** device N creates its identity and an ephemeral X25519 key `eN`, and shows
//!    the QR `aipass://pair?…` (TTL 10 minutes) — see [`NewDeviceSession::start`].
//! 2. The **trusted** device O scans it ([`TrustedSession::scan`]), creates `eO` and derives
//!    `shared = X25519(eO, eN)`, `th = SHA-256(JCS({pairing_id, eN, eO, relay}))`,
//!    `K = HKDF(shared, salt = th, info = "aipass/v1/pairing-key")` and
//!    `SAS = u32_be(HKDF(shared, salt = th, info = "aipass/v1/pairing-sas")[0..4]) mod 10^6`.
//! 3. O → mailbox `pairing.hello {eO, o_device, sealed: XChaCha20(K, {vault_id, o_name})}`
//!    (relay envelope HPKE-sealed to `eN`, signed by O).
//! 4. N → mailbox `pairing.join {sealed: XChaCha20(K, {device})}` (HPKE-sealed to O's KEM key,
//!    signed by N's long-term key — O verifies it with the key inside the sealed payload).
//! 5. Both show the SAS and the peer name; the user confirms **on O**. Scanning alone never
//!    grants access.
//! 6. O writes N's member record + manifest (done by the sync layer), then sends
//!    `pairing.welcome {sealed: XChaCha20(K, {vault_id, member_rev, checkpoint,
//!    storage_profile, storage_secret?, relay_base_url, trusted_devices})}`.
//! 7. N verifies `vault.json`, the member chain and the checkpoint, then syncs.
//!
//! AADs of the K-sealed boxes (not fixed by the contract; defined here):
//! `aipass:v1:pairing:hello:{pairing_id}:{b64u(SHA-256(JCS(o_device)))}`,
//! `aipass:v1:pairing:join:{pairing_id}`,
//! `aipass:v1:pairing:welcome:{pairing_id}:{n_device_id}`.

use core::fmt;
use std::time::Duration;

use aipass_crypto::{AeadBox, DeviceIdentity, KemKeypair, Key32, b64u, info, kdf};
use aipass_types::canonical::to_jcs_bytes;
use aipass_types::ids::{MailboxId, MessageId, PairingId, VaultId};
use aipass_types::pairing::{
    PAIRING_SECRET_LEN, PAIRING_TTL_SECS, PairingHello, PairingHelloInner, PairingJoin,
    PairingJoinInner, PairingOffer, PairingRole, PairingWelcome, PairingWelcomeInner,
    transcript_hash,
};
use aipass_types::relay::{
    RelayEnvelope, RelayMessage, RelayMessageType, open_envelope_unverified,
};
use aipass_types::vault::{DevicePublic, MemberRole};
use zeroize::Zeroizing;

use crate::error::{Result, VaultError};
use crate::member::{member_executor_id, validate_device_name};
use crate::relay::{RelayTransport, open_message, seal_message};

/// Channel key `K` and short authentication string derived from the pairing exchange.
pub struct PairingSecrets {
    k: Key32,
    sas: String,
}

impl fmt::Debug for PairingSecrets {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PairingSecrets")
            .field("sas", &self.sas)
            .finish_non_exhaustive()
    }
}

impl PairingSecrets {
    /// The 6-digit SAS (zero-padded).
    pub fn sas(&self) -> &str {
        &self.sas
    }
}

/// `K = HKDF(shared, salt = th, info = pairing-key)`, `SAS = u32_be(HKDF(shared, salt = th,
/// info = pairing-sas)[0..4]) mod 1_000_000`, zero-padded to 6 digits.
pub fn derive_pairing_secrets(shared: &Key32, th: &[u8; 32]) -> Result<PairingSecrets> {
    let k = kdf::hkdf_sha256(th, shared.expose(), info::PAIRING_KEY, 32)?
        .to_key32()
        .ok_or(VaultError::Internal("pairing key length"))?;
    let s = kdf::hkdf_sha256(th, shared.expose(), info::PAIRING_SAS, 4)?;
    let b = s.expose();
    let n = u32::from_be_bytes([b[0], b[1], b[2], b[3]]) % 1_000_000;
    Ok(PairingSecrets {
        k,
        sas: format!("{n:06}"),
    })
}

/// AAD of the `pairing.hello` box.
pub fn hello_aad(pairing_id: &PairingId, o_device: &DevicePublic) -> Result<String> {
    let h = aipass_crypto::sha256_b64u(to_jcs_bytes(o_device)?);
    Ok(format!("aipass:v1:pairing:hello:{pairing_id}:{h}"))
}

/// AAD of the `pairing.join` box.
pub fn join_aad(pairing_id: &PairingId) -> String {
    format!("aipass:v1:pairing:join:{pairing_id}")
}

/// AAD of the `pairing.welcome` box.
pub fn welcome_aad(pairing_id: &PairingId, n_device: &aipass_types::ids::DeviceId) -> String {
    format!("aipass:v1:pairing:welcome:{pairing_id}:{n_device}")
}

fn mailbox_for(device: &DevicePublic) -> MailboxId {
    match device.role {
        MemberRole::Executor => MailboxId::Executor(member_executor_id(&device.device_id)),
        _ => MailboxId::Device(device.device_id.clone()),
    }
}

fn now_unix() -> i64 {
    aipass_types::time::unix_now()
}

fn expired_err() -> VaultError {
    VaultError::Expired("pairing code expired")
}

/// What the new device learns from `pairing.hello`.
#[derive(Debug, Clone)]
pub struct HelloInfo {
    /// SAS to show.
    pub sas: String,
    /// The trusted device.
    pub peer: DevicePublic,
    /// Name the trusted device announced (`o_name`).
    pub peer_name: String,
    /// Vault being joined.
    pub vault_id: VaultId,
}

/// Pairing session on the **new** device (N).
pub struct NewDeviceSession {
    offer: PairingOffer,
    ephemeral: KemKeypair,
    identity: DeviceIdentity,
    device: DevicePublic,
    mailbox: MailboxId,
    from: MailboxId,
    cursor: Option<MessageId>,
    hello: Option<(HelloInfo, PairingSecrets)>,
    cancelled: bool,
}

impl fmt::Debug for NewDeviceSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NewDeviceSession")
            .field("pairing_id", &self.offer.pairing_id)
            .field("device", &self.device.device_id)
            .field("has_hello", &self.hello.is_some())
            .finish_non_exhaustive()
    }
}

impl NewDeviceSession {
    /// Create the offer. `device` is N's public description (role `member` or `executor`
    /// matching `role`), `identity` its long-term key.
    pub fn start(
        device: DevicePublic,
        identity: DeviceIdentity,
        role: PairingRole,
        relay_base_url: &str,
    ) -> Result<Self> {
        validate_device_name(&device.name)?;
        let expected = match role {
            PairingRole::Member => MemberRole::Member,
            PairingRole::Executor => MemberRole::Executor,
        };
        if device.role != expected {
            return Err(VaultError::InvalidInput(
                "device role does not match the pairing role",
            ));
        }
        if identity.public().sign_pk != device.sign_pk || identity.public().kem_pk != device.kem_pk
        {
            return Err(VaultError::InvalidInput(
                "device keys do not match the identity",
            ));
        }
        let ephemeral = KemKeypair::generate();
        let secret = aipass_crypto::rng::try_random_array::<PAIRING_SECRET_LEN>()?;
        let offer = PairingOffer {
            pairing_id: PairingId::generate(),
            secret,
            ephemeral_pk: ephemeral.public_key(),
            relay: relay_base_url.to_owned(),
            name: device.name.clone(),
            role,
            expires_at: now_unix() + PAIRING_TTL_SECS,
        };
        // validates the relay URL and name exactly like the scanning side will
        PairingOffer::parse(&offer.to_uri()).map_err(|_| {
            VaultError::InvalidInput("relay URL or device name not allowed in a pairing link")
        })?;
        let mailbox = MailboxId::Pairing(offer.pairing_id.clone());
        let from = mailbox_for(&device);
        Ok(Self {
            offer,
            ephemeral,
            identity,
            device,
            mailbox,
            from,
            cursor: None,
            hello: None,
            cancelled: false,
        })
    }

    /// The offer.
    pub fn offer(&self) -> &PairingOffer {
        &self.offer
    }

    /// QR / link payload (`aipass://pair?…`).
    pub fn qr_payload(&self) -> String {
        self.offer.to_uri()
    }

    /// This device's public description.
    pub fn device(&self) -> &DevicePublic {
        &self.device
    }

    /// This device's identity.
    pub fn identity(&self) -> &DeviceIdentity {
        &self.identity
    }

    /// SAS (after the hello arrived).
    pub fn sas(&self) -> Option<&str> {
        self.hello.as_ref().map(|(h, _)| h.sas.as_str())
    }

    /// Peer information (after the hello arrived).
    pub fn hello(&self) -> Option<&HelloInfo> {
        self.hello.as_ref().map(|(h, _)| h)
    }

    /// Stop the session; later calls fail.
    pub fn cancel(&mut self) {
        self.cancelled = true;
    }

    fn try_hello(&self, env: &RelayEnvelope) -> Result<(HelloInfo, PairingSecrets)> {
        let msg = open_envelope_unverified(&self.ephemeral, env)?;
        let RelayMessage::PairingHello(h) = msg else {
            return Err(VaultError::Integrity("unexpected pairing message"));
        };
        env.verify(&h.o_device.sign_pk)?;
        if !h.o_device.role.is_trusted_approver() {
            return Err(VaultError::Integrity(
                "pairing peer is not a trusted device",
            ));
        }
        let shared = self.ephemeral.diffie_hellman(&h.e_o)?;
        let th = transcript_hash(
            &self.offer.pairing_id,
            &self.offer.ephemeral_pk,
            &h.e_o,
            &self.offer.relay,
        )?;
        let secrets = derive_pairing_secrets(&shared, &th)?;
        let aad = hello_aad(&self.offer.pairing_id, &h.o_device)?;
        let pt = h
            .sealed
            .open(&secrets.k, aad.as_bytes())
            .map_err(|_| VaultError::Integrity("pairing hello could not be opened"))?;
        let inner: PairingHelloInner = serde_json::from_slice(pt.expose())
            .map_err(|_| VaultError::Integrity("pairing hello payload invalid"))?;
        Ok((
            HelloInfo {
                sas: secrets.sas.clone(),
                peer: h.o_device.clone(),
                peer_name: inner.o_name,
                vault_id: inner.vault_id,
            },
            secrets,
        ))
    }

    /// Wait for `pairing.hello`, derive the SAS and answer with `pairing.join`.
    /// Invalid or foreign messages are ignored; stops at QR expiry or `max_wait`.
    pub async fn wait_for_hello(
        &mut self,
        relay: &dyn RelayTransport,
        max_wait: Duration,
    ) -> Result<HelloInfo> {
        if let Some((h, _)) = &self.hello {
            return Ok(h.clone());
        }
        let deadline = tokio::time::Instant::now() + max_wait;
        loop {
            if self.cancelled {
                return Err(VaultError::Cancelled("pairing cancelled"));
            }
            if self.offer.is_expired(now_unix()) {
                return Err(expired_err());
            }
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Err(VaultError::Expired(
                    "timed out waiting for the trusted device",
                ));
            }
            let msgs = relay
                .fetch(
                    &self.mailbox,
                    self.cursor.as_ref(),
                    remaining.as_secs().clamp(1, 25),
                    Some(&self.offer.secret),
                )
                .await?;
            for m in msgs {
                self.cursor = Some(m.message_id.clone());
                if m.envelope.from == self.from
                    || m.envelope.message_type != RelayMessageType::PairingHello
                {
                    continue;
                }
                match self.try_hello(&m.envelope) {
                    Ok((info, secrets)) => {
                        self.send_join(relay, &info, &secrets).await?;
                        self.hello = Some((info.clone(), secrets));
                        return Ok(info);
                    }
                    Err(e) => tracing::debug!(error = %e, "ignoring invalid pairing.hello"),
                }
            }
        }
    }

    async fn send_join(
        &self,
        relay: &dyn RelayTransport,
        info: &HelloInfo,
        secrets: &PairingSecrets,
    ) -> Result<()> {
        let inner = Zeroizing::new(to_jcs_bytes(&PairingJoinInner {
            device: self.device.clone(),
        })?);
        let sealed = AeadBox::seal(
            &secrets.k,
            join_aad(&self.offer.pairing_id).as_bytes(),
            &inner,
        )?;
        let env = seal_message(
            &self.identity,
            self.from.clone(),
            self.mailbox.clone(),
            &info.peer.kem_pk,
            &RelayMessage::PairingJoin(PairingJoin { sealed }),
            aipass_types::time::now(),
        )?;
        relay
            .post(&self.mailbox, &env, Some(&self.offer.secret))
            .await?;
        Ok(())
    }

    /// Wait for `pairing.welcome` (sent after the user confirmed on the trusted device).
    pub async fn wait_for_welcome(
        &mut self,
        relay: &dyn RelayTransport,
        max_wait: Duration,
    ) -> Result<PairingWelcomeInner> {
        let Some((info, secrets)) = &self.hello else {
            return Err(VaultError::PreconditionFailed(
                "no pairing.hello received yet",
            ));
        };
        let (peer, vault_id) = (info.peer.clone(), info.vault_id.clone());
        let aad = welcome_aad(&self.offer.pairing_id, &self.device.device_id);
        let deadline = tokio::time::Instant::now() + max_wait;
        loop {
            if self.cancelled {
                return Err(VaultError::Cancelled("pairing cancelled"));
            }
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Err(VaultError::Expired(
                    "timed out waiting for confirmation on the trusted device",
                ));
            }
            let msgs = relay
                .fetch(
                    &self.mailbox,
                    self.cursor.as_ref(),
                    remaining.as_secs().clamp(1, 25),
                    Some(&self.offer.secret),
                )
                .await?;
            for m in msgs {
                self.cursor = Some(m.message_id.clone());
                if m.envelope.from == self.from
                    || m.envelope.message_type != RelayMessageType::PairingWelcome
                {
                    continue;
                }
                let opened = open_message(self.identity.kem_keypair(), &peer.sign_pk, &m.envelope);
                let Ok(RelayMessage::PairingWelcome(w)) = opened else {
                    tracing::debug!("ignoring invalid pairing.welcome");
                    continue;
                };
                let Ok(pt) = w.sealed.open(&secrets.k, aad.as_bytes()) else {
                    tracing::debug!("ignoring pairing.welcome that does not open");
                    continue;
                };
                let inner: PairingWelcomeInner = serde_json::from_slice(pt.expose())
                    .map_err(|_| VaultError::Integrity("pairing welcome payload invalid"))?;
                if inner.vault_id != vault_id || inner.checkpoint.vault_id != vault_id {
                    return Err(VaultError::Integrity(
                        "pairing welcome is for another vault",
                    ));
                }
                return Ok(inner);
            }
        }
    }
}

/// Pairing session on the **trusted** device (O).
pub struct TrustedSession {
    offer: PairingOffer,
    secrets: PairingSecrets,
    identity: DeviceIdentity,
    o_device: DevicePublic,
    vault_id: VaultId,
    mailbox: MailboxId,
    from: MailboxId,
    cursor: Option<MessageId>,
    peer: Option<DevicePublic>,
    confirmed: bool,
    welcomed: bool,
    cancelled: bool,
}

impl fmt::Debug for TrustedSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TrustedSession")
            .field("pairing_id", &self.offer.pairing_id)
            .field("confirmed", &self.confirmed)
            .field("welcomed", &self.welcomed)
            .finish_non_exhaustive()
    }
}

fn invalid_qr() -> VaultError {
    VaultError::Invalid(aipass_types::Localized::new(
        "这不是有效的 AI 通行证配对二维码",
        "This is not a valid AI Pass pairing code.",
    ))
}

impl TrustedSession {
    /// Scan a pairing link, derive `K`/SAS and send `pairing.hello`.
    pub async fn scan(
        uri: &str,
        identity: DeviceIdentity,
        o_device: DevicePublic,
        vault_id: VaultId,
        relay: &dyn RelayTransport,
    ) -> Result<Self> {
        let offer = PairingOffer::parse(uri).map_err(|_| invalid_qr())?;
        if offer.is_expired(now_unix()) {
            return Err(expired_err());
        }
        if !o_device.role.is_trusted_approver() {
            return Err(VaultError::Forbidden(
                "only trusted devices can approve pairing",
            ));
        }
        let e_o = KemKeypair::generate();
        let shared = e_o
            .diffie_hellman(&offer.ephemeral_pk)
            .map_err(|_| invalid_qr())?;
        let th = transcript_hash(
            &offer.pairing_id,
            &offer.ephemeral_pk,
            &e_o.public_key(),
            &offer.relay,
        )?;
        let secrets = derive_pairing_secrets(&shared, &th)?;
        let inner = Zeroizing::new(to_jcs_bytes(&PairingHelloInner {
            vault_id: vault_id.clone(),
            o_name: o_device.name.clone(),
        })?);
        let sealed = AeadBox::seal(
            &secrets.k,
            hello_aad(&offer.pairing_id, &o_device)?.as_bytes(),
            &inner,
        )?;
        let mailbox = MailboxId::Pairing(offer.pairing_id.clone());
        let from = MailboxId::Device(o_device.device_id.clone());
        let env = seal_message(
            &identity,
            from.clone(),
            mailbox.clone(),
            &offer.ephemeral_pk,
            &RelayMessage::PairingHello(Box::new(PairingHello {
                e_o: e_o.public_key(),
                o_device: o_device.clone(),
                sealed,
            })),
            aipass_types::time::now(),
        )?;
        relay.post(&mailbox, &env, Some(&offer.secret)).await?;
        Ok(Self {
            offer,
            secrets,
            identity,
            o_device,
            vault_id,
            mailbox,
            from,
            cursor: None,
            peer: None,
            confirmed: false,
            welcomed: false,
            cancelled: false,
        })
    }

    /// SAS to compare with the new device.
    pub fn sas(&self) -> &str {
        &self.secrets.sas
    }

    /// The offer that was scanned.
    pub fn offer(&self) -> &PairingOffer {
        &self.offer
    }

    /// Name shown in the QR code.
    pub fn offered_name(&self) -> &str {
        &self.offer.name
    }

    /// Role requested by the new device.
    pub fn offered_role(&self) -> PairingRole {
        self.offer.role
    }

    /// The new device (after `pairing.join`).
    pub fn peer(&self) -> Option<&DevicePublic> {
        self.peer.as_ref()
    }

    /// Whether the user confirmed.
    pub fn is_confirmed(&self) -> bool {
        self.confirmed
    }

    /// Cancel the session.
    pub fn cancel(&mut self) {
        self.cancelled = true;
    }

    fn try_join(&self, env: &RelayEnvelope) -> Result<DevicePublic> {
        let msg = open_envelope_unverified(self.identity.kem_keypair(), env)?;
        let RelayMessage::PairingJoin(j) = msg else {
            return Err(VaultError::Integrity("unexpected pairing message"));
        };
        let pt = j
            .sealed
            .open(&self.secrets.k, join_aad(&self.offer.pairing_id).as_bytes())
            .map_err(|_| VaultError::Integrity("pairing join could not be opened"))?;
        let inner: PairingJoinInner = serde_json::from_slice(pt.expose())
            .map_err(|_| VaultError::Integrity("pairing join payload invalid"))?;
        let d = inner.device;
        env.verify(&d.sign_pk)?;
        let expected = match self.offer.role {
            PairingRole::Member => MemberRole::Member,
            PairingRole::Executor => MemberRole::Executor,
        };
        if d.role != expected || d.name != self.offer.name || env.from != mailbox_for(&d) {
            return Err(VaultError::Integrity(
                "joining device does not match the pairing code",
            ));
        }
        aipass_crypto::identity::validate_ed25519_public_key(&d.sign_pk)?;
        Ok(d)
    }

    /// Wait for `pairing.join` from the new device.
    pub async fn wait_for_join(
        &mut self,
        relay: &dyn RelayTransport,
        max_wait: Duration,
    ) -> Result<DevicePublic> {
        if let Some(p) = &self.peer {
            return Ok(p.clone());
        }
        let deadline = tokio::time::Instant::now() + max_wait;
        loop {
            if self.cancelled {
                return Err(VaultError::Cancelled("pairing cancelled"));
            }
            if now_unix() > self.offer.expires_at + 60 {
                return Err(expired_err());
            }
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Err(VaultError::Expired("timed out waiting for the new device"));
            }
            let msgs = relay
                .fetch(
                    &self.mailbox,
                    self.cursor.as_ref(),
                    remaining.as_secs().clamp(1, 25),
                    Some(&self.offer.secret),
                )
                .await?;
            for m in msgs {
                self.cursor = Some(m.message_id.clone());
                if m.envelope.from == self.from
                    || m.envelope.message_type != RelayMessageType::PairingJoin
                {
                    continue;
                }
                match self.try_join(&m.envelope) {
                    Ok(d) => {
                        self.peer = Some(d.clone());
                        return Ok(d);
                    }
                    Err(e) => tracing::debug!(error = %e, "ignoring invalid pairing.join"),
                }
            }
        }
    }

    /// The user confirmed that both devices show the same SAS.
    pub fn confirm(&mut self) -> Result<DevicePublic> {
        if self.cancelled {
            return Err(VaultError::Cancelled("pairing cancelled"));
        }
        let p = self.peer.clone().ok_or(VaultError::PreconditionFailed(
            "the new device has not joined yet",
        ))?;
        self.confirmed = true;
        Ok(p)
    }

    /// Confirm by entering the code shown on the new device; a mismatch cancels the session
    /// (possible man-in-the-middle).
    pub fn confirm_code(&mut self, code_on_new_device: &str) -> Result<DevicePublic> {
        let typed: String = code_on_new_device
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        if !aipass_crypto::ct_eq(typed.as_bytes(), self.secrets.sas.as_bytes()) {
            self.cancelled = true;
            return Err(VaultError::Cancelled(
                "the codes do not match — pairing cancelled (possible interception)",
            ));
        }
        self.confirm()
    }

    /// Send `pairing.welcome` (after the member record has been committed).
    pub async fn send_welcome(
        &mut self,
        relay: &dyn RelayTransport,
        inner: &PairingWelcomeInner,
    ) -> Result<()> {
        if !self.confirmed || self.cancelled {
            return Err(VaultError::PreconditionFailed(
                "pairing not confirmed on this device",
            ));
        }
        let peer = self
            .peer
            .clone()
            .ok_or(VaultError::Internal("confirmed without peer"))?;
        if inner.vault_id != self.vault_id {
            return Err(VaultError::InvalidInput("welcome is for another vault"));
        }
        let pt = Zeroizing::new(to_jcs_bytes(inner)?);
        let sealed = AeadBox::seal(
            &self.secrets.k,
            welcome_aad(&self.offer.pairing_id, &peer.device_id).as_bytes(),
            &pt,
        )?;
        let env = seal_message(
            &self.identity,
            self.from.clone(),
            self.mailbox.clone(),
            &peer.kem_pk,
            &RelayMessage::PairingWelcome(PairingWelcome { sealed }),
            aipass_types::time::now(),
        )?;
        relay
            .post(&self.mailbox, &env, Some(&self.offer.secret))
            .await?;
        self.welcomed = true;
        Ok(())
    }

    /// The device this session runs on.
    pub fn o_device(&self) -> &DevicePublic {
        &self.o_device
    }
}

/// b64u of the pairing secret (for transports that send it as a header).
pub fn pairing_secret_header(offer: &PairingOffer) -> String {
    b64u::encode(offer.secret)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sas_is_six_digits_and_symmetric() {
        let a = KemKeypair::generate();
        let b = KemKeypair::generate();
        let s1 = a.diffie_hellman(&b.public_key()).unwrap();
        let s2 = b.diffie_hellman(&a.public_key()).unwrap();
        let th = [3u8; 32];
        let x = derive_pairing_secrets(&s1, &th).unwrap();
        let y = derive_pairing_secrets(&s2, &th).unwrap();
        assert_eq!(x.sas(), y.sas());
        assert_eq!(x.sas().len(), 6);
        assert!(x.sas().bytes().all(|c| c.is_ascii_digit()));
        assert_ne!(derive_pairing_secrets(&s1, &[4u8; 32]).unwrap().sas, x.sas);
        assert!(!format!("{x:?}").contains("k:"));
    }
}
