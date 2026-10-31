// SPDX-License-Identifier: Apache-2.0
//! Device / executor pairing payloads and the QR / link URI (CONTRACTS §5, design doc §9.5).
//!
//! ```text
//! aipass://pair?v=1&p=<pairing_id>&s=<b64u 16B secret>&k=<b64u ephemeral X25519 pk>
//!              &r=<urlencoded relay base URL>&n=<urlencoded name>&t=<member|executor>&e=<expiry unix>
//! ```
//! The QR never carries the VMK or long-term keys; scanning alone never grants access — the
//! user confirms the SAS on the trusted device. Key derivation (`K`, SAS) lives in
//! `aipass-vault`; this module defines the wire shapes and the transcript document.

use core::fmt;

use aipass_crypto::{AeadBox, SecretString, b64u};
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::canonical::{CanonicalError, to_jcs_bytes};
use crate::ids::{PairingId, VaultId};
use crate::storage::StorageProfile;
use crate::vault::{Checkpoint, DevicePublic};

/// URI version.
pub const PAIRING_URI_VERSION: u32 = 1;
/// QR lifetime (10 minutes).
pub const PAIRING_TTL_SECS: i64 = 600;
/// Pairing secret length.
pub const PAIRING_SECRET_LEN: usize = 16;
/// Header carrying the pairing secret for `pair_` mailboxes.
pub const PAIRING_SECRET_HEADER: &str = "X-AIPass-Pairing-Secret";
/// Maximum device name length (characters).
pub const MAX_NAME_CHARS: usize = 64;

/// Unreserved characters (RFC 3986) stay literal; everything else is percent-encoded.
const QUERY_VALUE: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

/// Role the new device will have.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PairingRole {
    /// Trusted member device (receives the VMK).
    Member,
    /// Executor (never receives the VMK; stores `trusted_devices` as approver set).
    Executor,
}

impl PairingRole {
    /// Wire string.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Member => "member",
            Self::Executor => "executor",
        }
    }
}

/// Pairing URI error.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PairingUriError {
    /// Not an `aipass://pair` URI.
    #[error("not an aipass pairing link")]
    NotPairingUri,
    /// Missing or duplicated parameter.
    #[error("pairing link parameter `{0}` missing or repeated")]
    Param(&'static str),
    /// Parameter has an invalid value.
    #[error("pairing link parameter `{0}` is invalid")]
    Invalid(&'static str),
    /// Unsupported version.
    #[error("unsupported pairing link version")]
    Version,
}

/// The content of the pairing QR code / link shown by the **new** device.
#[derive(Clone, PartialEq, Eq)]
pub struct PairingOffer {
    /// Pairing session (`pair_…`) — also the relay mailbox.
    pub pairing_id: PairingId,
    /// 16-byte mailbox secret (authorizes the `pair_` mailbox).
    pub secret: [u8; PAIRING_SECRET_LEN],
    /// New device's ephemeral X25519 public key `eN`.
    pub ephemeral_pk: [u8; 32],
    /// Relay base URL.
    pub relay: String,
    /// New device's display name.
    pub name: String,
    /// Role.
    pub role: PairingRole,
    /// Expiry (unix seconds).
    pub expires_at: i64,
}

impl fmt::Debug for PairingOffer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PairingOffer")
            .field("pairing_id", &self.pairing_id)
            .field("secret", &"[REDACTED]")
            .field("relay", &self.relay)
            .field("name", &self.name)
            .field("role", &self.role)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

fn valid_relay(url: &str) -> bool {
    match url::Url::parse(url) {
        Ok(u) => match u.scheme() {
            "https" => u.host_str().is_some(),
            // plain http only for loopback development relays
            "http" => matches!(
                u.host_str(),
                Some("127.0.0.1") | Some("localhost") | Some("[::1]")
            ),
            _ => false,
        },
        Err(_) => false,
    }
}

fn valid_name(name: &str) -> bool {
    !name.trim().is_empty()
        && name.chars().count() <= MAX_NAME_CHARS
        && !name.chars().any(char::is_control)
}

impl PairingOffer {
    /// Build the `aipass://pair?…` URI.
    pub fn to_uri(&self) -> String {
        format!(
            "aipass://pair?v={}&p={}&s={}&k={}&r={}&n={}&t={}&e={}",
            PAIRING_URI_VERSION,
            self.pairing_id,
            b64u::encode(self.secret),
            b64u::encode(self.ephemeral_pk),
            utf8_percent_encode(&self.relay, QUERY_VALUE),
            utf8_percent_encode(&self.name, QUERY_VALUE),
            self.role.as_str(),
            self.expires_at
        )
    }

    /// Parse and validate a pairing URI (does not check expiry — see [`PairingOffer::is_expired`]).
    pub fn parse(uri: &str) -> Result<Self, PairingUriError> {
        let u = url::Url::parse(uri.trim()).map_err(|_| PairingUriError::NotPairingUri)?;
        if u.scheme() != "aipass"
            || u.host_str() != Some("pair")
            || !(u.path().is_empty() || u.path() == "/")
        {
            return Err(PairingUriError::NotPairingUri);
        }
        let mut params: std::collections::HashMap<String, String> =
            std::collections::HashMap::new();
        for (k, v) in u.query_pairs() {
            if params.insert(k.to_string(), v.to_string()).is_some() {
                return Err(PairingUriError::Param(match k.as_ref() {
                    "v" => "v",
                    "p" => "p",
                    "s" => "s",
                    "k" => "k",
                    "r" => "r",
                    "n" => "n",
                    "t" => "t",
                    "e" => "e",
                    _ => "?",
                }));
            }
        }
        let get = |k: &'static str| params.get(k).cloned().ok_or(PairingUriError::Param(k));
        if get("v")? != "1" {
            return Err(PairingUriError::Version);
        }
        let pairing_id = PairingId::parse(&get("p")?).map_err(|_| PairingUriError::Invalid("p"))?;
        let secret = b64u::decode_array::<PAIRING_SECRET_LEN>(&get("s")?)
            .map_err(|_| PairingUriError::Invalid("s"))?;
        let ephemeral_pk =
            b64u::decode_array::<32>(&get("k")?).map_err(|_| PairingUriError::Invalid("k"))?;
        let relay = get("r")?;
        if !valid_relay(&relay) {
            return Err(PairingUriError::Invalid("r"));
        }
        let name = get("n")?;
        if !valid_name(&name) {
            return Err(PairingUriError::Invalid("n"));
        }
        let role = match get("t")?.as_str() {
            "member" => PairingRole::Member,
            "executor" => PairingRole::Executor,
            _ => return Err(PairingUriError::Invalid("t")),
        };
        let e = get("e")?;
        if e.is_empty() || !e.bytes().all(|b| b.is_ascii_digit()) || e.len() > 12 {
            return Err(PairingUriError::Invalid("e"));
        }
        let expires_at: i64 = e.parse().map_err(|_| PairingUriError::Invalid("e"))?;
        Ok(Self {
            pairing_id,
            secret,
            ephemeral_pk,
            relay,
            name,
            role,
            expires_at,
        })
    }

    /// Expired at `now` (unix seconds), or claims a lifetime longer than 10 minutes (+60 s skew).
    pub fn is_expired(&self, now: i64) -> bool {
        now >= self.expires_at || self.expires_at - now > PAIRING_TTL_SECS + 60
    }

    /// Value for the [`PAIRING_SECRET_HEADER`] header.
    pub fn secret_header_value(&self) -> String {
        b64u::encode(self.secret)
    }
}

/// `th = SHA-256(JCS({pairing_id, eN, eO, relay}))` — the pairing transcript hash (keys
/// exactly as in CONTRACTS §5; `eN` / `eO` as b64u).
pub fn transcript_hash(
    pairing_id: &PairingId,
    e_n: &[u8; 32],
    e_o: &[u8; 32],
    relay: &str,
) -> Result<[u8; 32], CanonicalError> {
    #[derive(Serialize)]
    struct Th<'a> {
        pairing_id: &'a str,
        #[serde(rename = "eN")]
        e_n: String,
        #[serde(rename = "eO")]
        e_o: String,
        relay: &'a str,
    }
    let bytes = to_jcs_bytes(&Th {
        pairing_id: pairing_id.as_str(),
        e_n: b64u::encode(e_n),
        e_o: b64u::encode(e_o),
        relay,
    })?;
    Ok(aipass_crypto::sha256(bytes))
}

/// `pairing.hello` (O → mailbox): `{eO, o_device, sealed: XChaCha20(K, PairingHelloInner)}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairingHello {
    /// O's ephemeral X25519 public key.
    #[serde(rename = "eO", with = "aipass_crypto::b64u::array")]
    pub e_o: [u8; 32],
    /// The trusted device O.
    pub o_device: DevicePublic,
    /// Sealed [`PairingHelloInner`].
    pub sealed: AeadBox,
}

/// Plaintext of `pairing.hello.sealed`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairingHelloInner {
    /// Vault being joined.
    pub vault_id: VaultId,
    /// O's display name.
    pub o_name: String,
}

/// `pairing.join` (N → mailbox): `{sealed: XChaCha20(K, PairingJoinInner)}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairingJoin {
    /// Sealed [`PairingJoinInner`].
    pub sealed: AeadBox,
}

/// Plaintext of `pairing.join.sealed`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairingJoinInner {
    /// The new device N.
    pub device: DevicePublic,
}

/// `pairing.welcome` (O → N): `{sealed: XChaCha20(K, PairingWelcomeInner)}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairingWelcome {
    /// Sealed [`PairingWelcomeInner`].
    pub sealed: AeadBox,
}

/// Plaintext of `pairing.welcome.sealed`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairingWelcomeInner {
    /// Vault.
    pub vault_id: VaultId,
    /// N's member record rev written by O.
    pub member_rev: u64,
    /// O's checkpoint (N verifies `vault.json`, member chain and checkpoint).
    pub checkpoint: Checkpoint,
    /// Storage configuration.
    pub storage_profile: StorageProfile,
    /// Storage secret (optional; avoids the recovery circular dependency of §10.5).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage_secret: Option<SecretString>,
    /// Relay base URL.
    pub relay_base_url: String,
    /// Trusted owner/member devices (executors store them as their approver set).
    pub trusted_devices: Vec<DevicePublic>,
}

impl fmt::Debug for PairingWelcomeInner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PairingWelcomeInner")
            .field("vault_id", &self.vault_id)
            .field("member_rev", &self.member_rev)
            .field("checkpoint", &self.checkpoint)
            .field("storage_profile", &self.storage_profile)
            .field(
                "storage_secret",
                &self.storage_secret.as_ref().map(|_| "[REDACTED]"),
            )
            .field("relay_base_url", &self.relay_base_url)
            .field("trusted_devices", &self.trusted_devices.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn offer() -> PairingOffer {
        PairingOffer {
            pairing_id: PairingId::parse("pair_01jbz3k6w8a7m2q4t5v9x0y1z9").unwrap(),
            secret: [7u8; 16],
            ephemeral_pk: [9u8; 32],
            relay: "https://cloud.aipass.example/v1/relay?x=1&y=2".into(),
            name: "我的 MacBook & Co+".into(),
            role: PairingRole::Executor,
            expires_at: 1_793_319_000,
        }
    }

    #[test]
    fn uri_roundtrip() {
        let o = offer();
        let uri = o.to_uri();
        assert!(uri.starts_with("aipass://pair?v=1&p=pair_01jbz3k6w8a7m2q4t5v9x0y1z9&s="));
        assert!(uri.contains("&t=executor&e=1793319000"));
        assert!(!uri.contains(' ') && !uri.contains('+'));
        assert_eq!(PairingOffer::parse(&uri).unwrap(), o);
        assert!(!format!("{o:?}").contains(&b64u::encode(o.secret)));
        assert!(!o.is_expired(1_793_318_500));
        assert!(o.is_expired(1_793_319_000));
        assert!(o.is_expired(1_793_317_000)); // lifetime too long
    }

    #[test]
    fn uri_rejections() {
        let good = offer().to_uri();
        assert_eq!(
            PairingOffer::parse("https://pair?v=1"),
            Err(PairingUriError::NotPairingUri)
        );
        assert_eq!(
            PairingOffer::parse(&good.replace("v=1", "v=2")),
            Err(PairingUriError::Version)
        );
        assert_eq!(
            PairingOffer::parse(&good.replace("&t=executor", "&t=owner")),
            Err(PairingUriError::Invalid("t"))
        );
        assert_eq!(
            PairingOffer::parse(&format!("{good}&e=1")),
            Err(PairingUriError::Param("e"))
        );
        let no_k: String = good
            .split('&')
            .filter(|p| !p.starts_with("k="))
            .collect::<Vec<_>>()
            .join("&");
        assert_eq!(PairingOffer::parse(&no_k), Err(PairingUriError::Param("k")));
        let http = PairingOffer {
            relay: "http://evil.example".into(),
            ..offer()
        }
        .to_uri();
        assert_eq!(
            PairingOffer::parse(&http),
            Err(PairingUriError::Invalid("r"))
        );
        let local = PairingOffer {
            relay: "http://127.0.0.1:7878".into(),
            ..offer()
        }
        .to_uri();
        PairingOffer::parse(&local).unwrap();
    }

    #[test]
    fn transcript_is_order_sensitive() {
        let p = offer().pairing_id;
        let a = transcript_hash(&p, &[1; 32], &[2; 32], "https://r").unwrap();
        let b = transcript_hash(&p, &[2; 32], &[1; 32], "https://r").unwrap();
        assert_ne!(a, b);
        assert_eq!(
            a,
            transcript_hash(&p, &[1; 32], &[2; 32], "https://r").unwrap()
        );
    }
}
