// SPDX-License-Identifier: Apache-2.0
//! Prefixed ULID identifiers (CONTRACTS §1.1): `<prefix>_<26 lowercase Crockford base32>`,
//! e.g. `res_01jbz3k6w8a7m2q4t5v9x0y1z2`.
//!
//! Every ID kind is a distinct newtype, so a `GrantId` can never be passed where a
//! `ResourceId` is expected. Parsing validates the prefix, the length, the lowercase
//! Crockford alphabet and the 128-bit range. Generation uses the current time plus 80 bits
//! from the OS CSPRNG.
//!
//! **IDs are not capabilities** (§12.1 of the design doc): possessing an ID never
//! authorises anything; every request is re-checked against the authenticated principal.

use core::fmt;
use core::str::FromStr;
use std::borrow::Borrow;
use std::time::{SystemTime, UNIX_EPOCH};

use thiserror::Error;

/// Length of the ULID part.
pub const ULID_LEN: usize = 26;

const CROCKFORD_LOWER: &[u8; 32] = b"0123456789abcdefghjkmnpqrstvwxyz";

/// Error parsing an identifier.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum IdError {
    /// The prefix did not match the expected kind.
    #[error("invalid id: expected prefix `{expected}_`")]
    WrongPrefix {
        /// Expected prefix.
        expected: &'static str,
    },
    /// The ULID part is malformed.
    #[error("invalid id: malformed ulid part")]
    Malformed,
    /// The prefix is not one of the known AI Pass prefixes.
    #[error("invalid id: unknown prefix")]
    UnknownPrefix,
}

fn is_valid_ulid_part(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == ULID_LEN
        // 26 × 5 = 130 bits; the first character may encode at most 3 bits (0..=7).
        && matches!(b[0], b'0'..=b'7')
        && b.iter().all(|c| CROCKFORD_LOWER.contains(c))
}

/// Validate `s` as `<prefix>_<ulid>`.
pub fn validate(prefix: &'static str, s: &str) -> Result<(), IdError> {
    let rest = s
        .strip_prefix(prefix)
        .and_then(|r| r.strip_prefix('_'))
        .ok_or(IdError::WrongPrefix { expected: prefix })?;
    if is_valid_ulid_part(rest) {
        Ok(())
    } else {
        Err(IdError::Malformed)
    }
}

fn encode_ulid(value: u128) -> String {
    let mut out = [0u8; ULID_LEN];
    let mut v = value;
    for i in (0..ULID_LEN).rev() {
        out[i] = CROCKFORD_LOWER[(v & 0x1f) as usize];
        v >>= 5;
    }
    // All bytes come from the ASCII alphabet.
    String::from_utf8(out.to_vec()).unwrap_or_default()
}

fn decode_ulid(s: &str) -> Option<u128> {
    if !is_valid_ulid_part(s) {
        return None;
    }
    let mut v: u128 = 0;
    for c in s.bytes() {
        let idx = CROCKFORD_LOWER.iter().position(|x| *x == c)? as u128;
        v = (v << 5) | idx;
    }
    Some(v)
}

/// Generate a raw `<prefix>_<ulid>` string: 48-bit millisecond timestamp + 80 random bits
/// from the OS CSPRNG.
pub fn generate_raw(prefix: &str) -> String {
    let ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
        & ((1u64 << 48) - 1);
    let rnd: [u8; 10] = aipass_crypto::rng::random_array();
    let mut random: u128 = 0;
    for b in rnd {
        random = (random << 8) | b as u128;
    }
    let ulid = ulid::Ulid::from_parts(ms, random);
    format!("{prefix}_{}", encode_ulid(ulid.0))
}

/// Split a prefixed id into `(prefix, ulid_part)` without checking the prefix set.
pub fn split(s: &str) -> Option<(&str, &str)> {
    let (p, rest) = s.split_once('_')?;
    if p.is_empty() || !p.bytes().all(|c| c.is_ascii_lowercase()) || !is_valid_ulid_part(rest) {
        return None;
    }
    Some((p, rest))
}

macro_rules! define_id {
    ($(#[$meta:meta])* $name:ident, $prefix:literal) => {
        $(#[$meta])*
        #[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(String);

        impl $name {
            /// The ID prefix (without the underscore).
            pub const PREFIX: &'static str = $prefix;

            /// Generate a new random ID.
            pub fn generate() -> Self {
                Self(generate_raw($prefix))
            }

            /// Parse and validate.
            pub fn parse(s: &str) -> Result<Self, IdError> {
                validate($prefix, s)?;
                Ok(Self(s.to_owned()))
            }

            /// The full textual ID.
            pub fn as_str(&self) -> &str {
                &self.0
            }

            /// Consume into the textual ID.
            pub fn into_string(self) -> String {
                self.0
            }

            /// Millisecond timestamp encoded in the ULID (informational only; never trust
            /// it for ordering decisions that matter for security).
            pub fn timestamp_ms(&self) -> u64 {
                let part = &self.0[$prefix.len() + 1..];
                decode_ulid(part).map(|v| (v >> 80) as u64).unwrap_or(0)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({})", stringify!($name), self.0)
            }
        }

        impl FromStr for $name {
            type Err = IdError;
            fn from_str(s: &str) -> Result<Self, IdError> {
                Self::parse(s)
            }
        }

        impl TryFrom<&str> for $name {
            type Error = IdError;
            fn try_from(s: &str) -> Result<Self, IdError> {
                Self::parse(s)
            }
        }

        impl TryFrom<String> for $name {
            type Error = IdError;
            fn try_from(s: String) -> Result<Self, IdError> {
                validate($prefix, &s)?;
                Ok(Self(s))
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                &self.0
            }
        }

        impl Borrow<str> for $name {
            fn borrow(&self) -> &str {
                &self.0
            }
        }

        impl From<$name> for String {
            fn from(id: $name) -> String {
                id.0
            }
        }

        impl PartialEq<str> for $name {
            fn eq(&self, other: &str) -> bool {
                self.0 == other
            }
        }

        impl PartialEq<&str> for $name {
            fn eq(&self, other: &&str) -> bool {
                self.0 == *other
            }
        }

        impl serde::Serialize for $name {
            fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                s.serialize_str(&self.0)
            }
        }

        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                let s = String::deserialize(d)?;
                Self::try_from(s).map_err(serde::de::Error::custom)
            }
        }
    };
}

define_id!(/// Vault (`vlt_`).
    VaultId, "vlt");
define_id!(/// Vault entry (`ent_`).
    EntryId, "ent");
define_id!(/// Trusted device — phone, desktop, CLI (`dev_`).
    DeviceId, "dev");
define_id!(/// Executor node (`exe_`).
    ExecutorId, "exe");
define_id!(/// App connection / AI host (`conn_`).
    ConnectionId, "conn");
define_id!(/// Resource (`res_`).
    ResourceId, "res");
define_id!(/// Project (`proj_`).
    ProjectId, "proj");
define_id!(/// Policy (`pol_`).
    PolicyId, "pol");
define_id!(/// Grant (`grt_`).
    GrantId, "grt");
define_id!(/// Approval request (`apr_`).
    ApprovalRequestId, "apr");
define_id!(/// Operation (`op_`).
    OperationId, "op");
define_id!(/// Lease (`lse_`).
    LeaseId, "lse");
define_id!(/// Audit event (`evt_`).
    EventId, "evt");
define_id!(/// Relay message (`msg_`).
    MessageId, "msg");
define_id!(/// Pairing session — device pairing and connection pairing requests (`pair_`).
    PairingId, "pair");
define_id!(/// HTTP request id echoed in error bodies (`req_`).
    RequestId, "req");
define_id!(/// Cloud user (`usr_`).
    UserId, "usr");
define_id!(/// Cloud organisation (`org_`).
    OrgId, "org");
define_id!(/// Cloud subscription (`sub_`).
    SubscriptionId, "sub");
define_id!(/// Cloud invitation (`inv_`).
    InvitationId, "inv");
define_id!(/// Cloud status incident (`inc_`).
    IncidentId, "inc");
define_id!(/// Cloud OAuth client (`oac_`).
    OAuthClientId, "oac");
define_id!(/// Cloud session (`ses_`).
    SessionId, "ses");

/// All known prefixes (CONTRACTS §1.1 plus `req`).
pub const PREFIXES: &[&str] = &[
    "vlt", "ent", "dev", "exe", "conn", "res", "proj", "pol", "grt", "apr", "op", "lse", "evt",
    "msg", "pair", "req", "usr", "org", "sub", "inv", "inc", "oac", "ses",
];

/// An authenticated request principal (`kid` of an `AIPass-Sig` header).
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum PrincipalId {
    /// AppConnection (`conn_`).
    Connection(ConnectionId),
    /// Trusted device (`dev_`).
    Device(DeviceId),
    /// Executor node (`exe_`).
    Executor(ExecutorId),
}

impl PrincipalId {
    /// Parse by prefix; only `conn_`, `dev_` and `exe_` are principals.
    pub fn parse(s: &str) -> Result<Self, IdError> {
        match split(s).map(|(p, _)| p) {
            Some("conn") => ConnectionId::parse(s).map(Self::Connection),
            Some("dev") => DeviceId::parse(s).map(Self::Device),
            Some("exe") => ExecutorId::parse(s).map(Self::Executor),
            Some(_) => Err(IdError::UnknownPrefix),
            None => Err(IdError::Malformed),
        }
    }

    /// Textual id.
    pub fn as_str(&self) -> &str {
        match self {
            Self::Connection(i) => i.as_str(),
            Self::Device(i) => i.as_str(),
            Self::Executor(i) => i.as_str(),
        }
    }
}

impl fmt::Display for PrincipalId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl fmt::Debug for PrincipalId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PrincipalId({})", self.as_str())
    }
}

impl serde::Serialize for PrincipalId {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for PrincipalId {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Self::parse(&s).map_err(serde::de::Error::custom)
    }
}

/// A relay mailbox id (CONTRACTS §4): a device, an executor or a pairing session.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum MailboxId {
    /// `dev_…` mailbox.
    Device(DeviceId),
    /// `exe_…` mailbox.
    Executor(ExecutorId),
    /// `pair_…` mailbox (10-minute TTL, pairing-secret auth).
    Pairing(PairingId),
}

impl MailboxId {
    /// Parse by prefix.
    pub fn parse(s: &str) -> Result<Self, IdError> {
        match split(s).map(|(p, _)| p) {
            Some("dev") => DeviceId::parse(s).map(Self::Device),
            Some("exe") => ExecutorId::parse(s).map(Self::Executor),
            Some("pair") => PairingId::parse(s).map(Self::Pairing),
            Some(_) => Err(IdError::UnknownPrefix),
            None => Err(IdError::Malformed),
        }
    }

    /// Textual id.
    pub fn as_str(&self) -> &str {
        match self {
            Self::Device(i) => i.as_str(),
            Self::Executor(i) => i.as_str(),
            Self::Pairing(i) => i.as_str(),
        }
    }

    /// True for `pair_` mailboxes.
    pub fn is_pairing(&self) -> bool {
        matches!(self, Self::Pairing(_))
    }
}

impl fmt::Display for MailboxId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl fmt::Debug for MailboxId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MailboxId({})", self.as_str())
    }
}

impl From<DeviceId> for MailboxId {
    fn from(d: DeviceId) -> Self {
        Self::Device(d)
    }
}
impl From<ExecutorId> for MailboxId {
    fn from(e: ExecutorId) -> Self {
        Self::Executor(e)
    }
}
impl From<PairingId> for MailboxId {
    fn from(p: PairingId) -> Self {
        Self::Pairing(p)
    }
}

impl serde::Serialize for MailboxId {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for MailboxId {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Self::parse(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_contract_examples() {
        let r = ResourceId::parse("res_01jbz3k6w8a7m2q4t5v9x0y1z2").unwrap();
        assert_eq!(r.as_str(), "res_01jbz3k6w8a7m2q4t5v9x0y1z2");
        assert_eq!(r.to_string(), "res_01jbz3k6w8a7m2q4t5v9x0y1z2");
        ConnectionId::parse("conn_01jbz3k6w8a7m2q4t5v9x0y1z4").unwrap();
        ProjectId::parse("proj_01jbz3k6w8a7m2q4t5v9x0y1z3").unwrap();
    }

    #[test]
    fn rejects_bad_ids() {
        // wrong prefix — an ID of another kind is never accepted
        assert_eq!(
            ResourceId::parse("grt_01jbz3k6w8a7m2q4t5v9x0y1z2"),
            Err(IdError::WrongPrefix { expected: "res" })
        );
        assert!(ResourceId::parse("res01jbz3k6w8a7m2q4t5v9x0y1z2").is_err());
        assert!(ResourceId::parse("res_01JBZ3K6W8A7M2Q4T5V9X0Y1Z2").is_err()); // uppercase
        assert!(ResourceId::parse("res_01jbz3k6w8a7m2q4t5v9x0y1z").is_err()); // short
        assert!(ResourceId::parse("res_01jbz3k6w8a7m2q4t5v9x0y1zu").is_err()); // 'u' not Crockford
        assert!(ResourceId::parse("res_81jbz3k6w8a7m2q4t5v9x0y1z2").is_err()); // > 128 bits
        assert!(ResourceId::parse("res_01jbz3k6w8a7m2q4t5v9x0y1z2 ").is_err());
        assert!(ResourceId::parse("").is_err());
        assert!(serde_json::from_str::<ResourceId>("\"res_x\"").is_err());
    }

    #[test]
    fn generate_is_unique_valid_and_time_ordered() {
        let a = OperationId::generate();
        let b = OperationId::generate();
        assert_ne!(a, b);
        OperationId::parse(a.as_str()).unwrap();
        assert!(a.as_str().starts_with("op_"));
        assert_eq!(a.as_str().len(), 3 + ULID_LEN);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        assert!(now.abs_diff(a.timestamp_ms()) < 60_000);
        // encode/decode roundtrip
        let part = &a.as_str()[3..];
        assert_eq!(encode_ulid(decode_ulid(part).unwrap()), part);
    }

    #[test]
    fn principal_and_mailbox() {
        let p = PrincipalId::parse("conn_01jbz3k6w8a7m2q4t5v9x0y1z4").unwrap();
        assert!(matches!(p, PrincipalId::Connection(_)));
        assert_eq!(
            PrincipalId::parse("res_01jbz3k6w8a7m2q4t5v9x0y1z2"),
            Err(IdError::UnknownPrefix)
        );
        let m: MailboxId = serde_json::from_str("\"pair_01jbz3k6w8a7m2q4t5v9x0y1z4\"").unwrap();
        assert!(m.is_pairing());
        assert!(MailboxId::parse("conn_01jbz3k6w8a7m2q4t5v9x0y1z4").is_err());
        let json = serde_json::to_string(&p).unwrap();
        assert_eq!(json, "\"conn_01jbz3k6w8a7m2q4t5v9x0y1z4\"");
    }

    #[test]
    fn serde_and_maps() {
        use std::collections::BTreeMap;
        let id = EntryId::generate();
        let mut m = BTreeMap::new();
        m.insert(id.clone(), 1u32);
        let json = serde_json::to_string(&m).unwrap();
        let back: BTreeMap<EntryId, u32> = serde_json::from_str(&json).unwrap();
        assert_eq!(back.get(&id), Some(&1));
        assert_eq!(back.get(id.as_str()), Some(&1));
    }
}
