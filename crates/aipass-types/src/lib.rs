// SPDX-License-Identifier: Apache-2.0
//! # aipass-types — shared models and protocol rules of AI Pass
//!
//! The binding cross-component shapes of `docs/spec/CONTRACTS.md`, implemented once in Rust:
//!
//! | module | contract |
//! | --- | --- |
//! | [`ids`] | §1.1 prefixed ULIDs (`res_01j…`), typed newtypes, CSPRNG generator |
//! | [`time`] | §1.3 RFC 3339 `Z`, second precision |
//! | [`canonical`] | §1.4 RFC 8785 JCS (`to_jcs_bytes`), floats rejected |
//! | [`error`] | §1.5 [`ErrorCode`], [`ApiError`], [`ErrorBody`], zh-CN / en messages |
//! | [`signing`] | §1.6 `AIPass-Sig` header, string-to-sign, sign/verify, [`signing::NonceCache`] |
//! | [`vault`] | §2.3 storage objects with `signing_bytes()`, keys, AAD strings |
//! | [`storage`] | §3.1 [`storage::StorageProfile`] |
//! | [`relay`] | §4 envelopes, inner messages, device control signatures |
//! | [`pairing`] | §5 QR/link URI and pairing payloads |
//! | [`models`] | §6.1 / §6.3 broker models and HTTP shapes, [`models::OperationStatus`] state machine |
//! | [`approval`] | §7 digest, signing message, subset checks, decision build/verify |
//! | [`policy`] | §7 policy signatures |
//! | [`exec`] | §8 [`exec::ExecutorBackend`] and execution types |
//!
//! Security notes: IDs are not capabilities; types that carry credentials
//! ([`vault::EntryPayload`], [`exec::CredentialMaterial`], [`pairing::PairingWelcomeInner`])
//! zeroize and redact in `Debug`; errors never carry secrets.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod approval;
pub mod canonical;
pub mod error;
pub mod exec;
pub mod ids;
pub mod models;
pub mod pairing;
pub mod policy;
pub mod relay;
pub mod signing;
pub mod storage;
pub mod time;
pub mod vault;

pub use canonical::{CanonicalError, to_jcs_bytes};
pub use error::{ApiError, ErrorBody, ErrorCode, ErrorObject, Lang, Localized};
pub use ids::*;
pub use time::Timestamp;

/// Re-export of the crypto crate so downstream crates can use one import path.
pub use aipass_crypto as crypto;

/// Signature verification failure for signed objects / messages.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SignatureError {
    /// The object could not be canonicalized.
    #[error(transparent)]
    Canonical(#[from] CanonicalError),
    /// Signature (or key) is not valid b64u of the right length.
    #[error("malformed signature")]
    Malformed,
    /// Signature does not verify.
    #[error("invalid signature")]
    Invalid,
}

impl From<SignatureError> for ApiError {
    fn from(_: SignatureError) -> Self {
        ApiError::new(ErrorCode::IntegrityFailed)
    }
}
