// SPDX-License-Identifier: Apache-2.0
//! # aipass-vault — Vault Core
//!
//! Responsibilities (CONTRACTS §2.2–§2.8, §4, §5, §7; design doc §6, §9.4, §9.5, §10):
//!
//! | module | what |
//! | --- | --- |
//! | [`keys`] | VMK per `key_epoch`, HPKE VMK wraps, recovery / master-password KEKs, keyring |
//! | [`entry`] | entry versions: per-version DEK, exact contract AADs, location-bound decryption |
//! | [`member`] | member records, recovery member identity, `exe_` ⇔ `dev_` mapping |
//! | [`manifest`] | signed manifests, [`manifest::VaultView`], chain verification rules, drafts |
//! | [`vault`] | genesis, [`vault::UnlockedVault`], add / revoke (+ key rotation), recovery |
//! | [`recovery`] | `AIPR-…` recovery key, recovery kit text (zh/en) |
//! | [`secret_store`] | [`secret_store::SecretStore`] + memory / file / OS keychain stores |
//! | [`generator`] | CSPRNG password generator + Apple `passwordrules` parser |
//! | [`totp`] | RFC 6238 TOTP, `otpauth://` parsing |
//! | [`import`] / [`export`] | CSV importers (7 formats), `.aipassx`, CSV export |
//! | [`matching`] | exact-origin / same-site matching (autofill, de-duplication) |
//! | [`pairing`] | pairing state machines for the new and the trusted device, SAS |
//! | [`relay`] | [`relay::RelayTransport`], [`relay::MemoryRelay`], envelope helpers |
//! | [`approval`] | approval decisions + credential envelopes, signed control messages |
//!
//! All wire shapes come from `aipass_types`; all primitives from `aipass_crypto` (no
//! home-made cryptography). Vault keys are never derived from subscription passwords,
//! email logins or passkey ids. Secrets never appear in `Debug` output or errors.
//!
//! Status: not yet independently audited.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod approval;
pub mod encoding;
pub mod entry;
pub mod error;
pub mod export;
pub mod fsutil;
pub mod generator;
pub mod import;
pub mod keys;
pub mod manifest;
pub mod matching;
pub mod member;
pub mod pairing;
pub mod recovery;
pub mod relay;
pub mod secret_store;
pub mod totp;
pub mod vault;

pub use error::{Result, VaultError};
pub use manifest::{ManifestCandidate, ManifestDraft, VaultView};
pub use recovery::RecoveryKey;
pub use relay::{MemoryRelay, RelayTransport};
pub use secret_store::{FileSecretStore, MemorySecretStore, SecretStore};
pub use vault::{Genesis, GenesisParams, PendingEpoch, UnlockedVault};
