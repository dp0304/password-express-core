// SPDX-License-Identifier: Apache-2.0
//! # aipass-ffi — uniffi bindings for iOS / Android (CONTRACTS §12)
//!
//! * [`AipassCore`] — vault, items, sync, recovery, devices, storage, autofill, pairing,
//!   approvals & control via the relay, offline license verification;
//! * [`SecretStore`] — callback interface implemented natively (Keychain / Keystore);
//! * [`PairingSession`] — device / executor pairing with SAS confirmation;
//! * [`LocalRelay`] — in-process relay for tests and single-process demos.
//!
//! Swift module `AIPassCore`, Kotlin package `com.aipass.core`. Errors cross the
//! boundary as [`CoreError`] `{ code, message }` and never contain secrets. Only
//! `reveal_secret`, `autofill_credential`, `generate_password`, `totp_now` and the
//! one-time recovery key of `create_vault` / `replace_recovery_key` return secret
//! material; the native side must require user presence before the first two.

#![deny(clippy::todo, clippy::unimplemented)]
#![forbid(clippy::dbg_macro)]

mod core;
mod error;
mod license;
mod pairing;
mod relay;
mod secret_store;
#[cfg(feature = "test-support")]
mod test_support;
mod types;

pub use crate::core::{AipassCore, core_version, default_password_rules};
pub use crate::error::{CoreError, SecretStoreError};
pub use crate::license::DEV_LICENSE_SEED_LABEL;
pub use crate::pairing::PairingSession;
pub use crate::relay::LocalRelay;
pub use crate::secret_store::SecretStore;
#[cfg(feature = "test-support")]
pub use crate::test_support::TestExecutor;
pub use crate::types::*;

uniffi::setup_scaffolding!("aipass_core");
