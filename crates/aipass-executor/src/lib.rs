// SPDX-License-Identifier: Apache-2.0
//! # aipass-executor — Executor + connectors
//!
//! The executor runs authorized operations for the Access Broker through
//! [`aipass_types::exec::ExecutorBackend`] (CONTRACTS §8; design doc §9.2–9.3, §9.6, §9.8):
//!
//! | piece | module |
//! | --- | --- |
//! | [`Executor`] / [`ExecutorBuilder`] — trait impl, running-operation registry, revocation levels 2–3 | [`executor`] |
//! | credential custody — HPKE-opened, per-grant, zeroizing, expiring | [`custody`] |
//! | `postgres.query_view` (+ experimental rotation / temporary roles) | [`connectors::postgres`] |
//! | `github.*` read operations | [`connectors::github`] |
//! | declarative `http_api.call` | [`connectors::http_api`] |
//! | egress guard (https only, pinned origin + vetted IP, SSRF ranges, no redirects, caps) | [`egress`] |
//! | output filter (field allowlists + secret detectors + exact credential match) | [`filter`] |
//! | experimental `accounts.create` / `browser.start_task` via `SiteAdapter` | `experimental` (feature) |
//!
//! Security invariants:
//! * credentials exist only in executor memory, zeroized on drop, keyed by grant, dropped on
//!   expiry / `drop_credential` / `end_sessions` / revocation; no type holding them
//!   implements `Serialize` or a revealing `Debug`;
//! * nothing returned to the broker (outcomes, errors, details) contains credential
//!   material, upstream error texts, URLs with query strings, or response headers;
//! * the model never supplies SQL, URLs, hosts or header names — only allowlisted names and
//!   typed values;
//! * all randomness comes from the OS CSPRNG (`aipass-crypto`); TLS is rustls/aws-lc-rs.
//!
//! Protection level: an executor embedded in the desktop app shares the user's environment
//! and is `compatible` (兼容连接); `isolated` (隔离执行) must be attested by the operator of a
//! separate host / VM. This crate has not been independently audited.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod connectors;
pub mod custody;
pub mod egress;
pub mod errors;
pub mod executor;
#[cfg(feature = "experimental")]
pub mod experimental;
pub mod filter;
pub mod schema;
pub mod tls;

pub use connectors::ConnectorDriver;
pub use custody::{CredentialCustody, InstalledCredential};
pub use egress::{DefaultResolver, EgressGuard, EgressResolver, StaticResolver, SystemResolver};
pub use executor::{DEFAULT_MAX_CREDENTIAL_TTL, Executor, ExecutorBuilder};
#[cfg(feature = "experimental")]
pub use executor::{RotationAad, open_rotation_result};
pub use filter::{FieldTree, OutputFilter, REDACTED};

/// Whether this build includes the experimental (V1.1) features.
pub const EXPERIMENTAL: bool = cfg!(feature = "experimental");
