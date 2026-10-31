// SPDX-License-Identifier: Apache-2.0
//! # aipass-client — broker API client, connection keys, pairing and cloud tunnel
//!
//! Responsibilities (CONTRACTS §1.6, §6.3, §9, §13):
//!
//! * [`BrokerClient`] — typed calls for the broker `/v1` API over a Unix domain socket
//!   (`unix:///abs/path.sock`) or HTTP(S) (rustls), with `AIPass-Sig` request signing
//!   ([`Auth::Signed`]) or bearer tokens ([`Auth::Bearer`]); error envelopes become
//!   [`aipass_types::ApiError`] ([`ClientError::Api`]).
//! * [`BrokerApi`] — the AI-facing operations as an async trait. The MCP bridge is written
//!   against it; `aipass-node` / the desktop app implement it in-process.
//! * [`keys`] — connection keys at `<AIPASS_HOME>/connections/<conn_id>.key` (0600).
//! * [`pairing`] — `POST /connections/pair` + signed status polling; approval only ever
//!   happens on a trusted device.
//! * [`endpoint`] — broker URL parsing and resolution (flag > `AIPASS_BROKER_URL` >
//!   `broker.json` > default socket).
//! * [`tunnel`] — outbound WebSocket from a node to the cloud gateway (`/v1/tunnel`).
//!
//! Security notes: the only secret this crate handles is a connection/device/node signing key
//! or a bearer token. Both are redacted from `Debug`, never put into URLs, logs or errors, and
//! HTTP redirects are disabled so credentials are never replayed to another origin. IDs are
//! never capabilities: every call is authorized by the broker against the caller's identity.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod api;
pub mod auth;
pub mod client;
pub mod endpoint;
pub mod error;
pub mod home;
pub mod keys;
pub mod pairing;
#[cfg(feature = "test-support")]
pub mod testing;
pub mod transport;
pub mod tunnel;

pub use api::{BrokerApi, UnavailableBroker};
pub use auth::Auth;
pub use client::{BrokerClient, BrokerClientBuilder, ConnectionAction};
pub use endpoint::{BrokerEndpoint, BrokerUrlSource, ResolveInputs, ResolvedBroker, resolve_broker};
pub use error::ClientError;
pub use home::AipassHome;
pub use keys::{ConnectionKey, ConnectionKeyMeta, KeyStore};
pub use transport::RawResponse;
