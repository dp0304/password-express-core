// SPDX-License-Identifier: Apache-2.0
//! # aipass-node — self-host server
//!
//! One process serving (CONTRACTS §1.7, §3.3, §4, §6, §9):
//! broker `/v1/*`, ciphertext sync `/v1/vaults*`, E2E relay `/v1/relay*`, remote MCP `/mcp`
//! (node-issued `aipc_` bearer tokens) and `/v1/health`, with an embedded executor
//! (`aipass-executor`) whose protection level is reported honestly: `compatible` unless the
//! operator attests a separate host/VM (`isolated`).
//!
//! * [`runtime::start`] — build and serve everything; returns a [`runtime::RunningNode`].
//! * [`pair::run_pairing`] — executor pairing (§5) as the new device.
//! * [`cloud::link`] / [`cloud::spawn_tunnel`] — optional commercial gateway link.
//! * [`enroll::FileEnrollAdmission`] — one-time enroll tokens for vault creation.

pub mod cloud;
pub mod config;
pub mod enroll;
pub mod fsutil;
pub mod identity;
pub mod pair;
pub mod relay_link;
pub mod remote_mcp;
pub mod runtime;

pub use config::NodeConfig;
pub use identity::NodeIdentity;
pub use runtime::{RunningNode, StartOptions, start};
