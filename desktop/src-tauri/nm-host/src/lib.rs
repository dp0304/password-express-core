// SPDX-License-Identifier: Apache-2.0
//! Native-messaging plumbing shared by the `aipass-nm-host` binary and the desktop app.
//!
//! * [`frame`] — Chrome native-messaging framing (u32 little-endian length + UTF-8 JSON),
//!   used both on the browser side (stdin/stdout) and on the desktop IPC side.
//! * [`ipc`] — where the desktop IPC endpoint and its per-install token live, the auth
//!   handshake, and a small client used by the host binary.
//! * [`proto`] — request/response envelope helpers (CONTRACTS §11).
//!
//! Nothing in this crate ever logs message bodies: they may carry passwords (`fill`
//! responses, `save` requests).

pub mod frame;
pub mod ipc;
pub mod proto;
