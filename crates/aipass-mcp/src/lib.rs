// SPDX-License-Identifier: Apache-2.0
//! # aipass-mcp — MCP bridge
//!
//! Responsibilities (CONTRACTS §9; design doc §7.3, §7.6, §12.1–12.3):
//!
//! * [`McpServer`] — JSON-RPC 2.0 MCP server core: lifecycle, protocol version negotiation
//!   (`2025-11-25`, `2025-06-18`, `2025-03-26`, `2024-11-05`), `tools/list` with input and
//!   output schemas, `tools/call` → [`aipass_client::BrokerApi`], `structuredContent` + text
//!   content, `isError` mapping, bilingual server instructions, batching rules per version.
//!   Library entry point: [`McpServer::handle`]`(message, ctx) -> Option<response>`.
//! * Transports: [`stdio`] (stdout carries protocol messages only) and Streamable HTTP
//!   ([`http::StreamableHttp`], axum; usable by `aipass-node` for `/mcp` and tunnel frames).
//! * Tools use underscores (`resources_list`, `operations_request`, …). `approval_required`
//!   is not an error: the model is told to ask the user to approve on a trusted device and
//!   never to request passwords or keys in chat. No tool returns raw credentials, and there is
//!   no keyed `exec` or arbitrary HTTP forwarding.
//! * The bridge holds no business secrets — only its connection key.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod doctor;
pub mod http;
pub mod instructions;
pub mod protocol;
pub mod server;
pub mod stdio;
pub mod tools;

pub use http::{BearerResolver, HttpConfig, HttpMode, HttpReply, McpHttpRequest, Principal, StreamableHttp};
pub use protocol::{LATEST_VERSION, ProtocolVersion, SUPPORTED_VERSIONS};
pub use server::{McpContext, McpServer, McpServerConfig, McpSession};
