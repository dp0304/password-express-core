// SPDX-License-Identifier: Apache-2.0
//! The transport-independent MCP server: JSON-RPC 2.0 + MCP lifecycle, version negotiation,
//! `tools/list` / `tools/call`, batching rules per version and robust handling of malformed
//! input. Transports ([`crate::stdio`], [`crate::http`]) call [`McpServer::handle`].

use std::sync::{Arc, Mutex};

use aipass_client::BrokerApi;
use aipass_types::Lang;
use futures::future::join_all;
use serde_json::{Value, json};

use crate::protocol::{
    self, INVALID_PARAMS, INVALID_REQUEST, METHOD_NOT_FOUND, NOT_INITIALIZED, PARSE_ERROR,
    ProtocolVersion,
};
use crate::tools::{self, ToolDef};

/// Largest accepted JSON-RPC message (bytes).
pub const MAX_MESSAGE_BYTES: usize = 4 * 1024 * 1024;
/// Largest accepted batch.
pub const MAX_BATCH: usize = 64;

/// Server configuration.
#[derive(Debug, Clone)]
pub struct McpServerConfig {
    /// Offer the V1.1 experimental tools (`--experimental`).
    pub experimental: bool,
    /// Language for titles and error messages (hints are always bilingual).
    pub lang: Lang,
    /// `serverInfo.version`.
    pub version: String,
}

impl Default for McpServerConfig {
    fn default() -> Self {
        Self {
            experimental: false,
            lang: Lang::ZhCn,
            version: env!("CARGO_PKG_VERSION").to_owned(),
        }
    }
}

/// Per-session state (one stdio process, or one `Mcp-Session-Id`).
#[derive(Debug, Default)]
pub struct McpSession {
    inner: Mutex<SessionInner>,
}

#[derive(Debug, Default, Clone)]
struct SessionInner {
    version: Option<ProtocolVersion>,
    initialized: bool,
    client_name: Option<String>,
}

impl McpSession {
    /// New, uninitialized session.
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    fn get(&self) -> SessionInner {
        match self.inner.lock() {
            Ok(g) => g.clone(),
            Err(p) => p.into_inner().clone(),
        }
    }

    fn update(&self, f: impl FnOnce(&mut SessionInner)) {
        let mut g = match self.inner.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        f(&mut g);
    }

    /// Negotiated version (after `initialize`).
    pub fn protocol_version(&self) -> Option<ProtocolVersion> {
        self.get().version
    }

    /// `notifications/initialized` received.
    pub fn is_initialized(&self) -> bool {
        self.get().initialized
    }

    /// `clientInfo.name` — a label for logs only, never identity (§7.3).
    pub fn client_name(&self) -> Option<String> {
        self.get().client_name
    }
}

/// What a message is handled against.
#[derive(Clone)]
pub struct McpContext {
    /// The broker, bound to one authenticated connection.
    pub broker: Arc<dyn BrokerApi>,
    /// Session state.
    pub session: Arc<McpSession>,
}

impl McpContext {
    /// New context with a fresh session.
    pub fn new(broker: Arc<dyn BrokerApi>) -> Self {
        Self {
            broker,
            session: McpSession::new(),
        }
    }
}

/// The MCP server (stateless; share it behind an `Arc`).
pub struct McpServer {
    config: McpServerConfig,
    tools: Vec<ToolDef>,
}

impl McpServer {
    /// Build with the tool set implied by `config.experimental`.
    pub fn new(config: McpServerConfig) -> Self {
        let tools = tools::all_tools()
            .into_iter()
            .filter(|t| config.experimental || !t.experimental)
            .collect();
        Self { config, tools }
    }

    /// Configuration.
    pub fn config(&self) -> &McpServerConfig {
        &self.config
    }

    /// Offered tools.
    pub fn tools(&self) -> &[ToolDef] {
        &self.tools
    }

    /// Server instructions (design doc §7.6).
    pub fn instructions(&self) -> String {
        crate::instructions::text(self.config.experimental)
    }

    /// Handle one raw message (a single JSON-RPC message or a batch). Returns the response to
    /// send, or `None` when nothing must be sent (notifications, client responses).
    pub async fn handle(&self, message: &[u8], ctx: &McpContext) -> Option<Value> {
        if message.len() > MAX_MESSAGE_BYTES {
            return Some(protocol::error(&Value::Null, INVALID_REQUEST, "message too large"));
        }
        let value: Value = match serde_json::from_slice(message) {
            Ok(v) => v,
            Err(_) => return Some(protocol::error(&Value::Null, PARSE_ERROR, "Parse error")),
        };
        self.handle_value(value, ctx).await
    }

    /// Handle a parsed message or batch.
    pub async fn handle_value(&self, value: Value, ctx: &McpContext) -> Option<Value> {
        match value {
            Value::Array(items) => {
                let batches_ok = ctx
                    .session
                    .protocol_version()
                    .is_some_and(|v| v.allows_batches());
                if !batches_ok {
                    return Some(protocol::error(
                        &Value::Null,
                        INVALID_REQUEST,
                        "JSON-RPC batches are not supported by the negotiated protocol version",
                    ));
                }
                if items.is_empty() || items.len() > MAX_BATCH {
                    return Some(protocol::error(&Value::Null, INVALID_REQUEST, "invalid batch size"));
                }
                let responses: Vec<Value> = join_all(items.into_iter().map(|m| self.handle_one(m, ctx, true)))
                    .await
                    .into_iter()
                    .flatten()
                    .collect();
                if responses.is_empty() { None } else { Some(Value::Array(responses)) }
            }
            other => self.handle_one(other, ctx, false).await,
        }
    }

    async fn handle_one(&self, msg: Value, ctx: &McpContext, in_batch: bool) -> Option<Value> {
        let Value::Object(obj) = &msg else {
            return Some(protocol::error(&Value::Null, INVALID_REQUEST, "Invalid Request"));
        };
        let id = obj.get("id").cloned();
        let id_for_error = id.clone().filter(protocol::valid_id).unwrap_or(Value::Null);
        if obj.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
            return Some(protocol::error(&id_for_error, INVALID_REQUEST, "Invalid Request: jsonrpc must be \"2.0\""));
        }
        let Some(method) = obj.get("method") else {
            if obj.contains_key("result") || obj.contains_key("error") {
                // a response from the client — this server never sends requests; ignore
                return None;
            }
            return Some(protocol::error(&id_for_error, INVALID_REQUEST, "Invalid Request"));
        };
        let Some(method) = method.as_str() else {
            return Some(protocol::error(&id_for_error, INVALID_REQUEST, "Invalid Request: method must be a string"));
        };
        let params = obj.get("params").cloned().unwrap_or(Value::Null);
        if !(params.is_null() || params.is_object()) {
            return id.map(|_| protocol::error(&id_for_error, INVALID_PARAMS, "params must be an object"));
        }
        let Some(id) = id else {
            self.notification(method, ctx);
            return None;
        };
        if !protocol::valid_id(&id) {
            return Some(protocol::error(&Value::Null, INVALID_REQUEST, "Invalid Request: id must be a string or an integer"));
        }
        Some(self.request(&id, method, &params, ctx, in_batch).await)
    }

    fn notification(&self, method: &str, ctx: &McpContext) {
        match method {
            "notifications/initialized" => {
                if ctx.session.protocol_version().is_some() {
                    ctx.session.update(|s| s.initialized = true);
                }
            }
            // cancellation of an in-flight request: broker operations are not cancelled by
            // this (use operations_cancel); nothing to do.
            "notifications/cancelled" => {}
            other => tracing::debug!(method = other, "ignoring notification"),
        }
    }

    async fn request(&self, id: &Value, method: &str, params: &Value, ctx: &McpContext, in_batch: bool) -> Value {
        if method == "initialize" {
            return self.initialize(id, params, ctx, in_batch);
        }
        if method == "ping" {
            return protocol::result(id, json!({}));
        }
        let Some(version) = ctx.session.protocol_version() else {
            return protocol::error(id, NOT_INITIALIZED, "Server not initialized: send initialize first");
        };
        match method {
            "tools/list" => {
                if params.get("cursor").is_some_and(|c| !c.is_null()) {
                    return protocol::error(id, INVALID_PARAMS, "Invalid cursor");
                }
                let tools: Vec<Value> = self
                    .tools
                    .iter()
                    .map(|t| t.to_json(version, self.config.lang))
                    .collect();
                protocol::result(id, json!({"tools": tools}))
            }
            "tools/call" => self.tools_call(id, params, ctx, version).await,
            "resources/list" => protocol::result(id, json!({"resources": []})),
            "resources/templates/list" => protocol::result(id, json!({"resourceTemplates": []})),
            "prompts/list" => protocol::result(id, json!({"prompts": []})),
            _ => protocol::error(id, METHOD_NOT_FOUND, "Method not found"),
        }
    }

    fn initialize(&self, id: &Value, params: &Value, ctx: &McpContext, in_batch: bool) -> Value {
        if in_batch {
            return protocol::error(id, INVALID_REQUEST, "initialize must not be part of a batch");
        }
        if ctx.session.protocol_version().is_some() {
            return protocol::error(id, INVALID_REQUEST, "Session already initialized");
        }
        let Some(requested) = params.get("protocolVersion").and_then(Value::as_str) else {
            return protocol::error(id, INVALID_PARAMS, "protocolVersion is required");
        };
        let version = ProtocolVersion::negotiate(requested);
        let client_name = params
            .pointer("/clientInfo/name")
            .and_then(Value::as_str)
            .map(|n| n.chars().take(64).collect::<String>());
        tracing::info!(
            requested,
            negotiated = version.as_str(),
            client = client_name.as_deref().unwrap_or("?"),
            "MCP session initialized (clientInfo.name is a label, not identity)"
        );
        ctx.session.update(|s| {
            s.version = Some(version);
            s.client_name = client_name;
        });
        let mut server_info = json!({"name": "aipass", "version": self.config.version});
        if version.has_structured_output() {
            server_info["title"] = json!("AI 通行证 (AI Pass)");
        }
        if version >= ProtocolVersion::V2025_11_25 {
            server_info["websiteUrl"] = json!("https://aipass.example");
        }
        protocol::result(
            id,
            json!({
                "protocolVersion": version.as_str(),
                "capabilities": {"tools": {"listChanged": false}},
                "serverInfo": server_info,
                "instructions": self.instructions(),
            }),
        )
    }

    async fn tools_call(&self, id: &Value, params: &Value, ctx: &McpContext, version: ProtocolVersion) -> Value {
        let Some(name) = params.get("name").and_then(Value::as_str) else {
            return protocol::error(id, INVALID_PARAMS, "tools/call needs a tool name");
        };
        let Some(def) = self.tools.iter().find(|t| t.name == name) else {
            let shown: String = name.chars().take(64).collect();
            return protocol::error(id, INVALID_PARAMS, &format!("Unknown tool: {shown}"));
        };
        let args = match params.get("arguments") {
            None | Some(Value::Null) => json!({}),
            Some(v @ Value::Object(_)) => v.clone(),
            Some(_) => {
                let out = tools::error_output(
                    &aipass_types::ApiError::invalid_request("arguments 必须是对象", "arguments must be an object"),
                    self.config.lang,
                );
                return protocol::result(id, out.to_result(version));
            }
        };
        let started = std::time::Instant::now();
        let out = tools::call_tool(def, &args, ctx.broker.as_ref(), self.config.lang).await;
        tracing::info!(
            tool = def.name,
            is_error = out.is_error,
            ms = started.elapsed().as_millis() as u64,
            "tools/call"
        );
        protocol::result(id, out.to_result(version))
    }
}
