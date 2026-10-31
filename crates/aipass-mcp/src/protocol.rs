// SPDX-License-Identifier: Apache-2.0
//! JSON-RPC 2.0 + MCP protocol constants and helpers.

use serde_json::{Value, json};

/// Protocol versions supported, newest first.
pub const SUPPORTED_VERSIONS: [&str; 4] = ["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"];
/// Newest supported version (answered when the client asks for an unknown one).
pub const LATEST_VERSION: &str = "2025-11-25";

/// JSON-RPC parse error.
pub const PARSE_ERROR: i64 = -32700;
/// JSON-RPC invalid request.
pub const INVALID_REQUEST: i64 = -32600;
/// JSON-RPC method not found.
pub const METHOD_NOT_FOUND: i64 = -32601;
/// JSON-RPC invalid params.
pub const INVALID_PARAMS: i64 = -32602;
/// JSON-RPC internal error.
pub const INTERNAL_ERROR: i64 = -32603;
/// Request before `initialize` (implementation-defined server error range).
pub const NOT_INITIALIZED: i64 = -32002;

/// A negotiated protocol version with feature switches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ProtocolVersion {
    /// 2024-11-05.
    V2024_11_05,
    /// 2025-03-26.
    V2025_03_26,
    /// 2025-06-18.
    V2025_06_18,
    /// 2025-11-25.
    V2025_11_25,
}

impl ProtocolVersion {
    /// Parse a supported version string.
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "2024-11-05" => Self::V2024_11_05,
            "2025-03-26" => Self::V2025_03_26,
            "2025-06-18" => Self::V2025_06_18,
            "2025-11-25" => Self::V2025_11_25,
            _ => return None,
        })
    }

    /// Wire string.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::V2024_11_05 => "2024-11-05",
            Self::V2025_03_26 => "2025-03-26",
            Self::V2025_06_18 => "2025-06-18",
            Self::V2025_11_25 => "2025-11-25",
        }
    }

    /// Newest.
    pub fn latest() -> Self {
        Self::V2025_11_25
    }

    /// Negotiate: the requested version if supported, else the newest (the client then
    /// decides whether it can continue).
    pub fn negotiate(requested: &str) -> Self {
        Self::parse(requested).unwrap_or_else(Self::latest)
    }

    /// JSON-RPC batches accepted (2024-11-05 and 2025-03-26; removed in 2025-06-18).
    pub fn allows_batches(&self) -> bool {
        *self <= Self::V2025_03_26
    }

    /// Tool `annotations` (2025-03-26+).
    pub fn has_tool_annotations(&self) -> bool {
        *self >= Self::V2025_03_26
    }

    /// Tool `outputSchema`, `structuredContent` and `title` (2025-06-18+).
    pub fn has_structured_output(&self) -> bool {
        *self >= Self::V2025_06_18
    }

    /// `MCP-Protocol-Version` HTTP header is mandatory on requests after initialize.
    pub fn requires_version_header(&self) -> bool {
        *self >= Self::V2025_06_18
    }
}

/// Request id (string or integer; never null).
pub fn valid_id(id: &Value) -> bool {
    match id {
        Value::String(_) => true,
        Value::Number(n) => n.is_i64() || n.is_u64(),
        _ => false,
    }
}

/// Success response.
pub fn result(id: &Value, result: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "result": result})
}

/// Error response (`id` may be null when it could not be determined).
pub fn error(id: &Value, code: i64, message: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}})
}

/// Error response with `data`.
pub fn error_with_data(id: &Value, code: i64, message: &str, data: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message, "data": data}})
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions() {
        for v in SUPPORTED_VERSIONS {
            assert_eq!(ProtocolVersion::parse(v).unwrap().as_str(), v);
        }
        assert_eq!(ProtocolVersion::negotiate("1999-01-01"), ProtocolVersion::latest());
        assert!(ProtocolVersion::V2025_03_26.allows_batches());
        assert!(ProtocolVersion::V2024_11_05.allows_batches());
        assert!(!ProtocolVersion::V2025_06_18.allows_batches());
        assert!(!ProtocolVersion::V2024_11_05.has_tool_annotations());
        assert!(ProtocolVersion::V2025_06_18.has_structured_output());
        assert!(!ProtocolVersion::V2025_03_26.has_structured_output());
        assert_eq!(LATEST_VERSION, ProtocolVersion::latest().as_str());
    }

    #[test]
    fn ids() {
        assert!(valid_id(&json!(1)));
        assert!(valid_id(&json!("a")));
        assert!(!valid_id(&json!(null)));
        assert!(!valid_id(&json!(1.5)));
        assert!(!valid_id(&json!({})));
    }
}
