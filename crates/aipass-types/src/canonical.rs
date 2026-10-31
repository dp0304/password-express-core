// SPDX-License-Identifier: Apache-2.0
//! RFC 8785 JSON Canonicalization Scheme (JCS) for the AI Pass value subset (CONTRACTS §1.4).
//!
//! Signed or hashed payloads may contain only strings, integers with |n| < 2^53, booleans,
//! null, arrays and objects. Floats (including integral floats like `1.0` produced by
//! serde) and out-of-range integers are **rejected**, never silently converted.
//!
//! Output rules (RFC 8785 §3.2): no whitespace; object members sorted by the UTF-16 code
//! units of their names; strings serialized as ECMAScript `JSON.stringify` does (escape `"`,
//! `\` and U+0000–U+001F using `\b \t \n \f \r` or lowercase `\u00xx`; everything else
//! literal UTF-8); integers in plain decimal.
//!
//! This is the single implementation used by every digest and signature in Rust (broker,
//! CLI, desktop, FFI). TypeScript/Python never compute approval digests.

use serde::Serialize;
use serde_json::{Map, Value};
use thiserror::Error;

/// Largest integer allowed in canonical payloads (2^53 − 1).
pub const MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991;

/// Canonicalization failure.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CanonicalError {
    /// A floating-point number was present.
    #[error("floats are not allowed in canonical payloads")]
    Float,
    /// An integer outside ±(2^53 − 1).
    #[error("integer outside the safe range ±(2^53-1)")]
    IntegerOutOfRange,
    /// The value could not be converted to JSON.
    #[error("value is not representable as JSON: {0}")]
    Serialize(String),
    /// A field expected for removal / signing was missing or the value was not an object.
    #[error("expected a JSON object")]
    NotAnObject,
}

/// Canonical JSON bytes of any serializable value.
pub fn to_jcs_bytes<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>, CanonicalError> {
    let v = serde_json::to_value(value).map_err(|e| CanonicalError::Serialize(e.to_string()))?;
    value_to_jcs(&v)
}

/// Canonical JSON text of any serializable value.
pub fn to_jcs_string<T: Serialize + ?Sized>(value: &T) -> Result<String, CanonicalError> {
    let bytes = to_jcs_bytes(value)?;
    // The writer only emits valid UTF-8.
    String::from_utf8(bytes).map_err(|e| CanonicalError::Serialize(e.to_string()))
}

/// Canonical JSON bytes of a `serde_json::Value`.
pub fn value_to_jcs(value: &Value) -> Result<Vec<u8>, CanonicalError> {
    let mut out = Vec::with_capacity(128);
    write_value(value, &mut out)?;
    Ok(out)
}

/// Parse JSON text and canonicalize it (rejects floats / unsafe integers).
pub fn canonicalize_json_text(text: &str) -> Result<Vec<u8>, CanonicalError> {
    let v: Value =
        serde_json::from_str(text).map_err(|e| CanonicalError::Serialize(e.to_string()))?;
    value_to_jcs(&v)
}

/// b64u(SHA-256(JCS(value))).
pub fn jcs_sha256_b64u<T: Serialize + ?Sized>(value: &T) -> Result<String, CanonicalError> {
    Ok(aipass_crypto::sha256_b64u(to_jcs_bytes(value)?))
}

/// JCS of `value` with the top-level member `field` removed — the "object minus signature"
/// construction used for VaultHeader, MemberRecord, Manifest, Policy, RelayEnvelope and
/// device control messages.
pub fn jcs_without_field<T: Serialize + ?Sized>(
    value: &T,
    field: &str,
) -> Result<Vec<u8>, CanonicalError> {
    let mut v =
        serde_json::to_value(value).map_err(|e| CanonicalError::Serialize(e.to_string()))?;
    let obj = v.as_object_mut().ok_or(CanonicalError::NotAnObject)?;
    obj.remove(field);
    value_to_jcs(&v)
}

/// Same as [`jcs_without_field`] but on raw JSON (preserves unknown members, so newer
/// writers' fields stay covered by the signature).
pub fn value_jcs_without_field(value: &Value, field: &str) -> Result<Vec<u8>, CanonicalError> {
    let obj = value.as_object().ok_or(CanonicalError::NotAnObject)?;
    let mut copy: Map<String, Value> = obj.clone();
    copy.remove(field);
    value_to_jcs(&Value::Object(copy))
}

fn write_value(v: &Value, out: &mut Vec<u8>) -> Result<(), CanonicalError> {
    match v {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                if !(-MAX_SAFE_INTEGER..=MAX_SAFE_INTEGER).contains(&i) {
                    return Err(CanonicalError::IntegerOutOfRange);
                }
                out.extend_from_slice(i.to_string().as_bytes());
            } else if n.as_u64().is_some() {
                // u64 that does not fit i64 is necessarily > 2^53.
                return Err(CanonicalError::IntegerOutOfRange);
            } else {
                return Err(CanonicalError::Float);
            }
        }
        Value::String(s) => write_string(s, out),
        Value::Array(items) => {
            out.push(b'[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_value(item, out)?;
            }
            out.push(b']');
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
            out.push(b'{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_string(k, out);
                out.push(b':');
                // key came from the map, so the lookup succeeds
                if let Some(val) = map.get(*k) {
                    write_value(val, out)?;
                }
            }
            out.push(b'}');
        }
    }
    Ok(())
}

fn write_string(s: &str, out: &mut Vec<u8>) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    out.push(b'"');
    for ch in s.chars() {
        match ch {
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(b"\\\\"),
            '\u{08}' => out.extend_from_slice(b"\\b"),
            '\t' => out.extend_from_slice(b"\\t"),
            '\n' => out.extend_from_slice(b"\\n"),
            '\u{0c}' => out.extend_from_slice(b"\\f"),
            '\r' => out.extend_from_slice(b"\\r"),
            c if (c as u32) < 0x20 => {
                let b = c as u32 as u8;
                out.extend_from_slice(b"\\u00");
                out.push(HEX[(b >> 4) as usize]);
                out.push(HEX[(b & 0xf) as usize]);
            }
            c => {
                let mut buf = [0u8; 4];
                out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            }
        }
    }
    out.push(b'"');
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn rfc8785_sorting_example() {
        // RFC 8785 §3.2.3 — keys ordered by UTF-16 code units (emoji surrogates sort before U+FB33).
        let text = r#"{"\u20ac":"Euro Sign","\r":"Carriage Return","\ufb33":"Hebrew Letter Dalet With Dagesh","1":"One","\ud83d\ude00":"Emoji: Grinning Face","\u0080":"Control","\u00f6":"Latin Small Letter O With Diaeresis"}"#;
        let out = String::from_utf8(canonicalize_json_text(text).unwrap()).unwrap();
        assert_eq!(
            out,
            "{\"\\r\":\"Carriage Return\",\"1\":\"One\",\"\u{80}\":\"Control\",\"\u{f6}\":\"Latin Small Letter O With Diaeresis\",\"\u{20ac}\":\"Euro Sign\",\"\u{1f600}\":\"Emoji: Grinning Face\",\"\u{fb33}\":\"Hebrew Letter Dalet With Dagesh\"}"
        );
    }

    #[test]
    fn rfc8785_string_and_literals() {
        let text = r#"{"string":"\u20ac$\u000F\u000aA'\u0042\u0022\u005c\\\"\/","literals":[null,true,false]}"#;
        let out = String::from_utf8(canonicalize_json_text(text).unwrap()).unwrap();
        assert_eq!(
            out,
            "{\"literals\":[null,true,false],\"string\":\"\u{20ac}$\\u000f\\nA'B\\\"\\\\\\\\\\\"/\"}"
        );
    }

    #[test]
    fn rejects_floats_and_big_ints() {
        assert_eq!(value_to_jcs(&json!({"a": 1.5})), Err(CanonicalError::Float));
        assert_eq!(value_to_jcs(&json!([1.0])), Err(CanonicalError::Float));
        assert_eq!(
            value_to_jcs(&json!(9_007_199_254_740_992i64)),
            Err(CanonicalError::IntegerOutOfRange)
        );
        assert_eq!(
            value_to_jcs(&json!(u64::MAX)),
            Err(CanonicalError::IntegerOutOfRange)
        );
        assert_eq!(
            value_to_jcs(&json!(-9_007_199_254_740_992i64)),
            Err(CanonicalError::IntegerOutOfRange)
        );
        assert_eq!(
            value_to_jcs(&json!(9_007_199_254_740_991i64)).unwrap(),
            b"9007199254740991"
        );
        assert_eq!(
            value_to_jcs(&json!(-9_007_199_254_740_991i64)).unwrap(),
            b"-9007199254740991"
        );
        assert!(canonicalize_json_text("1E30").is_err());
    }

    #[test]
    fn nested_and_without_field() {
        let v = json!({"b": {"z": [3, {"y": null, "x": "\u{2028}"}], "a": true}, "a": "", "signature": "sig"});
        assert_eq!(
            String::from_utf8(value_to_jcs(&v).unwrap()).unwrap(),
            "{\"a\":\"\",\"b\":{\"a\":true,\"z\":[3,{\"x\":\"\u{2028}\",\"y\":null}]},\"signature\":\"sig\"}"
        );
        assert_eq!(
            String::from_utf8(value_jcs_without_field(&v, "signature").unwrap()).unwrap(),
            "{\"a\":\"\",\"b\":{\"a\":true,\"z\":[3,{\"x\":\"\u{2028}\",\"y\":null}]}}"
        );
        assert_eq!(
            jcs_without_field(&v, "signature").unwrap(),
            value_jcs_without_field(&v, "signature").unwrap()
        );
        assert_eq!(
            jcs_without_field(&json!([1]), "x"),
            Err(CanonicalError::NotAnObject)
        );
    }

    #[test]
    fn control_characters() {
        let v = json!("\u{0}\u{1f}\u{7f}");
        assert_eq!(
            String::from_utf8(value_to_jcs(&v).unwrap()).unwrap(),
            "\"\\u0000\\u001f\u{7f}\""
        );
    }
}
