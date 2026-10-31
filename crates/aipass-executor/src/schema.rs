// SPDX-License-Identifier: Apache-2.0
//! A deliberately small JSON-Schema subset validator for declarative `http_api` request
//! bodies (`body_schema`). Unsupported keywords make the *schema* invalid (fail closed)
//! rather than being ignored.
//!
//! Supported: `type` (`object`, `string`, `integer`, `boolean`, `array`, `null`),
//! `properties`, `required`, `additionalProperties` (boolean, **default false**),
//! `maxProperties`, `enum` (strings/integers), `minLength`, `maxLength` (default 4096),
//! `pattern` (full-match), `minimum`, `maximum`, `items`, `minItems`, `maxItems`
//! (default 100), plus the annotations `title`, `description`, `default`, `examples`.
//! Floats are rejected everywhere (signed/hashed payloads are integer-only, CONTRACTS §1.4).

use regex::Regex;
use serde_json::Value;

/// Maximum nesting depth of a validated value.
pub const MAX_DEPTH: usize = 16;
/// Default string length cap.
pub const DEFAULT_MAX_LENGTH: u64 = 4096;
/// Default array length cap.
pub const DEFAULT_MAX_ITEMS: u64 = 100;
/// JSON-safe integer bound (2^53 − 1).
pub const MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991;

const KNOWN: &[&str] = &[
    "type",
    "properties",
    "required",
    "additionalProperties",
    "maxProperties",
    "enum",
    "minLength",
    "maxLength",
    "pattern",
    "minimum",
    "maximum",
    "items",
    "minItems",
    "maxItems",
    "title",
    "description",
    "default",
    "examples",
];

/// Check that `schema` only uses the supported subset. Returns the JSON pointer of the first
/// problem.
pub fn check_schema(schema: &Value) -> Result<(), String> {
    check_schema_at(schema, "", 0)
}

fn check_schema_at(schema: &Value, at: &str, depth: usize) -> Result<(), String> {
    if depth > MAX_DEPTH {
        return Err(format!("{at}: too deep"));
    }
    let obj = schema
        .as_object()
        .ok_or_else(|| format!("{at}: schema must be an object"))?;
    for k in obj.keys() {
        if !KNOWN.contains(&k.as_str()) {
            return Err(format!("{at}/{k}: unsupported keyword"));
        }
    }
    let ty = obj
        .get("type")
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{at}/type: required string"))?;
    match ty {
        "object" => {
            if let Some(props) = obj.get("properties") {
                let props = props
                    .as_object()
                    .ok_or_else(|| format!("{at}/properties: must be an object"))?;
                for (name, sub) in props {
                    check_schema_at(sub, &format!("{at}/properties/{name}"), depth + 1)?;
                }
            }
            if let Some(req) = obj.get("required") {
                let ok = req
                    .as_array()
                    .is_some_and(|a| a.iter().all(|v| v.is_string()));
                if !ok {
                    return Err(format!("{at}/required: must be an array of strings"));
                }
            }
            if let Some(ap) = obj.get("additionalProperties")
                && !ap.is_boolean()
            {
                return Err(format!("{at}/additionalProperties: must be a boolean"));
            }
        }
        "array" => {
            let items = obj
                .get("items")
                .ok_or_else(|| format!("{at}/items: required for arrays"))?;
            check_schema_at(items, &format!("{at}/items"), depth + 1)?;
        }
        "string" => {
            if let Some(p) = obj.get("pattern") {
                let p = p
                    .as_str()
                    .ok_or_else(|| format!("{at}/pattern: must be a string"))?;
                Regex::new(&format!("^(?:{p})$")).map_err(|_| format!("{at}/pattern: invalid"))?;
            }
        }
        "integer" | "boolean" | "null" => {}
        other => return Err(format!("{at}/type: unsupported type {other}")),
    }
    for k in [
        "minLength",
        "maxLength",
        "minItems",
        "maxItems",
        "maxProperties",
    ] {
        if let Some(v) = obj.get(k)
            && v.as_u64().is_none()
        {
            return Err(format!("{at}/{k}: must be a non-negative integer"));
        }
    }
    for k in ["minimum", "maximum"] {
        if let Some(v) = obj.get(k)
            && v.as_i64().is_none()
        {
            return Err(format!("{at}/{k}: must be an integer"));
        }
    }
    if let Some(e) = obj.get("enum") {
        let ok = e
            .as_array()
            .is_some_and(|a| !a.is_empty() && a.iter().all(|v| v.is_string() || v.is_i64()));
        if !ok {
            return Err(format!(
                "{at}/enum: must be a non-empty array of strings/integers"
            ));
        }
    }
    Ok(())
}

/// Validate `value` against `schema`. The error names the path of the offending value
/// (never the value itself).
pub fn validate(schema: &Value, value: &Value) -> Result<(), String> {
    validate_at(schema, value, "$", 0)
}

fn validate_at(schema: &Value, value: &Value, at: &str, depth: usize) -> Result<(), String> {
    if depth > MAX_DEPTH {
        return Err(format!("{at}: too deep"));
    }
    let obj = schema
        .as_object()
        .ok_or_else(|| format!("{at}: invalid schema"))?;
    let ty = obj.get("type").and_then(Value::as_str).unwrap_or("");
    if let Some(Value::Array(allowed)) = obj.get("enum")
        && !allowed.contains(value)
    {
        return Err(format!("{at}: value not in enum"));
    }
    match (ty, value) {
        ("null", Value::Null) => Ok(()),
        ("boolean", Value::Bool(_)) => Ok(()),
        ("integer", Value::Number(n)) => {
            let i = n
                .as_i64()
                .filter(|i| i.abs() <= MAX_SAFE_INTEGER)
                .ok_or_else(|| format!("{at}: must be a safe integer"))?;
            if let Some(min) = obj.get("minimum").and_then(Value::as_i64)
                && i < min
            {
                return Err(format!("{at}: below minimum"));
            }
            if let Some(max) = obj.get("maximum").and_then(Value::as_i64)
                && i > max
            {
                return Err(format!("{at}: above maximum"));
            }
            Ok(())
        }
        ("string", Value::String(s)) => {
            let len = s.chars().count() as u64;
            let max = obj
                .get("maxLength")
                .and_then(Value::as_u64)
                .unwrap_or(DEFAULT_MAX_LENGTH);
            if len > max {
                return Err(format!("{at}: too long"));
            }
            if let Some(min) = obj.get("minLength").and_then(Value::as_u64)
                && len < min
            {
                return Err(format!("{at}: too short"));
            }
            if s.contains('\0') {
                return Err(format!("{at}: contains NUL"));
            }
            if let Some(p) = obj.get("pattern").and_then(Value::as_str) {
                let re = Regex::new(&format!("^(?:{p})$"))
                    .map_err(|_| format!("{at}: invalid pattern"))?;
                if !re.is_match(s) {
                    return Err(format!("{at}: does not match pattern"));
                }
            }
            Ok(())
        }
        ("array", Value::Array(items)) => {
            let max = obj
                .get("maxItems")
                .and_then(Value::as_u64)
                .unwrap_or(DEFAULT_MAX_ITEMS);
            if items.len() as u64 > max {
                return Err(format!("{at}: too many items"));
            }
            if let Some(min) = obj.get("minItems").and_then(Value::as_u64)
                && (items.len() as u64) < min
            {
                return Err(format!("{at}: too few items"));
            }
            let item_schema = obj
                .get("items")
                .ok_or_else(|| format!("{at}: invalid schema"))?;
            for (i, v) in items.iter().enumerate() {
                validate_at(item_schema, v, &format!("{at}[{i}]"), depth + 1)?;
            }
            Ok(())
        }
        ("object", Value::Object(map)) => {
            let empty = serde_json::Map::new();
            let props = obj
                .get("properties")
                .and_then(Value::as_object)
                .unwrap_or(&empty);
            let additional = obj
                .get("additionalProperties")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            if let Some(max) = obj.get("maxProperties").and_then(Value::as_u64)
                && map.len() as u64 > max
            {
                return Err(format!("{at}: too many properties"));
            }
            if let Some(Value::Array(req)) = obj.get("required") {
                for r in req.iter().filter_map(Value::as_str) {
                    if !map.contains_key(r) {
                        return Err(format!("{at}.{r}: required"));
                    }
                }
            }
            for (k, v) in map {
                match props.get(k) {
                    Some(sub) => validate_at(sub, v, &format!("{at}.{k}"), depth + 1)?,
                    None if additional => reject_floats(v, &format!("{at}.{k}"), depth + 1)?,
                    None => return Err(format!("{at}.{k}: unknown property")),
                }
            }
            Ok(())
        }
        _ => Err(format!("{at}: expected {ty}")),
    }
}

fn reject_floats(v: &Value, at: &str, depth: usize) -> Result<(), String> {
    if depth > MAX_DEPTH {
        return Err(format!("{at}: too deep"));
    }
    match v {
        Value::Number(n) if n.as_i64().is_none_or(|i| i.abs() > MAX_SAFE_INTEGER) => {
            Err(format!("{at}: only safe integers are allowed"))
        }
        Value::Array(a) => a.iter().try_for_each(|x| reject_floats(x, at, depth + 1)),
        Value::Object(m) => m.values().try_for_each(|x| reject_floats(x, at, depth + 1)),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn subset_validation() {
        let s = json!({"type":"object","required":["amount"],"properties":{
            "amount":{"type":"integer","minimum":1,"maximum":10000},
            "reason":{"type":"string","enum":["duplicate","fraud"]},
            "tags":{"type":"array","items":{"type":"string","maxLength":8},"maxItems":3}
        }});
        check_schema(&s).unwrap();
        validate(&s, &json!({"amount": 5, "reason": "fraud"})).unwrap();
        assert!(validate(&s, &json!({"amount": 0})).is_err());
        assert!(validate(&s, &json!({"amount": 5, "extra": 1})).is_err());
        assert!(validate(&s, &json!({"amount": 5.5})).is_err());
        assert!(validate(&s, &json!({"reason": "fraud"})).is_err());
        assert!(validate(&s, &json!({"amount": 1, "tags": ["a","b","c","d"]})).is_err());
        assert!(validate(&s, &json!({"amount": 1, "reason": "other"})).is_err());
        assert!(check_schema(&json!({"type":"object","$ref":"#/x"})).is_err());
        assert!(check_schema(&json!({"type":"number"})).is_err());
    }
}
