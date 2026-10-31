// SPDX-License-Identifier: Apache-2.0
//! Time helpers (CONTRACTS §1.3): RFC 3339 UTC with `Z`, **second precision** in anything
//! signed; signature headers use unix seconds.

use chrono::{DateTime, SecondsFormat, TimeZone, Timelike, Utc};
use thiserror::Error;

/// A UTC timestamp. Serialize with [`rfc3339`] to get the canonical wire form.
pub type Timestamp = DateTime<Utc>;

/// Error parsing a timestamp.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("invalid RFC 3339 timestamp")]
pub struct TimeError;

/// Current time truncated to whole seconds.
pub fn now() -> Timestamp {
    truncate(Utc::now())
}

/// Current unix time in seconds.
pub fn unix_now() -> i64 {
    Utc::now().timestamp()
}

/// Drop sub-second precision.
pub fn truncate(t: Timestamp) -> Timestamp {
    t.with_nanosecond(0).unwrap_or(t)
}

/// Timestamp from unix seconds.
pub fn from_unix(secs: i64) -> Option<Timestamp> {
    Utc.timestamp_opt(secs, 0).single()
}

/// Canonical form: `2026-10-30T12:00:00Z`.
pub fn format_rfc3339(t: &Timestamp) -> String {
    truncate(*t).to_rfc3339_opts(SecondsFormat::Secs, true)
}

/// Parse any RFC 3339 timestamp, convert to UTC and truncate to seconds.
pub fn parse_rfc3339(s: &str) -> Result<Timestamp, TimeError> {
    DateTime::parse_from_rfc3339(s)
        .map(|t| truncate(t.with_timezone(&Utc)))
        .map_err(|_| TimeError)
}

/// Add seconds (saturating at the representable range).
pub fn add_secs(t: &Timestamp, secs: i64) -> Timestamp {
    t.checked_add_signed(chrono::Duration::seconds(secs))
        .unwrap_or(*t)
}

/// serde adapter: `#[serde(with = "aipass_types::time::rfc3339")]`.
pub mod rfc3339 {
    use super::*;
    use serde::{Deserialize, Deserializer, Serializer};

    /// Serialize as canonical RFC 3339 (seconds, `Z`).
    pub fn serialize<S: Serializer>(t: &Timestamp, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&format_rfc3339(t))
    }

    /// Deserialize any RFC 3339 timestamp.
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Timestamp, D::Error> {
        let s = String::deserialize(d)?;
        parse_rfc3339(&s).map_err(serde::de::Error::custom)
    }
}

/// serde adapter for `Option<Timestamp>` (`null` when absent):
/// `#[serde(default, with = "aipass_types::time::rfc3339_option")]`.
pub mod rfc3339_option {
    use super::*;
    use serde::{Deserialize, Deserializer, Serializer};

    /// Serialize as canonical RFC 3339 or null.
    pub fn serialize<S: Serializer>(t: &Option<Timestamp>, s: S) -> Result<S::Ok, S::Error> {
        match t {
            Some(t) => s.serialize_str(&format_rfc3339(t)),
            None => s.serialize_none(),
        }
    }

    /// Deserialize an RFC 3339 timestamp or null.
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Timestamp>, D::Error> {
        let s = Option::<String>::deserialize(d)?;
        s.map(|s| parse_rfc3339(&s).map_err(serde::de::Error::custom))
            .transpose()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_format() {
        let t = parse_rfc3339("2026-10-30T20:00:00.987+08:00").unwrap();
        assert_eq!(format_rfc3339(&t), "2026-10-30T12:00:00Z");
        assert_eq!(
            from_unix(1_793_318_400)
                .map(|t| format_rfc3339(&t))
                .unwrap(),
            "2026-10-30T00:00:00Z"
        );
        assert!(parse_rfc3339("2026-10-30 12:00:00").is_err());
        assert_eq!(now().nanosecond(), 0);
        assert_eq!(format_rfc3339(&add_secs(&t, 90)), "2026-10-30T12:01:30Z");
    }
}
