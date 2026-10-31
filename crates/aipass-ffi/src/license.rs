// SPDX-License-Identifier: Apache-2.0
//! Offline license verification (CONTRACTS §13).
//!
//! Token: `b64u(JCS(payload)) + "." + b64u(Ed25519(signature over those payload bytes))`,
//! payload `{v:1, sub, plan_id, features:[…], device_id, iat, exp, grace_until}`.
//!
//! The verifying key is, in order: the key passed to `set_license_public_key`, the
//! compile-time `AIPASS_LICENSE_PUBLIC_KEY` (b64u, 32 bytes), or the built-in
//! **development** key (seed = SHA-256(`"aipass/dev/license-signing-key/v1"`), public, so
//! only for development builds — `LicenseStatusFfi.dev_key` reports it).
//!
//! A failed check only disables premium features (§5.5, §16.2); nothing in the core
//! gates unlock, export, recovery or revocation on a license.

use aipass_crypto::{Ed25519Keypair, b64u, identity, sha256};
use serde::Deserialize;

use crate::types::LicenseStatusFfi;

/// Label hashed into the public development signing seed.
pub const DEV_LICENSE_SEED_LABEL: &[u8] = b"aipass/dev/license-signing-key/v1";

/// The development signing keypair (public seed — never trust it in production).
pub(crate) fn dev_keypair() -> Ed25519Keypair {
    Ed25519Keypair::from_seed(&sha256(DEV_LICENSE_SEED_LABEL))
}

/// Built-in verifying key and whether it is the development key.
pub(crate) fn builtin_key() -> Option<([u8; 32], bool)> {
    match option_env!("AIPASS_LICENSE_PUBLIC_KEY") {
        Some(k) => b64u::decode_array::<32>(k.trim()).ok().map(|k| (k, false)),
        None => Some((dev_keypair().public_key(), true)),
    }
}

#[derive(Deserialize)]
struct Payload {
    v: u32,
    #[allow(dead_code)]
    sub: String,
    plan_id: String,
    #[serde(default)]
    features: Vec<String>,
    device_id: String,
    #[allow(dead_code)]
    iat: i64,
    exp: i64,
    #[serde(default)]
    grace_until: Option<i64>,
}

fn invalid(reason: &str, dev_key: bool) -> LicenseStatusFfi {
    LicenseStatusFfi {
        valid: false,
        plan_id: None,
        features: Vec::new(),
        expires_at: None,
        grace_until: None,
        in_grace_period: false,
        reason: Some(reason.to_owned()),
        dev_key,
    }
}

/// Verify `token` offline against `key` for `device_id` at `now` (Unix seconds).
pub(crate) fn verify(
    token: &str,
    key: Option<([u8; 32], bool)>,
    device_id: Option<&str>,
    now: i64,
) -> LicenseStatusFfi {
    let Some((pk, dev_key)) = key else {
        return invalid("no_public_key", false);
    };
    let Some((p64, s64)) = token.trim().split_once('.') else {
        return invalid("bad_format", dev_key);
    };
    let (Ok(payload), Ok(sig)) = (b64u::decode(p64), b64u::decode_array::<64>(s64)) else {
        return invalid("bad_format", dev_key);
    };
    if identity::verify(&pk, &payload, &sig).is_err() {
        return invalid("bad_signature", dev_key);
    }
    let Ok(p) = serde_json::from_slice::<Payload>(&payload) else {
        return invalid("bad_format", dev_key);
    };
    if p.v != 1 {
        return invalid("unsupported_version", dev_key);
    }
    if device_id != Some(p.device_id.as_str()) {
        return invalid("wrong_device", dev_key);
    }
    let grace = p.grace_until.unwrap_or(p.exp).max(p.exp);
    if now >= grace {
        let mut s = invalid("expired", dev_key);
        s.plan_id = Some(p.plan_id);
        s.expires_at = Some(p.exp);
        s.grace_until = p.grace_until;
        return s;
    }
    LicenseStatusFfi {
        valid: true,
        plan_id: Some(p.plan_id),
        features: p.features,
        expires_at: Some(p.exp),
        grace_until: p.grace_until,
        in_grace_period: now >= p.exp,
        reason: None,
        dev_key,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn token(kp: &Ed25519Keypair, payload: &str) -> String {
        format!(
            "{}.{}",
            b64u::encode(payload.as_bytes()),
            b64u::encode(kp.sign(payload.as_bytes()))
        )
    }

    const DEV: &str = "dev_01jbxyzabcdefghjkmnpqrstvw";

    fn payload(exp: i64, grace: i64) -> String {
        format!(
            r#"{{"device_id":"{DEV}","exp":{exp},"features":["official_sync","relay"],"grace_until":{grace},"iat":1,"plan_id":"personal_yearly","sub":"usr_x","v":1}}"#
        )
    }

    #[test]
    fn valid_grace_expired_and_tampered() {
        let kp = dev_keypair();
        let key = builtin_key();
        let t = token(&kp, &payload(1000, 2000));
        let s = verify(&t, key, Some(DEV), 500);
        assert!(s.valid && !s.in_grace_period && s.dev_key);
        assert_eq!(s.features, vec!["official_sync", "relay"]);
        let s = verify(&t, key, Some(DEV), 1500);
        assert!(s.valid && s.in_grace_period);
        let s = verify(&t, key, Some(DEV), 2000);
        assert_eq!(s.reason.as_deref(), Some("expired"));
        assert!(!verify(&t, key, Some("dev_other"), 500).valid);
        // tampered payload
        let (_, sig) = t.split_once('.').unwrap();
        let forged = format!("{}.{sig}", b64u::encode(payload(9999, 9999).as_bytes()));
        assert_eq!(
            verify(&forged, key, Some(DEV), 500).reason.as_deref(),
            Some("bad_signature")
        );
        // other key
        let other = Ed25519Keypair::from_seed(&[7u8; 32]);
        let t2 = token(&other, &payload(1000, 2000));
        assert!(!verify(&t2, key, Some(DEV), 500).valid);
        assert_eq!(verify("garbage", key, Some(DEV), 0).reason.as_deref(), Some("bad_format"));
    }
}
