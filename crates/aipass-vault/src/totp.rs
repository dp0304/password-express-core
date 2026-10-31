// SPDX-License-Identifier: Apache-2.0
//! TOTP (RFC 6238 over RFC 4226 HOTP; SHA1 / SHA256 / SHA512; 6–8 digits; any period) and
//! `otpauth://totp/…` URI parsing (CONTRACTS §2.7, design doc §6.5).

use aipass_crypto::SecretString;
use aipass_types::vault::{TotpAlgorithm, TotpConfig};
use hmac::{Hmac, KeyInit, Mac};
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::{Result, VaultError};

/// Minimum decoded secret length accepted from users (80 bits, the smallest common size).
pub const MIN_SECRET_BYTES: usize = 10;

/// A current TOTP code.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TotpCode {
    /// Zero-padded code.
    pub code: SecretString,
    /// Seconds until the code changes.
    pub remaining_seconds: u32,
    /// Period.
    pub period: u32,
}

impl core::fmt::Debug for TotpCode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TotpCode")
            .field("code", &"[REDACTED]")
            .field("remaining_seconds", &self.remaining_seconds)
            .finish()
    }
}

fn invalid_totp() -> VaultError {
    VaultError::Invalid(aipass_types::Localized::new(
        "两步验证密钥格式不正确",
        "The two-factor (TOTP) secret is not valid.",
    ))
}

/// Decode an RFC 4648 base32 secret (case-insensitive; spaces, dashes and `=` padding
/// ignored).
pub fn decode_base32_secret(s: &str) -> Result<Zeroizing<Vec<u8>>> {
    let cleaned: Zeroizing<String> = Zeroizing::new(
        s.chars()
            .filter(|c| !c.is_whitespace() && *c != '-' && *c != '=')
            .map(|c| c.to_ascii_uppercase())
            .collect(),
    );
    if cleaned.is_empty() {
        return Err(invalid_totp());
    }
    let mut spec = data_encoding::BASE32_NOPAD.specification();
    spec.check_trailing_bits = false;
    let enc = spec
        .encoding()
        .map_err(|_| VaultError::Internal("base32 spec"))?;
    enc.decode(cleaned.as_bytes())
        .map(Zeroizing::new)
        .map_err(|_| invalid_totp())
}

/// Validate a TOTP configuration (secret decodes, ≥ 80 bits, 6–8 digits, period 1–300 s).
pub fn validate(cfg: &TotpConfig) -> Result<()> {
    let k = decode_base32_secret(cfg.secret.expose())?;
    if k.len() < MIN_SECRET_BYTES
        || !(6..=8).contains(&cfg.digits)
        || !(1..=300).contains(&cfg.period)
    {
        return Err(invalid_totp());
    }
    Ok(())
}

fn mac(alg: TotpAlgorithm, key: &[u8], msg: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let out = match alg {
        TotpAlgorithm::Sha1 => {
            let mut m =
                <Hmac<sha1::Sha1> as KeyInit>::new_from_slice(key).map_err(|_| invalid_totp())?;
            m.update(msg);
            m.finalize().into_bytes().to_vec()
        }
        TotpAlgorithm::Sha256 => {
            let mut m =
                <Hmac<sha2::Sha256> as KeyInit>::new_from_slice(key).map_err(|_| invalid_totp())?;
            m.update(msg);
            m.finalize().into_bytes().to_vec()
        }
        TotpAlgorithm::Sha512 => {
            let mut m =
                <Hmac<sha2::Sha512> as KeyInit>::new_from_slice(key).map_err(|_| invalid_totp())?;
            m.update(msg);
            m.finalize().into_bytes().to_vec()
        }
    };
    Ok(Zeroizing::new(out))
}

/// HOTP (RFC 4226) with dynamic truncation; returns the numeric code.
pub fn hotp(key: &[u8], counter: u64, digits: u32, alg: TotpAlgorithm) -> Result<u32> {
    if !(6..=8).contains(&digits) {
        return Err(invalid_totp());
    }
    let h = mac(alg, key, &counter.to_be_bytes())?;
    let offset = (h[h.len() - 1] & 0x0f) as usize;
    let bin = (u32::from(h[offset]) & 0x7f) << 24
        | u32::from(h[offset + 1]) << 16
        | u32::from(h[offset + 2]) << 8
        | u32::from(h[offset + 3]);
    Ok(bin % 10u32.pow(digits))
}

/// TOTP code at unix time `unix`.
pub fn totp_at(cfg: &TotpConfig, unix: i64) -> Result<TotpCode> {
    validate_runtime(cfg)?;
    let key = decode_base32_secret(cfg.secret.expose())?;
    let t = u64::try_from(unix).map_err(|_| VaultError::InvalidInput("time before 1970"))?;
    let period = u64::from(cfg.period);
    let code = hotp(&key, t / period, cfg.digits, cfg.algorithm)?;
    let remaining = (period - (t % period)) as u32;
    Ok(TotpCode {
        code: SecretString::new(format!("{code:0width$}", width = cfg.digits as usize)),
        remaining_seconds: remaining,
        period: cfg.period,
    })
}

fn validate_runtime(cfg: &TotpConfig) -> Result<()> {
    if !(6..=8).contains(&cfg.digits) || !(1..=300).contains(&cfg.period) {
        return Err(invalid_totp());
    }
    Ok(())
}

/// TOTP code now.
pub fn totp_now(cfg: &TotpConfig) -> Result<TotpCode> {
    totp_at(cfg, aipass_types::time::unix_now())
}

/// A parsed `otpauth://totp/…` URI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OtpAuth {
    /// TOTP configuration.
    pub config: TotpConfig,
    /// `issuer` parameter or label prefix.
    pub issuer: Option<String>,
    /// Account part of the label.
    pub account: Option<String>,
}

/// Parse `otpauth://totp/Issuer:account?secret=…&issuer=…&algorithm=…&digits=…&period=…`.
/// HOTP URIs are rejected (not supported).
pub fn parse_otpauth(uri: &str) -> Result<OtpAuth> {
    let u = url::Url::parse(uri.trim()).map_err(|_| invalid_totp())?;
    if u.scheme() != "otpauth" {
        return Err(invalid_totp());
    }
    match u.host_str().map(str::to_ascii_lowercase).as_deref() {
        Some("totp") => {}
        Some("hotp") => {
            return Err(VaultError::Unsupported(
                "HOTP counters are not supported; use TOTP",
            ));
        }
        _ => return Err(invalid_totp()),
    }
    let label = percent_encoding::percent_decode_str(u.path().trim_start_matches('/'))
        .decode_utf8()
        .map_err(|_| invalid_totp())?
        .to_string();
    let (label_issuer, account) = match label.split_once(':') {
        Some((i, a)) => (Some(i.trim().to_owned()), Some(a.trim().to_owned())),
        None if label.trim().is_empty() => (None, None),
        None => (None, Some(label.trim().to_owned())),
    };
    let mut secret: Option<Zeroizing<String>> = None;
    let mut issuer = None;
    let mut algorithm = TotpAlgorithm::Sha1;
    let mut digits = 6u32;
    let mut period = 30u32;
    for (k, v) in u.query_pairs() {
        match k.to_ascii_lowercase().as_str() {
            "secret" => secret = Some(Zeroizing::new(v.into_owned())),
            "issuer" => issuer = Some(v.into_owned()),
            "algorithm" => {
                algorithm = match v.to_ascii_uppercase().as_str() {
                    "SHA1" => TotpAlgorithm::Sha1,
                    "SHA256" => TotpAlgorithm::Sha256,
                    "SHA512" => TotpAlgorithm::Sha512,
                    _ => return Err(invalid_totp()),
                }
            }
            "digits" => digits = v.parse().map_err(|_| invalid_totp())?,
            "period" => period = v.parse().map_err(|_| invalid_totp())?,
            _ => {}
        }
    }
    let secret = secret.ok_or_else(invalid_totp)?;
    let normalized: String = secret
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '=')
        .map(|c| c.to_ascii_uppercase())
        .collect();
    let config = TotpConfig {
        secret: SecretString::new(normalized),
        algorithm,
        digits,
        period,
    };
    validate(&config)?;
    Ok(OtpAuth {
        config,
        issuer: issuer.or(label_issuer).filter(|s| !s.is_empty()),
        account: account.filter(|s| !s.is_empty()),
    })
}

/// Accept either an `otpauth://` URI or a bare base32 secret (defaults SHA1/6/30).
pub fn parse_totp_input(input: &str) -> Result<TotpConfig> {
    let t = input.trim();
    if t.to_ascii_lowercase().starts_with("otpauth://") {
        return Ok(parse_otpauth(t)?.config);
    }
    let normalized: String = t
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-' && *c != '=')
        .map(|c| c.to_ascii_uppercase())
        .collect();
    let cfg = TotpConfig {
        secret: SecretString::new(normalized),
        algorithm: TotpAlgorithm::Sha1,
        digits: 6,
        period: 30,
    };
    validate(&cfg)?;
    Ok(cfg)
}

/// Build an `otpauth://totp/` URI (used by CSV export).
pub fn to_otpauth(cfg: &TotpConfig, issuer: Option<&str>, account: Option<&str>) -> SecretString {
    let enc = |s: &str| utf8_percent_encode(s, NON_ALPHANUMERIC).to_string();
    let label = match (issuer, account) {
        (Some(i), Some(a)) => format!("{}:{}", enc(i), enc(a)),
        (None, Some(a)) => enc(a),
        (Some(i), None) => enc(i),
        (None, None) => String::from("AI%20Pass"),
    };
    let alg = match cfg.algorithm {
        TotpAlgorithm::Sha1 => "SHA1",
        TotpAlgorithm::Sha256 => "SHA256",
        TotpAlgorithm::Sha512 => "SHA512",
    };
    let mut s = format!(
        "otpauth://totp/{label}?secret={}&algorithm={alg}&digits={}&period={}",
        cfg.secret.expose(),
        cfg.digits,
        cfg.period
    );
    if let Some(i) = issuer {
        s.push_str("&issuer=");
        s.push_str(&enc(i));
    }
    SecretString::new(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn b32(ascii: &str) -> SecretString {
        SecretString::new(data_encoding::BASE32_NOPAD.encode(ascii.as_bytes()))
    }

    /// RFC 6238 Appendix B.
    #[test]
    fn rfc6238_vectors() {
        let sha1 = b32("12345678901234567890");
        let sha256 = b32("12345678901234567890123456789012");
        let sha512 = b32("1234567890123456789012345678901234567890123456789012345678901234");
        let cases: [(i64, &str, &str, &str); 6] = [
            (59, "94287082", "46119246", "90693936"),
            (1111111109, "07081804", "68084774", "25091201"),
            (1111111111, "14050471", "67062674", "99943326"),
            (1234567890, "89005924", "91819424", "93441116"),
            (2000000000, "69279037", "90698825", "38618901"),
            (20000000000, "65353130", "77737706", "47863826"),
        ];
        for (t, c1, c256, c512) in cases {
            for (secret, alg, want) in [
                (&sha1, TotpAlgorithm::Sha1, c1),
                (&sha256, TotpAlgorithm::Sha256, c256),
                (&sha512, TotpAlgorithm::Sha512, c512),
            ] {
                let cfg = TotpConfig {
                    secret: secret.clone(),
                    algorithm: alg,
                    digits: 8,
                    period: 30,
                };
                assert_eq!(
                    totp_at(&cfg, t).unwrap().code.expose(),
                    want,
                    "t={t} {alg:?}"
                );
            }
        }
        let six = TotpConfig {
            secret: sha1,
            algorithm: TotpAlgorithm::Sha1,
            digits: 6,
            period: 30,
        };
        let c = totp_at(&six, 59).unwrap();
        assert_eq!(c.code.expose(), "287082");
        assert_eq!(c.remaining_seconds, 1);
        assert!(!format!("{c:?}").contains("287082"));
    }

    /// RFC 4226 Appendix D.
    #[test]
    fn rfc4226_hotp() {
        let want = [
            755224, 287082, 359152, 969429, 338314, 254676, 287922, 162583, 399871, 520489,
        ];
        for (i, w) in want.iter().enumerate() {
            assert_eq!(
                hotp(b"12345678901234567890", i as u64, 6, TotpAlgorithm::Sha1).unwrap(),
                *w
            );
        }
    }

    #[test]
    fn otpauth_parsing() {
        let a = parse_otpauth("otpauth://totp/Example%20Co:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example%20Co&algorithm=SHA256&digits=8&period=60").unwrap();
        assert_eq!(a.issuer.as_deref(), Some("Example Co"));
        assert_eq!(a.account.as_deref(), Some("alice@example.com"));
        assert_eq!(a.config.algorithm, TotpAlgorithm::Sha256);
        assert_eq!((a.config.digits, a.config.period), (8, 60));
        let back = parse_otpauth(
            to_otpauth(&a.config, a.issuer.as_deref(), a.account.as_deref()).expose(),
        )
        .unwrap();
        assert_eq!(back, a);
        assert!(parse_otpauth("otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP&counter=1").is_err());
        assert!(parse_otpauth("otpauth://totp/x?secret=!!").is_err());
        assert!(parse_otpauth("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=12").is_err());
        assert!(parse_otpauth("https://totp/x?secret=JBSWY3DPEHPK3PXP").is_err());
        let c = parse_totp_input("jbsw y3dp ehpk 3pxp").unwrap();
        assert_eq!(c.secret.expose(), "JBSWY3DPEHPK3PXP");
        assert!(parse_totp_input("ABC").is_err());
    }
}
