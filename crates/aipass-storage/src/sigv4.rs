// SPDX-License-Identifier: Apache-2.0
//! AWS Signature Version 4 (header-based, signed payload) for S3-compatible storage.
//!
//! A small, careful implementation on top of the workspace's HMAC-SHA256 / SHA-256
//! (`aipass_crypto::hash`). It is verified in the unit tests against the AWS published
//! vectors: the S3 developer guide examples (GET Object, PUT Object, GET Bucket Lifecycle,
//! List Objects) and the `aws-sig-v4-test-suite` cases `get-vanilla`,
//! `get-vanilla-query-order-key-case`, `get-vanilla-with-session-token`,
//! `post-x-www-form-urlencoded` and `get-space-normalized`.
//!
//! S3 rules applied here: the canonical URI is **not** normalized (no dot-segment removal,
//! no double encoding), `/` stays literal in object keys and is encoded as `%2F` in query
//! values; header values are trimmed and inner runs of spaces collapsed.
//!
//! Intermediate signing keys are zeroized; secrets never appear in `Debug` output.

use zeroize::Zeroizing;

/// Signing algorithm identifier.
pub const ALGORITHM: &str = "AWS4-HMAC-SHA256";
/// Hex SHA-256 of the empty string.
pub const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
/// Header carrying the payload hash.
pub const CONTENT_SHA256_HEADER: &str = "x-amz-content-sha256";
/// Header carrying the request time.
pub const DATE_HEADER: &str = "x-amz-date";
/// Header carrying an STS session token.
pub const SECURITY_TOKEN_HEADER: &str = "x-amz-security-token";

/// AWS `UriEncode`: every byte except `A-Z a-z 0-9 - . _ ~` is `%XX` (upper-case hex);
/// `/` is kept literal unless `encode_slash`.
pub fn uri_encode(input: &str, encode_slash: bool) -> String {
    let mut out = String::with_capacity(input.len());
    for b in input.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char)
            }
            b'/' if !encode_slash => out.push('/'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Canonical query string from **decoded** `(name, value)` pairs: each encoded, sorted by
/// encoded name (then value), joined with `&`.
pub fn canonical_query(pairs: &[(String, String)]) -> String {
    let mut enc: Vec<(String, String)> = pairs
        .iter()
        .map(|(k, v)| (uri_encode(k, true), uri_encode(v, true)))
        .collect();
    enc.sort();
    enc.iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&")
}

fn trim_all(v: &str) -> String {
    v.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Canonical headers and the signed-headers list from `(name, value)` pairs (any case;
/// repeated names are joined with `,` in order of appearance).
pub fn canonical_headers(headers: &[(String, String)]) -> (String, String) {
    let mut map: std::collections::BTreeMap<String, Vec<String>> = Default::default();
    for (k, v) in headers {
        map.entry(k.trim().to_ascii_lowercase())
            .or_default()
            .push(trim_all(v));
    }
    let canon: String = map
        .iter()
        .map(|(k, vs)| format!("{k}:{}\n", vs.join(",")))
        .collect();
    let signed = map.keys().cloned().collect::<Vec<_>>().join(";");
    (canon, signed)
}

/// The canonical request.
pub fn canonical_request(
    method: &str,
    canonical_uri: &str,
    canonical_query: &str,
    headers: &[(String, String)],
    payload_hash: &str,
) -> (String, String) {
    let (canon_headers, signed) = canonical_headers(headers);
    let cr = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        method.to_ascii_uppercase(),
        canonical_uri,
        canonical_query,
        canon_headers,
        signed,
        payload_hash
    );
    (cr, signed)
}

/// Hex SHA-256.
pub fn hex_sha256(data: &[u8]) -> String {
    hex::encode(aipass_crypto::sha256(data))
}

/// `yyyymmdd/region/service/aws4_request`.
pub fn scope(date: &str, region: &str, service: &str) -> String {
    format!("{date}/{region}/{service}/aws4_request")
}

/// String to sign.
pub fn string_to_sign(amz_date: &str, scope: &str, canonical_request: &str) -> String {
    format!(
        "{ALGORITHM}\n{amz_date}\n{scope}\n{}",
        hex_sha256(canonical_request.as_bytes())
    )
}

/// Derived signing key `HMAC(HMAC(HMAC(HMAC("AWS4"+secret, date), region), service), "aws4_request")`.
pub fn signing_key(secret: &str, date: &str, region: &str, service: &str) -> Zeroizing<[u8; 32]> {
    use aipass_crypto::hash::hmac_sha256;
    let k0 = Zeroizing::new(format!("AWS4{secret}").into_bytes());
    let k_date = Zeroizing::new(hmac_sha256(&k0, date.as_bytes()));
    let k_region = Zeroizing::new(hmac_sha256(&*k_date, region.as_bytes()));
    let k_service = Zeroizing::new(hmac_sha256(&*k_region, service.as_bytes()));
    Zeroizing::new(hmac_sha256(&*k_service, b"aws4_request"))
}

/// Hex signature of `string_to_sign`.
pub fn signature(key: &[u8; 32], string_to_sign: &str) -> String {
    hex::encode(aipass_crypto::hash::hmac_sha256(
        key,
        string_to_sign.as_bytes(),
    ))
}

/// Inputs of one signature.
pub struct SigningInput<'a> {
    /// Access key id (not secret by itself, but never logged alongside a request).
    pub access_key_id: &'a str,
    /// Secret access key.
    pub secret_access_key: &'a str,
    /// Region (`us-east-1`, …).
    pub region: &'a str,
    /// Service (`s3`).
    pub service: &'a str,
    /// `yyyymmddThhmmssZ`.
    pub amz_date: &'a str,
}

impl core::fmt::Debug for SigningInput<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SigningInput")
            .field("region", &self.region)
            .field("service", &self.service)
            .field("amz_date", &self.amz_date)
            .finish_non_exhaustive()
    }
}

/// Result of signing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signed {
    /// Full `Authorization` header value.
    pub authorization: String,
    /// `;`-joined signed header names.
    pub signed_headers: String,
    /// Hex signature.
    pub signature: String,
    /// Canonical request (for diagnostics in tests only; contains no secrets).
    pub canonical_request: String,
    /// String to sign.
    pub string_to_sign: String,
}

/// Sign a request. `headers` must include `host` and every `x-amz-*` header that will be
/// sent (including `x-amz-date`, and `x-amz-security-token` for session credentials).
pub fn sign(
    input: &SigningInput<'_>,
    method: &str,
    canonical_uri: &str,
    query: &[(String, String)],
    headers: &[(String, String)],
    payload_hash: &str,
) -> Signed {
    let cq = canonical_query(query);
    let (cr, signed_headers) = canonical_request(method, canonical_uri, &cq, headers, payload_hash);
    let date = &input.amz_date[..input.amz_date.len().min(8)];
    let sc = scope(date, input.region, input.service);
    let sts = string_to_sign(input.amz_date, &sc, &cr);
    let key = signing_key(input.secret_access_key, date, input.region, input.service);
    let sig = signature(&key, &sts);
    Signed {
        authorization: format!(
            "{ALGORITHM} Credential={}/{sc}, SignedHeaders={signed_headers}, Signature={sig}",
            input.access_key_id
        ),
        signed_headers,
        signature: sig,
        canonical_request: cr,
        string_to_sign: sts,
    }
}

/// Parsed `Authorization: AWS4-HMAC-SHA256 …` header (used by verifying mocks/proxies).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedAuthorization {
    /// Access key id.
    pub access_key_id: String,
    /// `yyyymmdd`.
    pub date: String,
    /// Region.
    pub region: String,
    /// Service.
    pub service: String,
    /// Signed header names (lower-case).
    pub signed_headers: Vec<String>,
    /// Hex signature.
    pub signature: String,
}

/// Parse an `Authorization` header produced by SigV4 signers (`,` or `, ` separated).
pub fn parse_authorization(value: &str) -> Option<ParsedAuthorization> {
    let rest = value.strip_prefix(ALGORITHM)?.trim_start();
    let (mut cred, mut signed, mut sig) = (None, None, None);
    for part in rest.split(',') {
        let (k, v) = part.trim().split_once('=')?;
        match k {
            "Credential" => cred = Some(v.to_owned()),
            "SignedHeaders" => signed = Some(v.to_owned()),
            "Signature" => sig = Some(v.to_owned()),
            _ => return None,
        }
    }
    let cred = cred?;
    let mut it = cred.split('/');
    let (ak, date, region, service, term) =
        (it.next()?, it.next()?, it.next()?, it.next()?, it.next()?);
    if term != "aws4_request" || it.next().is_some() {
        return None;
    }
    Some(ParsedAuthorization {
        access_key_id: ak.to_owned(),
        date: date.to_owned(),
        region: region.to_owned(),
        service: service.to_owned(),
        signed_headers: signed?.split(';').map(str::to_owned).collect(),
        signature: sig?,
    })
}

/// Format a timestamp as `yyyymmddThhmmssZ`.
pub fn amz_date(t: &chrono::DateTime<chrono::Utc>) -> String {
    t.format("%Y%m%dT%H%M%SZ").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    const S3_AK: &str = "AKIAIOSFODNN7EXAMPLE";
    const S3_SK: &str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

    fn s3_input() -> SigningInput<'static> {
        SigningInput {
            access_key_id: S3_AK,
            secret_access_key: S3_SK,
            region: "us-east-1",
            service: "s3",
            amz_date: "20130524T000000Z",
        }
    }

    // --- AWS S3 developer guide: "Examples: Signature Calculations" -------------------

    #[test]
    fn s3_get_object() {
        let s = sign(
            &s3_input(),
            "GET",
            "/test.txt",
            &[],
            &h(&[
                ("Host", "examplebucket.s3.amazonaws.com"),
                ("Range", "bytes=0-9"),
                ("x-amz-content-sha256", EMPTY_SHA256),
                ("x-amz-date", "20130524T000000Z"),
            ]),
            EMPTY_SHA256,
        );
        assert_eq!(
            s.canonical_request,
            "GET\n/test.txt\n\nhost:examplebucket.s3.amazonaws.com\nrange:bytes=0-9\nx-amz-content-sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\nx-amz-date:20130524T000000Z\n\nhost;range;x-amz-content-sha256;x-amz-date\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert!(
            s.string_to_sign
                .ends_with("\n7344ae5b7ee6c3e7e6b0fe0640412a37625d1fbfff95c48bbb2dc43964946972")
        );
        assert_eq!(
            s.signature,
            "f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
        );
        assert_eq!(
            s.authorization,
            "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
        );
        let p = parse_authorization(&s.authorization).unwrap();
        assert_eq!(p.access_key_id, S3_AK);
        assert_eq!(p.signed_headers.len(), 4);
        // the AWS doc form without spaces parses too
        assert!(parse_authorization("AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,SignedHeaders=host;range;x-amz-content-sha256;x-amz-date,Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41").is_some());
    }

    #[test]
    fn s3_put_object() {
        let body = b"Welcome to Amazon S3.";
        let ph = hex_sha256(body);
        assert_eq!(
            ph,
            "44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072"
        );
        let s = sign(
            &s3_input(),
            "PUT",
            &format!("/{}", uri_encode("test$file.text", false)),
            &[],
            &h(&[
                ("Date", "Fri, 24 May 2013 00:00:00 GMT"),
                ("Host", "examplebucket.s3.amazonaws.com"),
                ("x-amz-content-sha256", &ph),
                ("x-amz-date", "20130524T000000Z"),
                ("x-amz-storage-class", "REDUCED_REDUNDANCY"),
            ]),
            &ph,
        );
        assert!(
            s.canonical_request
                .starts_with("PUT\n/test%24file.text\n\n")
        );
        assert!(
            s.string_to_sign
                .ends_with("\n9e0e90d9c76de8fa5b200d8c849cd5b8dc7a3be3951ddb7f6a76b4158342019d")
        );
        assert_eq!(
            s.signature,
            "98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd"
        );
    }

    #[test]
    fn s3_get_bucket_lifecycle() {
        let s = sign(
            &s3_input(),
            "GET",
            "/",
            &[("lifecycle".into(), String::new())],
            &h(&[
                ("Host", "examplebucket.s3.amazonaws.com"),
                ("x-amz-date", "20130524T000000Z"),
                ("x-amz-content-sha256", EMPTY_SHA256),
            ]),
            EMPTY_SHA256,
        );
        assert!(s.canonical_request.starts_with("GET\n/\nlifecycle=\n"));
        assert!(
            s.string_to_sign
                .ends_with("\n9766c798316ff2757b517bc739a67f6213b4ab36dd5da2f94eaebf79c77395ca")
        );
        assert_eq!(
            s.signature,
            "fea454ca298b7da1c68078a5d1bdbfbbe0d65c699e0f91ac7a200a0136783543"
        );
    }

    #[test]
    fn s3_list_objects() {
        let s = sign(
            &s3_input(),
            "GET",
            "/",
            &[
                ("prefix".into(), "J".into()),
                ("max-keys".into(), "2".into()),
            ],
            &h(&[
                ("Host", "examplebucket.s3.amazonaws.com"),
                ("x-amz-date", "20130524T000000Z"),
                ("x-amz-content-sha256", EMPTY_SHA256),
            ]),
            EMPTY_SHA256,
        );
        assert!(
            s.canonical_request
                .starts_with("GET\n/\nmax-keys=2&prefix=J\n")
        );
        assert!(
            s.string_to_sign
                .ends_with("\ndf57d21db20da04d7fa30298dd4488ba3a2b47ca3a489c74750e0f1e7df1b9b7")
        );
        assert_eq!(
            s.signature,
            "34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7"
        );
    }

    // --- aws-sig-v4-test-suite (awslabs/aws-c-auth tests/aws-signing-test-suite/v4) ---

    const SUITE_SK: &str = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";

    fn suite_input() -> SigningInput<'static> {
        SigningInput {
            access_key_id: "AKIDEXAMPLE",
            secret_access_key: SUITE_SK,
            region: "us-east-1",
            service: "service",
            amz_date: "20150830T123600Z",
        }
    }

    #[test]
    fn suite_get_vanilla() {
        let s = sign(
            &suite_input(),
            "GET",
            "/",
            &[],
            &h(&[
                ("Host", "example.amazonaws.com"),
                ("X-Amz-Date", "20150830T123600Z"),
            ]),
            EMPTY_SHA256,
        );
        assert_eq!(
            s.canonical_request,
            "GET\n/\n\nhost:example.amazonaws.com\nx-amz-date:20150830T123600Z\n\nhost;x-amz-date\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            s.string_to_sign,
            "AWS4-HMAC-SHA256\n20150830T123600Z\n20150830/us-east-1/service/aws4_request\nbb579772317eb040ac9ed261061d46c1f17a8133879d6129b6e1c25292927e63"
        );
        assert_eq!(
            s.signature,
            "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
        );
    }

    #[test]
    fn suite_get_vanilla_query_order_key_case() {
        let s = sign(
            &suite_input(),
            "GET",
            "/",
            &[
                ("Param2".into(), "value2".into()),
                ("Param1".into(), "value1".into()),
            ],
            &h(&[
                ("Host", "example.amazonaws.com"),
                ("X-Amz-Date", "20150830T123600Z"),
            ]),
            EMPTY_SHA256,
        );
        assert!(
            s.canonical_request
                .starts_with("GET\n/\nParam1=value1&Param2=value2\n")
        );
        assert_eq!(
            s.signature,
            "b97d918cfa904a5beff61c982a1b6f458b799221646efd99d3219ec94cdf2500"
        );
    }

    #[test]
    fn suite_get_vanilla_with_session_token() {
        let s = sign(
            &suite_input(),
            "GET",
            "/",
            &[],
            &h(&[
                ("Host", "example.amazonaws.com"),
                ("X-Amz-Date", "20150830T123600Z"),
                (
                    "X-Amz-Security-Token",
                    "6e86291e8372ff2a2260956d9b8aae1d763fbf315fa00fa31553b73ebf194267",
                ),
            ]),
            EMPTY_SHA256,
        );
        assert_eq!(s.signed_headers, "host;x-amz-date;x-amz-security-token");
        assert!(
            s.string_to_sign
                .ends_with("\n067b36aa60031588cea4a4cde1f21215227a047690c72247f1d70b32fbbfad2b")
        );
        assert_eq!(
            s.signature,
            "07ec1639c89043aa0e3e2de82b96708f198cceab042d4a97044c66dd9f74e7f8"
        );
    }

    #[test]
    fn suite_post_x_www_form_urlencoded() {
        let body = b"Param1=value1";
        let ph = hex_sha256(body);
        let s = sign(
            &suite_input(),
            "POST",
            "/",
            &[],
            &h(&[
                ("Content-Type", "application/x-www-form-urlencoded"),
                ("Host", "example.amazonaws.com"),
                ("Content-Length", "13"),
                ("X-Amz-Content-Sha256", &ph),
                ("X-Amz-Date", "20150830T123600Z"),
            ]),
            &ph,
        );
        assert_eq!(
            s.signed_headers,
            "content-length;content-type;host;x-amz-content-sha256;x-amz-date"
        );
        assert!(
            s.string_to_sign
                .ends_with("\nb1edd1d03544c25390e32085d55b57acc9a3961bb59415ff86c45c3d89d16cfb")
        );
        assert_eq!(
            s.signature,
            "d3875051da38690788ef43de4db0d8f280229d82040bfac253562e56c3f20e0b"
        );
    }

    #[test]
    fn suite_get_space_normalized() {
        let s = sign(
            &suite_input(),
            "GET",
            &uri_encode("/example space/", false),
            &[],
            &h(&[
                ("Host", "example.amazonaws.com"),
                ("X-Amz-Date", "20150830T123600Z"),
            ]),
            EMPTY_SHA256,
        );
        assert!(s.canonical_request.starts_with("GET\n/example%20space/\n"));
        assert_eq!(
            s.signature,
            "652487583200325589f1fba4c7e578f72c47cb61beeca81406b39ddec1366741"
        );
    }

    #[test]
    fn encoding_rules() {
        assert_eq!(uri_encode("a/b c~d", false), "a/b%20c~d");
        assert_eq!(uri_encode("a/b", true), "a%2Fb");
        assert_eq!(uri_encode("ü", true), "%C3%BC");
        assert_eq!(trim_all("  a   b  "), "a b");
        let input = s3_input();
        assert!(!format!("{input:?}").contains("EXAMPLEKEY"));
    }
}
