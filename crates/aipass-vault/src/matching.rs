// SPDX-License-Identifier: Apache-2.0
//! Site matching for autofill and import de-duplication (CONTRACTS §2.8, §11.3).
//!
//! * `exact_origin` — same scheme, host and port.
//! * `same_site` — same registrable domain (PSL eTLD+1), **https on both sides only**;
//!   clients offer it only after an explicit click ("相关站点").
//! * An entry saved for https never matches an http page; page-declared branding is never
//!   trusted.

use serde::{Deserialize, Serialize};
use url::Url;

/// How an entry matched a page / service identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchKind {
    /// Same scheme + host + port.
    ExactOrigin,
    /// Same registrable domain over https.
    SameSite,
}

/// Parse a stored URL or a bare domain (`example.com` → `https://example.com/`).
pub fn parse_site(input: &str) -> Option<Url> {
    let t = input.trim();
    if t.is_empty() || t.len() > 2048 {
        return None;
    }
    let u = if t.contains("://") {
        Url::parse(t).ok()?
    } else {
        Url::parse(&format!("https://{t}")).ok()?
    };
    match u.scheme() {
        "https" | "http" => u.host_str().is_some().then_some(u),
        _ => None,
    }
}

/// Lower-case host of a URL / domain.
pub fn host_of(input: &str) -> Option<String> {
    parse_site(input).and_then(|u| {
        u.host_str()
            .map(|h| h.trim_end_matches('.').to_ascii_lowercase())
    })
}

/// Registrable domain (eTLD+1) of a host, or the host itself for IPs / single labels.
pub fn registrable_domain(host: &str) -> String {
    let h = host.trim_end_matches('.').to_ascii_lowercase();
    if h.parse::<std::net::IpAddr>().is_ok() || h.starts_with('[') || !h.contains('.') {
        return h;
    }
    psl::domain_str(&h).map(str::to_owned).unwrap_or(h)
}

/// Registrable domain of the first parseable URL.
pub fn site_key(urls: &[String]) -> Option<String> {
    urls.iter()
        .find_map(|u| host_of(u))
        .map(|h| registrable_domain(&h))
}

/// Match a page / service identifier against an entry's URLs (best match wins).
pub fn match_entry(entry_urls: &[String], target: &str) -> Option<MatchKind> {
    let t = parse_site(target)?;
    let mut best: Option<MatchKind> = None;
    for raw in entry_urls {
        let Some(e) = parse_site(raw) else { continue };
        if e.scheme() == "https" && t.scheme() != "https" {
            continue; // never fill an https entry on http
        }
        if e.origin() == t.origin() {
            return Some(MatchKind::ExactOrigin);
        }
        if e.scheme() == "https"
            && t.scheme() == "https"
            && let (Some(eh), Some(th)) = (e.host_str(), t.host_str())
            && registrable_domain(eh) == registrable_domain(th)
        {
            best = Some(MatchKind::SameSite);
        }
    }
    best
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matching_rules() {
        let urls = vec!["https://login.example.co.uk/signin".to_owned()];
        assert_eq!(
            match_entry(&urls, "https://login.example.co.uk/other"),
            Some(MatchKind::ExactOrigin)
        );
        assert_eq!(
            match_entry(&urls, "https://www.example.co.uk/"),
            Some(MatchKind::SameSite)
        );
        assert_eq!(match_entry(&urls, "http://login.example.co.uk/"), None);
        assert_eq!(match_entry(&urls, "https://example-co.uk.evil.com/"), None);
        assert_eq!(
            match_entry(&urls, "https://login.example.co.uk:8443/"),
            Some(MatchKind::SameSite)
        );
        let http = vec!["http://intranet.local:8080".to_owned()];
        assert_eq!(
            match_entry(&http, "http://intranet.local:8080/x"),
            Some(MatchKind::ExactOrigin)
        );
        assert_eq!(match_entry(&http, "https://intranet.local:8080/x"), None);
        assert_eq!(registrable_domain("a.b.github.io"), "b.github.io");
        assert_eq!(registrable_domain("127.0.0.1"), "127.0.0.1");
        assert_eq!(
            site_key(&["example.com".into()]),
            Some("example.com".into())
        );
        assert_eq!(host_of("javascript:alert(1)"), None);
    }
}
