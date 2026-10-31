// SPDX-License-Identifier: Apache-2.0
//! CSV import (CONTRACTS §2.8, design doc §6.1): `chrome`, `firefox`, `safari`,
//! `bitwarden`, `1password`, `lastpass` and `generic` (header auto-mapping).
//!
//! Import runs locally only. Imported entries get `lifecycle: "imported"` (never
//! "verified") and `source: "import:<format>"`. Duplicates — same registrable domain of the
//! first URL **and** the same lower-cased username, against existing entries and earlier
//! rows of the same file — are not imported but reported so the UI can offer a merge.
//! Report reasons never contain secrets. Clients show the "delete the CSV file" guidance
//! ([`delete_csv_guidance`]) without promising secure deletion on SSDs.

use std::collections::HashMap;

use aipass_crypto::SecretString;
use aipass_types::Localized;
use aipass_types::ids::EntryId;
use aipass_types::vault::{CustomField, EntryKind, EntryPayload, EntrySource, Lifecycle};
use serde::{Deserialize, Serialize};

use crate::error::{Result, VaultError};
use crate::matching::{host_of, registrable_domain, site_key};

/// Maximum accepted CSV size (bytes).
pub const MAX_CSV_BYTES: usize = 50 * 1024 * 1024;
/// Maximum number of data rows.
pub const MAX_ROWS: usize = 100_000;

/// Localized "delete the CSV" guidance (honest: no secure-deletion promise on SSDs).
pub fn delete_csv_guidance() -> Localized {
    Localized::new(
        "导入已完成。CSV 是未加密的明文文件，请立即删除它并清空废纸篓；在 SSD 和云盘上，删除不一定能保证数据无法恢复。",
        "Import finished. The CSV file is unencrypted plaintext — delete it now and empty the trash. On SSDs and cloud drives deletion cannot guarantee the data is unrecoverable.",
    )
}

/// Supported CSV formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CsvFormat {
    /// Google Chrome / Chromium password export.
    #[serde(rename = "chrome")]
    Chrome,
    /// Mozilla Firefox.
    #[serde(rename = "firefox")]
    Firefox,
    /// Apple Safari / Passwords app.
    #[serde(rename = "safari")]
    Safari,
    /// Bitwarden CSV.
    #[serde(rename = "bitwarden")]
    Bitwarden,
    /// 1Password CSV.
    #[serde(rename = "1password")]
    OnePassword,
    /// LastPass CSV.
    #[serde(rename = "lastpass")]
    LastPass,
    /// Any CSV with recognisable headers.
    #[serde(rename = "generic")]
    Generic,
}

impl CsvFormat {
    /// Wire name (also the `import:<format>` source suffix).
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Chrome => "chrome",
            Self::Firefox => "firefox",
            Self::Safari => "safari",
            Self::Bitwarden => "bitwarden",
            Self::OnePassword => "1password",
            Self::LastPass => "lastpass",
            Self::Generic => "generic",
        }
    }

    /// Parse a wire name.
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s.trim().to_ascii_lowercase().as_str() {
            "chrome" | "chromium" | "edge" | "brave" => Self::Chrome,
            "firefox" => Self::Firefox,
            "safari" | "apple" => Self::Safari,
            "bitwarden" => Self::Bitwarden,
            "1password" | "onepassword" => Self::OnePassword,
            "lastpass" => Self::LastPass,
            "generic" | "csv" => Self::Generic,
            _ => return None,
        })
    }

    /// All formats.
    pub const ALL: [CsvFormat; 7] = [
        Self::Chrome,
        Self::Firefox,
        Self::Safari,
        Self::Bitwarden,
        Self::OnePassword,
        Self::LastPass,
        Self::Generic,
    ];
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Col {
    Title,
    Url,
    Username,
    Password,
    Notes,
    Totp,
    Type,
    Fields,
    Tags,
    Folder,
}

fn aliases(format: CsvFormat) -> &'static [(&'static str, Col)] {
    use Col::*;
    match format {
        CsvFormat::Chrome => &[
            ("name", Title),
            ("url", Url),
            ("username", Username),
            ("password", Password),
            ("note", Notes),
            ("notes", Notes),
        ],
        CsvFormat::Firefox => &[("url", Url), ("username", Username), ("password", Password)],
        CsvFormat::Safari => &[
            ("title", Title),
            ("url", Url),
            ("website", Url),
            ("username", Username),
            ("password", Password),
            ("notes", Notes),
            ("otpauth", Totp),
        ],
        CsvFormat::Bitwarden => &[
            ("name", Title),
            ("login_uri", Url),
            ("login_username", Username),
            ("login_password", Password),
            ("notes", Notes),
            ("login_totp", Totp),
            ("type", Type),
            ("fields", Fields),
            ("folder", Folder),
        ],
        CsvFormat::OnePassword => &[
            ("title", Title),
            ("url", Url),
            ("website", Url),
            ("urls", Url),
            ("username", Username),
            ("password", Password),
            ("notes", Notes),
            ("notesplain", Notes),
            ("otpauth", Totp),
            ("one-time password", Totp),
            ("tags", Tags),
            ("type", Type),
        ],
        CsvFormat::LastPass => &[
            ("name", Title),
            ("url", Url),
            ("username", Username),
            ("password", Password),
            ("extra", Notes),
            ("totp", Totp),
            ("grouping", Folder),
        ],
        CsvFormat::Generic => &[
            ("title", Title),
            ("name", Title),
            ("item", Title),
            ("account", Title),
            ("名称", Title),
            ("标题", Title),
            ("url", Url),
            ("uri", Url),
            ("website", Url),
            ("site", Url),
            ("login_uri", Url),
            ("address", Url),
            ("网址", Url),
            ("网站", Url),
            ("username", Username),
            ("user", Username),
            ("login", Username),
            ("email", Username),
            ("user name", Username),
            ("login_username", Username),
            ("用户名", Username),
            ("账号", Username),
            ("password", Password),
            ("pass", Password),
            ("pwd", Password),
            ("login_password", Password),
            ("密码", Password),
            ("notes", Notes),
            ("note", Notes),
            ("extra", Notes),
            ("comment", Notes),
            ("comments", Notes),
            ("备注", Notes),
            ("totp", Totp),
            ("otp", Totp),
            ("otpauth", Totp),
            ("login_totp", Totp),
            ("2fa", Totp),
            ("tags", Tags),
            ("folder", Folder),
            ("group", Folder),
            ("grouping", Folder),
        ],
    }
}

fn required_cols(format: CsvFormat) -> &'static [Col] {
    match format {
        CsvFormat::Bitwarden => &[Col::Title, Col::Type],
        CsvFormat::Generic => &[],
        _ => &[Col::Url, Col::Username, Col::Password],
    }
}

fn map_header(format: CsvFormat, header: &csv::StringRecord) -> HashMap<Col, usize> {
    let table = aliases(format);
    let mut map = HashMap::new();
    for (i, h) in header.iter().enumerate() {
        let h = h.trim().trim_start_matches('\u{feff}').to_lowercase();
        if let Some((_, col)) = table.iter().find(|(name, _)| *name == h) {
            map.entry(*col).or_insert(i);
        }
    }
    map
}

/// Guess the format from the header line.
pub fn detect_format(bytes: &[u8]) -> Option<CsvFormat> {
    let text = std::str::from_utf8(bytes).ok()?;
    let first = text
        .trim_start_matches('\u{feff}')
        .lines()
        .next()?
        .to_lowercase();
    let has = |s: &str| first.split(',').any(|h| h.trim().trim_matches('"') == s);
    if has("login_uri") && has("login_password") {
        Some(CsvFormat::Bitwarden)
    } else if has("httprealm") || has("formactionorigin") {
        Some(CsvFormat::Firefox)
    } else if has("grouping") && has("extra") {
        Some(CsvFormat::LastPass)
    } else if has("otpauth") && has("title") && (has("archived") || has("favorite")) {
        Some(CsvFormat::OnePassword)
    } else if has("otpauth") && has("title") {
        Some(CsvFormat::Safari)
    } else if has("name") && has("url") && has("username") && has("password") {
        Some(CsvFormat::Chrome)
    } else {
        Some(CsvFormat::Generic)
    }
}

/// An existing entry used for de-duplication.
#[derive(Debug, Clone)]
pub struct ExistingEntry {
    /// Entry id.
    pub entry_id: EntryId,
    /// Username.
    pub username: Option<String>,
    /// URLs.
    pub urls: Vec<String>,
}

/// A duplicate that was not imported.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DuplicateInfo {
    /// The entry it duplicates (existing, or imported from an earlier row).
    pub existing_entry_id: EntryId,
    /// Title of the skipped row.
    pub title: String,
    /// Username of the skipped row.
    pub username: Option<String>,
    /// First URL of the skipped row.
    pub url: Option<String>,
    /// 1-based line number in the file (header = 1). Additive field.
    #[serde(default)]
    pub row: u64,
}

/// A row that was not imported (or imported with a caveat, see `warnings`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkippedRow {
    /// 1-based line number in the file (header = 1).
    pub row: u64,
    /// Non-sensitive reason.
    pub reason: String,
}

/// `ImportReport {imported, duplicates, skipped}` (+ additive `warnings`).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ImportReport {
    /// Number of entries imported.
    pub imported: u32,
    /// Duplicates not imported.
    pub duplicates: Vec<DuplicateInfo>,
    /// Rows skipped.
    pub skipped: Vec<SkippedRow>,
    /// Rows imported with a caveat (e.g. an invalid TOTP value was dropped).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<SkippedRow>,
}

/// Parsed entries plus the report.
pub struct ImportResult {
    /// New entries (fresh ids).
    pub entries: Vec<(EntryId, EntryPayload)>,
    /// Report.
    pub report: ImportReport,
}

impl core::fmt::Debug for ImportResult {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ImportResult")
            .field("entries", &self.entries.len())
            .field("report", &self.report)
            .finish()
    }
}

fn dedup_key(urls: &[String], username: &Option<String>) -> Option<(String, String)> {
    let site = site_key(urls)?;
    let user = username.as_deref().unwrap_or("").trim().to_lowercase();
    Some((site, user))
}

fn normalize_url(raw: &str) -> Option<String> {
    let t = raw.trim();
    if t.is_empty() || t == "http://sn" {
        return None;
    }
    host_of(t)?;
    Some(if t.contains("://") {
        t.to_owned()
    } else {
        format!("https://{t}")
    })
}

fn parse_bitwarden_fields(raw: &str) -> Vec<CustomField> {
    raw.lines()
        .filter_map(|l| {
            let (n, v) = l.split_once(": ").or_else(|| l.split_once(':'))?;
            let n = n.trim();
            (!n.is_empty()).then(|| CustomField {
                name: n.to_owned(),
                value: SecretString::from(v.trim()),
                sensitive: true,
            })
        })
        .collect()
}

/// Parse a CSV export. `existing` are the vault's current entries (for de-duplication).
pub fn import_csv(
    format: CsvFormat,
    bytes: &[u8],
    existing: &[ExistingEntry],
) -> Result<ImportResult> {
    if bytes.len() > MAX_CSV_BYTES {
        return Err(VaultError::InvalidInput("CSV file too large"));
    }
    let text = std::str::from_utf8(bytes).map_err(|_| {
        VaultError::Invalid(Localized::new(
            "CSV 文件不是 UTF-8 编码",
            "The CSV file is not UTF-8 encoded.",
        ))
    })?;
    let text = text.trim_start_matches('\u{feff}');
    let mut rdr = csv::ReaderBuilder::new()
        .flexible(true)
        .has_headers(true)
        .from_reader(text.as_bytes());
    let header = rdr
        .headers()
        .map_err(|_| VaultError::InvalidInput("CSV header could not be read"))?
        .clone();
    let cols = map_header(format, &header);
    let missing = required_cols(format).iter().any(|c| !cols.contains_key(c));
    let usable = cols.contains_key(&Col::Password)
        || cols.contains_key(&Col::Notes)
        || cols.contains_key(&Col::Totp);
    if missing || !usable {
        return Err(VaultError::Invalid(Localized::new(
            format!(
                "CSV 表头与所选格式（{}）不符，请确认导出来源",
                format.as_str()
            ),
            format!(
                "The CSV header does not match the selected format ({}).",
                format.as_str()
            ),
        )));
    }

    let mut seen: HashMap<(String, String), EntryId> = HashMap::new();
    for e in existing {
        if let Some(k) = dedup_key(&e.urls, &e.username) {
            seen.entry(k).or_insert_with(|| e.entry_id.clone());
        }
    }
    let now = aipass_types::time::now();
    let mut out = ImportResult {
        entries: Vec::new(),
        report: ImportReport::default(),
    };
    let mut record = csv::StringRecord::new();
    let mut count = 0usize;
    loop {
        let line = rdr.position().line();
        match rdr.read_record(&mut record) {
            Ok(false) => break,
            Ok(true) => {}
            Err(_) => {
                out.report.skipped.push(SkippedRow {
                    row: line,
                    reason: "malformed CSV row".into(),
                });
                continue;
            }
        }
        let row = record.position().map_or(line, |p| p.line());
        count += 1;
        if count > MAX_ROWS {
            return Err(VaultError::InvalidInput("CSV file has too many rows"));
        }
        let get = |c: Col| -> Option<String> {
            cols.get(&c)
                .and_then(|i| record.get(*i))
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
        };
        if record.iter().all(|f| f.trim().is_empty()) {
            continue;
        }
        let mut password = get(Col::Password).map(SecretString::new);
        let username = get(Col::Username);
        let notes = get(Col::Notes);
        let url_raw = get(Col::Url);
        let urls: Vec<String> = url_raw
            .as_deref()
            .map(|u| u.split([',', '\n']).filter_map(normalize_url).collect())
            .unwrap_or_default();
        let item_type = get(Col::Type).map(|t| t.to_lowercase());

        let mut kind = EntryKind::Login;
        match format {
            CsvFormat::Bitwarden => match item_type.as_deref() {
                Some("login") | None => {}
                Some("note") | Some("securenote") | Some("secure note") => {
                    kind = EntryKind::SecureNote
                }
                Some(_) => {
                    out.report.skipped.push(SkippedRow {
                        row,
                        reason: "unsupported item type (card / identity)".into(),
                    });
                    continue;
                }
            },
            CsvFormat::LastPass if url_raw.as_deref() == Some("http://sn") => {
                kind = EntryKind::SecureNote
            }
            _ => {}
        }
        let totp_raw = get(Col::Totp);
        if kind == EntryKind::Login && password.is_none() && totp_raw.is_none() {
            if notes.is_some() && username.is_none() && urls.is_empty() {
                kind = EntryKind::SecureNote;
            } else {
                out.report.skipped.push(SkippedRow {
                    row,
                    reason: "no password in this row".into(),
                });
                continue;
            }
        }
        let mut fields = match (format, get(Col::Fields)) {
            (CsvFormat::Bitwarden, Some(f)) => parse_bitwarden_fields(&f),
            _ => Vec::new(),
        };
        if kind == EntryKind::SecureNote {
            if notes.is_none() && password.is_none() && fields.is_empty() {
                out.report.skipped.push(SkippedRow {
                    row,
                    reason: "empty note".into(),
                });
                continue;
            }
            // a note that carries a secret keeps it as a sensitive field
            if let Some(pw) = password.take() {
                fields.push(CustomField {
                    name: "password".into(),
                    value: pw,
                    sensitive: true,
                });
            }
        }
        let mut totp = None;
        if let Some(t) = totp_raw {
            match crate::totp::parse_totp_input(&t) {
                Ok(cfg) => totp = Some(cfg),
                Err(_) => out.report.warnings.push(SkippedRow {
                    row,
                    reason: "invalid TOTP value was not imported".into(),
                }),
            }
        }
        push_entry(
            &mut out,
            &mut seen,
            Row {
                row,
                format,
                kind,
                title: get(Col::Title),
                username,
                urls,
                notes,
                secret: password,
                totp,
                fields,
                tags: get(Col::Tags),
                folder: get(Col::Folder),
            },
            &now,
        );
    }
    out.report.imported = u32::try_from(out.entries.len()).unwrap_or(u32::MAX);
    Ok(out)
}

struct Row {
    row: u64,
    format: CsvFormat,
    kind: EntryKind,
    title: Option<String>,
    username: Option<String>,
    urls: Vec<String>,
    notes: Option<String>,
    secret: Option<SecretString>,
    totp: Option<aipass_types::vault::TotpConfig>,
    fields: Vec<CustomField>,
    tags: Option<String>,
    folder: Option<String>,
}

fn push_entry(
    out: &mut ImportResult,
    seen: &mut HashMap<(String, String), EntryId>,
    r: Row,
    now: &aipass_types::time::Timestamp,
) {
    let Row {
        row,
        format,
        kind,
        title,
        username,
        urls,
        notes,
        secret,
        totp,
        fields,
        tags,
        folder,
    } = r;
    let title = title
        .or_else(|| {
            urls.first()
                .and_then(|u| host_of(u))
                .map(|h| registrable_domain(&h))
        })
        .or_else(|| username.clone())
        .unwrap_or_else(|| "未命名 / Untitled".to_owned());
    if kind == EntryKind::Login
        && let Some(k) = dedup_key(&urls, &username)
        && let Some(existing) = seen.get(&k)
    {
        out.report.duplicates.push(DuplicateInfo {
            existing_entry_id: existing.clone(),
            title,
            username,
            url: urls.first().cloned(),
            row,
        });
        return;
    }
    let mut p = EntryPayload::new(kind, title);
    p.username = username.clone();
    p.urls = urls.clone();
    p.notes = notes;
    p.secret = secret;
    p.totp = totp;
    p.fields = fields;
    let mut tag_list: Vec<String> = tags
        .map(|t| {
            t.split([',', ';'])
                .map(|s| s.trim().to_owned())
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default();
    if let Some(f) = folder.filter(|f| !f.is_empty()) {
        tag_list.push(f);
    }
    tag_list.sort();
    tag_list.dedup();
    p.tags = tag_list;
    p.lifecycle = Lifecycle::Imported;
    p.source = EntrySource::Import(format.as_str().to_owned());
    p.created_at = *now;
    p.updated_at = *now;
    let id = EntryId::generate();
    if kind == EntryKind::Login
        && let Some(k) = dedup_key(&urls, &username)
    {
        seen.insert(k, id.clone());
    }
    out.entries.push((id, p));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chrome_basic_and_dedup() {
        let csv = "name,url,username,password,note\n\
                   Example,https://www.example.com/login,Alice@Example.com,pw1,\n\
                   Example 2,https://accounts.example.com/,alice@example.com,pw2,dup\n\
                   NoPass,https://nopass.example,bob,,\n";
        let r = import_csv(CsvFormat::Chrome, csv.as_bytes(), &[]).unwrap();
        assert_eq!(r.report.imported, 1);
        assert_eq!(r.report.duplicates.len(), 1);
        assert_eq!(r.report.duplicates[0].existing_entry_id, r.entries[0].0);
        assert_eq!(r.report.skipped.len(), 1);
        assert_eq!(r.report.skipped[0].row, 4);
        let p = &r.entries[0].1;
        assert_eq!(p.lifecycle, Lifecycle::Imported);
        assert_eq!(p.source.as_string(), "import:chrome");
        assert!(!format!("{:?}", r.report).contains("pw1"));
    }

    #[test]
    fn wrong_header_is_rejected() {
        let csv = "foo,bar\n1,2\n";
        assert!(import_csv(CsvFormat::Chrome, csv.as_bytes(), &[]).is_err());
    }
}
