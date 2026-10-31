// SPDX-License-Identifier: Apache-2.0
//! CSV import fixtures for every supported format (CONTRACTS §2.8).

use aipass_types::vault::{EntryKind, Lifecycle};
use aipass_vault::import::{CsvFormat, ExistingEntry, detect_format, import_csv};

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(name),
    )
    .unwrap()
}

fn find<'a>(
    r: &'a aipass_vault::import::ImportResult,
    title: &str,
) -> &'a aipass_types::vault::EntryPayload {
    &r.entries
        .iter()
        .find(|(_, p)| p.title == title)
        .unwrap_or_else(|| panic!("missing {title}"))
        .1
}

#[test]
fn chrome() {
    let b = fixture("chrome.csv");
    assert_eq!(detect_format(&b), Some(CsvFormat::Chrome));
    let r = import_csv(CsvFormat::Chrome, &b, &[]).unwrap();
    assert_eq!(r.report.imported, 2);
    assert_eq!(
        r.report.duplicates.len(),
        1,
        "same site + case-insensitive username"
    );
    assert_eq!(r.report.duplicates[0].title, "Duplicate");
    assert_eq!(r.report.skipped.len(), 1);
    assert_eq!(r.report.skipped[0].row, 5);
    let shop = find(&r, "Shop");
    assert_eq!(shop.notes.as_deref(), Some("multi\nline note"));
    assert_eq!(shop.secret.as_ref().unwrap().expose(), "shop-pw");
    assert_eq!(shop.lifecycle, Lifecycle::Imported);
    assert_eq!(shop.source.as_string(), "import:chrome");
    // nothing secret in the report
    let rep = serde_json::to_string(&r.report).unwrap();
    for s in ["gh-pass-1", "shop-pw", "other-pw"] {
        assert!(!rep.contains(s));
    }
}

#[test]
fn firefox() {
    let b = fixture("firefox.csv");
    assert_eq!(detect_format(&b), Some(CsvFormat::Firefox));
    let r = import_csv(CsvFormat::Firefox, &b, &[]).unwrap();
    assert_eq!(r.report.imported, 2);
    let intra = r
        .entries
        .iter()
        .find(|(_, p)| p.urls[0].contains(":8443"))
        .unwrap();
    assert_eq!(intra.1.title, "intranet.example");
    assert_eq!(intra.1.username.as_deref(), Some("admin"));
}

#[test]
fn safari_with_totp() {
    let b = fixture("safari.csv");
    assert_eq!(detect_format(&b), Some(CsvFormat::Safari));
    let r = import_csv(CsvFormat::Safari, &b, &[]).unwrap();
    assert_eq!(r.report.imported, 2);
    let e = find(&r, "example.com (me@example.com)");
    assert_eq!(e.totp.as_ref().unwrap().secret.expose(), "JBSWY3DPEHPK3PXP");
    assert_eq!(
        r.report.warnings.len(),
        1,
        "invalid TOTP dropped with a warning"
    );
    assert!(find(&r, "Bad TOTP").totp.is_none());
}

#[test]
fn bitwarden_types_fields_and_folders() {
    let b = fixture("bitwarden.csv");
    assert_eq!(detect_format(&b), Some(CsvFormat::Bitwarden));
    let r = import_csv(CsvFormat::Bitwarden, &b, &[]).unwrap();
    assert_eq!(r.report.imported, 2);
    assert_eq!(r.report.skipped.len(), 1, "cards are not imported");
    let jira = find(&r, "Jira");
    assert_eq!(jira.fields.len(), 2);
    assert!(jira.fields.iter().all(|f| f.sensitive));
    assert_eq!(jira.tags, vec!["Work".to_owned()]);
    assert!(jira.totp.is_some());
    let note = find(&r, "Wifi notes");
    assert_eq!(note.kind, EntryKind::SecureNote);
}

#[test]
fn onepassword() {
    let b = fixture("1password.csv");
    assert_eq!(detect_format(&b), Some(CsvFormat::OnePassword));
    let r = import_csv(CsvFormat::OnePassword, &b, &[]).unwrap();
    assert_eq!(r.report.imported, 2);
    let aws = find(&r, "AWS Console");
    assert_eq!(aws.tags, vec!["cloud".to_owned(), "work".to_owned()]);
    assert_eq!(find(&r, "Server note").kind, EntryKind::SecureNote);
}

#[test]
fn lastpass_secure_notes() {
    let b = fixture("lastpass.csv");
    assert_eq!(detect_format(&b), Some(CsvFormat::LastPass));
    let r = import_csv(CsvFormat::LastPass, &b, &[]).unwrap();
    assert_eq!(r.report.imported, 2);
    let n = find(&r, "My Note");
    assert_eq!(n.kind, EntryKind::SecureNote);
    assert_eq!(n.notes.as_deref(), Some("Secret note body"));
    assert!(n.urls.is_empty());
    assert_eq!(find(&r, "LP Site").tags, vec!["Personal".to_owned()]);
}

#[test]
fn generic_with_chinese_headers_and_bom() {
    let b = fixture("generic.csv");
    let r = import_csv(CsvFormat::Generic, &b, &[]).unwrap();
    assert_eq!(r.report.imported, 2);
    let cn = find(&r, "中文站点");
    assert_eq!(cn.username.as_deref(), Some("张三"));
    assert_eq!(cn.notes.as_deref(), Some("备注内容"));
    assert_eq!(
        find(&r, "plain.example").secret.as_ref().unwrap().expose(),
        "pw2"
    );
}

#[test]
fn dedup_against_existing_vault_entries() {
    let b = fixture("chrome.csv");
    let existing = vec![ExistingEntry {
        entry_id: aipass_types::ids::EntryId::generate(),
        username: Some("OctoCat".into()),
        urls: vec!["https://github.com".into()],
    }];
    let r = import_csv(CsvFormat::Chrome, &b, &existing).unwrap();
    assert!(
        r.report
            .duplicates
            .iter()
            .any(|d| d.existing_entry_id == existing[0].entry_id && d.title == "GitHub")
    );
    assert_eq!(r.report.imported, 1);
}

#[test]
fn wrong_format_and_bad_encoding_rejected() {
    assert!(import_csv(CsvFormat::Bitwarden, &fixture("chrome.csv"), &[]).is_err());
    assert!(import_csv(CsvFormat::Chrome, &[0xff, 0xfe, 0x00], &[]).is_err());
}
