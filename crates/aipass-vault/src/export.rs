// SPDX-License-Identifier: Apache-2.0
//! Exports (CONTRACTS §2.5): encrypted `.aipassx` and plaintext CSV.
//!
//! `.aipassx` = `{format:"aipass-export-1", created_at, kdf:{alg:"argon2id",m,t,p,salt},
//! nonce, ciphertext}` where `ciphertext = XChaCha20-Poly1305(Argon2id(password), nonce,
//! JCS({vault_id, entries:[{entry_id, version, payload}]}), aad = "aipass:v1:export:aipass-export-1")`.
//!
//! CSV export `title,url,username,password,notes,totp,kind` requires re-authentication by
//! the client and must show [`csv_export_warning`]. Exports are never offered to AI.

use aipass_crypto::{Argon2Params, Argon2idDescriptor, SecretString, aead};
use aipass_types::Localized;
use aipass_types::canonical::to_jcs_bytes;
use aipass_types::ids::{EntryId, VaultId};
use aipass_types::time::{Timestamp, rfc3339};
use aipass_types::vault::{EntryKind, EntryPayload};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::{Result, VaultError};

/// Format tag of encrypted exports.
pub const EXPORT_FORMAT: &str = "aipass-export-1";
/// AAD of the export ciphertext.
pub const EXPORT_AAD: &str = "aipass:v1:export:aipass-export-1";
/// Minimum export password length (characters).
pub const MIN_EXPORT_PASSWORD_CHARS: usize = 10;

/// The `.aipassx` file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedExport {
    /// `aipass-export-1`.
    pub format: String,
    /// Created.
    #[serde(with = "rfc3339")]
    pub created_at: Timestamp,
    /// Argon2id parameters + salt.
    pub kdf: Argon2idDescriptor,
    /// XChaCha20 nonce.
    #[serde(with = "aipass_crypto::b64u::array")]
    pub nonce: [u8; 24],
    /// Ciphertext ‖ tag.
    #[serde(with = "aipass_crypto::b64u::bytes")]
    pub ciphertext: Vec<u8>,
}

/// One exported entry.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportEntry {
    /// Entry id.
    pub entry_id: EntryId,
    /// Version exported.
    pub version: u64,
    /// Decrypted payload.
    pub payload: EntryPayload,
}

impl core::fmt::Debug for ExportEntry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ExportEntry")
            .field("entry_id", &self.entry_id)
            .field("version", &self.version)
            .finish_non_exhaustive()
    }
}

/// Decrypted body of an export.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportBody {
    /// Source vault.
    pub vault_id: VaultId,
    /// Entries.
    pub entries: Vec<ExportEntry>,
}

fn weak_password() -> VaultError {
    VaultError::Invalid(Localized::new(
        "导出密码至少需要 10 个字符",
        "The export password must be at least 10 characters.",
    ))
}

/// Encrypt an export. Use [`Argon2Params::CONTRACT_V1`] in production.
pub fn export_encrypted(
    body: &ExportBody,
    password: &SecretString,
    params: Argon2Params,
    now: &Timestamp,
) -> Result<Vec<u8>> {
    if password.expose().chars().count() < MIN_EXPORT_PASSWORD_CHARS {
        return Err(weak_password());
    }
    let kdf = Argon2idDescriptor::generate(params)?;
    let key = kdf.derive(password.expose().as_bytes())?;
    let pt = Zeroizing::new(to_jcs_bytes(body)?);
    let (nonce, ciphertext) = aead::seal(&key, EXPORT_AAD.as_bytes(), &pt)?;
    let file = EncryptedExport {
        format: EXPORT_FORMAT.to_owned(),
        created_at: aipass_types::time::truncate(*now),
        kdf,
        nonce,
        ciphertext,
    };
    Ok(to_jcs_bytes(&file)?)
}

/// Decrypt an `.aipassx` file.
pub fn import_encrypted(bytes: &[u8], password: &SecretString) -> Result<ExportBody> {
    let file: EncryptedExport = serde_json::from_slice(bytes).map_err(|_| {
        VaultError::Invalid(Localized::new(
            "不是有效的 AI 通行证导出文件",
            "Not a valid AI Pass export file.",
        ))
    })?;
    if file.format != EXPORT_FORMAT {
        return Err(VaultError::Unsupported("export format"));
    }
    let key = file
        .kdf
        .derive(password.expose().as_bytes())
        .map_err(|_| VaultError::InvalidInput("export KDF parameters rejected"))?;
    let pt =
        aead::open(&key, &file.nonce, EXPORT_AAD.as_bytes(), &file.ciphertext).map_err(|_| {
            VaultError::Invalid(Localized::new(
                "导出密码不正确，或文件已损坏",
                "Wrong export password, or the file is damaged.",
            ))
        })?;
    serde_json::from_slice(pt.expose()).map_err(|_| VaultError::Integrity("export body invalid"))
}

/// Warning shown before a CSV export (plaintext file risk, §6.1).
pub fn csv_export_warning() -> Localized {
    Localized::new(
        "CSV 是未加密的明文文件，任何能读取它的人或程序都能看到全部密码。请只在必要时导出，导入目标后立即删除；在 SSD 和云盘上删除不一定能保证无法恢复。导出不会提供给 AI。",
        "A CSV export is unencrypted plaintext: anyone or any program that can read it sees every password. Export only when necessary and delete it right after importing elsewhere; on SSDs and cloud drives deletion cannot guarantee the data is unrecoverable. Exports are never offered to AI.",
    )
}

fn kind_str(k: EntryKind) -> &'static str {
    match k {
        EntryKind::Login => "login",
        EntryKind::ApiKey => "api_key",
        EntryKind::Database => "database",
        EntryKind::OauthToken => "oauth_token",
        EntryKind::SshKey => "ssh_key",
        EntryKind::SecureNote => "secure_note",
        EntryKind::StorageCredential => "storage_credential",
    }
}

/// CSV export `title,url,username,password,notes,totp,kind` (totp as `otpauth://` URI).
/// The buffer is zeroized on drop.
pub fn export_csv(entries: &[&EntryPayload]) -> Result<Zeroizing<Vec<u8>>> {
    let mut w = csv::WriterBuilder::new()
        .terminator(csv::Terminator::CRLF)
        .from_writer(Vec::new());
    w.write_record([
        "title", "url", "username", "password", "notes", "totp", "kind",
    ])
    .map_err(|_| VaultError::Internal("csv write failed"))?;
    for p in entries {
        let totp = p
            .totp
            .as_ref()
            .map(|t| crate::totp::to_otpauth(t, Some(&p.title), p.username.as_deref()));
        let rec = [
            p.title.as_str(),
            p.urls.first().map(String::as_str).unwrap_or(""),
            p.username.as_deref().unwrap_or(""),
            p.secret.as_ref().map(|s| s.expose()).unwrap_or(""),
            p.notes.as_deref().unwrap_or(""),
            totp.as_ref().map(|t| t.expose()).unwrap_or(""),
            kind_str(p.kind),
        ];
        w.write_record(rec)
            .map_err(|_| VaultError::Internal("csv write failed"))?;
    }
    let inner = w
        .into_inner()
        .map_err(|_| VaultError::Internal("csv write failed"))?;
    Ok(Zeroizing::new(inner))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypted_roundtrip_and_wrong_password() {
        let mut p = EntryPayload::new(EntryKind::Login, "Site");
        p.secret = Some(SecretString::from("s3cret"));
        let body = ExportBody {
            vault_id: VaultId::generate(),
            entries: vec![ExportEntry {
                entry_id: EntryId::generate(),
                version: 2,
                payload: p,
            }],
        };
        let pw = SecretString::from("export-password-1");
        let bytes = export_encrypted(
            &body,
            &pw,
            Argon2Params::INSECURE_FAST_FOR_TESTS_ONLY,
            &aipass_types::time::now(),
        )
        .unwrap();
        assert!(!String::from_utf8_lossy(&bytes).contains("s3cret"));
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["format"], EXPORT_FORMAT);
        assert_eq!(v["kdf"]["alg"], "argon2id");
        assert_eq!(import_encrypted(&bytes, &pw).unwrap(), body);
        assert!(import_encrypted(&bytes, &SecretString::from("wrong-password-1")).is_err());
        assert!(
            export_encrypted(
                &body,
                &SecretString::from("short"),
                Argon2Params::INSECURE_FAST_FOR_TESTS_ONLY,
                &aipass_types::time::now()
            )
            .is_err()
        );
    }

    #[test]
    fn csv_has_contract_header() {
        let mut p = EntryPayload::new(EntryKind::Login, "A, \"quoted\"");
        p.urls = vec!["https://a.example".into()];
        p.secret = Some(SecretString::from("pw"));
        let out = export_csv(&[&p]).unwrap();
        let text = String::from_utf8(out.to_vec()).unwrap();
        assert!(text.starts_with("title,url,username,password,notes,totp,kind\r\n"));
        assert!(text.contains("\"A, \"\"quoted\"\"\",https://a.example,,pw,,,login"));
    }
}
