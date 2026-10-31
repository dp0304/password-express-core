// SPDX-License-Identifier: Apache-2.0
//! Recovery key and recovery kit (CONTRACTS §2.4, design doc §5.1, §10.5).
//!
//! `recovery key = 32 random bytes ‖ first 2 bytes of SHA-256(those 32)` → Crockford
//! base32 (55 characters) → `AIPR-` + groups of 4 joined by `-`. Parsing ignores case,
//! spaces and dashes, maps O→0 and I/L→1 and verifies the checksum.
//!
//! The kit is generated locally and never uploaded. It contains the vault id, the
//! recovery key, the creation time, the non-secret storage profile (access keys only if the
//! user explicitly opts in, avoiding the circular dependency of §10.5) and zh/en
//! instructions. Clients must run a recovery verification (the user re-enters the key).

use core::fmt;

use aipass_crypto::{DeviceIdentity, SecretString, sha256};
use aipass_types::ids::VaultId;
use aipass_types::storage::StorageProfile;
use aipass_types::time::{Timestamp, format_rfc3339};
use zeroize::{Zeroize, Zeroizing};

use crate::encoding::{crockford_decode, crockford_encode};
use crate::error::{Result, VaultError};

/// Prefix of formatted recovery keys.
pub const RECOVERY_KEY_PREFIX: &str = "AIPR";
/// Number of Crockford characters of a recovery key (34 bytes → 55 chars).
pub const RECOVERY_KEY_CHARS: usize = 55;

/// A 32-byte recovery secret. Zeroized on drop; `Debug` is redacted.
#[derive(Clone, PartialEq, Eq)]
pub struct RecoveryKey {
    secret: [u8; 32],
}

impl Drop for RecoveryKey {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

impl fmt::Debug for RecoveryKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RecoveryKey([REDACTED])")
    }
}

impl RecoveryKey {
    /// Generate a fresh recovery secret from the OS CSPRNG.
    pub fn generate() -> Result<Self> {
        Ok(Self {
            secret: aipass_crypto::rng::try_random_array::<32>()?,
        })
    }

    /// From raw secret bytes (test vectors, recovery).
    pub fn from_bytes(secret: [u8; 32]) -> Self {
        Self { secret }
    }

    /// `AIPR-XXXX-XXXX-…-XXX` (13 groups of 4 and one of 3 after the prefix).
    pub fn format(&self) -> SecretString {
        let mut raw = Zeroizing::new([0u8; 34]);
        raw[..32].copy_from_slice(&self.secret);
        let check = sha256(self.secret);
        raw[32..].copy_from_slice(&check[..2]);
        let encoded = Zeroizing::new(crockford_encode(raw.as_ref()));
        let mut out = String::with_capacity(5 + RECOVERY_KEY_CHARS + 14);
        out.push_str(RECOVERY_KEY_PREFIX);
        for chunk in encoded.as_bytes().chunks(4) {
            out.push('-');
            for b in chunk {
                out.push(*b as char);
            }
        }
        SecretString::new(out)
    }

    /// Parse a recovery key as typed by a user. Errors never echo the input.
    pub fn parse(input: &str) -> Result<Self> {
        let mut cleaned = Zeroizing::new(String::with_capacity(input.len()));
        for c in input.chars() {
            if c.is_whitespace() || c == '-' || c == '—' || c == '–' {
                continue;
            }
            cleaned.push(c.to_ascii_uppercase());
        }
        let body: &str = if cleaned.len() == RECOVERY_KEY_CHARS + RECOVERY_KEY_PREFIX.len()
            && cleaned.starts_with(RECOVERY_KEY_PREFIX)
        {
            &cleaned[RECOVERY_KEY_PREFIX.len()..]
        } else {
            &cleaned[..]
        };
        if body.len() != RECOVERY_KEY_CHARS {
            return Err(invalid_key());
        }
        let raw = Zeroizing::new(crockford_decode(body).ok_or_else(invalid_key)?);
        if raw.len() != 34 {
            return Err(invalid_key());
        }
        let mut secret = [0u8; 32];
        secret.copy_from_slice(&raw[..32]);
        let check = sha256(secret);
        if !aipass_crypto::ct_eq(&check[..2], &raw[32..]) {
            secret.zeroize();
            return Err(invalid_key());
        }
        Ok(Self { secret })
    }

    /// KEK for the `recovery_key` recovery wrap of `vault_id`.
    pub fn kek(&self, vault_id: &VaultId) -> aipass_crypto::Key32 {
        crate::keys::recovery_kek(&self.secret, vault_id)
    }

    /// The recovery identity enrolled as the vault's recovery member.
    pub fn identity(&self, vault_id: &VaultId) -> DeviceIdentity {
        crate::member::recovery_identity(&self.secret, vault_id)
    }
}

fn invalid_key() -> VaultError {
    VaultError::Invalid(aipass_types::Localized::new(
        "恢复密钥格式不正确或校验失败，请检查是否抄写有误",
        "The recovery key is malformed or its checksum does not match; check for typos.",
    ))
}

/// Inputs of the recovery kit text.
#[derive(Debug, Clone)]
pub struct RecoveryKit<'a> {
    /// Vault.
    pub vault_id: &'a VaultId,
    /// Formatted recovery key, or `None` once it has been verified and removed from the
    /// device (the kit then tells the user to use their saved copy).
    pub recovery_key: Option<&'a SecretString>,
    /// When the vault (or this key) was created.
    pub created_at: &'a Timestamp,
    /// Non-secret storage profile.
    pub storage: &'a StorageProfile,
    /// Storage access secret — only when the user explicitly opted in.
    pub storage_secret: Option<&'a SecretString>,
}

fn storage_lines(p: &StorageProfile, out: &mut String, zh: bool) {
    let kind = match p.kind {
        aipass_types::storage::StorageKind::Local => {
            if zh {
                "本机目录"
            } else {
                "local directory"
            }
        }
        aipass_types::storage::StorageKind::Official => {
            if zh {
                "官方密文同步"
            } else {
                "official encrypted sync"
            }
        }
        aipass_types::storage::StorageKind::S3 => {
            if zh {
                "S3 兼容存储"
            } else {
                "S3-compatible storage"
            }
        }
        aipass_types::storage::StorageKind::Webdav => "WebDAV",
        aipass_types::storage::StorageKind::Selfhost => {
            if zh {
                "自托管同步服务"
            } else {
                "self-hosted sync service"
            }
        }
    };
    let label = |zh_l: &str, en_l: &str| if zh { zh_l.to_owned() } else { en_l.to_owned() };
    out.push_str(&format!("  {}: {kind}\n", label("类型", "Kind")));
    let mut field = |zh_l: &str, en_l: &str, v: &Option<String>| {
        if let Some(v) = v {
            out.push_str(&format!("  {}: {v}\n", label(zh_l, en_l)));
        }
    };
    field("地址", "Endpoint", &p.endpoint);
    field("服务地址", "Base URL", &p.base_url);
    field("区域", "Region", &p.region);
    field("存储桶", "Bucket", &p.bucket);
    field("前缀", "Prefix", &p.prefix);
    field("目录", "Path", &p.path);
    field("用户名", "Username", &p.username);
}

/// Render the recovery kit as plain text (zh-CN first, then English).
pub fn recovery_kit_text(kit: &RecoveryKit<'_>) -> String {
    let mut s = String::new();
    s.push_str("AI 通行证 · 恢复包 / AI Pass · Recovery kit\n");
    s.push_str("==========================================\n\n");
    s.push_str(&format!("账号库 ID / Vault ID: {}\n", kit.vault_id));
    s.push_str(&format!(
        "创建时间 / Created: {}\n",
        format_rfc3339(kit.created_at)
    ));
    match kit.recovery_key {
        Some(k) => s.push_str(&format!("恢复密钥 / Recovery key:\n  {}\n", k.expose())),
        None => s.push_str(
            "恢复密钥 / Recovery key: 已验证并从本设备移除，请使用你之前保存的副本。\n  \
             (verified and removed from this device — use the copy you saved)\n",
        ),
    }
    s.push_str("\n存储位置 / Storage:\n");
    storage_lines(kit.storage, &mut s, true);
    if let Some(sec) = kit.storage_secret {
        s.push_str(&format!(
            "  存储访问密钥（你选择了写入恢复包）/ Storage access secret (you opted in): {}\n",
            sec.expose()
        ));
    } else {
        s.push_str(
            "  存储访问密钥未写入本恢复包。恢复时请在存储服务重新签发访问权限，或通过已配对的设备传递存储配置。\n",
        );
    }
    s.push_str("\n—— 中文说明 ——\n");
    s.push_str(
        "1. 请把本恢复包打印或抄写后离线保存，存放地点应独立于你唯一的手机和唯一的云存储。\n\
         2. 恢复密钥可以解开这个账号库。任何拿到它的人都可能读取你的账号，请勿拍照上传、发到聊天或交给 AI。\n\
         3. 恢复步骤：在新设备安装 AI 通行证 → 选择“用恢复密钥恢复” → 填写上面的存储位置和存储访问权限 → 输入恢复密钥。\n\
         4. 恢复后，请在“设备”中撤销丢失的设备，并按提示轮换它可能读取过的长期密码和 Key。\n\
         5. 官方服务无法凭邮箱或订阅账号帮你解密账号库；同时丢失全部可信设备和本恢复包时，数据无法找回。\n\
         6. 新设备只面对一个被整体回滚的存储时，若没有其他可信检查点，无法保证识别最新状态。\n",
    );
    s.push_str("\n—— Instructions (English) ——\n");
    s.push_str(
        "1. Print or copy this kit and keep it offline, somewhere independent of your only phone and your only cloud storage.\n\
         2. The recovery key unlocks this vault. Anyone who has it may read your accounts — never photograph, upload, paste it into a chat or give it to an AI.\n\
         3. To recover: install AI Pass on a new device → choose \"Recover with recovery key\" → enter the storage location above and storage access → enter the recovery key.\n\
         4. After recovering, revoke the lost device under Devices and rotate the long-term passwords and keys it could read, as suggested.\n\
         5. The official service cannot decrypt your vault from your email or subscription account. If every trusted device and this kit are lost, the data cannot be recovered.\n\
         6. A brand-new device facing storage that was rolled back as a whole cannot be guaranteed to detect the newest state without another trusted checkpoint.\n",
    );
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_parse_roundtrip_and_checksum() {
        // fixed secret so the single-typo checksum check below is deterministic
        let k = RecoveryKey::from_bytes(core::array::from_fn(|i| (i * 7 + 3) as u8));
        let f = k.format();
        let text = f.expose();
        assert!(text.starts_with("AIPR-"));
        let g = RecoveryKey::generate().unwrap();
        assert_eq!(RecoveryKey::parse(g.format().expose()).unwrap(), g);
        let groups: Vec<&str> = text.split('-').collect();
        assert_eq!(groups.len(), 15);
        assert!(groups[1..14].iter().all(|g| g.len() == 4));
        assert_eq!(groups[14].len(), 3);
        assert_eq!(RecoveryKey::parse(text).unwrap(), k);
        // case, spaces, no dashes, aliases
        let messy = text.to_lowercase().replace('-', " ");
        assert_eq!(RecoveryKey::parse(&messy).unwrap(), k);
        let without_prefix = &text[5..];
        assert_eq!(RecoveryKey::parse(without_prefix).unwrap(), k);
        let aliased = text[5..].replace('0', "o").replace('1', "I");
        assert_eq!(RecoveryKey::parse(&aliased).unwrap(), k);
        // single substitution breaks the checksum (or the encoding)
        let mut chars: Vec<char> = text.chars().collect();
        let i = 7;
        chars[i] = if chars[i] == 'A' { 'B' } else { 'A' };
        let typo: String = chars.into_iter().collect();
        assert!(RecoveryKey::parse(&typo).is_err());
        assert!(RecoveryKey::parse("AIPR-1234").is_err());
        let err = RecoveryKey::parse(&typo).unwrap_err();
        assert!(!format!("{err:?} {err}").contains(&typo[5..]));
        assert!(!format!("{k:?}").contains(&text[5..9]));
    }

    #[test]
    fn kit_contains_required_parts() {
        let k = RecoveryKey::generate().unwrap();
        let f = k.format();
        let v = VaultId::generate();
        let mut sp = StorageProfile::new(aipass_types::storage::StorageKind::S3);
        sp.bucket = Some("my-bucket".into());
        sp.credential_ref = Some("ref-should-not-print".into());
        let now = aipass_types::time::now();
        let text = recovery_kit_text(&RecoveryKit {
            vault_id: &v,
            recovery_key: Some(&f),
            created_at: &now,
            storage: &sp,
            storage_secret: None,
        });
        assert!(text.contains(v.as_str()));
        assert!(text.contains(f.expose()));
        assert!(text.contains("my-bucket"));
        assert!(text.contains("中文说明") && text.contains("English"));
        assert!(!text.contains("ref-should-not-print"));
    }
}
