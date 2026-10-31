// SPDX-License-Identifier: Apache-2.0
//! Connection keys of AI host bridges (CONTRACTS §9: `<AIPASS_HOME>/connections/<conn_id>.key`, 0600).
//!
//! A connection key is the Ed25519 key an MCP bridge / SDK uses to sign broker requests
//! (`AIPass-Sig kid=conn_…`). It is the bridge's *only* secret — it authorizes nothing by
//! itself: every request is still checked against the connection status, policies, grants and
//! budgets by the broker. The single canonical file format (CONTRACTS §16.7), written by
//! this crate and by both SDKs, is JSON:
//!
//! ```json
//! {"format":"aipass-connection-key-1","connection_id":"conn_…","seed":"<b64u 32 bytes>",
//!  "public_key":"<b64u>","broker_url":"https://node.example.com","host_type":"codex",
//!  "display_name":"Codex","created_at":"2026-10-30T12:00:00Z"}
//! ```
//!
//! `broker_url` is omitted when unknown; an SDK file may also omit `host_type` (read as
//! `sdk`), `display_name` and `created_at`. The loader still reads the legacy Rust layout
//! `{"format":1,"kind":"aipass-connection-key",…}` written by earlier builds.
//!
//! `broker_url` is recorded only when the pairing explicitly targeted a broker (`--broker` /
//! `AIPASS_BROKER_URL`). On Unix the file must not be readable by group/others; loading a key
//! with a looser mode fails (like OpenSSH) instead of silently using it.

use std::fmt;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use aipass_crypto::{Ed25519Keypair, Ed25519Signer, SecretString, b64u};
use aipass_types::models::HostType;
use aipass_types::time::{Timestamp, rfc3339};
use aipass_types::ConnectionId;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::auth::Auth;
use crate::error::ClientError;
use crate::home::{AipassHome, ensure_private_dir};

/// `format` of the canonical key file (shared with the Python and TypeScript SDKs).
pub const KEY_FILE_FORMAT: &str = "aipass-connection-key-1";
/// `kind` of the legacy Rust key file (`format: 1`), still accepted by the loader.
const LEGACY_KIND: &str = "aipass-connection-key";
const MAX_KEY_FILE: u64 = 64 * 1024;

/// Non-secret metadata stored next to a connection key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectionKeyMeta {
    /// Host type label used at pairing.
    pub host_type: HostType,
    /// Display label used at pairing (self-declared — never identity).
    pub display_name: String,
    /// Broker the connection was explicitly paired against, if any.
    #[serde(default)]
    pub broker_url: Option<String>,
    /// When the key was stored.
    #[serde(with = "rfc3339")]
    pub created_at: Timestamp,
}

/// A connection id + its Ed25519 signing key.
#[derive(Clone)]
pub struct ConnectionKey {
    connection_id: ConnectionId,
    keypair: Arc<Ed25519Keypair>,
    meta: ConnectionKeyMeta,
}

impl fmt::Debug for ConnectionKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConnectionKey")
            .field("connection_id", &self.connection_id)
            .field("public_key", &self.keypair.public_key_b64u())
            .field("seed", &"[REDACTED]")
            .field("meta", &self.meta)
            .finish()
    }
}

impl ConnectionKey {
    /// Wrap an existing keypair.
    pub fn new(connection_id: ConnectionId, keypair: Ed25519Keypair, meta: ConnectionKeyMeta) -> Self {
        Self {
            connection_id,
            keypair: Arc::new(keypair),
            meta,
        }
    }

    /// Connection id (`kid`).
    pub fn connection_id(&self) -> &ConnectionId {
        &self.connection_id
    }

    /// Metadata.
    pub fn meta(&self) -> &ConnectionKeyMeta {
        &self.meta
    }

    /// Public key (b64u).
    pub fn public_key_b64u(&self) -> String {
        self.keypair.public_key_b64u()
    }

    /// Public key bytes.
    pub fn public_key(&self) -> [u8; 32] {
        self.keypair.public_key()
    }

    /// Short, non-secret fingerprint of the public key (first 12 b64u chars of its SHA-256).
    pub fn fingerprint(&self) -> String {
        let h = aipass_crypto::sha256_b64u(self.keypair.public_key());
        h.chars().take(12).collect()
    }

    /// The signer (shared).
    pub fn signer(&self) -> Arc<dyn Ed25519Signer + Send + Sync> {
        self.keypair.clone()
    }

    /// `AIPass-Sig kid=conn_…` authentication.
    pub fn auth(&self) -> Auth {
        Auth::signed(self.connection_id.as_str(), self.signer())
    }
}

/// Canonical key file as written (field order kept stable for readability).
#[derive(Serialize)]
struct KeyFileOut<'a> {
    format: &'static str,
    connection_id: &'a ConnectionId,
    seed: &'a str,
    public_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    broker_url: Option<&'a str>,
    host_type: HostType,
    display_name: &'a str,
    created_at: String,
}

/// Key file as read: the canonical format or the legacy Rust layout.
#[derive(Deserialize)]
struct KeyFileIn {
    format: serde_json::Value,
    #[serde(default)]
    kind: Option<String>,
    connection_id: ConnectionId,
    #[serde(default)]
    public_key: Option<String>,
    seed: SecretString,
    #[serde(default)]
    host_type: Option<String>,
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default)]
    broker_url: Option<String>,
    #[serde(default)]
    created_at: Option<String>,
}

impl KeyFileIn {
    /// True for the canonical format; false for the legacy layout; `None` otherwise.
    fn canonical(&self) -> Option<bool> {
        match &self.format {
            serde_json::Value::String(f) if f == KEY_FILE_FORMAT => Some(true),
            serde_json::Value::Number(n) if n.as_u64() == Some(1) && self.kind.as_deref() == Some(LEGACY_KIND) => Some(false),
            _ => None,
        }
    }
}

/// Directory of connection key files.
#[derive(Debug, Clone)]
pub struct KeyStore {
    dir: PathBuf,
}

impl KeyStore {
    /// `<home>/connections`.
    pub fn new(home: &AipassHome) -> Self {
        Self {
            dir: home.connections_dir(),
        }
    }

    /// Explicit directory.
    pub fn at(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    /// Directory.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// `<dir>/<conn_id>.key`.
    pub fn path_for(&self, id: &ConnectionId) -> PathBuf {
        self.dir.join(format!("{}.key", id.as_str()))
    }

    /// Store a key (atomic, 0600; directory 0700). Overwrites an existing file for the id.
    pub fn save(&self, key: &ConnectionKey) -> Result<PathBuf, ClientError> {
        ensure_private_dir(&self.dir)?;
        let seed = key.keypair.seed();
        let seed_b64 = Zeroizing::new(b64u::encode(seed.expose()));
        let file = KeyFileOut {
            format: KEY_FILE_FORMAT,
            connection_id: &key.connection_id,
            seed: &seed_b64,
            public_key: key.public_key_b64u(),
            broker_url: key.meta.broker_url.as_deref(),
            host_type: key.meta.host_type,
            display_name: &key.meta.display_name,
            created_at: aipass_types::time::format_rfc3339(&key.meta.created_at),
        };
        let body = Zeroizing::new(
            serde_json::to_vec_pretty(&file).map_err(|e| ClientError::Key(e.to_string()))?,
        );
        let path = self.path_for(&key.connection_id);
        atomic_write(&path, &body, 0o600)?;
        Ok(path)
    }

    /// Load the key of `id`.
    pub fn load(&self, id: &ConnectionId) -> Result<ConnectionKey, ClientError> {
        let path = self.path_for(id);
        let key = load_key_file(&path)?;
        if key.connection_id != *id {
            return Err(ClientError::Key(format!(
                "{} belongs to a different connection",
                path.display()
            )));
        }
        Ok(key)
    }

    /// Connection ids with a key file, sorted.
    pub fn list(&self) -> Result<Vec<ConnectionId>, ClientError> {
        let rd = match std::fs::read_dir(&self.dir) {
            Ok(rd) => rd,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e.into()),
        };
        let mut ids = Vec::new();
        for ent in rd {
            let ent = ent?;
            let name = ent.file_name();
            let Some(name) = name.to_str() else { continue };
            if let Some(stem) = name.strip_suffix(".key")
                && let Ok(id) = ConnectionId::parse(stem)
            {
                ids.push(id);
            }
        }
        ids.sort_by(|a, b| a.as_str().cmp(b.as_str()));
        Ok(ids)
    }

    /// Load `id`, or — when `id` is `None` — the only stored key. Several keys without an
    /// explicit id is an error listing them (the bridge never guesses between connections).
    pub fn load_selected(&self, id: Option<&ConnectionId>) -> Result<ConnectionKey, ClientError> {
        if let Some(id) = id {
            return self.load(id);
        }
        let ids = self.list()?;
        match ids.as_slice() {
            [] => Err(ClientError::Key(format!(
                "no connection key in {} — run `aipass-mcp pair` first",
                self.dir.display()
            ))),
            [one] => self.load(one),
            many => Err(ClientError::Key(format!(
                "several connections are paired ({}); pass --connection <id>",
                many.iter().map(|i| i.as_str()).collect::<Vec<_>>().join(", ")
            ))),
        }
    }

    /// Delete the key file of `id` (missing file is not an error).
    pub fn delete(&self, id: &ConnectionId) -> Result<(), ClientError> {
        match std::fs::remove_file(self.path_for(id)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }
}

/// Problems found when inspecting a key file without loading the secret into use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyFileCheck {
    /// Path.
    pub path: PathBuf,
    /// Unix mode bits (if available).
    pub mode: Option<u32>,
    /// Mode allows group/other access.
    pub too_open: bool,
}

/// Inspect a key file's permissions.
pub fn check_key_file(path: &Path) -> Result<KeyFileCheck, ClientError> {
    let meta = std::fs::metadata(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = meta.permissions().mode() & 0o777;
        Ok(KeyFileCheck {
            path: path.to_owned(),
            mode: Some(mode),
            too_open: mode & 0o077 != 0,
        })
    }
    #[cfg(not(unix))]
    {
        let _ = meta;
        Ok(KeyFileCheck {
            path: path.to_owned(),
            mode: None,
            too_open: false,
        })
    }
}

/// Load and validate a key file.
pub fn load_key_file(path: &Path) -> Result<ConnectionKey, ClientError> {
    let meta = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(ClientError::Key(format!(
                "{} does not exist — run `aipass-mcp pair` first",
                path.display()
            )));
        }
        Err(e) => return Err(e.into()),
    };
    if !meta.is_file() || meta.len() > MAX_KEY_FILE {
        return Err(ClientError::Key(format!(
            "{} is not a connection key file",
            path.display()
        )));
    }
    let check = check_key_file(path)?;
    if check.too_open {
        return Err(ClientError::Key(format!(
            "{} is accessible by other users (mode {:o}); run `chmod 600 {}`",
            path.display(),
            check.mode.unwrap_or(0),
            path.display()
        )));
    }
    let bytes = Zeroizing::new(std::fs::read(path)?);
    let file: KeyFileIn = serde_json::from_slice(&bytes).map_err(|_| {
        ClientError::Key(format!("{} is not a valid connection key file", path.display()))
    })?;
    let Some(canonical) = file.canonical() else {
        return Err(ClientError::Key(format!(
            "{} has an unsupported format",
            path.display()
        )));
    };
    let seed = Zeroizing::new(
        b64u::decode_array::<32>(file.seed.expose())
            .map_err(|_| ClientError::Key(format!("{} has a malformed key", path.display())))?,
    );
    let keypair = Ed25519Keypair::from_seed(&seed);
    // the legacy layout always carried the public key; the canonical one does too, but an
    // SDK file without it is still usable (the key is derived from the seed)
    match file.public_key.as_deref() {
        Some(pk) if pk == keypair.public_key_b64u() => {}
        None if canonical => {}
        _ => {
            return Err(ClientError::Key(format!(
                "{} is corrupted (public key mismatch)",
                path.display()
            )));
        }
    }
    let malformed = |what: &str| ClientError::Key(format!("{} has a malformed {what}", path.display()));
    let host_type = match file.host_type.as_deref() {
        None if canonical => HostType::Sdk,
        None => return Err(malformed("host_type")),
        // a host label this build does not know is kept as `custom` (labels never grant anything)
        Some(h) => serde_json::from_value(serde_json::Value::String(h.to_owned())).unwrap_or(HostType::Custom),
    };
    let display_name = match file.display_name {
        Some(d) => d,
        None if canonical => file.connection_id.as_str().to_owned(),
        None => return Err(malformed("display_name")),
    };
    let created_at = match file.created_at.as_deref() {
        Some(t) => aipass_types::time::parse_rfc3339(t).map_err(|_| malformed("created_at"))?,
        None if canonical => std::fs::metadata(path)
            .and_then(|m| m.modified())
            .map(Timestamp::from)
            .unwrap_or_else(|_| aipass_types::time::now()),
        None => return Err(malformed("created_at")),
    };
    let broker_url = file.broker_url.filter(|u| !u.is_empty());
    Ok(ConnectionKey::new(
        file.connection_id,
        keypair,
        ConnectionKeyMeta { host_type, display_name, broker_url, created_at },
    ))
}

/// Atomically write `bytes` to `path` with Unix `mode` (temp file in the same directory,
/// fsync, rename, fsync directory).
pub fn atomic_write(path: &Path, bytes: &[u8], mode: u32) -> Result<(), ClientError> {
    let dir = path
        .parent()
        .ok_or_else(|| ClientError::Config(format!("{} has no parent", path.display())))?;
    std::fs::create_dir_all(dir)?;
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("file");
    let suffix = b64u::encode(aipass_crypto::rng::try_random_array::<6>().map_err(|_| {
        ClientError::Config("OS random number generator unavailable".into())
    })?);
    let tmp = dir.join(format!(".{name}.tmp-{suffix}"));
    let result = (|| -> Result<(), ClientError> {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(mode);
        }
        #[cfg(not(unix))]
        let _ = mode;
        let mut f = opts.open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        drop(f);
        std::fs::rename(&tmp, path)?;
        #[cfg(unix)]
        if let Ok(d) = std::fs::File::open(dir) {
            let _ = d.sync_all();
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta() -> ConnectionKeyMeta {
        ConnectionKeyMeta {
            host_type: HostType::Codex,
            display_name: "Codex".into(),
            broker_url: None,
            created_at: aipass_types::time::now(),
        }
    }

    #[test]
    fn save_load_list_delete() {
        let dir = tempfile::tempdir().unwrap();
        let store = KeyStore::at(dir.path().join("connections"));
        assert!(store.list().unwrap().is_empty());
        assert!(store.load_selected(None).is_err());
        let id = ConnectionId::generate();
        let key = ConnectionKey::new(id.clone(), Ed25519Keypair::generate(), meta());
        let path = store.save(&key).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
            assert_eq!(
                std::fs::metadata(store.dir()).unwrap().permissions().mode() & 0o777,
                0o700
            );
        }
        let loaded = store.load(&id).unwrap();
        assert_eq!(loaded.public_key(), key.public_key());
        assert_eq!(store.load_selected(None).unwrap().connection_id(), &id);
        let id2 = ConnectionId::generate();
        store
            .save(&ConnectionKey::new(id2.clone(), Ed25519Keypair::generate(), meta()))
            .unwrap();
        assert_eq!(store.list().unwrap().len(), 2);
        let err = store.load_selected(None).unwrap_err().to_string();
        assert!(err.contains(id.as_str()) && err.contains(id2.as_str()));
        store.delete(&id2).unwrap();
        store.delete(&id2).unwrap();
        assert_eq!(store.list().unwrap(), vec![id]);
    }

    #[test]
    fn debug_never_shows_seed() {
        let kp = Ed25519Keypair::from_seed(&[7u8; 32]);
        let seed_b64 = b64u::encode([7u8; 32]);
        let key = ConnectionKey::new(ConnectionId::generate(), kp, meta());
        let dbg = format!("{key:?}");
        assert!(dbg.contains("[REDACTED]"));
        assert!(!dbg.contains(&seed_b64));
    }

    #[cfg(unix)]
    #[test]
    fn refuses_group_readable_and_tampered_files() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let store = KeyStore::at(dir.path());
        let id = ConnectionId::generate();
        let key = ConnectionKey::new(id.clone(), Ed25519Keypair::generate(), meta());
        let path = store.save(&key).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let err = store.load(&id).unwrap_err().to_string();
        assert!(err.contains("chmod 600"), "{err}");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        let other = Ed25519Keypair::generate().public_key_b64u();
        let tampered = text.replace(&key.public_key_b64u(), &other);
        std::fs::write(&path, tampered).unwrap();
        assert!(store.load(&id).unwrap_err().to_string().contains("mismatch"));
    }
}
