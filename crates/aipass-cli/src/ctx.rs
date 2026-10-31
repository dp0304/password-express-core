// SPDX-License-Identifier: Apache-2.0
//! Shared state of one `aipass` invocation: home directory, the vault client over a
//! passphrase-protected secret store, the CLI config and broker clients.

use std::io::{BufRead, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use aipass_client::{Auth, BrokerClient, BrokerEndpoint};
use aipass_crypto::{DeviceIdentity, SecretString};
use aipass_crypto::password::Argon2Params;
use aipass_sync::{ClientConfig, StandardStoreFactory, VaultClient};
use aipass_types::error::Lang;
use aipass_types::ids::ExecutorId;
use aipass_types::vault::Platform;
use aipass_vault::SecretStore;
use aipass_vault::secret_store::FileSecretStore;
use anyhow::{Context, bail};
use serde::{Deserialize, Serialize};

/// Environment variable with the local passphrase (automation only).
pub const ENV_PASSPHRASE: &str = "AIPASS_PASSPHRASE";

/// Opt-in (`=1`, off by default) that lets approval-class commands (`approvals approve/deny`,
/// `connections approve`, `policy add`) run without a human at an interactive terminal.
/// Meant for automated tests and scripted single-user setups only; see
/// [`Ctx::require_human_approval`].
pub const ENV_UNATTENDED_APPROVALS: &str = "AIPASS_UNATTENDED_APPROVALS";

/// True when [`ENV_UNATTENDED_APPROVALS`] is exactly `1`.
pub fn unattended_approvals() -> bool {
    std::env::var(ENV_UNATTENDED_APPROVALS).is_ok_and(|v| v == "1")
}

/// A paired executor remembered by the CLI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairedExecutor {
    /// Executor id.
    pub executor_id: ExecutorId,
    /// Name.
    pub name: String,
    /// Relay / node base URL from the pairing link.
    pub relay_url: String,
}

/// `<home>/cli.json`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CliConfig {
    /// Broker URL used for broker commands.
    #[serde(default)]
    pub broker_url: Option<String>,
    /// Paired executors.
    #[serde(default)]
    pub executors: Vec<PairedExecutor>,
}

/// Invocation context.
pub struct Ctx {
    /// Home.
    pub home: PathBuf,
    /// Broker flag / env.
    pub broker_flag: Option<String>,
    /// JSON output.
    pub json: bool,
    /// Language.
    pub lang: Lang,
    secrets: Option<Arc<FileSecretStore>>,
    vault: Option<Arc<VaultClient>>,
}

impl Ctx {
    /// Build.
    pub fn new(home: Option<PathBuf>, broker_flag: Option<String>, json: bool, lang: &str) -> anyhow::Result<Self> {
        let home = match home {
            Some(h) => h,
            None => directories::BaseDirs::new().context("no home directory")?.home_dir().join(".aipass"),
        };
        let lang = if lang.to_ascii_lowercase().starts_with("en") { Lang::En } else { Lang::ZhCn };
        Ok(Self { home, broker_flag, json, lang, secrets: None, vault: None })
    }

    /// Vault client data directory.
    pub fn vault_dir(&self) -> PathBuf {
        self.home.join("vault")
    }
    fn secrets_path(&self) -> PathBuf {
        self.home.join("secrets.aipass")
    }
    fn config_path(&self) -> PathBuf {
        self.home.join("cli.json")
    }

    /// Pick the localized string.
    pub fn t<'a>(&self, zh: &'a str, en: &'a str) -> &'a str {
        if self.lang == Lang::En { en } else { zh }
    }

    /// Load `cli.json`.
    pub fn config(&self) -> anyhow::Result<CliConfig> {
        Ok(aipass_node::fsutil::read_json(&self.config_path())?.unwrap_or_default())
    }

    /// Save `cli.json` (0600).
    pub fn save_config(&self, c: &CliConfig) -> anyhow::Result<()> {
        aipass_node::fsutil::private_dir(&self.home)?;
        aipass_node::fsutil::write_json(&self.config_path(), c)
    }

    /// Human-presence check (design §7.5) for commands that hand out decryptable secrets:
    /// stdin must be an interactive terminal and the local passphrase is re-entered there
    /// every time — `AIPASS_PASSPHRASE`, `--yes` and [`ENV_UNATTENDED_APPROVALS`] never
    /// satisfy it, so an AI agent driving a non-interactive shell cannot use these commands.
    pub fn require_human(&self, what: (&str, &str), warning: (&str, &str)) -> anyhow::Result<()> {
        if !stdin_is_tty() {
            bail!(
                "{}",
                if self.lang == Lang::En {
                    format!("{} requires re-entering the passphrase on an interactive terminal", what.1)
                } else {
                    format!("{}需要在交互式终端中重新输入口令", what.0)
                }
            );
        }
        eprintln!("{}", self.t(warning.0, warning.1));
        let path = self.secrets_path();
        if !path.exists() {
            bail!("{}", self.t("本机尚未初始化（aipass init）", "this device is not initialised (aipass init)"));
        }
        let again = prompt_secret(self.t("请重新输入本机口令: ", "Re-enter the local passphrase: "))?;
        FileSecretStore::open_or_create(&path, &again, Argon2Params::CONTRACT_V1)
            .map_err(|_| anyhow::anyhow!("{}", self.t("口令错误", "wrong passphrase")))?;
        Ok(())
    }

    /// Fail fast — before any network call — when an approval-class command cannot get a
    /// human confirmation (no interactive terminal and no [`ENV_UNATTENDED_APPROVALS`]).
    pub fn ensure_approval_terminal(&self, what: (&str, &str)) -> anyhow::Result<()> {
        if unattended_approvals() || stdin_is_tty() {
            return Ok(());
        }
        bail!(
            "{}",
            if self.lang == Lang::En {
                format!(
                    "{} requires a confirmation and the passphrase on an interactive terminal (automation: see {ENV_UNATTENDED_APPROVALS})",
                    what.1
                )
            } else {
                format!("{}需要在交互式终端中确认并重新输入口令（自动化场景见 {ENV_UNATTENDED_APPROVALS}）", what.0)
            }
        );
    }

    /// Human-presence guard for approval-class commands (approve/deny an access request,
    /// approve a connection, add a policy): the same terminal + passphrase re-entry as
    /// [`Ctx::require_human`], preceded by a y/N confirmation unless `yes`. It runs
    /// before anything is signed, so an AI agent with shell access and `AIPASS_PASSPHRASE`
    /// cannot approve its own requests from a non-interactive shell.
    ///
    /// `AIPASS_UNATTENDED_APPROVALS=1` (off by default) skips it with a warning: that is the
    /// design §9.3 *compatible* mode — anything running as this OS user can then approve,
    /// so it is only for automated tests and scripted setups where no AI agent shares the
    /// user account.
    pub fn require_human_approval(&self, what: (&str, &str), question: (&str, &str), yes: bool) -> anyhow::Result<()> {
        if unattended_approvals() {
            eprintln!(
                "{}",
                self.t(
                    "⚠ AIPASS_UNATTENDED_APPROVALS=1：未经终端确认即执行批准类操作。同一系统用户下运行的任何程序（包括有 shell 权限的 AI 代理）都能借此批准自己的请求——这是设计 §9.3 的“兼容连接”等级，不提供人在场保证；只应用于自动化测试。",
                    "⚠ AIPASS_UNATTENDED_APPROVALS=1: approving without a terminal confirmation. Anything running as this OS user (an AI agent with shell access included) can approve its own requests — this is the design §9.3 compatible mode with no human-presence guarantee; use it only for automated tests."
                )
            );
            return Ok(());
        }
        self.ensure_approval_terminal(what)?;
        if !yes && !confirm(self.t(question.0, question.1))? {
            bail!("{}", self.t("已取消", "cancelled"));
        }
        self.require_human(what, ("⚠ 批准前请核对上面显示的内容。", "⚠ Check what is shown above before approving."))
    }

    /// Passphrase from AIPASS_PASSPHRASE or the terminal.
    pub fn passphrase(&self, confirm: bool) -> anyhow::Result<SecretString> {
        if let Ok(p) = std::env::var(ENV_PASSPHRASE) {
            if p.is_empty() {
                bail!("{ENV_PASSPHRASE} is empty");
            }
            return Ok(SecretString::new(p));
        }
        let p = prompt_secret(self.t("本机口令（保护设备密钥）: ", "Local passphrase (protects the device key): "))?;
        if confirm {
            let again = prompt_secret(self.t("再次输入口令: ", "Repeat passphrase: "))?;
            if again.expose() != p.expose() {
                bail!("{}", self.t("两次输入不一致", "passphrases do not match"));
            }
            if p.expose().chars().count() < 8 {
                bail!("{}", self.t("口令至少 8 个字符", "the passphrase needs at least 8 characters"));
            }
        }
        Ok(p)
    }

    fn open_secrets(&mut self, creating: bool) -> anyhow::Result<Arc<FileSecretStore>> {
        if let Some(s) = &self.secrets {
            return Ok(s.clone());
        }
        let path = self.secrets_path();
        if !creating && !path.exists() {
            bail!("{}", self.t("此设备上没有保管库，请先运行 `aipass vault init`", "no vault on this device; run `aipass vault init` first"));
        }
        aipass_node::fsutil::private_dir(&self.home)?;
        let pass = self.passphrase(creating && !path.exists())?;
        let store = FileSecretStore::open_or_create(&path, &pass, Argon2Params::CONTRACT_V1)
            .map_err(|e| anyhow::anyhow!("{}", e.localized().pick(self.lang)))?;
        let store = Arc::new(store);
        self.secrets = Some(store.clone());
        Ok(store)
    }

    /// Vault client (secret store opened with the passphrase).
    pub fn vault(&mut self, creating: bool) -> anyhow::Result<Arc<VaultClient>> {
        if self.vault.is_none() {
            let secrets = self.open_secrets(creating)?;
            let cfg = ClientConfig::new(self.vault_dir(), Platform::Cli, env!("CARGO_PKG_VERSION"));
            let client = VaultClient::open(cfg, secrets, Arc::new(StandardStoreFactory::new()))
                .map_err(|e| anyhow::anyhow!("{}", e.localized().pick(self.lang)))?;
            self.vault = Some(Arc::new(client));
        }
        self.vault.clone().context("vault")
    }

    /// Recover the vault on this fresh device with the recovery key (see
    /// [`VaultClient::recover_with_key`]); the local secret store is created with the
    /// passphrase like `vault init`.
    pub async fn recover_vault(
        &mut self,
        vault_id: &aipass_types::ids::VaultId,
        profile: aipass_storage::StorageProfile,
        storage_secret: Option<SecretString>,
        recovery_key: &SecretString,
        device_name: &str,
    ) -> anyhow::Result<Arc<VaultClient>> {
        if self.vault.is_some() || self.secrets_path().exists() {
            bail!("{}", self.t("此 AIPASS_HOME 已有保管库", "a vault already exists in this AIPASS_HOME"));
        }
        let secrets = self.open_secrets(true)?;
        let cfg = ClientConfig::new(self.vault_dir(), Platform::Cli, env!("CARGO_PKG_VERSION"));
        let client = VaultClient::recover_with_key(
            cfg,
            secrets,
            Arc::new(StandardStoreFactory::new()),
            vault_id,
            profile,
            storage_secret,
            recovery_key.expose(),
            device_name,
        )
        .await
        .map_err(|e| anyhow::anyhow!("{} ({})", e.localized().pick(self.lang), e.code().as_str()))?;
        let client = Arc::new(client);
        self.vault = Some(client.clone());
        Ok(client)
    }

    /// Unlocked vault client.
    pub async fn unlocked(&mut self) -> anyhow::Result<Arc<VaultClient>> {
        let lang = self.lang;
        let v = self.vault(false)?;
        if !v.has_vault() {
            bail!("no vault on this device; run `aipass vault init` first");
        }
        if !v.is_unlocked() {
            v.unlock().await.map_err(|e| anyhow::anyhow!("{}", e.localized().pick(lang)))?;
        }
        Ok(v)
    }

    /// This device's long-term identity (for signing broker / relay requests).
    pub fn device_identity(&mut self) -> anyhow::Result<(String, Arc<DeviceIdentity>)> {
        let dev = self.vault(false)?.device_id().context("no device")?;
        let secrets = self.open_secrets(false)?;
        let key = format!("aipass.device.{dev}");
        let raw = secrets
            .get(&key)
            .map_err(|e| anyhow::anyhow!("{}", e.localized().pick(self.lang)))?
            .context("device key missing from the secret store")?;
        let id = DeviceIdentity::from_secret_bytes(raw.expose()).context("device key is corrupt")?;
        Ok((dev.to_string(), Arc::new(id)))
    }

    /// Broker endpoint: flag/env, then cli.json, then the embedded broker socket.
    pub fn broker_endpoint(&self) -> anyhow::Result<BrokerEndpoint> {
        let url = match &self.broker_flag {
            Some(u) => u.clone(),
            None => match self.config()?.broker_url {
                Some(u) => u,
                None => format!("unix://{}", self.home.join("run").join("broker.sock").display()),
            },
        };
        BrokerEndpoint::parse(&url).map_err(|e| anyhow::anyhow!("broker URL: {e}"))
    }

    /// Broker client signing as this trusted device (principal class D).
    pub async fn device_broker(&mut self) -> anyhow::Result<BrokerClient> {
        self.unlocked().await?;
        let (kid, id) = self.device_identity()?;
        let ep = self.broker_endpoint()?;
        BrokerClient::builder(ep)
            .auth(Auth::signed(kid, id))
            .lang(self.lang)
            .build()
            .map_err(|e| anyhow::anyhow!("{e}"))
    }

    /// The only (or given) paired executor.
    pub fn executor(&self, given: Option<&str>) -> anyhow::Result<ExecutorId> {
        if let Some(g) = given {
            return ExecutorId::parse(g).map_err(|_| anyhow::anyhow!("invalid executor id"));
        }
        let c = self.config()?;
        match c.executors.as_slice() {
            [one] => Ok(one.executor_id.clone()),
            [] => bail!("no paired executor; run `aipass device pair --uri …` or pass --executor"),
            _ => bail!("several executors are paired; pass --executor"),
        }
    }

    /// Print a serialisable value as JSON.
    pub fn print_json<T: Serialize>(&self, v: &T) -> anyhow::Result<()> {
        println!("{}", serde_json::to_string_pretty(v)?);
        Ok(())
    }
}

/// Read a secret from the terminal without echo.
pub fn prompt_secret(prompt: &str) -> anyhow::Result<SecretString> {
    let s = rpassword::prompt_password(prompt).context("cannot read from the terminal")?;
    Ok(SecretString::new(s))
}

/// Ask a yes/no question on the terminal (default no).
pub fn confirm(prompt: &str) -> anyhow::Result<bool> {
    let line = read_line(&format!("{prompt} [y/N] "))?;
    Ok(matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes" | "是"))
}

/// Read one line from stdin (after printing `prompt` on stderr).
pub fn read_line(prompt: &str) -> anyhow::Result<String> {
    eprint!("{prompt}");
    let _ = std::io::stderr().flush();
    let mut s = String::new();
    std::io::stdin().lock().read_line(&mut s)?;
    Ok(s.trim_end_matches(['\r', '\n']).to_string())
}

/// True when stdin is an interactive terminal.
pub fn stdin_is_tty() -> bool {
    std::io::stdin().is_terminal()
}

/// Parse a snake_case enum through serde.
pub fn parse_enum<T: serde::de::DeserializeOwned>(what: &str, s: &str) -> anyhow::Result<T> {
    serde_json::from_value(serde_json::Value::String(s.to_string())).map_err(|_| anyhow::anyhow!("invalid {what}: {s}"))
}

/// Write a file with mode 0600.
pub fn write_private(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    aipass_node::fsutil::write_private(path, bytes)
}

/// Localized helper on `aipass_types::Localized`.
pub trait Pick {
    /// Pick by language.
    fn pick(&self, lang: Lang) -> String;
}
impl Pick for aipass_types::error::Localized {
    fn pick(&self, lang: Lang) -> String {
        if lang == Lang::En { self.en.clone() } else { self.zh.clone() }
    }
}
