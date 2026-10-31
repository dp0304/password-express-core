// SPDX-License-Identifier: Apache-2.0
//! Vault, storage, items, import/export, sync, conflicts, recovery and devices.

use std::time::Duration;

use aipass_crypto::SecretString;
use aipass_storage::RelayClient;
use aipass_sync::models::{FieldInput, ItemInput, SecretField};
use aipass_types::ids::{DeviceId, EntryId, ProjectId};
use aipass_types::pairing::{PairingOffer, PairingRole};
use aipass_types::storage::{StorageKind, StorageProfile};
use aipass_types::vault::{DatabaseInfo, EntryKind, PasswordRules};
use anyhow::{Context, bail};

use crate::args::*;
use crate::ctx::{Ctx, PairedExecutor, Pick, confirm, parse_enum, prompt_secret, read_line, write_private};

/// Build a storage profile + optional secret from flags.
pub fn storage_profile(ctx: &Ctx, a: &StorageArgs) -> anyhow::Result<(StorageProfile, Option<SecretString>)> {
    let kind: StorageKind = parse_enum("storage", &a.storage)?;
    let mut p = StorageProfile::new(kind);
    match kind {
        StorageKind::Local => {
            let path = a.path.clone().unwrap_or_else(|| ctx.home.join("storage"));
            std::fs::create_dir_all(&path)?;
            p.path = Some(std::fs::canonicalize(&path)?.display().to_string());
        }
        StorageKind::S3 => {
            p.endpoint = Some(a.endpoint.clone().context("--endpoint is required for s3")?);
            p.region = a.region.clone();
            p.bucket = Some(a.bucket.clone().context("--bucket is required for s3")?);
            p.prefix = a.prefix.clone();
            p.path_style = Some(!a.virtual_host);
            p.username = Some(a.username.clone().context("--username (access key id) is required for s3")?);
        }
        StorageKind::Webdav => {
            eprintln!("{}", ctx.t("⚠ WebDAV 为实验功能（V1.1），仅当能力测试通过时才可同步。", "⚠ WebDAV is experimental (V1.1); it syncs only if the capability test passes."));
            p.endpoint = Some(a.endpoint.clone().context("--endpoint is required for webdav")?);
            p.username = a.username.clone();
        }
        StorageKind::Selfhost | StorageKind::Official => {
            p.base_url = Some(a.base_url.clone().context("--base-url is required")?);
        }
    }
    let secret = if let Some(var) = &a.secret_env {
        Some(SecretString::new(std::env::var(var).with_context(|| format!("environment variable {var} is not set"))?))
    } else if a.secret_prompt {
        Some(prompt_secret(ctx.t("存储密钥: ", "Storage secret: "))?)
    } else {
        None
    };
    Ok((p, secret))
}

/// `vault …`
pub async fn vault(ctx: &mut Ctx, cmd: VaultCmd) -> anyhow::Result<()> {
    match cmd {
        VaultCmd::Init { device_name, storage, master_password, kit_out } => {
            let (profile, secret) = storage_profile(ctx, &storage)?;
            let master = if master_password { Some(prompt_secret(ctx.t("主密码: ", "Master password: "))?) } else { None };
            let lang = ctx.lang;
            let v = ctx.vault(true)?;
            if v.has_vault() {
                bail!("a vault already exists in this AIPASS_HOME");
            }
            let r = v
                .create_vault(&device_name, profile, secret, master)
                .await
                .map_err(|e| anyhow::anyhow!("{}", e.localized().pick(lang)))?;
            println!("vault_id: {}", r.vault_id);
            println!("device_id: {}", r.device_id);
            match kit_out {
                Some(path) => {
                    write_private(&path, r.recovery_kit_text.expose().as_bytes())?;
                    println!("{} {}", ctx.t("恢复包已写入（请离线保存后删除文件）:", "recovery kit written (store it offline, then delete the file):"), path.display());
                }
                None => {
                    println!("\n{}", r.recovery_kit_text.expose());
                }
            }
            println!("{}", ctx.t("请运行 `aipass recovery verify` 确认已保存恢复密钥。", "Run `aipass recovery verify` to confirm you saved the recovery key."));
            Ok(())
        }
        VaultCmd::Recover { vault_id, device_name, storage, recovery_key_env, recovery_key_file } => {
            let vid = aipass_types::ids::VaultId::parse(&vault_id).map_err(|_| anyhow::anyhow!("invalid vault id"))?;
            let key = recovery_key_input(ctx, recovery_key_env.as_deref(), recovery_key_file.as_deref())?;
            let (profile, secret) = storage_profile(ctx, &storage)?;
            let v = ctx.recover_vault(&vid, profile, secret, &key, &device_name).await?;
            let st = v.status();
            if ctx.json {
                return ctx.print_json(&st);
            }
            println!("vault_id: {}", st.vault_id.map(|v| v.to_string()).unwrap_or_default());
            println!("device_id: {}", st.device_id.map(|d| d.to_string()).unwrap_or_default());
            println!(
                "{}",
                ctx.t(
                    "已用恢复密钥恢复保管库，本设备已作为新的所有者设备加入。没有自动撤销任何设备：请用 `aipass device list` 检查，用 `aipass device revoke <id>` 撤销丢失的设备，然后用 `aipass rotation list` 查看需要轮换的凭证。",
                    "vault recovered with the recovery key; this device joined as a new owner. No device was revoked automatically: check `aipass device list`, revoke the lost device with `aipass device revoke <id>`, then see `aipass rotation list` for credentials to rotate."
                )
            );
            Ok(())
        }
        VaultCmd::Status => {
            let v = ctx.vault(false)?;
            let st = v.status();
            if ctx.json {
                return ctx.print_json(&st);
            }
            println!("vault_id: {}", st.vault_id.map(|v| v.to_string()).unwrap_or_else(|| "-".into()));
            println!("device: {} {}", st.device_id.map(|d| d.to_string()).unwrap_or_default(), st.device_name.unwrap_or_default());
            println!("storage: {:?}", st.storage_kind);
            let conflicts = match st.conflicts {
                Some(n) => n.to_string(),
                None => ctx.t("未知（需解锁）", "unknown (unlock to check)").to_owned(),
            };
            println!("pending_changes: {}  conflicts: {}  recovery_verified: {}", st.pending_changes, conflicts, st.recovery_verified);
            if st.rollback_detected {
                println!("⚠ {}", ctx.t("检测到存储回滚，已暂停同步", "storage rollback detected; sync paused"));
            }
            if st.revoked {
                println!("⚠ {}", ctx.t("此设备已被撤销", "this device has been revoked"));
            }
            Ok(())
        }
        VaultCmd::UnlockCheck => {
            ctx.unlocked().await?;
            println!("{}", ctx.t("可以解锁 ✓", "unlock ok ✓"));
            Ok(())
        }
    }
}

/// `storage …`
pub async fn storage(ctx: &mut Ctx, cmd: StorageCmd) -> anyhow::Result<()> {
    let (a, migrate) = match cmd {
        StorageCmd::Test(a) => (a, false),
        StorageCmd::Migrate(a) | StorageCmd::Configure(a) => (a, true),
    };
    let (profile, secret) = storage_profile(ctx, &a)?;
    let lang = ctx.lang;
    let v = ctx.unlocked().await?;
    if migrate {
        let r = v.migrate_storage(profile, secret).await.map_err(|e| anyhow::anyhow!("{}", e.localized().pick(lang)))?;
        println!("{}", serde_json::to_string_pretty(&r)?);
    } else {
        let r = v.test_storage(&profile, secret.as_ref()).await.map_err(|e| anyhow::anyhow!("{}", e.localized().pick(lang)))?;
        println!("verdict: {:?}", r.verdict);
        for d in &r.details {
            println!("  {d}");
        }
    }
    Ok(())
}

fn read_secret(ctx: &Ctx, f: &ItemFields, v: &aipass_sync::VaultClient) -> anyhow::Result<Option<SecretString>> {
    if let Some(len) = f.generate {
        let rules = PasswordRules { length: len, ..PasswordRules::default() };
        return Ok(Some(v.generate_password(&rules).map_err(|e| anyhow::anyhow!("{}", e.localized().pick(ctx.lang)))?));
    }
    if let Some(var) = &f.secret_env {
        return Ok(Some(SecretString::new(std::env::var(var).with_context(|| format!("environment variable {var} is not set"))?)));
    }
    if f.secret_stdin {
        let mut s = String::new();
        std::io::stdin().read_line(&mut s)?;
        let s = s.trim_end_matches(['\r', '\n']).to_string();
        if s.is_empty() {
            bail!("empty secret on stdin");
        }
        return Ok(Some(SecretString::new(s)));
    }
    if f.secret_prompt {
        return Ok(Some(prompt_secret(ctx.t("密钥/密码: ", "Secret / password: "))?));
    }
    Ok(None)
}

fn apply_fields(input: &mut ItemInput, f: &ItemFields) -> anyhow::Result<()> {
    if let Some(t) = &f.title {
        input.title = t.clone();
    }
    if f.username.is_some() {
        input.username = f.username.clone();
    }
    if !f.urls.is_empty() {
        input.urls = f.urls.clone();
    }
    if f.notes.is_some() {
        input.notes = f.notes.clone();
    }
    if let Some(var) = &f.totp_env {
        input.totp = Some(SecretString::new(std::env::var(var).with_context(|| format!("environment variable {var} is not set"))?));
    }
    if let Some(p) = &f.project {
        input.project_id = Some(ProjectId::parse(p).map_err(|_| anyhow::anyhow!("invalid project id"))?);
    }
    if f.db_host.is_some() || f.db_name.is_some() {
        let old = input.database.clone();
        input.database = Some(DatabaseInfo {
            engine: "postgres".into(),
            host: f.db_host.clone().or(old.as_ref().map(|d| d.host.clone())).context("--db-host is required")?,
            port: f.db_port.or(old.as_ref().map(|d| d.port)).unwrap_or(5432),
            dbname: f.db_name.clone().or(old.as_ref().map(|d| d.dbname.clone())).context("--db-name is required")?,
            sslmode: f.db_sslmode.clone().or(old.as_ref().map(|d| d.sslmode.clone())).unwrap_or_else(|| "require".into()),
        });
    }
    Ok(())
}

fn entry_id(s: &str) -> anyhow::Result<EntryId> {
    EntryId::parse(s).map_err(|_| anyhow::anyhow!("invalid entry id: {s}"))
}

/// `item …`
pub async fn item(ctx: &mut Ctx, cmd: ItemCmd) -> anyhow::Result<()> {
    let lang = ctx.lang;
    let json = ctx.json;
    let e = |e: aipass_sync::VaultError| anyhow::anyhow!("{} ({})", e.localized().pick(lang), e.code().as_str());
    match cmd {
        ItemCmd::Add(f) => {
            let kind: EntryKind = parse_enum("kind", f.kind.as_deref().unwrap_or("login"))?;
            let title = f.title.clone().context("--title is required")?;
            let v = ctx.unlocked().await?;
            let mut input = ItemInput::new(kind, title);
            apply_fields(&mut input, &f)?;
            input.secret = read_secret(ctx, &f, &v)?;
            let id = v.save_item(input).await.map_err(e)?;
            println!("{id}");
            Ok(())
        }
        ItemCmd::List { query } => {
            let v = ctx.unlocked().await?;
            let items = v.list_items(query.as_deref(), None).map_err(e)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&items)?);
                return Ok(());
            }
            for i in items {
                println!(
                    "{}  {:<11} {:<28} {}{}",
                    i.entry_id,
                    serde_json::to_value(i.kind)?.as_str().unwrap_or(""),
                    i.title,
                    i.username.unwrap_or_default(),
                    if i.has_conflict { "  ⚠ conflict" } else { "" }
                );
            }
            Ok(())
        }
        ItemCmd::Show { id } => {
            let v = ctx.unlocked().await?;
            let d = v.get_item(&entry_id(&id)?).map_err(e)?;
            println!("{}", serde_json::to_string_pretty(&d)?);
            Ok(())
        }
        ItemCmd::Edit { id, fields } => {
            let id = entry_id(&id)?;
            let v = ctx.unlocked().await?;
            let d = v.get_item(&id).map_err(e)?;
            let mut input = ItemInput::new(d.summary.kind, d.summary.title.clone());
            input.entry_id = Some(id.clone());
            input.username = d.summary.username.clone();
            input.urls = d.urls.clone();
            input.notes = d.notes.clone();
            input.database = d.database.clone();
            input.project_id = d.summary.project_id.clone();
            input.tags = d.summary.tags.clone();
            input.fields = d.fields.iter().map(|f| FieldInput { name: f.name.clone(), value: None, sensitive: f.sensitive }).collect();
            if let Some(k) = &fields.kind {
                input.kind = parse_enum("kind", k)?;
            }
            apply_fields(&mut input, &fields)?;
            input.secret = read_secret(ctx, &fields, &v)?;
            v.save_item(input).await.map_err(e)?;
            println!("{}", ctx.t("已保存", "saved"));
            Ok(())
        }
        ItemCmd::Rm { id } => {
            let v = ctx.unlocked().await?;
            v.delete_item(&entry_id(&id)?).await.map_err(e)?;
            println!("{}", ctx.t("已删除（墓碑记录会同步到其他设备）", "deleted (a tombstone syncs to other devices)"));
            Ok(())
        }
        ItemCmd::Reveal { id, field } => {
            ctx.require_human(
                ("显示密钥", "revealing a secret"),
                ("⚠ 如果有 AI 代理能读取本终端，它可能看到显示的密钥。", "⚠ If an AI agent can read this terminal it may see the revealed secret."),
            )?;
            let v = ctx.unlocked().await?;
            let f = match field.as_str() {
                "secret" => SecretField::Secret,
                "totp" => SecretField::TotpSecret,
                other => SecretField::Field(other.to_string()),
            };
            let s = v.reveal_secret(&entry_id(&id)?, &f).map_err(e)?;
            println!("{}", s.expose());
            Ok(())
        }
        ItemCmd::Generate { length, no_symbols } => {
            let mut rules = PasswordRules { length, ..PasswordRules::default() };
            if no_symbols {
                rules.symbols = false;
            }
            let v = ctx.vault(false)?;
            let s = v.generate_password(&rules).map_err(e)?;
            println!("{}", s.expose());
            Ok(())
        }
        ItemCmd::Totp { id } => {
            let v = ctx.unlocked().await?;
            let c = v.totp_now(&entry_id(&id)?).map_err(e)?;
            println!("{}  ({}s)", c.code, c.remaining_seconds);
            Ok(())
        }
    }
}

/// `import`
pub async fn import(ctx: &mut Ctx, format: &str, file: &std::path::Path) -> anyhow::Result<()> {
    let fmt = aipass_vault::import::CsvFormat::parse(format).context("unknown CSV format")?;
    let bytes = zeroize::Zeroizing::new(std::fs::read(file).with_context(|| format!("cannot read {}", file.display()))?);
    let lang = ctx.lang;
    let v = ctx.unlocked().await?;
    let r = v.import_csv(fmt, &bytes).await.map_err(|e| anyhow::anyhow!("{}", e.localized().pick(lang)))?;
    println!("{}", serde_json::to_string_pretty(&r)?);
    println!("{}", aipass_vault::import::delete_csv_guidance().pick(lang));
    Ok(())
}

/// `export`
pub async fn export(ctx: &mut Ctx, encrypted: Option<std::path::PathBuf>, csv: Option<std::path::PathBuf>, yes: bool) -> anyhow::Result<()> {
    let lang = ctx.lang;
    match (encrypted, csv) {
        (Some(out), None) => {
            // whoever picks the export password can decrypt the export: human-only, like
            // `item reveal`; the password is typed on the terminal (never from the environment)
            ctx.require_human(
                ("导出账号库", "exporting the vault"),
                ("⚠ 导出文件包含全部密钥，只能用你在此输入的导出密码解开。", "⚠ The export holds every secret; only the export password you type here opens it."),
            )?;
            if std::env::var_os("AIPASS_EXPORT_PASSWORD").is_some() {
                eprintln!("{}", ctx.t("已忽略 AIPASS_EXPORT_PASSWORD：导出密码只能在终端输入", "AIPASS_EXPORT_PASSWORD is ignored: the export password is typed on the terminal"));
            }
            let pw = prompt_secret(ctx.t("导出密码: ", "Export password: "))?;
            let again = prompt_secret(ctx.t("再次输入导出密码: ", "Repeat the export password: "))?;
            if !aipass_crypto::ct_eq(pw.expose().as_bytes(), again.expose().as_bytes()) {
                bail!("{}", ctx.t("两次输入的导出密码不一致", "the export passwords do not match"));
            }
            let v = ctx.unlocked().await?;
            let bytes = v.export_encrypted(&pw).map_err(|e| anyhow::anyhow!("{}", e.localized().pick(lang)))?;
            write_private(&out, &bytes)?;
            println!("{}", out.display());
            Ok(())
        }
        (None, Some(out)) => {
            // plaintext secrets: human-only, like `item reveal` (`--yes` does not skip this)
            let warning = aipass_vault::export::csv_export_warning().pick(lang);
            ctx.require_human(("导出明文 CSV", "exporting plaintext CSV"), (&warning, &warning))?;
            if yes {
                eprintln!("{}", ctx.t("明文导出总是需要在终端确认；--yes 对 --csv 无效", "plaintext export is always confirmed on the terminal; --yes has no effect with --csv"));
            }
            if !confirm(ctx.t("仍要导出明文 CSV？", "Export plaintext CSV anyway?"))? {
                bail!("cancelled");
            }
            let v = ctx.unlocked().await?;
            let bytes = v.export_csv().map_err(|e| anyhow::anyhow!("{}", e.localized().pick(lang)))?;
            write_private(&out, &bytes)?;
            println!("{}", out.display());
            Ok(())
        }
        _ => bail!("pass --encrypted FILE or --csv FILE"),
    }
}

/// `sync`
pub async fn sync(ctx: &mut Ctx) -> anyhow::Result<()> {
    let lang = ctx.lang;
    let v = ctx.unlocked().await?;
    let r = v.sync().await.map_err(|e| anyhow::anyhow!("{}", e.localized().pick(lang)))?;
    println!("{}", serde_json::to_string_pretty(&r)?);
    Ok(())
}

/// `conflicts …`
pub async fn conflicts(ctx: &mut Ctx, cmd: ConflictsCmd) -> anyhow::Result<()> {
    let lang = ctx.lang;
    let v = ctx.unlocked().await?;
    match cmd {
        ConflictsCmd::List => {
            let c = v.conflicts().await.map_err(|e| anyhow::anyhow!("{}", e.localized().pick(lang)))?;
            println!("{}", serde_json::to_string_pretty(&c)?);
        }
        ConflictsCmd::Resolve { id, keep } => {
            v.resolve_conflict(&entry_id(&id)?, keep).await.map_err(|e| anyhow::anyhow!("{}", e.localized().pick(lang)))?;
            println!("resolved");
        }
    }
    Ok(())
}

/// `recovery …`
pub async fn recovery(ctx: &mut Ctx, cmd: RecoveryCmd) -> anyhow::Result<()> {
    let lang = ctx.lang;
    match cmd {
        RecoveryCmd::Kit { include_storage_secret } => {
            let v = ctx.unlocked().await?;
            let kit = v.recovery_kit_text(include_storage_secret).map_err(|e| anyhow::anyhow!("{}", e.localized().pick(lang)))?;
            println!("{}", kit.expose());
        }
        RecoveryCmd::Verify => {
            let key = match std::env::var("AIPASS_RECOVERY_KEY") {
                Ok(k) => SecretString::new(k),
                Err(_) => prompt_secret(ctx.t("输入恢复密钥 (AIPR-…): ", "Enter the recovery key (AIPR-…): "))?,
            };
            let v = ctx.unlocked().await?;
            let ok = v.verify_recovery_key(key.expose()).map_err(|e| anyhow::anyhow!("{}", e.localized().pick(lang)))?;
            if !ok {
                bail!("{}", ctx.t("恢复密钥不匹配", "the recovery key does not match"));
            }
            println!("{}", ctx.t("恢复密钥已验证 ✓", "recovery key verified ✓"));
        }
    }
    Ok(())
}

/// `device …`
pub async fn device(ctx: &mut Ctx, cmd: DeviceCmd) -> anyhow::Result<()> {
    let lang = ctx.lang;
    let e = |e: aipass_sync::VaultError| anyhow::anyhow!("{} ({})", e.localized().pick(lang), e.code().as_str());
    match cmd {
        DeviceCmd::Pair { uri, share_storage_secret, timeout_secs } => {
            let offer = PairingOffer::parse(uri.trim()).map_err(|_| anyhow::anyhow!("{}", ctx.t("配对链接无效或已过期", "invalid or expired pairing link")))?;
            let relay = RelayClient::for_pairing(url::Url::parse(&offer.relay)?, offer.secret).map_err(|e| anyhow::anyhow!("relay: {e}"))?;
            let v = ctx.unlocked().await?;
            let mut s = v.scan_pairing(uri.trim(), &relay).await.map_err(e)?;
            let role = match s.offered_role() {
                PairingRole::Executor => "executor / 执行设备",
                PairingRole::Member => "member / 可信设备",
            };
            eprintln!("{} \"{}\" ({role}) …", ctx.t("等待新设备", "waiting for the new device"), s.offered_name());
            let peer = s.wait_for_join(&relay, Duration::from_secs(timeout_secs)).await.map_err(e)?;
            println!("配对码 / Pairing code: {}", s.sas());
            println!("{}: {} ({})", ctx.t("新设备", "new device"), peer.name, peer.device_id);
            let answer = read_line(ctx.t(
                "请核对新设备上显示的 6 位数字：输入该数字，或在一致时输入 y: ",
                "Compare with the 6 digits on the new device: type them, or y if they match: ",
            ))?;
            let a = answer.trim();
            if a.eq_ignore_ascii_case("y") || a.eq_ignore_ascii_case("yes") {
                s.confirm().map_err(e)?;
            } else if a.len() == 6 && a.chars().all(|c| c.is_ascii_digit()) {
                s.confirm_code(a).map_err(e)?;
            } else {
                s.cancel();
                bail!("{}", ctx.t("已取消配对", "pairing cancelled"));
            }
            let info = v.confirm_pairing(&mut s, &relay, share_storage_secret).await.map_err(e)?;
            println!("{} {} ({:?})", ctx.t("已加入:", "joined:"), info.device_id, info.role);
            if s.offered_role() == PairingRole::Executor {
                let exe = aipass_sync::executor_principal(&info.device_id);
                let mut c = ctx.config()?;
                c.executors.retain(|x| x.executor_id != exe);
                c.executors.push(PairedExecutor { executor_id: exe.clone(), name: info.name.clone(), relay_url: offer.relay.clone() });
                if c.broker_url.is_none() {
                    c.broker_url = Some(offer.relay.clone());
                }
                ctx.save_config(&c)?;
                println!("executor_id: {exe}");
            }
            Ok(())
        }
        DeviceCmd::Join { device_name, relay, timeout_secs, storage_secret_env } => {
            let secret = match &storage_secret_env {
                Some(var) => Some(SecretString::new(std::env::var(var).with_context(|| format!("environment variable {var} is not set"))?)),
                None => None,
            };
            let base = url::Url::parse(relay.trim()).context("--relay must be an http(s) URL")?;
            let v = ctx.vault(true)?;
            if v.has_vault() {
                bail!("a vault already exists in this AIPASS_HOME");
            }
            let mut s = v.begin_join(&device_name, base.as_str().trim_end_matches('/')).map_err(e)?;
            let offer = s.offer().clone();
            let rc = RelayClient::for_pairing(url::Url::parse(&offer.relay)?, offer.secret).map_err(|e| anyhow::anyhow!("relay: {e}"))?;
            println!("{}", ctx.t("在已有账号库的可信设备上打开此配对链接（10 分钟内有效）:", "Open this pairing link on a trusted device that has the vault (valid for 10 minutes):"));
            println!("{}", s.qr_payload());
            use std::io::Write as _;
            let _ = std::io::stdout().flush();
            let wait = Duration::from_secs(timeout_secs);
            let hello = s.wait_for_hello(&rc, wait).await.map_err(e)?;
            println!("配对码 / Pairing code: {}", hello.sas);
            println!(
                "{} \"{}\"",
                ctx.t("请确认此 6 位数字与可信设备上显示的一致，并在该设备上确认:", "Check that these 6 digits match the trusted device and confirm there:"),
                hello.peer_name
            );
            let _ = std::io::stdout().flush();
            let welcome = s.wait_for_welcome(&rc, wait).await.map_err(e)?;
            v.complete_join(&s, welcome, secret).await.map_err(e)?;
            let st = v.status();
            println!("{}", ctx.t("已加入账号库 ✓", "joined the vault ✓"));
            println!("vault_id: {}", st.vault_id.map(|x| x.to_string()).unwrap_or_default());
            println!("device_id: {}", st.device_id.map(|x| x.to_string()).unwrap_or_default());
            Ok(())
        }
        DeviceCmd::List => {
            let v = ctx.unlocked().await?;
            let list = v.devices().map_err(e)?;
            if ctx.json {
                return ctx.print_json(&list);
            }
            for d in list {
                println!(
                    "{}  {:<20} {:?} {:?} {:?}{}",
                    d.device_id,
                    d.name,
                    d.platform,
                    d.role,
                    d.status,
                    if d.is_this_device { "  (this device)" } else { "" }
                );
            }
            Ok(())
        }
        DeviceCmd::Revoke { id } => {
            let id = DeviceId::parse(&id).map_err(|_| anyhow::anyhow!("invalid device id"))?;
            let v = ctx.unlocked().await?;
            let r = v.revoke_device(&id).await.map_err(e)?;
            println!("{}", serde_json::to_string_pretty(&r)?);
            Ok(())
        }
    }
}

/// The recovery key for `vault recover`: from an environment variable, a key/kit file, or
/// the terminal — never from a command-line value.
fn recovery_key_input(ctx: &Ctx, env: Option<&str>, file: Option<&std::path::Path>) -> anyhow::Result<SecretString> {
    if let Some(var) = env {
        let v = std::env::var(var).with_context(|| format!("environment variable {var} is not set"))?;
        return Ok(SecretString::new(v.trim().to_owned()));
    }
    if let Some(path) = file {
        let text = zeroize::Zeroizing::new(std::fs::read_to_string(path).with_context(|| format!("cannot read {}", path.display()))?);
        // a bare key, or the `AIPR-…` key inside a recovery kit
        let key = text
            .split(|c: char| c.is_whitespace() || c == '`' || c == '"')
            .find(|t| t.starts_with("AIPR-"))
            .map(str::to_owned)
            .or_else(|| Some(text.trim().to_owned()).filter(|t| !t.is_empty() && !t.contains('\n')))
            .with_context(|| format!("no recovery key (AIPR-…) found in {}", path.display()))?;
        return Ok(SecretString::new(key));
    }
    if !crate::ctx::stdin_is_tty() {
        bail!("{}", ctx.t("请用 --recovery-key-env 或 --recovery-key-file 提供恢复密钥", "give the recovery key with --recovery-key-env or --recovery-key-file"));
    }
    prompt_secret(ctx.t("恢复密钥 (AIPR-…): ", "Recovery key (AIPR-…): "))
}

/// `rotation …`
pub async fn rotation(ctx: &mut Ctx, cmd: crate::args::RotationCmd) -> anyhow::Result<()> {
    let lang = ctx.lang;
    let v = ctx.unlocked().await?;
    let e = |e: aipass_vault::VaultError| anyhow::anyhow!("{}", e.localized().pick(lang));
    match cmd {
        crate::args::RotationCmd::List => {
            let tasks = v.rotation_tasks().map_err(e)?;
            if ctx.json {
                return ctx.print_json(&tasks);
            }
            if tasks.is_empty() {
                println!("{}", ctx.t("没有待轮换的凭证", "no credentials to rotate"));
            }
            for t in tasks {
                println!("{}  {:<24} {:?}  {}", t.entry_id, t.title, t.kind, t.reason.pick(lang));
            }
        }
        crate::args::RotationCmd::Done { entry_id: id } => {
            v.dismiss_rotation_task(&entry_id(&id)?).map_err(e)?;
            println!("{}", ctx.t("已标记为已轮换", "marked as rotated"));
        }
    }
    Ok(())
}
