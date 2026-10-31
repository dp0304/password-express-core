// SPDX-License-Identifier: Apache-2.0
//! Executor pairing (CONTRACTS §5, node = new device N with role executor).
//!
//! `aipass-node pair` shows an `aipass://pair?…` link + QR, waits for the trusted device's
//! `pairing.hello`, prints the 6-digit code to compare, and after the user confirmed on the
//! trusted device receives `pairing.welcome`. The trusted devices it lists become the
//! broker's approver set (registered through the running node's admin API). Scanning
//! alone never grants anything; executors never receive the VMK or storage secrets.

use std::path::Path;
use std::time::Duration;

use aipass_client::{Auth, BrokerClient, BrokerEndpoint};
use aipass_storage::RelayClient;
use aipass_types::models::ProtectionLevel;
use aipass_types::pairing::PairingRole;
use aipass_types::vault::{DevicePublic, MemberRole, Platform};
use aipass_vault::pairing::NewDeviceSession;
use anyhow::{Context, bail};
use serde::{Deserialize, Serialize};

use crate::config::NodeConfig;
use crate::fsutil;
use crate::identity::NodeIdentity;

/// Record of the last successful pairing (`<data>/pairing.json`).
pub const PAIRING_FILE: &str = "pairing.json";

/// Persisted pairing result (public data only).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairingRecord {
    /// Vault joined.
    pub vault_id: aipass_types::ids::VaultId,
    /// Approver set received in `pairing.welcome`.
    pub trusted_devices: Vec<DevicePublic>,
    /// Relay the trusted devices use.
    pub relay_base_url: String,
    /// When.
    #[serde(with = "aipass_types::time::rfc3339")]
    pub paired_at: aipass_types::time::Timestamp,
}

/// Render `data` as a terminal QR code (two modules per character row).
pub fn render_qr(data: &str) -> anyhow::Result<String> {
    let code = qrcode::QrCode::new(data.as_bytes()).context("cannot encode QR")?;
    let w = code.width();
    let colors = code.to_colors();
    let dark = |x: isize, y: isize| -> bool {
        if x < 0 || y < 0 || x >= w as isize || y >= w as isize {
            return false;
        }
        colors[y as usize * w + x as usize] == qrcode::Color::Dark
    };
    let mut out = String::new();
    let q: isize = 2; // quiet zone
    let mut y = -q;
    while y < w as isize + q {
        for x in -q..w as isize + q {
            out.push(match (dark(x, y), dark(x, y + 1)) {
                (true, true) => ' ',
                (true, false) => '▄',
                (false, true) => '▀',
                (false, false) => '█',
            });
        }
        out.push('\n');
        y += 2;
    }
    Ok(out)
}

/// Options for [`run_pairing`].
pub struct PairOptions {
    /// Relay override (default: config relay URL).
    pub relay_url: Option<String>,
    /// Admin URL of the running node (default: loopback URL of `node.listen`).
    pub admin_url: Option<String>,
    /// How long to wait in total.
    pub timeout: Duration,
    /// Print the QR code.
    pub show_qr: bool,
}

/// Run the pairing flow; prints instructions on stdout. Returns the record.
pub async fn run_pairing(cfg: &NodeConfig, opts: PairOptions) -> anyhow::Result<PairingRecord> {
    let data = &cfg.node.data_dir;
    let node = NodeIdentity::load_or_create(data)?;
    let relay = opts.relay_url.clone().unwrap_or_else(|| cfg.relay_url());
    let device = DevicePublic {
        device_id: node.member_device_id(),
        name: cfg.node.name.clone(),
        platform: Platform::Node,
        role: MemberRole::Executor,
        sign_pk: node.identity.public().sign_pk,
        kem_pk: node.identity.public().kem_pk,
    };
    // the admin API of the running node must be reachable before we show a code
    let admin = admin_client(cfg, opts.admin_url.as_deref())?;
    admin.health().await.context("the node is not running; start `aipass-node run` first (节点未运行)")?;

    let mut session = NewDeviceSession::start(device, (*node.identity).clone(), PairingRole::Executor, &relay)
        .map_err(|e| anyhow::anyhow!("{}", e.localized().en))?;
    let offer = session.offer().clone();
    let relay_client = RelayClient::for_pairing(url::Url::parse(&relay)?, offer.secret)
        .map_err(|e| anyhow::anyhow!("relay: {e}"))?;
    let uri = session.qr_payload();
    println!("在可信设备（手机或 `aipass device pair`）上扫描或粘贴此配对链接（10 分钟内有效）:");
    println!("Scan or paste this pairing link on a trusted device (valid for 10 minutes):\n");
    println!("{uri}\n");
    if opts.show_qr {
        println!("{}", render_qr(&uri)?);
    }
    println!("执行设备 / executor: {} ({})", cfg.node.name, node.executor_id);
    println!(
        "保护级别 / protection: {}",
        match cfg.executor.protection_level {
            ProtectionLevel::Isolated => "隔离执行 / isolated",
            ProtectionLevel::Compatible => "兼容连接 / compatible",
        }
    );
    use std::io::Write as _;
    let _ = std::io::stdout().flush();

    let hello = session
        .wait_for_hello(&relay_client, opts.timeout)
        .await
        .map_err(|e| anyhow::anyhow!("pairing: {}", e.localized().en))?;
    println!("\n配对码 / Pairing code: {}", hello.sas);
    println!("请确认可信设备「{}」上显示的是同一个 6 位数字，并在该设备上确认。", hello.peer_name);
    println!("Check that the trusted device \"{}\" shows the same 6 digits and confirm there.", hello.peer_name);
    let _ = std::io::stdout().flush();

    let welcome = session
        .wait_for_welcome(&relay_client, opts.timeout)
        .await
        .map_err(|e| anyhow::anyhow!("pairing: {}", e.localized().en))?;
    if welcome.vault_id != hello.vault_id {
        bail!("pairing.welcome is for a different vault");
    }
    if welcome.storage_secret.is_some() {
        // never expected for executors; drop it without storing
        tracing::warn!("ignoring a storage secret sent to an executor");
    }
    let approvers: Vec<DevicePublic> = welcome
        .trusted_devices
        .iter()
        .filter(|d| matches!(d.role, MemberRole::Owner | MemberRole::Member))
        .cloned()
        .collect();
    if approvers.is_empty() {
        bail!("pairing.welcome lists no trusted approver devices");
    }
    for d in &approvers {
        let body = serde_json::to_value(d)?;
        match admin.admin_add_device(&body).await {
            Ok(_) => {}
            Err(e) if e.code() == Some(aipass_types::error::ErrorCode::PreconditionFailed) => {}
            Err(e) => return Err(anyhow::anyhow!("could not register trusted device {}: {e}", d.device_id)),
        }
    }
    let record = PairingRecord {
        vault_id: welcome.vault_id.clone(),
        trusted_devices: approvers,
        relay_base_url: welcome.relay_base_url.clone(),
        paired_at: aipass_types::time::now(),
    };
    fsutil::write_json(&data.join(PAIRING_FILE), &record)?;
    println!("\n已配对 ✓ 可信设备 / trusted devices: {}", record.trusted_devices.iter().map(|d| d.name.as_str()).collect::<Vec<_>>().join(", "));
    println!("Paired. The broker now accepts approvals from these devices only.");
    Ok(record)
}

/// Admin client for the running node (bearer token from `<data>/broker/admin.token`).
pub fn admin_client(cfg: &NodeConfig, url: Option<&str>) -> anyhow::Result<BrokerClient> {
    let ep = match url {
        Some(u) => BrokerEndpoint::parse(u).map_err(|e| anyhow::anyhow!("{e}"))?,
        None => BrokerEndpoint::parse(&cfg.loopback_url()?).map_err(|e| anyhow::anyhow!("{e}"))?,
    };
    let auth: Auth = aipass_client::auth::load_admin_token(&cfg.admin_token_path())
        .map_err(|e| anyhow::anyhow!("cannot read the admin token {}: {e}", cfg.admin_token_path().display()))?;
    BrokerClient::builder(ep).auth(auth).build().map_err(|e| anyhow::anyhow!("{e}"))
}

/// Load the last pairing record.
pub fn load_record(data_dir: &Path) -> anyhow::Result<Option<PairingRecord>> {
    fsutil::read_json(&data_dir.join(PAIRING_FILE))
}

#[cfg(test)]
mod tests {
    #[test]
    fn qr_renders() {
        let s = super::render_qr("aipass://pair?v=1").expect("qr");
        assert!(s.lines().count() > 10);
    }
}
