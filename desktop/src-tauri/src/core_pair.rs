// SPDX-License-Identifier: Apache-2.0
//! Device pairing (CONTRACTS §5, design doc §9.5), both directions:
//!
//! * **Desktop as trusted device** — the user pastes the `aipass://pair?…` link shown by a
//!   phone (or another computer / a server node). The desktop sends `pairing.hello`, waits
//!   for `pairing.join`, shows the 6-digit SAS, and only after the user confirms that both
//!   screens show the same code does it enrol the new device and send `pairing.welcome`.
//! * **Desktop as new device** — on a computer without a vault, the desktop shows a QR /
//!   link, waits for the phone's hello, shows the SAS, and installs the vault after the
//!   phone confirms.
//!
//! Scanning alone never grants access; confirmation happens on the trusted device.

use std::sync::Arc;
use std::time::Duration;

use aipass_crypto::SecretString;
use aipass_storage::RelayClient;
use aipass_types::pairing::PairingOffer;
use aipass_vault::pairing::{NewDeviceSession, TrustedSession};
use serde_json::{Value, json};
use tokio_util::sync::CancellationToken;

use crate::core::AppCore;
use crate::error::{UiError, UiResult};

/// How long we wait for the other side (QR lifetime, CONTRACTS §5).
pub const PAIRING_WAIT: Duration = Duration::from_secs(600);

/// Current pairing flow.
#[derive(Default)]
pub struct PairingState {
    /// Trusted-side session waiting for the user's SAS confirmation.
    trusted: Option<(TrustedSession, Arc<RelayClient>)>,
    /// Cancels the running wait task.
    cancel: Option<CancellationToken>,
}

/// Render `data` as an SVG QR code (no external resources).
pub fn qr_svg(data: &str) -> UiResult<String> {
    let code = qrcode::QrCode::with_error_correction_level(data.as_bytes(), qrcode::EcLevel::M)
        .map_err(|_| UiError::internal("qr"))?;
    Ok(code
        .render::<qrcode::render::svg::Color<'_>>()
        .min_dimensions(240, 240)
        .quiet_zone(true)
        .dark_color(qrcode::render::svg::Color("#0F172A"))
        .light_color(qrcode::render::svg::Color("#FFFFFF"))
        .build())
}

fn relay_for(offer: &PairingOffer) -> UiResult<Arc<RelayClient>> {
    let url = url::Url::parse(&offer.relay).map_err(|_| UiError::invalid("配对链接中的中继地址无效", "Invalid relay URL in the pairing link"))?;
    let loopback = matches!(url.host_str(), Some("127.0.0.1" | "localhost" | "[::1]"));
    if url.scheme() != "https" && !(url.scheme() == "http" && loopback) {
        return Err(UiError::invalid("中继地址必须使用 https", "The relay URL must use https"));
    }
    let c = RelayClient::for_pairing(url, offer.secret).map_err(|e| UiError::from(aipass_types::ApiError::from(e)))?;
    Ok(Arc::new(c))
}

impl AppCore {
    async fn replace_pairing_task(&self) -> CancellationToken {
        let mut g = self.pairing.lock().await;
        if let Some(c) = g.cancel.take() {
            c.cancel();
        }
        g.trusted = None;
        let t = CancellationToken::new();
        g.cancel = Some(t.clone());
        t
    }

    /// Cancel any pairing flow.
    pub async fn pair_cancel(&self) {
        let mut g = self.pairing.lock().await;
        if let Some(c) = g.cancel.take() {
            c.cancel();
        }
        if let Some((mut s, _)) = g.trusted.take() {
            s.cancel();
        }
    }

    /// Trusted side, step 1: paste the new device's link. Returns who it claims to be; the
    /// SAS arrives later as a `pairing` event (`stage: "sas"`).
    pub async fn pair_scan(self: &Arc<Self>, uri: &str) -> UiResult<Value> {
        self.require_unlocked()?;
        let uri = uri.trim();
        if uri.len() > 2048 {
            return Err(UiError::invalid("配对链接过长", "Pairing link too long"));
        }
        let offer = PairingOffer::parse(uri).map_err(|_| UiError::invalid("这不是有效的 AI 通行证配对链接", "This is not a valid AI Pass pairing link"))?;
        if offer.is_expired(aipass_types::time::unix_now()) {
            return Err(UiError::new("APPROVAL_EXPIRED", "配对链接已过期，请在新设备上重新生成。", "The pairing link expired; create a new one on the new device."));
        }
        let relay = relay_for(&offer)?;
        let session = self.vault.scan_pairing(uri, &*relay).await?;
        let info = json!({"name": session.offered_name(), "role": session.offered_role()});
        let token = self.replace_pairing_task().await;
        let me = self.clone();
        tokio::spawn(async move {
            let mut session = session;
            let res = tokio::select! {
                _ = token.cancelled() => return,
                r = session.wait_for_join(&*relay, PAIRING_WAIT) => r,
            };
            match res {
                Ok(peer) => {
                    let sas = session.sas().to_owned();
                    me.sink.emit("pairing", json!({"stage": "sas", "side": "trusted", "sas": sas, "peer_name": peer.name, "peer_role": peer.role}));
                    me.pairing.lock().await.trusted = Some((session, relay));
                }
                Err(e) => {
                    let err = UiError::from(e);
                    me.sink.emit("pairing", json!({"stage": "failed", "error": err}));
                }
            }
        });
        Ok(info)
    }

    /// Trusted side, step 2: the user confirmed the SAS matches (optionally typing the code
    /// shown on the new device). Enrols the device and sends the welcome.
    pub async fn pair_confirm(&self, code_on_new_device: Option<String>, share_storage_secret: bool) -> UiResult<Value> {
        self.require_unlocked()?;
        let (mut session, relay) = self
            .pairing
            .lock()
            .await
            .trusted
            .take()
            .ok_or_else(|| UiError::invalid("没有等待确认的配对", "No pairing is waiting for confirmation"))?;
        match code_on_new_device.as_deref().map(str::trim).filter(|c| !c.is_empty()) {
            Some(code) => {
                session.confirm_code(code)?;
            }
            None => {
                session.confirm()?;
            }
        }
        let peer = session.peer().cloned();
        let info = self.vault.confirm_pairing(&mut session, &*relay, share_storage_secret).await?;
        // A phone / computer that joined as owner or member also becomes an approver of the
        // embedded broker, so approvals can be handled there (转到手机处理).
        if let (Some(p), Ok(n)) = (peer, self.node().await)
            && p.role.is_trusted_approver()
        {
            let mut p = p;
            p.role = info.role;
            if let Err(e) = crate::node::ensure_trusted_device(&n.broker, p).await {
                tracing::warn!(code = %e.code, "could not add paired device as approver");
            }
        }
        self.sink.emit("pairing", json!({"stage": "done", "side": "trusted"}));
        Ok(serde_json::to_value(info).unwrap_or(Value::Null))
    }

    /// New-device side: show a QR on a computer without a vault. The local unlock password
    /// is set now because the joined vault's device key must be stored encrypted.
    pub async fn join_begin(self: &Arc<Self>, device_name: &str, relay_url: &str, unlock_password: SecretString) -> UiResult<Value> {
        if self.vault.has_vault() {
            return Err(UiError::new("CONFLICT", "此设备上已有账号库。", "A vault already exists on this device."));
        }
        let name = device_name.trim();
        if name.is_empty() || name.chars().count() > 64 {
            return Err(UiError::invalid("设备名称需为 1–64 个字符", "Device name must be 1–64 characters"));
        }
        if !self.secrets.exists() {
            self.secrets.create(&unlock_password)?;
        } else {
            self.secrets.open(&unlock_password)?;
        }
        let session: NewDeviceSession = self.vault.begin_join(name, relay_url)?;
        let offer = session.offer().clone();
        let relay = relay_for(&offer)?;
        let qr = session.qr_payload();
        let svg = qr_svg(&qr)?;
        let token = self.replace_pairing_task().await;
        let me = self.clone();
        tokio::spawn(async move {
            let mut session = session;
            let hello = tokio::select! {
                _ = token.cancelled() => return,
                r = session.wait_for_hello(&*relay, PAIRING_WAIT) => r,
            };
            let hello = match hello {
                Ok(h) => h,
                Err(e) => {
                    me.sink.emit("pairing", json!({"stage": "failed", "error": UiError::from(e)}));
                    return;
                }
            };
            me.sink.emit("pairing", json!({"stage": "sas", "side": "new", "sas": hello.sas, "peer_name": hello.peer_name}));
            let welcome = tokio::select! {
                _ = token.cancelled() => return,
                r = session.wait_for_welcome(&*relay, PAIRING_WAIT) => r,
            };
            let (res, approvers) = match welcome {
                Ok(w) => {
                    // The welcoming phone / computer (and every other trusted device it
                    // listed from the verified member chain) approves for our broker.
                    let approvers = w.trusted_devices.clone();
                    (me.vault.complete_join(&session, w, None).await.map_err(UiError::from), approvers)
                }
                Err(e) => (Err(UiError::from(e)), Vec::new()),
            };
            let res = match res {
                Ok(()) => me.finish_join(approvers).await,
                Err(e) => Err(e),
            };
            match res {
                Ok(()) => me.sink.emit("pairing", json!({"stage": "done", "side": "new"})),
                Err(e) => me.sink.emit("pairing", json!({"stage": "failed", "error": e})),
            }
        });
        Ok(json!({"qr_payload": qr, "qr_svg": svg, "expires_at": offer.expires_at}))
    }

    /// After joining an existing vault: unlock, start the embedded node, register the
    /// welcoming trusted devices as broker approvers, then the same steps as an unlock
    /// (enrol the embedded executor as a vault member so the phone can seal credentials to
    /// it, start the relay and the sync loop).
    async fn finish_join(&self, approvers: Vec<aipass_types::vault::DevicePublic>) -> UiResult<()> {
        if !self.vault.is_unlocked() {
            self.vault.unlock().await?;
        }
        let n = self.ensure_node().await?;
        let me = self.vault.device_id();
        for d in approvers {
            if Some(&d.device_id) == me.as_ref() || !d.role.is_trusted_approver() {
                continue;
            }
            crate::node::ensure_trusted_device(&n.broker, d).await?;
        }
        self.after_unlock().await
    }

    /// Enrol the embedded executor as a vault member (role executor, no VMK) by running
    /// the real pairing protocol in-process over a memory relay. Afterwards other trusted
    /// devices (the phone) see it in the member list, can seal credentials to it, and the
    /// sync / relay servers accept its `exe_…` signatures. Returns false if already enrolled.
    pub async fn enroll_embedded_executor(&self) -> UiResult<bool> {
        self.require_unlocked()?;
        let n = self.node().await?;
        let member = aipass_vault::member::executor_member_id(&n.executor_id);
        if self.vault.devices()?.iter().any(|d| d.device_id == member) {
            return Ok(false);
        }
        let key = crate::core::executor_secret_key(&n.executor_id);
        let bytes = aipass_vault::SecretStore::get(&*self.secrets, &key)?.ok_or_else(|| UiError::internal("executor identity"))?;
        let identity = aipass_crypto::DeviceIdentity::from_secret_bytes(bytes.expose()).map_err(|_| UiError::internal("executor identity"))?;
        let public = identity.public();
        let dp = aipass_types::vault::DevicePublic {
            device_id: member,
            name: "本机执行设备".into(),
            platform: self.device_public()?.platform,
            role: aipass_types::vault::MemberRole::Executor,
            sign_pk: public.sign_pk,
            kem_pk: public.kem_pk,
        };
        let relay = aipass_vault::MemoryRelay::new();
        let wait = Duration::from_secs(10);
        let mut new_side = NewDeviceSession::start(dp, identity, aipass_types::pairing::PairingRole::Executor, "https://relay.invalid")?;
        let mut trusted = self.vault.scan_pairing(&new_side.qr_payload(), &relay).await?;
        let hello = new_side.wait_for_hello(&relay, wait).await?;
        trusted.wait_for_join(&relay, wait).await?;
        trusted.confirm_code(&hello.sas)?;
        self.vault.confirm_pairing(&mut trusted, &relay, false).await?;
        let welcome = new_side.wait_for_welcome(&relay, wait).await?;
        for d in welcome.trusted_devices {
            crate::node::ensure_trusted_device(&n.broker, d).await?;
        }
        Ok(true)
    }
}
