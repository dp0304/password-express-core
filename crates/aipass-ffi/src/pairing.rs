// SPDX-License-Identifier: Apache-2.0
//! `PairingSession` (CONTRACTS §5 / §12) for both roles.
//!
//! * **New device** (`pairing_offer`): show `qr_payload()`; `wait()` → stage
//!   `confirm_code` with the SAS; after the user confirmed the same code **on the trusted
//!   device**, `confirm()` (or `wait()` again) receives `pairing.welcome`, verifies the vault
//!   and installs it → `completed`.
//! * **Trusted device** (`pairing_scan`): `wait()` for `pairing.join` → `confirm_code`;
//!   the user compares the SAS on both screens and taps confirm → `confirm()` writes the
//!   member record and sends `pairing.welcome` → `completed`. Scanning alone never grants
//!   access.

use std::sync::Arc;
use std::time::Duration;

use aipass_types::pairing::PairingOffer;
use aipass_vault::RelayTransport;
use aipass_vault::pairing::{NewDeviceSession, TrustedSession};
use tokio::sync::Mutex;

use crate::core::Shared;
use crate::error::{CoreError, CoreResult};
use crate::relay::RelaySetting;
use crate::types::{DeviceFfi, PairingProgressFfi, enum_str};

enum Side {
    New(Box<NewDeviceSession>),
    Trusted(Box<TrustedSession>),
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Stage {
    WaitingForPeer,
    ConfirmCode,
    Completed,
    Cancelled,
}

impl Stage {
    fn as_str(self) -> &'static str {
        match self {
            Stage::WaitingForPeer => "waiting_for_peer",
            Stage::ConfirmCode => "confirm_code",
            Stage::Completed => "completed",
            Stage::Cancelled => "cancelled",
        }
    }
}

struct Inner {
    side: Side,
    stage: Stage,
    sas: Option<String>,
    peer_name: Option<String>,
    peer_role: Option<String>,
    device: Option<DeviceFfi>,
    share_storage_secret: bool,
}

/// A running pairing (either role).
#[derive(uniffi::Object)]
pub struct PairingSession {
    shared: Arc<Shared>,
    transport: Arc<dyn RelayTransport>,
    qr: String,
    expires_at: i64,
    relay_url: String,
    is_new_device: bool,
    inner: Mutex<Inner>,
}

impl PairingSession {
    pub(crate) fn offer(shared: Arc<Shared>, device_name: &str) -> CoreResult<Arc<Self>> {
        let relay = shared.relay();
        let url = relay.advertised_url()?;
        let session = shared.client().begin_join(device_name, &url)?;
        let offer = session.offer().clone();
        let transport = relay.pairing(&offer.relay, offer.secret)?;
        Ok(Arc::new(Self {
            shared,
            transport,
            qr: session.qr_payload(),
            expires_at: offer.expires_at,
            relay_url: offer.relay.clone(),
            is_new_device: true,
            inner: Mutex::new(Inner {
                side: Side::New(Box::new(session)),
                stage: Stage::WaitingForPeer,
                sas: None,
                peer_name: None,
                peer_role: None,
                device: None,
                share_storage_secret: false,
            }),
        }))
    }

    pub(crate) async fn scan(shared: Arc<Shared>, qr: &str) -> CoreResult<Arc<Self>> {
        let offer = PairingOffer::parse(qr.trim()).map_err(|_| {
            CoreError::invalid("配对二维码无效", "invalid pairing code")
        })?;
        if offer.is_expired(aipass_types::time::unix_now()) {
            return Err(CoreError::new(
                aipass_types::ErrorCode::ApprovalExpired,
                "配对二维码已过期，请在新设备上重新生成",
                "this pairing code expired; create a new one on the new device",
            ));
        }
        let transport = shared.relay().pairing(&offer.relay, offer.secret)?;
        let session = shared.client().scan_pairing(qr.trim(), &*transport).await?;
        let peer_name = session.offered_name().to_owned();
        let peer_role = enum_str(&session.offered_role());
        Ok(Arc::new(Self {
            shared,
            transport,
            qr: qr.trim().to_owned(),
            expires_at: offer.expires_at,
            relay_url: offer.relay.clone(),
            is_new_device: false,
            inner: Mutex::new(Inner {
                side: Side::Trusted(Box::new(session)),
                stage: Stage::WaitingForPeer,
                sas: None,
                peer_name: Some(peer_name),
                peer_role: Some(peer_role),
                device: None,
                share_storage_secret: true,
            }),
        }))
    }

    fn remaining(&self, timeout_secs: u32) -> Duration {
        let left = (self.expires_at - aipass_types::time::unix_now()).max(1) as u64;
        let t = if timeout_secs == 0 {
            left
        } else {
            u64::from(timeout_secs).min(left)
        };
        Duration::from_secs(t)
    }

    fn snapshot_of(g: &Inner) -> PairingProgressFfi {
        PairingProgressFfi {
            stage: g.stage.as_str().to_owned(),
            sas: g.sas.clone(),
            peer_name: g.peer_name.clone(),
            peer_role: g.peer_role.clone(),
            device: g.device.clone(),
        }
    }

    async fn finish_new_device(&self, g: &mut Inner, wait: Duration) -> CoreResult<()> {
        let Side::New(session) = &mut g.side else {
            return Err(CoreError::code(aipass_types::ErrorCode::Internal));
        };
        let welcome = session.wait_for_welcome(&*self.transport, wait).await?;
        let client = self.shared.client();
        client.complete_join(session, welcome, None).await?;
        // the vault's relay is the one used for pairing
        if let RelaySetting::Http(_) = self.shared.relay()
            && let Ok(u) = url::Url::parse(&self.relay_url)
        {
            self.shared
                .update_state(|s| s.relay_url = Some(u.as_str().to_owned()))?;
            self.shared.set_relay(RelaySetting::Http(u));
        }
        g.device = client
            .devices()?
            .into_iter()
            .find(|d| d.is_this_device)
            .map(Into::into);
        g.stage = Stage::Completed;
        Ok(())
    }

    async fn finish_trusted(&self, g: &mut Inner, code: Option<String>) -> CoreResult<()> {
        let share = g.share_storage_secret;
        let Side::Trusted(session) = &mut g.side else {
            return Err(CoreError::code(aipass_types::ErrorCode::Internal));
        };
        match code {
            Some(c) => {
                session.confirm_code(c.trim())?;
            }
            None => {
                session.confirm()?;
            }
        }
        let info = self
            .shared
            .client()
            .confirm_pairing(session, &*self.transport, share)
            .await?;
        g.device = Some(info.into());
        g.stage = Stage::Completed;
        Ok(())
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl PairingSession {
    /// `aipass://pair?…` link to render as a QR code (new device) or the scanned link.
    pub fn qr_payload(&self) -> String {
        self.qr.clone()
    }

    /// `true` on the device that joins, `false` on the trusted (approving) device.
    pub fn is_new_device(&self) -> bool {
        self.is_new_device
    }

    /// Unix time the pairing link expires (10 minutes after creation).
    pub fn expires_at(&self) -> i64 {
        self.expires_at
    }

    /// 6-digit short authentication string once both sides exchanged keys.
    pub async fn sas(&self) -> Option<String> {
        self.inner.lock().await.sas.clone()
    }

    /// Name of the other device (trusted side: from the link; new side: after `wait`).
    pub async fn peer_name(&self) -> Option<String> {
        self.inner.lock().await.peer_name.clone()
    }

    /// `member` | `executor` (trusted side) or the trusted device's role (new side).
    pub async fn peer_role(&self) -> Option<String> {
        self.inner.lock().await.peer_role.clone()
    }

    /// Current stage without waiting.
    pub async fn progress(&self) -> PairingProgressFfi {
        Self::snapshot_of(&*self.inner.lock().await)
    }

    /// Trusted side: whether to pass the storage access secret (end-to-end encrypted) to
    /// a new **member** device (never to executors). Default `true`.
    pub async fn set_share_storage_secret(&self, share: bool) {
        self.inner.lock().await.share_storage_secret = share;
    }

    /// Advance: wait for the peer (`timeout_secs = 0` waits until the link expires).
    pub async fn wait(&self, timeout_secs: u32) -> CoreResult<PairingProgressFfi> {
        let wait = self.remaining(timeout_secs);
        let mut g = self.inner.lock().await;
        match (g.stage, self.is_new_device) {
            (Stage::WaitingForPeer, true) => {
                let Side::New(session) = &mut g.side else {
                    return Err(CoreError::code(aipass_types::ErrorCode::Internal));
                };
                let hello = session.wait_for_hello(&*self.transport, wait).await?;
                g.sas = Some(hello.sas.clone());
                g.peer_name = Some(hello.peer_name.clone());
                g.peer_role = Some(enum_str(&hello.peer.role));
                g.stage = Stage::ConfirmCode;
            }
            (Stage::WaitingForPeer, false) => {
                let Side::Trusted(session) = &mut g.side else {
                    return Err(CoreError::code(aipass_types::ErrorCode::Internal));
                };
                session.wait_for_join(&*self.transport, wait).await?;
                g.sas = Some(session.sas().to_owned());
                g.stage = Stage::ConfirmCode;
            }
            (Stage::ConfirmCode, true) => self.finish_new_device(&mut g, wait).await?,
            _ => {}
        }
        Ok(Self::snapshot_of(&g))
    }

    /// Trusted side: the user confirmed that both screens show the same code → enrol the
    /// device. New side: wait for the trusted device's confirmation and install the vault.
    pub async fn confirm(&self) -> CoreResult<PairingProgressFfi> {
        let mut g = self.inner.lock().await;
        if g.stage != Stage::ConfirmCode {
            return Err(CoreError::new(
                aipass_types::ErrorCode::PreconditionFailed,
                "请先等待对方设备并核对验证码",
                "wait for the other device and compare the code first",
            ));
        }
        if self.is_new_device {
            let wait = self.remaining(0);
            self.finish_new_device(&mut g, wait).await?;
        } else {
            self.finish_trusted(&mut g, None).await?;
        }
        Ok(Self::snapshot_of(&g))
    }

    /// Trusted side: confirm by typing the code shown on the new device (a mismatch
    /// cancels the pairing).
    pub async fn confirm_code(&self, code: String) -> CoreResult<PairingProgressFfi> {
        let mut g = self.inner.lock().await;
        if self.is_new_device || g.stage != Stage::ConfirmCode {
            return Err(CoreError::new(
                aipass_types::ErrorCode::PreconditionFailed,
                "只能在已信任的设备上核对验证码",
                "codes are confirmed on the trusted device",
            ));
        }
        let r = self.finish_trusted(&mut g, Some(code)).await;
        if r.is_err() {
            g.stage = Stage::Cancelled;
        }
        r?;
        Ok(Self::snapshot_of(&g))
    }

    /// Cancel; nothing is enrolled.
    pub async fn cancel(&self) {
        let mut g = self.inner.lock().await;
        match &mut g.side {
            Side::New(s) => s.cancel(),
            Side::Trusted(s) => s.cancel(),
        }
        if g.stage != Stage::Completed {
            g.stage = Stage::Cancelled;
        }
    }
}
