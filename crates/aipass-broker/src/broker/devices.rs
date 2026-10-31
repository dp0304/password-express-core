// SPDX-License-Identifier: Apache-2.0
//! Trusted approver devices and inbound relay messages from them.
//!
//! The approver set is fed by the embedding process (node: `pairing.welcome`
//! `trusted_devices`; desktop: its own vault members) or by the local admin. Only active
//! owner/member devices may approve, sign policies, or act as principal `D`.
//!
//! Inbound envelopes ([`Broker::handle_device_message`]) must be addressed to the broker's
//! mailbox, come from an active approver device, verify (envelope signature + HPKE), be
//! fresh (≤ 24 h old, ≤ 5 min in the future), never seen before (replay cache), and —
//! for control messages — carry a valid device control signature from the same device.
//! Connection controls are applied in `signed_at` order (an old `resume` replayed after a
//! newer `pause` is rejected).

use std::sync::Arc;

use aipass_types::error::{ApiError, ErrorCode};
use aipass_types::ids::{DeviceId, MailboxId};
use aipass_types::models::Decision;
use aipass_types::relay::{
    DeviceSigned, MESSAGE_TTL_SECS, RelayEnvelope, RelayMessage, open_envelope, seal_envelope,
};
use aipass_types::vault::{DevicePublic, MemberStatus};
use rusqlite::params;
use serde_json::json;

use super::Broker;
use crate::audit::{self, Audit};
use crate::db::{enum_str, unix};
use crate::principal::Actor;
use crate::store;
use crate::types::{DevicesResponse, TrustedDevice};

/// Clock skew tolerated for envelopes / control messages from the future.
const FUTURE_SKEW_SECS: i64 = 300;

impl Broker {
    /// `GET /v1/admin/devices`.
    pub async fn list_devices(&self) -> Result<DevicesResponse, ApiError> {
        let devices = self.db.call(|c| store::list_devices(c)).await?;
        Ok(DevicesResponse { devices })
    }

    /// `POST /v1/admin/devices` — add a trusted device, or update the name/role of an
    /// existing one. A revoked device can never be re-activated under the same id, and an
    /// existing device's signing / KEM keys can never be replaced: a key change would let
    /// whoever holds the admin credential sign approvals *as* the user's real device
    /// (audit attributing them to it). Rotation is revoke + join under a new id; attempts
    /// are audited (`device.key_change_rejected`).
    pub async fn add_trusted_device(&self, actor: &Actor, device: DevicePublic) -> Result<TrustedDevice, ApiError> {
        aipass_crypto::identity::validate_ed25519_public_key(&device.sign_pk)
            .map_err(|_| ApiError::invalid_request("sign_pk 无效", "invalid sign_pk").with_detail("field", "sign_pk"))?;
        let name = device.name.trim();
        if name.is_empty() || name.chars().count() > 64 || name.chars().any(char::is_control) {
            return Err(ApiError::invalid_request("设备名称无效", "invalid device name").with_detail("field", "name"));
        }
        let now = self.now();
        let act = actor.audit_name();
        let (did, act2) = (device.device_id.clone(), act.clone());
        let r = self
            .db
            .call(move |c| {
                let tx = c.transaction()?;
                let existing = store::get_device(&tx, &device.device_id)?;
                if existing.as_ref().is_some_and(|d| d.status == MemberStatus::Revoked) {
                    return Err(ApiError::invalid_request("已撤销的设备不能重新加入", "A revoked device cannot be re-added.").into());
                }
                if existing
                    .as_ref()
                    .is_some_and(|d| d.device.sign_pk != device.sign_pk || d.device.kem_pk != device.kem_pk)
                {
                    return Ok(None);
                }
                let td = TrustedDevice {
                    device: device.clone(),
                    status: MemberStatus::Active,
                    added_at: existing.as_ref().map(|d| d.added_at).unwrap_or(now),
                    added_by: existing.map(|d| d.added_by).unwrap_or_else(|| act.clone()),
                    revoked_at: None,
                };
                store::upsert_device(&tx, &td)?;
                audit::append(
                    &tx,
                    now,
                    Audit::new(act, "device.added").detail(json!({
                        "device_id": device.device_id.as_str(),
                        "role": enum_str(&device.role),
                        "platform": enum_str(&device.platform),
                    })),
                )?;
                tx.commit()?;
                Ok(Some(td))
            })
            .await?;
        match r {
            Some(td) => Ok(td),
            None => {
                self.audit(
                    Audit::new(act2, "device.key_change_rejected")
                        .outcome("rejected")
                        .error(ErrorCode::PreconditionFailed)
                        .detail(json!({ "device_id": did.as_str() })),
                )
                .await;
                Err(ApiError::new(ErrorCode::PreconditionFailed).with_message(
                    "不能替换已加入设备的密钥；请先撤销该设备，再以新设备身份加入",
                    "An existing device's keys cannot be replaced; revoke it and join as a new device.",
                ))
            }
        }
    }

    /// `POST /v1/admin/devices/{id}/revoke` — remove a device from the approver set and
    /// revoke every grant it approved (a lost device's approvals are not trusted).
    pub async fn revoke_device(&self, actor: &Actor, id: &DeviceId) -> Result<TrustedDevice, ApiError> {
        let now = self.now();
        let (did, act) = (id.clone(), actor.audit_name());
        let td = self
            .db
            .call(move |c| {
                let tx = c.transaction()?;
                let mut d = store::get_device(&tx, &did)?.ok_or_else(ApiError::not_found)?;
                if d.status != MemberStatus::Revoked {
                    d.status = MemberStatus::Revoked;
                    d.revoked_at = Some(now);
                    store::upsert_device(&tx, &d)?;
                }
                audit::append(&tx, now, Audit::new(act, "device.revoked").detail(json!({ "device_id": did.as_str() })))?;
                tx.commit()?;
                Ok(d)
            })
            .await?;
        self.revoke_grants_approved_by(actor, id.as_str()).await?;
        Ok(td)
    }

    /// Process one envelope from the broker's own relay mailbox. Returns reply envelopes
    /// (`state.snapshot`, `revoke.report`) sealed to the sending device; the caller posts
    /// them to the relay. Rejections are audited (`relay.message_rejected`).
    pub async fn handle_device_message(self: &Arc<Self>, env: &RelayEnvelope) -> Result<Vec<RelayEnvelope>, ApiError> {
        let r = self.handle_device_message_inner(env).await;
        if let Err(e) = &r {
            self.audit(
                Audit::new(env.from.as_str(), "relay.message_rejected")
                    .error(e.code)
                    .outcome("rejected")
                    .detail(json!({ "type": env.message_type.as_str() })),
            )
            .await;
        }
        r
    }

    async fn handle_device_message_inner(self: &Arc<Self>, env: &RelayEnvelope) -> Result<Vec<RelayEnvelope>, ApiError> {
        let link = self
            .relay_link()
            .ok_or_else(|| ApiError::new(ErrorCode::NotSupported).with_message("未配置中继身份", "No relay identity is configured."))?;
        if env.to != link.identity.mailbox {
            return Err(ApiError::invalid_request("消息不是发给本节点的", "The envelope is not addressed to this broker."));
        }
        let MailboxId::Device(sender) = &env.from else {
            return Err(ApiError::identity_unverified());
        };
        let sid = sender.clone();
        let device = self
            .db
            .call(move |c| store::get_device(c, &sid))
            .await?
            .filter(|d| d.is_active_approver())
            .ok_or_else(ApiError::identity_unverified)?;
        let now = self.now();
        let age = unix(&now) - unix(&env.created_at);
        if !(-FUTURE_SKEW_SECS..=MESSAGE_TTL_SECS).contains(&age) {
            return Err(ApiError::invalid_request("消息已过期", "The envelope is too old or from the future."));
        }
        let msg = open_envelope(link.identity.identity.kem_keypair(), &device.device.sign_pk, env)
            .map_err(|_| ApiError::integrity_failed())?;
        let sig_hash = aipass_crypto::sha256_b64u(env.sig.as_bytes());
        if !self.db.call(move |c| store::relay_first_seen(c, &sig_hash, &now)).await? {
            return Err(ApiError::invalid_request("重复的消息", "Replayed envelope."));
        }
        let actor = Actor::Device(sender.clone());
        let pk = device.device.sign_pk;
        let check_signed_at = |signed_at: &aipass_types::Timestamp| -> Result<(), ApiError> {
            let a = unix(&now) - unix(signed_at);
            if !(-FUTURE_SKEW_SECS..=MESSAGE_TTL_SECS).contains(&a) {
                return Err(ApiError::invalid_request("控制指令已过期", "The control message is too old."));
            }
            Ok(())
        };
        let mut replies = Vec::new();
        match msg {
            RelayMessage::ApprovalDecision(d) => {
                if &d.signer_device_id != sender {
                    return Err(ApiError::identity_unverified());
                }
                self.submit_decision(*d).await?;
            }
            RelayMessage::ConnectionDecision(d) => {
                d.verify_control(&pk).map_err(|_| ApiError::integrity_failed())?;
                check_signed_at(&d.signed_at)?;
                self.check_control_order(&d.connection_id, &d.signed_at).await?;
                match d.decision {
                    Decision::Approve => {
                        self.approve_connection(&actor, &d.connection_id, d.allowed_projects.clone()).await?;
                    }
                    Decision::Deny => {
                        self.deny_connection(&actor, &d.connection_id).await?;
                    }
                }
            }
            RelayMessage::GrantRevoke(g) => {
                g.verify_control(&pk).map_err(|_| ApiError::integrity_failed())?;
                check_signed_at(&g.signed_at)?;
                let report = self.revoke_grant(&actor, &g.grant_id, g.level).await?;
                replies.push(RelayMessage::RevokeReport(report));
            }
            RelayMessage::ConnectionControl(ctl) => {
                ctl.verify_control(&pk).map_err(|_| ApiError::integrity_failed())?;
                check_signed_at(&ctl.signed_at)?;
                self.check_control_order(&ctl.connection_id, &ctl.signed_at).await?;
                let out = self.control_connection(&actor, &ctl.connection_id, ctl.action).await?;
                for r in out.reports {
                    replies.push(RelayMessage::RevokeReport(r));
                }
                if replies.is_empty() {
                    replies.push(RelayMessage::StateSnapshot(Box::new(self.state_snapshot().await?)));
                }
            }
            RelayMessage::StateRequest(_) => {
                replies.push(RelayMessage::StateSnapshot(Box::new(self.state_snapshot().await?)));
            }
            other => {
                return Err(ApiError::invalid_request("不支持的消息类型", "Unsupported message type for the broker.")
                    .with_detail("type", other.message_type().as_str()));
            }
        }
        let mut out = Vec::new();
        for m in replies {
            let e = seal_envelope(
                &*link.identity.identity,
                link.identity.mailbox.clone(),
                env.from.clone(),
                &device.device.kem_pk,
                &m,
                self.now(),
            )
            .map_err(|_| ApiError::internal())?;
            out.push(e);
        }
        Ok(out)
    }

    /// Reject control messages older than the last applied one for that connection.
    async fn check_control_order(&self, conn: &aipass_types::ids::ConnectionId, signed_at: &aipass_types::Timestamp) -> Result<(), ApiError> {
        let (cid, at) = (conn.clone(), unix(signed_at));
        self.db
            .call(move |c| {
                let row = store::get_connection(c, &cid)?.ok_or_else(ApiError::not_found)?;
                if row.last_control_at.is_some_and(|last| at < last) {
                    return Err(ApiError::invalid_request("控制指令早于已执行的指令", "A newer control message was already applied.").into());
                }
                c.execute(
                    "UPDATE connections SET last_control_at = ?2 WHERE connection_id = ?1",
                    params![cid.as_str(), at],
                )?;
                Ok(())
            })
            .await
    }
}
