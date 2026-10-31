// SPDX-License-Identifier: Apache-2.0
//! [`VaultClient`] operations beyond items and sync: conflicts, devices and revocation,
//! recovery, storage test / migration, import / export, autofill, approvals, relay
//! helpers and pairing.

use std::collections::BTreeMap;
use std::sync::Arc;

use aipass_crypto::{DeviceIdentity, Key32, SecretString};
use aipass_storage::{ObjectStore, PutCondition, PutOutcome, StorageProfile, StorageVerdict};
use aipass_types::Localized;
use aipass_types::ids::{
    ConnectionId, DeviceId, EntryId, ExecutorId, GrantId, MailboxId, MessageId, VaultId,
};
use aipass_types::models::{
    AccessSpec, AllowedProjects, ApprovalDecision, ApprovalRequest, Decision, RevocationLevel,
};
use aipass_types::pairing::{PairingRole, PairingWelcomeInner};
use aipass_types::relay::{
    ConnectionControl, ConnectionDecision, ControlAction, GrantRevoke, RelayEnvelope, RelayMessage,
};
use aipass_types::vault::{
    EntryKind, EntryPayload, EntrySource, Lifecycle, MemberRole, MemberStatus, keys,
};
use aipass_vault::import::{CsvFormat, ExistingEntry, ImportReport};
use aipass_vault::manifest::VaultView;
use aipass_vault::member::{
    device_public, executor_member_id, is_recovery_member, member_executor_id,
};
use aipass_vault::pairing::{NewDeviceSession, TrustedSession};
use aipass_vault::{RecoveryKey, RelayTransport, Result, SecretStore, UnlockedVault, VaultError};
use zeroize::Zeroizing;

use crate::cache::FileStore;
use crate::client::*;
use crate::engine::SyncEngine;
use crate::models::*;
use crate::outbox::{self, ChangeOp, Outbox};
use crate::planners::{AddMemberPlanner, ReplaceRecoveryPlanner, ResolvePlanner, RevokePlanner};

/// Kinds that are long-term credentials worth rotating after a revocation.
fn rotatable(kind: EntryKind) -> bool {
    !matches!(kind, EntryKind::SecureNote)
}

impl VaultClient {
    // ---------------------------------------------------------------------------------
    // conflicts
    // ---------------------------------------------------------------------------------

    /// Entries with unresolved conflicts and the details of every version.
    pub async fn conflicts(&self) -> Result<Vec<ConflictInfo>> {
        let (device, state, vault, view) = self.unlocked_snapshot()?;
        let engine = self
            .engine_for(&state, Self::ctx_for(&device, &vault, &state.vault_id))
            .await;
        let mut out = Vec::new();
        for id in view.conflicted_entries() {
            let me = &view.manifest.entries[&id];
            let mut versions = Vec::new();
            let current_ev = engine.entry_object(&view, &id, me.version).await?;
            let current = vault.decrypt_entry(&id, me.version, &current_ev)?;
            for v in std::iter::once(me.version).chain(me.conflict_versions.iter().copied()) {
                let ev = engine.entry_object(&view, &id, v).await?;
                let p = vault.decrypt_entry(&id, v, &ev)?;
                versions.push(ConflictVersion {
                    version: v,
                    is_current: v == me.version,
                    author_name: view.member(&ev.author_device_id).map(|m| m.name.clone()),
                    author_device_id: ev.author_device_id.clone(),
                    created_at: ev.created_at,
                    username: p.username.clone(),
                    secret_differs: p.secret != current.secret || p.totp != current.totp,
                });
            }
            out.push(ConflictInfo {
                entry_id: id.clone(),
                title: current.title.clone(),
                current_version: me.version,
                conflict_versions: me.conflict_versions.clone(),
                versions,
            });
        }
        Ok(out)
    }

    /// Resolve a conflict on this trusted client by keeping `keep_version` (written as a
    /// new current version; automatic use resumes).
    pub async fn resolve_conflict(&self, entry_id: &EntryId, keep_version: u64) -> Result<()> {
        let _op = self.op.lock().await;
        let (device, state, mut vault, view) = self.unlocked_snapshot()?;
        let me = view
            .manifest
            .entries
            .get(entry_id)
            .ok_or(VaultError::NotFound("entry"))?
            .clone();
        let engine = self
            .engine_for(&state, Self::ctx_for(&device, &vault, &state.vault_id))
            .await;
        let mut planner = ResolvePlanner::new(
            entry_id.clone(),
            keep_version,
            me.version,
            me.conflict_versions.clone(),
        );
        let out = engine.commit(&view, &mut vault, &mut planner).await?;
        self.after_commit(&engine, out.view, vault).await
    }

    /// Store a committed view + refreshed vault and re-decrypt changed entries.
    pub(crate) async fn after_commit(
        &self,
        engine: &SyncEngine,
        view: VaultView,
        vault: UnlockedVault,
    ) -> Result<()> {
        let items = decrypt_all(engine, &view, &vault, &BTreeMap::new()).await?;
        let now = aipass_types::time::now();
        let mut st = self.snapshot()?.1;
        st.checkpoint = view.checkpoint();
        st.last_sync_at = Some(now);
        st.membership_verified_at = Some(now);
        self.save_state(&st)?;
        let mut g = self.lock_inner();
        g.state = Some(st);
        g.view = Some(view);
        if let Some(sess) = g.session.as_mut() {
            sess.vault = vault;
            sess.items = items;
        }
        Ok(())
    }

    // ---------------------------------------------------------------------------------
    // devices
    // ---------------------------------------------------------------------------------

    /// Members of the vault (devices, executors, the recovery-key member).
    pub fn devices(&self) -> Result<Vec<DeviceInfo>> {
        let g = self.lock_inner();
        let view = g.view.as_ref().ok_or(VaultError::Locked)?;
        let me = g.device.as_ref().map(|d| d.device_id.clone());
        let mut out: Vec<DeviceInfo> = view
            .members
            .values()
            .map(|m| DeviceInfo {
                device_id: m.device_id.clone(),
                name: m.name.clone(),
                platform: m.platform,
                role: m.role,
                status: m.status,
                is_this_device: Some(&m.device_id) == me.as_ref(),
                is_recovery_key: is_recovery_member(m),
                added_by: m.added_by.clone(),
                updated_at: m.created_at,
                key_epoch: m.key_epoch,
                sign_pk: aipass_crypto::b64u::encode(m.sign_pk),
                kem_pk: aipass_crypto::b64u::encode(m.kem_pk),
            })
            .collect();
        out.sort_by_key(|a| (a.status == MemberStatus::Revoked, a.name.clone()));
        Ok(out)
    }

    /// Revoke a device (owners only): revoked member record, new key epoch sealed to the
    /// remaining members, keyring. Returns rotation tasks for long-term credentials the
    /// device could read — its existing copies cannot be remotely erased.
    pub async fn revoke_device(&self, device_id: &DeviceId) -> Result<RevokeResult> {
        let _op = self.op.lock().await;
        // push pending edits first so they are not encrypted under a key the revoked
        // device still has after the rotation… they would be re-encrypted anyway, but this
        // keeps the order of operations simple for the user
        let _ = self.sync_locked().await;
        let (device, state, mut vault, view) = self.unlocked_snapshot()?;
        let engine = self
            .engine_for(&state, Self::ctx_for(&device, &vault, &state.vault_id))
            .await;
        let mut planner = RevokePlanner::new(device_id.clone());
        let out = engine.commit(&view, &mut vault, &mut planner).await?;
        let was_trusted = out
            .view
            .member(device_id)
            .is_some_and(|m| m.role.is_trusted_approver());
        let was_executor = out
            .view
            .member(device_id)
            .is_some_and(|m| m.role == MemberRole::Executor);
        let executor_id = aipass_vault::member::member_executor_id(device_id);
        if let Some(p) = planner.pending.take() {
            vault.install_epoch(p);
        }
        let epoch = vault.key_epoch();
        let tasks: Vec<RotationTask> = if was_trusted {
            self.with_session(|s, _| {
                Ok(s.items
                    .iter()
                    .filter(|(_, c)| rotatable(c.payload.kind) && c.payload.has_secret_material())
                    .map(|(id, c)| RotationTask {
                        entry_id: id.clone(),
                        title: c.payload.title.clone(),
                        kind: c.payload.kind,
                        reason: rotation_reason(),
                    })
                    .collect())
            })?
        } else if was_executor {
            // the executor saw the plaintext of every credential sealed to it
            self.with_session(|s, st| {
                Ok(st
                    .executor_deliveries
                    .get(&executor_id)
                    .into_iter()
                    .flat_map(|m| m.keys())
                    .filter_map(|id| Some((id, s.items.get(id)?)))
                    .filter(|(_, c)| rotatable(c.payload.kind) && c.payload.has_secret_material())
                    .map(|(id, c)| RotationTask {
                        entry_id: id.clone(),
                        title: c.payload.title.clone(),
                        kind: c.payload.kind,
                        reason: rotation_reason(),
                    })
                    .collect())
            })?
        } else {
            Vec::new()
        };
        {
            let mut g = self.lock_inner();
            if let Some(st) = g.state.as_mut() {
                if was_executor {
                    st.executor_deliveries.remove(&executor_id);
                }
                for t in &tasks {
                    if !st.rotation_tasks.iter().any(|x| x.entry_id == t.entry_id) {
                        let version = out
                            .view
                            .manifest
                            .entries
                            .get(&t.entry_id)
                            .map_or(0, |e| e.version);
                        st.rotation_tasks.push(StoredRotationTask {
                            entry_id: t.entry_id.clone(),
                            version,
                            revoked_device: device_id.clone(),
                        });
                    }
                }
            }
        }
        self.after_commit(&engine, out.view, vault).await?;
        Ok(RevokeResult {
            device_id: device_id.clone(),
            key_epoch: epoch,
            rotation_tasks: tasks,
            note: Localized::new(
                "已撤销的设备无法再获得新的密钥和新版本，但它此前已经拿到的数据无法远程抹除。请按提示轮换它可能读取过的长期密码和 Key。",
                "The revoked device cannot obtain new keys or new versions, but data it already had cannot be remotely erased. Rotate the long-term passwords and keys it could read, as listed.",
            ),
        })
    }

    /// Open rotation tasks.
    pub fn rotation_tasks(&self) -> Result<Vec<RotationTask>> {
        self.with_session(|s, st| {
            Ok(st
                .rotation_tasks
                .iter()
                .filter_map(|t| {
                    let c = s.items.get(&t.entry_id)?;
                    Some(RotationTask {
                        entry_id: t.entry_id.clone(),
                        title: c.payload.title.clone(),
                        kind: c.payload.kind,
                        reason: rotation_reason(),
                    })
                })
                .collect())
        })
    }

    /// Mark a rotation task as done.
    pub fn dismiss_rotation_task(&self, entry_id: &EntryId) -> Result<()> {
        self.complete_rotation_task(entry_id)
    }

    // ---------------------------------------------------------------------------------
    // recovery
    // ---------------------------------------------------------------------------------

    /// Recovery verification: the user re-enters the recovery key. On success the pending
    /// copy is removed from this device and `recovery_verified_at` is recorded; when the
    /// current key epoch has no recovery-key wrap yet, one is queued for the next sync.
    pub fn verify_recovery_key(&self, key: &str) -> Result<bool> {
        let Ok(k) = RecoveryKey::parse(key) else {
            return Ok(false);
        };
        let (vault_id, ok, wrap) = {
            let g = self.lock_inner();
            let view = g.view.as_ref().ok_or(VaultError::Locked)?;
            let ok = aipass_vault::vault::recovery_key_matches(view, &k);
            let wrap = match (&g.session, ok) {
                (Some(s), true) => Some(s.vault.recovery_key_wrap(&k)?),
                _ => None,
            };
            (view.vault_id().clone(), ok, wrap)
        };
        if !ok {
            return Ok(false);
        }
        let mut st = self.snapshot()?.1;
        st.recovery_verified_at = Some(aipass_types::time::now());
        if let Some((key_name, bytes)) = wrap {
            st.pending_objects
                .insert(key_name, aipass_crypto::b64u::encode(bytes));
        }
        self.save_state(&st)?;
        self.lock_inner().state = Some(st);
        self.secrets.delete(&recovery_pending_key(&vault_id))?;
        Ok(true)
    }

    /// Recovery kit text. Contains the recovery key only while it is still pending
    /// verification on this device. `include_storage_secret` adds the storage access secret
    /// (explicit user opt-in).
    pub fn recovery_kit_text(&self, include_storage_secret: bool) -> Result<SecretString> {
        let (_, st) = self.snapshot()?;
        let pending = self
            .secrets
            .get(&recovery_pending_key(&st.vault_id))?
            .and_then(|b| b.into_secret_string().ok());
        let secret = if include_storage_secret {
            self.storage_secret(&st.vault_id)?
        } else {
            None
        };
        Ok(SecretString::new(
            aipass_vault::recovery::recovery_kit_text(&aipass_vault::recovery::RecoveryKit {
                vault_id: &st.vault_id,
                recovery_key: pending.as_ref(),
                created_at: &st.created_at,
                storage: &st.storage,
                storage_secret: secret.as_ref(),
            }),
        ))
    }

    /// Generate a new recovery key (revokes the old recovery member with key rotation).
    pub async fn replace_recovery_key(&self) -> Result<CreateVaultResult> {
        let _op = self.op.lock().await;
        let (device, state, mut vault, view) = self.unlocked_snapshot()?;
        let key = RecoveryKey::generate()?;
        let engine = self
            .engine_for(&state, Self::ctx_for(&device, &vault, &state.vault_id))
            .await;
        let mut planner = ReplaceRecoveryPlanner::new(key.clone());
        let out = engine.commit(&view, &mut vault, &mut planner).await?;
        if let Some(p) = planner.pending.take() {
            vault.install_epoch(p);
        }
        self.after_commit(&engine, out.view, vault).await?;
        let formatted = key.format();
        self.secrets.set(
            &recovery_pending_key(&state.vault_id),
            formatted.expose().as_bytes(),
            true,
        )?;
        let mut st = self.snapshot()?.1;
        st.recovery_verified_at = None;
        self.save_state(&st)?;
        self.lock_inner().state = Some(st);
        let kit = self.recovery_kit_text(false)?;
        Ok(CreateVaultResult {
            vault_id: state.vault_id,
            device_id: device.device_id,
            recovery_key: formatted,
            recovery_kit_text: kit,
        })
    }

    /// Set (or change) the optional master password. Recovery wraps are immutable per key
    /// epoch, so changing an existing one rotates the key epoch.
    pub async fn set_master_password(&self, password: &SecretString) -> Result<()> {
        let _op = self.op.lock().await;
        let (device, state, mut vault, view) = self.unlocked_snapshot()?;
        let engine = self
            .engine_for(&state, Self::ctx_for(&device, &vault, &state.vault_id))
            .await;
        let key = keys::recovery(
            vault.key_epoch(),
            aipass_types::vault::RecoveryKind::MasterPassword,
        );
        if engine.object(&key).await?.is_none() {
            let (k, b) = vault.master_password_wrap(password, self.cfg.argon2)?;
            if engine.put_create_only(&k, b).await? {
                return Ok(());
            }
        }
        struct Rotate {
            pending: Option<aipass_vault::PendingEpoch>,
            password: SecretString,
            params: aipass_crypto::Argon2Params,
        }
        #[async_trait::async_trait]
        impl crate::engine::CommitPlanner for Rotate {
            async fn plan(
                &mut self,
                ctx: &crate::engine::PlanContext<'_>,
                draft: &mut aipass_vault::ManifestDraft,
            ) -> Result<()> {
                let p = aipass_vault::vault::stage_rotation(ctx.vault, ctx.view, draft, &ctx.now)?;
                let (k, b) =
                    p.master_password_wrap(ctx.vault.vault_id(), &self.password, self.params)?;
                draft.add_object(k, b);
                self.pending = Some(p);
                Ok(())
            }
        }
        let mut planner = Rotate {
            pending: None,
            password: password.clone(),
            params: self.cfg.argon2,
        };
        let out = engine.commit(&view, &mut vault, &mut planner).await?;
        if let Some(p) = planner.pending.take() {
            vault.install_epoch(p);
        }
        self.after_commit(&engine, out.view, vault).await
    }

    /// Recover the vault on a **fresh** device with the recovery key: verify the vault from
    /// storage (a brand-new device has no checkpoint — §10.4 limitation), act as the
    /// recovery member to enrol this device as an owner, then open as this device.
    #[allow(clippy::too_many_arguments)]
    pub async fn recover_with_key(
        cfg: ClientConfig,
        secrets: Arc<dyn SecretStore>,
        factory: Arc<dyn crate::client::StoreFactory>,
        vault_id: &VaultId,
        storage: StorageProfile,
        storage_secret: Option<SecretString>,
        recovery_key: &str,
        device_name: &str,
    ) -> Result<Self> {
        let client = Self::open(cfg, secrets, factory)?;
        if client.has_vault() {
            return Err(VaultError::AlreadyExists);
        }
        aipass_vault::member::validate_device_name(device_name)?;
        let key = RecoveryKey::parse(recovery_key)?;
        let rid = key.identity(vault_id);
        let rdev = aipass_vault::member::recovery_device_id(&rid.public().sign_pk);
        let ctx = StoreContext {
            vault_id: vault_id.clone(),
            device_id: Some(rdev.clone()),
            identity: Some(rid.clone()),
        };
        let remote = client
            .factory
            .open(&storage, storage_secret.as_ref(), &ctx)
            .await?;
        let engine = SyncEngine::new(remote, client.cache_store(), vault_id.clone());
        let g = engine.genesis_view().await?;
        let (view, _) = engine.pull(&g).await?;
        let rec_epoch = view.member(&rdev).map(|m| m.key_epoch).unwrap_or(1);
        let kr = engine.keyring_bytes(rec_epoch).await?;
        let rw = engine
            .object(&keys::recovery(
                rec_epoch,
                aipass_types::vault::RecoveryKind::RecoveryKey,
            ))
            .await?;
        let mut acting =
            aipass_vault::vault::open_with_recovery_key(&view, &key, kr.as_deref(), rw.as_deref())?;
        let identity = DeviceIdentity::generate();
        let device_id = DeviceId::generate();
        let dp = device_public(
            &device_id,
            &identity,
            device_name.trim(),
            client.cfg.platform,
            MemberRole::Owner,
        );
        let mut planner = AddMemberPlanner::new(dp.clone());
        let out = engine.commit(&view, &mut acting, &mut planner).await?;
        client
            .install_joined(
                &engine,
                out.view,
                device_id,
                identity,
                MemberRole::Owner,
                device_name,
                storage,
                storage_secret,
            )
            .await?;
        Ok(client)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn install_joined(
        &self,
        engine: &SyncEngine,
        view: VaultView,
        device_id: DeviceId,
        identity: DeviceIdentity,
        role: MemberRole,
        device_name: &str,
        storage: StorageProfile,
        storage_secret: Option<SecretString>,
    ) -> Result<()> {
        let vault_id = view.vault_id().clone();
        let vault = engine
            .open_vault(&view, &device_id, identity.clone())
            .await?;
        let items = decrypt_all(engine, &view, &vault, &BTreeMap::new()).await?;
        self.secrets.set(
            &device_secret_key(&device_id),
            identity.to_secret_bytes().expose(),
            true,
        )?;
        let local_key = Key32::generate()?;
        self.secrets
            .set(&local_key_name(&vault_id), local_key.expose(), false)?;
        if let Some(s) = &storage_secret {
            self.secrets
                .set(&storage_secret_key(&vault_id), s.expose().as_bytes(), false)?;
        }
        let now = aipass_types::time::now();
        let p = identity.public();
        let device = DeviceFile {
            format: 1,
            device_id: device_id.clone(),
            name: device_name.trim().to_owned(),
            platform: self.cfg.platform,
            role,
            sign_pk: p.sign_pk,
            kem_pk: p.kem_pk,
            created_at: now,
            app_version: self.cfg.app_version.clone(),
        };
        let state = StateFile {
            format: 1,
            vault_id: vault_id.clone(),
            storage,
            checkpoint: view.checkpoint(),
            last_sync_at: Some(now),
            membership_verified_at: Some(now),
            recovery_verified_at: None,
            rollback_detected: false,
            revoked: false,
            relay_base_url: None,
            last_error: None,
            resource_bindings: BTreeMap::new(),
            known_executors: BTreeMap::new(),
            pending_objects: BTreeMap::new(),
            rotation_tasks: Vec::new(),
            executor_deliveries: BTreeMap::new(),
            created_at: view.header.created_at,
        };
        self.save_device(&device)?;
        self.save_state(&state)?;
        outbox::save(
            &self.outbox_path(),
            &local_key,
            &vault_id,
            &device_id,
            &Outbox::default(),
        )?;
        let mut g = self.lock_inner();
        g.device = Some(device);
        g.state = Some(state);
        g.view = Some(view);
        g.session = Some(Session {
            vault,
            items,
            outbox: Outbox::default(),
            local_key,
        });
        Ok(())
    }

    // ---------------------------------------------------------------------------------
    // storage
    // ---------------------------------------------------------------------------------

    /// Run the storage capability test against a candidate profile (§10.2).
    pub async fn test_storage(
        &self,
        profile: &StorageProfile,
        secret: Option<&SecretString>,
    ) -> Result<aipass_storage::CapabilityReport> {
        let ctx = {
            let g = self.lock_inner();
            match (g.state.as_ref(), g.device.as_ref(), g.session.as_ref()) {
                (Some(st), Some(d), Some(s)) => Self::ctx_for(d, &s.vault, &st.vault_id),
                (Some(st), d, _) => StoreContext {
                    vault_id: st.vault_id.clone(),
                    device_id: d.map(|d| d.device_id.clone()),
                    identity: None,
                },
                _ => StoreContext {
                    vault_id: VaultId::generate(),
                    device_id: None,
                    identity: None,
                },
            }
        };
        let store = self.factory.open(profile, secret, &ctx).await?;
        Ok(aipass_storage::capability_test(store.as_ref(), "_aipass_captest").await)
    }

    /// Migrate to another storage (§10.2): sync, capability-test the target (must be
    /// `sync_capable`), copy every object create-only, verify the target restores to the
    /// same checkpoint and decrypts, then switch. The old copy is kept.
    pub async fn migrate_storage(
        &self,
        profile: StorageProfile,
        secret: Option<SecretString>,
    ) -> Result<MigrationReport> {
        let _op = self.op.lock().await;
        let report = self.sync_locked().await?;
        if !matches!(report.status, SyncStatus::Ok | SyncStatus::Conflict) {
            return Err(VaultError::PreconditionFailed(
                "sync must succeed before migrating storage",
            ));
        }
        let (device, state, vault, view) = self.unlocked_snapshot()?;
        if !self.with_session(|s, _| Ok(s.outbox.is_empty()))? {
            return Err(VaultError::PreconditionFailed(
                "pending changes must be synced before migrating",
            ));
        }
        let ctx = Self::ctx_for(&device, &vault, &state.vault_id);
        let source = self.engine_for(&state, ctx.clone()).await;
        let target = self.factory.open(&profile, secret.as_ref(), &ctx).await?;
        let cap = aipass_storage::capability_test(target.as_ref(), "_aipass_captest").await;
        if cap.verdict != StorageVerdict::SyncCapable {
            return Err(VaultError::Invalid(Localized::new(
                "目标存储未通过条件写入测试，仅可备份，不能作为加密同步的主存储",
                "The target storage failed the conditional-write test; it is backup-only and cannot be the primary sync storage.",
            )));
        }
        let genesis = view
            .member(&view.header.genesis_device_id)
            .ok_or(VaultError::Internal("genesis member missing"))?;
        self.factory
            .provision(&profile, secret.as_ref(), &ctx, &view.header, genesis)
            .await?;

        let mut keys_list: Vec<String> = Vec::new();
        for prefix in [
            keys::VAULT_HEADER,
            keys::MEMBERS_PREFIX,
            keys::RECOVERY_PREFIX,
            keys::KEYRING_PREFIX,
            keys::ENTRIES_PREFIX,
        ] {
            for m in aipass_storage::list_all(source.remote().as_ref(), prefix).await? {
                if keys::is_valid(&m.key) {
                    keys_list.push(m.key);
                }
            }
        }
        let mut manifests: Vec<String> =
            aipass_storage::list_all(source.remote().as_ref(), keys::MANIFESTS_PREFIX)
                .await?
                .into_iter()
                .map(|m| m.key)
                .filter(|k| keys::parse_manifest(k).is_some())
                .collect();
        manifests.sort();
        keys_list.extend(manifests);
        let (mut copied, mut present) = (0u64, 0u64);
        for k in &keys_list {
            let obj = source
                .remote()
                .get(k)
                .await?
                .ok_or(VaultError::Integrity("object vanished during migration"))?;
            match target
                .put(k, obj.bytes.clone(), PutCondition::IfAbsent)
                .await?
            {
                PutOutcome::Written { .. } => copied += 1,
                PutOutcome::PreconditionFailed => match target.get(k).await? {
                    Some(o) if o.bytes == obj.bytes => present += 1,
                    _ => {
                        return Err(VaultError::Invalid(Localized::new(
                            "目标位置已有不同的数据，请选择一个空的目录或前缀",
                            "The target location already contains different data; choose an empty directory or prefix.",
                        )));
                    }
                },
            }
        }
        let _ = target
            .put(
                keys::HEAD,
                view.seq().to_string().into_bytes(),
                PutCondition::None,
            )
            .await;

        // verify the target is restorable from scratch before switching
        let scratch: Arc<dyn ObjectStore> = Arc::new(aipass_storage::MemoryStore::new());
        let check = SyncEngine::new(target.clone(), scratch, state.vault_id.clone());
        let g = check.genesis_view().await?;
        let (tv, _) = check.pull(&g).await?;
        if tv.checkpoint() != view.checkpoint() {
            return Err(VaultError::Integrity(
                "the migrated copy does not reach the current checkpoint",
            ));
        }
        let mut entries_verified = 0u64;
        for (id, me) in &tv.manifest.entries {
            let ev = check.entry_object(&tv, id, me.version).await?;
            vault.decrypt_entry(id, me.version, &ev)?;
            entries_verified += 1;
        }

        let mut st = self.snapshot()?.1;
        let mut p = profile.clone();
        p.verdict = Some(cap.verdict);
        p.tested_at = Some(aipass_types::time::now());
        st.storage = p;
        match &secret {
            Some(s) => self.secrets.set(
                &storage_secret_key(&st.vault_id),
                s.expose().as_bytes(),
                false,
            )?,
            None => self.secrets.delete(&storage_secret_key(&st.vault_id))?,
        }
        self.save_state(&st)?;
        let cp = view
            .checkpoint()
            .ok_or(VaultError::Internal("no checkpoint"))?;
        self.lock_inner().state = Some(st);
        Ok(MigrationReport {
            objects_copied: copied,
            objects_already_present: present,
            verified_checkpoint: cp,
            entries_verified,
            old_storage_kept: true,
            target_report: cap,
        })
    }

    // ---------------------------------------------------------------------------------
    // import / export
    // ---------------------------------------------------------------------------------

    /// Import a CSV export (local only). Imported entries are `imported`, not `verified`.
    pub async fn import_csv(&self, format: CsvFormat, bytes: &[u8]) -> Result<ImportReport> {
        let existing: Vec<ExistingEntry> = self.with_session(|s, _| {
            Ok(Self::effective(s)
                .iter()
                .map(|(id, e)| ExistingEntry {
                    entry_id: id.clone(),
                    username: e.payload.username.clone(),
                    urls: e.payload.urls.clone(),
                })
                .collect())
        })?;
        let result = aipass_vault::import::import_csv(format, bytes, &existing)?;
        for (id, payload) in result.entries {
            self.queue_change(id, ChangeOp::Upsert { payload })?;
        }
        if self.cfg.auto_sync {
            let _ = self.sync().await;
        }
        Ok(result.report)
    }

    /// Encrypted `.aipassx` export of every entry (the client re-authenticates first).
    pub fn export_encrypted(&self, password: &SecretString) -> Result<Vec<u8>> {
        let body = self.with_session(|s, st| {
            Ok(aipass_vault::export::ExportBody {
                vault_id: st.vault_id.clone(),
                entries: Self::effective(s)
                    .into_iter()
                    .map(|(id, e)| aipass_vault::export::ExportEntry {
                        entry_id: id,
                        version: e.version.unwrap_or(0),
                        payload: e.payload,
                    })
                    .collect(),
            })
        })?;
        aipass_vault::export::export_encrypted(
            &body,
            password,
            self.cfg.argon2,
            &aipass_types::time::now(),
        )
    }

    /// Import an `.aipassx` file: entries whose id is unknown are created; existing or
    /// deleted ids are skipped (reported as duplicates) — nothing is silently resurrected.
    pub async fn import_encrypted(
        &self,
        bytes: &[u8],
        password: &SecretString,
    ) -> Result<ImportReport> {
        let body = aipass_vault::export::import_encrypted(bytes, password)?;
        let (known, tombstoned) = {
            let g = self.lock_inner();
            let v = g.view.as_ref().ok_or(VaultError::Locked)?;
            (
                v.manifest
                    .entries
                    .keys()
                    .cloned()
                    .collect::<std::collections::BTreeSet<_>>(),
                v.manifest
                    .tombstones
                    .keys()
                    .cloned()
                    .collect::<std::collections::BTreeSet<_>>(),
            )
        };
        let mut report = ImportReport::default();
        for (i, e) in body.entries.into_iter().enumerate() {
            if known.contains(&e.entry_id) || tombstoned.contains(&e.entry_id) {
                report.duplicates.push(aipass_vault::import::DuplicateInfo {
                    existing_entry_id: e.entry_id.clone(),
                    title: e.payload.title.clone(),
                    username: e.payload.username.clone(),
                    url: e.payload.urls.first().cloned(),
                    row: i as u64 + 1,
                });
                continue;
            }
            let mut p = e.payload;
            p.lifecycle = Lifecycle::Imported;
            p.source = EntrySource::Import("aipassx".into());
            self.queue_change(e.entry_id, ChangeOp::Upsert { payload: p })?;
            report.imported += 1;
        }
        if self.cfg.auto_sync {
            let _ = self.sync().await;
        }
        Ok(report)
    }

    /// Plaintext CSV export (`title,url,username,password,notes,totp,kind`). The client must
    /// re-authenticate and show [`aipass_vault::export::csv_export_warning`]. Never offered
    /// to AI.
    pub fn export_csv(&self) -> Result<Zeroizing<Vec<u8>>> {
        let payloads: Vec<EntryPayload> = self.with_session(|s, _| {
            Ok(Self::effective(s)
                .into_values()
                .map(|e| e.payload)
                .collect())
        })?;
        let refs: Vec<&EntryPayload> = payloads.iter().collect();
        aipass_vault::export::export_csv(&refs)
    }

    // ---------------------------------------------------------------------------------
    // autofill / browser extension
    // ---------------------------------------------------------------------------------

    /// Logins matching a page or OS service identifier (no secrets). Same-site matches
    /// must only be offered after an explicit click.
    pub fn autofill_candidates(&self, service_identifier: &str) -> Result<Vec<AutofillCandidate>> {
        self.with_session(|s, _| {
            let mut out: Vec<AutofillCandidate> = Self::effective(s)
                .iter()
                .filter(|(_, e)| e.payload.kind == EntryKind::Login && e.payload.secret.is_some())
                .filter_map(|(id, e)| {
                    aipass_vault::matching::match_entry(&e.payload.urls, service_identifier).map(
                        |m| AutofillCandidate {
                            entry_id: id.clone(),
                            title: e.payload.title.clone(),
                            username: e.payload.username.clone(),
                            match_kind: m,
                        },
                    )
                })
                .collect();
            out.sort_by(|a, b| a.match_kind.cmp(&b.match_kind).then(a.title.cmp(&b.title)));
            Ok(out)
        })
    }

    /// Username + password (+ TOTP) for a user-initiated fill. Refuses entries with an
    /// unresolved conflict (`SYNC_CONFLICT`).
    pub fn autofill_credential(&self, entry_id: &EntryId) -> Result<AutofillCredential> {
        self.with_session(|s, _| {
            let eff = Self::effective(s);
            let e = eff.get(entry_id).ok_or(VaultError::NotFound("entry"))?;
            if !e.conflict_versions.is_empty() {
                return Err(VaultError::SyncConflict);
            }
            let password = e
                .payload
                .secret
                .clone()
                .ok_or(VaultError::NotFound("password"))?;
            let totp = match &e.payload.totp {
                Some(t) => Some(aipass_vault::totp::totp_now(t)?.code),
                None => None,
            };
            Ok(AutofillCredential {
                username: e.payload.username.clone(),
                password,
                totp,
            })
        })
    }

    /// Identities to register with the OS credential provider.
    pub fn all_credential_identities(&self) -> Result<Vec<CredentialIdentity>> {
        self.with_session(|s, _| {
            let mut out = Vec::new();
            for (id, e) in Self::effective(s) {
                if e.payload.kind != EntryKind::Login || e.payload.secret.is_none() {
                    continue;
                }
                for u in &e.payload.urls {
                    if let Some(h) = aipass_vault::matching::host_of(u) {
                        out.push(CredentialIdentity {
                            entry_id: id.clone(),
                            service_identifier: h,
                            username: e.payload.username.clone(),
                        });
                    }
                }
            }
            Ok(out)
        })
    }

    /// Save a credential captured by the browser extension (exact origin only).
    pub async fn save_from_browser(
        &self,
        origin: &str,
        username: Option<&str>,
        password: SecretString,
        form_kind: &str,
    ) -> Result<(SaveStatus, Option<EntryId>)> {
        let site = aipass_vault::matching::parse_site(origin)
            .ok_or(VaultError::InvalidInput("invalid origin"))?;
        let origin_url = site.origin().ascii_serialization();
        let user = username
            .map(|u| u.trim().to_owned())
            .filter(|u| !u.is_empty());
        let matches: Vec<(EntryId, EntryPayload)> = self.with_session(|s, _| {
            Ok(Self::effective(s)
                .into_iter()
                .filter(|(_, e)| e.payload.kind == EntryKind::Login)
                .filter(|(_, e)| {
                    aipass_vault::matching::match_entry(&e.payload.urls, &origin_url)
                        == Some(aipass_vault::matching::MatchKind::ExactOrigin)
                })
                .map(|(id, e)| (id, e.payload))
                .collect())
        })?;
        let same_user: Vec<&(EntryId, EntryPayload)> = matches
            .iter()
            .filter(|(_, p)| match &user {
                Some(u) => p
                    .username
                    .as_deref()
                    .is_some_and(|x| x.eq_ignore_ascii_case(u)),
                None => form_kind == "change_password",
            })
            .collect();
        let lifecycle = if form_kind == "login" {
            Lifecycle::Verified
        } else {
            Lifecycle::NeedsAttention
        };
        match same_user.len() {
            0 if user.is_some() || form_kind != "change_password" => {
                let mut input = ItemInput::new(
                    EntryKind::Login,
                    aipass_vault::matching::registrable_domain(site.host_str().unwrap_or("site")),
                );
                input.username = user;
                input.secret = Some(password);
                input.urls = vec![origin_url];
                input.lifecycle = Some(lifecycle);
                let id = self.save_item(input).await?;
                Ok((SaveStatus::Saved, Some(id)))
            }
            1 => {
                let (id, p) = same_user[0].clone();
                if p.secret.as_ref() == Some(&password) {
                    return Ok((SaveStatus::Updated, Some(id)));
                }
                let mut np = p.clone();
                np.secret = Some(password);
                np.lifecycle = lifecycle;
                np.updated_at = aipass_types::time::now();
                self.queue_change(id.clone(), ChangeOp::Upsert { payload: np })?;
                self.complete_rotation_task(&id)?;
                if self.cfg.auto_sync {
                    let _ = self.sync().await;
                }
                Ok((SaveStatus::Updated, Some(id)))
            }
            _ => Ok((SaveStatus::NeedsConfirmation, None)),
        }
    }

    // ---------------------------------------------------------------------------------
    // approvals & control
    // ---------------------------------------------------------------------------------

    /// Bind a broker resource to the vault entry holding its credential.
    pub fn bind_resource(
        &self,
        resource_id: &aipass_types::ids::ResourceId,
        entry_id: &EntryId,
    ) -> Result<()> {
        let mut st = self.snapshot()?.1;
        st.resource_bindings
            .insert(resource_id.clone(), entry_id.clone());
        self.save_state(&st)?;
        self.lock_inner().state = Some(st);
        Ok(())
    }

    /// Register an executor that is not a vault member (e.g. the desktop-embedded one).
    pub fn register_executor(&self, executor_id: &ExecutorId, info: KnownExecutor) -> Result<()> {
        let mut st = self.snapshot()?.1;
        st.known_executors.insert(executor_id.clone(), info);
        self.save_state(&st)?;
        self.lock_inner().state = Some(st);
        Ok(())
    }

    /// Executor keys from a trusted source: its vault member record (`exe_X` ⇔ `dev_X`,
    /// active, role executor) or an explicitly registered executor.
    pub fn executor_keys(&self, executor_id: &ExecutorId) -> Result<KnownExecutor> {
        let g = self.lock_inner();
        if let Some(view) = g.view.as_ref()
            && let Some(m) = view.member(&executor_member_id(executor_id))
        {
            if m.role == MemberRole::Executor && m.status == MemberStatus::Active {
                return Ok(KnownExecutor {
                    name: m.name.clone(),
                    sign_pk: m.sign_pk,
                    kem_pk: m.kem_pk,
                });
            }
            return Err(VaultError::Forbidden(
                "executor is revoked or not an executor",
            ));
        }
        g.state
            .as_ref()
            .and_then(|s| s.known_executors.get(executor_id).cloned())
            .ok_or(VaultError::SecretUnavailable(
                "unknown executor; pair it first",
            ))
    }

    /// Approve with the credential bound to the request's resource (see
    /// [`VaultClient::bind_resource`]).
    pub async fn approve(
        &self,
        request: &ApprovalRequest,
        narrowed: Option<AccessSpec>,
    ) -> Result<ApprovalDecision> {
        let entry = {
            let g = self.lock_inner();
            g.state.as_ref().and_then(|s| {
                s.resource_bindings
                    .get(&request.resource.resource_id)
                    .cloned()
            })
        };
        self.approve_with_entry(request, narrowed, entry.as_ref())
            .await
    }

    /// Approve on this trusted device: recompute the digest from the displayed request,
    /// sign it and seal `entry`'s credential to the executor. `entry = None` approves
    /// without a credential envelope (in-process executors).
    pub async fn approve_with_entry(
        &self,
        request: &ApprovalRequest,
        narrowed: Option<AccessSpec>,
        entry: Option<&EntryId>,
    ) -> Result<ApprovalDecision> {
        if let Some(e) = entry {
            let pending = self.with_session(|s, _| Ok(s.outbox.get(e).is_some()))?;
            if pending {
                let _ = self.sync().await;
            }
        }
        let exe = match entry {
            Some(_) => Some(self.executor_keys(&request.executor.executor_id)?),
            None => None,
        };
        let (decision, delivered) = self.with_session(|s, _| {
            let now = aipass_types::time::now();
            match (entry, exe) {
                (Some(e), Some(k)) => {
                    let c = s
                        .items
                        .get(e)
                        .ok_or(VaultError::NotFound("credential entry"))?;
                    let src = aipass_vault::approval::CredentialSource {
                        entry_id: e,
                        version: c.version,
                        payload: &c.payload,
                        has_conflict: !c.conflict_versions.is_empty(),
                    };
                    let d = aipass_vault::approval::approve_request(
                        s.vault.identity(),
                        s.vault.device_id(),
                        request,
                        narrowed,
                        Some((&src, &k.kem_pk)),
                        &now,
                    )?;
                    Ok((d, Some(c.version)))
                }
                _ => aipass_vault::approval::approve_request(
                    s.vault.identity(),
                    s.vault.device_id(),
                    request,
                    narrowed,
                    None,
                    &now,
                )
                .map(|d| (d, None)),
            }
        })?;
        if let (Some(e), Some(version)) = (entry, delivered)
            && decision.credential_envelope.is_some()
        {
            // log the delivery before releasing the sealed credential (fail closed)
            let mut st = self.snapshot()?.1;
            let v = st
                .executor_deliveries
                .entry(request.executor.executor_id.clone())
                .or_default()
                .entry(e.clone())
                .or_insert(0);
            *v = (*v).max(version);
            self.save_state(&st)?;
            self.lock_inner().state = Some(st);
        }
        Ok(decision)
    }

    /// Deny (signed).
    pub fn deny(&self, request: &ApprovalRequest) -> Result<ApprovalDecision> {
        self.with_session(|s, _| {
            aipass_vault::approval::deny_request(
                s.vault.identity(),
                s.vault.device_id(),
                request,
                &aipass_types::time::now(),
            )
        })
    }

    /// Signed `connection.decision`.
    pub fn sign_connection_decision(
        &self,
        connection_id: &ConnectionId,
        decision: Decision,
        allowed_projects: AllowedProjects,
    ) -> Result<ConnectionDecision> {
        self.with_session(|s, _| {
            aipass_vault::approval::sign_connection_decision(
                s.vault.identity(),
                connection_id,
                decision,
                allowed_projects,
                &aipass_types::time::now(),
            )
        })
    }

    /// Signed `grant.revoke`.
    pub fn sign_grant_revoke(
        &self,
        grant_id: &GrantId,
        level: RevocationLevel,
    ) -> Result<GrantRevoke> {
        self.with_session(|s, _| {
            aipass_vault::approval::sign_grant_revoke(
                s.vault.identity(),
                grant_id,
                level,
                &aipass_types::time::now(),
            )
        })
    }

    /// Signed `connection.control`.
    pub fn sign_connection_control(
        &self,
        connection_id: &ConnectionId,
        action: ControlAction,
    ) -> Result<ConnectionControl> {
        self.with_session(|s, _| {
            aipass_vault::approval::sign_connection_control(
                s.vault.identity(),
                connection_id,
                action,
                &aipass_types::time::now(),
            )
        })
    }

    /// Seal a message from this device to an executor / broker mailbox.
    pub fn seal_for_executor(
        &self,
        executor_id: &ExecutorId,
        message: &RelayMessage,
    ) -> Result<RelayEnvelope> {
        let k = self.executor_keys(executor_id)?;
        self.with_session(|s, _| {
            aipass_vault::relay::seal_message(
                s.vault.identity(),
                MailboxId::Device(s.vault.device_id().clone()),
                MailboxId::Executor(executor_id.clone()),
                &k.kem_pk,
                message,
                aipass_types::time::now(),
            )
        })
    }

    /// Seal `message` for an executor / broker and post it to its relay mailbox.
    pub async fn send_to_executor(
        &self,
        relay: &dyn RelayTransport,
        executor_id: &ExecutorId,
        message: &RelayMessage,
    ) -> Result<MessageId> {
        let env = self.seal_for_executor(executor_id, message)?;
        relay
            .post(&MailboxId::Executor(executor_id.clone()), &env, None)
            .await
    }

    /// Open a message sent to this device by an executor / broker (sender key from a
    /// trusted source).
    pub fn open_from_executor(
        &self,
        envelope: &RelayEnvelope,
    ) -> Result<(ExecutorId, RelayMessage)> {
        let MailboxId::Executor(exe) = &envelope.from else {
            return Err(VaultError::Integrity("message is not from an executor"));
        };
        let k = self.executor_keys(exe)?;
        let me = self.device_id().ok_or(VaultError::NoVault)?;
        if envelope.to != MailboxId::Device(me) {
            return Err(VaultError::Integrity(
                "message is addressed to another device",
            ));
        }
        let msg = self.with_session(|s, _| {
            aipass_vault::relay::open_message(
                s.vault.identity().kem_keypair(),
                &k.sign_pk,
                envelope,
            )
        })?;
        Ok((exe.clone(), msg))
    }

    /// Fetch this device's relay inbox (approval requests, reports, snapshots). Messages
    /// that cannot be verified are skipped.
    pub async fn fetch_inbox(
        &self,
        relay: &dyn RelayTransport,
        after: Option<&MessageId>,
        wait_secs: u64,
    ) -> Result<(
        Vec<(MessageId, ExecutorId, RelayMessage)>,
        Option<MessageId>,
    )> {
        let me = self.device_id().ok_or(VaultError::NoVault)?;
        let msgs = relay
            .fetch(&MailboxId::Device(me), after, wait_secs, None)
            .await?;
        let mut cursor = after.cloned();
        let mut out = Vec::new();
        for m in msgs {
            cursor = Some(m.message_id.clone());
            match self.open_from_executor(&m.envelope) {
                Ok((exe, msg)) => out.push((m.message_id, exe, msg)),
                Err(e) => tracing::debug!(error = %e, "skipping unverifiable inbox message"),
            }
        }
        Ok((out, cursor))
    }

    // ---------------------------------------------------------------------------------
    // pairing
    // ---------------------------------------------------------------------------------

    /// Trusted side: scan a pairing link and send `pairing.hello`.
    pub async fn scan_pairing(
        &self,
        qr_payload: &str,
        relay: &dyn RelayTransport,
    ) -> Result<TrustedSession> {
        let (device, state, vault, view) = self.unlocked_snapshot()?;
        let me = view
            .member(&device.device_id)
            .ok_or(VaultError::Forbidden("not a member"))?;
        if !view.is_active_approver(&device.device_id) {
            return Err(VaultError::Forbidden(
                "only trusted devices can approve pairing",
            ));
        }
        TrustedSession::scan(
            qr_payload,
            vault.identity().clone(),
            me.device_public(),
            state.vault_id.clone(),
            relay,
        )
        .await
    }

    /// Trusted side: after the user confirmed the SAS on this device
    /// (`session.confirm()` / `confirm_code()`), write the member record + manifest and
    /// send `pairing.welcome`. `share_storage_secret` passes the storage access secret
    /// end-to-end encrypted to a new **member** (never to executors).
    ///
    /// A new trusted device joins as **owner** when this device is an owner (a personal
    /// vault: every device of the user can later revoke a lost one), otherwise as member;
    /// use [`VaultClient::confirm_pairing_with_role`] to choose explicitly.
    pub async fn confirm_pairing(
        &self,
        session: &mut TrustedSession,
        relay: &dyn RelayTransport,
        share_storage_secret: bool,
    ) -> Result<DeviceInfo> {
        let role = match session.offered_role() {
            PairingRole::Executor => MemberRole::Executor,
            PairingRole::Member => {
                let me = self.device_id().ok_or(VaultError::NoVault)?;
                let owner = self
                    .lock_inner()
                    .view
                    .as_ref()
                    .is_some_and(|v| v.is_active_owner(&me));
                if owner {
                    MemberRole::Owner
                } else {
                    MemberRole::Member
                }
            }
        };
        self.confirm_pairing_with_role(session, relay, share_storage_secret, role)
            .await
    }

    /// [`VaultClient::confirm_pairing`] with an explicit role for a new trusted device
    /// (`owner` or `member`; executors always get `executor`).
    pub async fn confirm_pairing_with_role(
        &self,
        session: &mut TrustedSession,
        relay: &dyn RelayTransport,
        share_storage_secret: bool,
        role: MemberRole,
    ) -> Result<DeviceInfo> {
        if !session.is_confirmed() {
            return Err(VaultError::PreconditionFailed(
                "confirm the matching code on this device first",
            ));
        }
        let mut peer = session
            .peer()
            .cloned()
            .ok_or(VaultError::PreconditionFailed(
                "the new device has not joined",
            ))?;
        peer.role = match (peer.role, role) {
            (MemberRole::Executor, _) => MemberRole::Executor,
            (_, MemberRole::Executor) => {
                return Err(VaultError::InvalidInput(
                    "a trusted device cannot be enrolled as an executor",
                ));
            }
            (_, r) => r,
        };
        let _op = self.op.lock().await;
        let (device, state, mut vault, view) = self.unlocked_snapshot()?;
        let engine = self
            .engine_for(&state, Self::ctx_for(&device, &vault, &state.vault_id))
            .await;
        let mut planner = AddMemberPlanner::new(peer.clone());
        let out = engine.commit(&view, &mut vault, &mut planner).await?;
        let rec = planner
            .record
            .clone()
            .ok_or(VaultError::Internal("member record missing"))?;
        let new_view = out.view.clone();
        self.after_commit(&engine, out.view, vault).await?;
        let trusted: Vec<aipass_types::vault::DevicePublic> = new_view
            .members
            .values()
            .filter(|m| {
                m.status == MemberStatus::Active
                    && m.role.is_trusted_approver()
                    && !is_recovery_member(m)
            })
            .map(|m| m.device_public())
            .collect();
        let storage_secret = if share_storage_secret && peer.role != MemberRole::Executor {
            self.storage_secret(&state.vault_id)?
        } else {
            None
        };
        let inner = PairingWelcomeInner {
            vault_id: state.vault_id.clone(),
            member_rev: rec.record.rev,
            checkpoint: new_view
                .checkpoint()
                .ok_or(VaultError::Internal("no checkpoint"))?,
            storage_profile: StorageProfile {
                credential_ref: None,
                ..state.storage.clone()
            },
            storage_secret,
            relay_base_url: session.offer().relay.clone(),
            trusted_devices: trusted,
        };
        session.send_welcome(relay, &inner).await?;
        Ok(DeviceInfo {
            device_id: peer.device_id.clone(),
            name: peer.name.clone(),
            platform: peer.platform,
            role: peer.role,
            status: MemberStatus::Active,
            is_this_device: false,
            is_recovery_key: false,
            added_by: device.device_id,
            updated_at: rec.record.created_at,
            key_epoch: rec.record.key_epoch,
            sign_pk: aipass_crypto::b64u::encode(peer.sign_pk),
            kem_pk: aipass_crypto::b64u::encode(peer.kem_pk),
        })
    }

    /// New-device side: create this device's identity and the pairing offer (QR).
    pub fn begin_join(&self, device_name: &str, relay_base_url: &str) -> Result<NewDeviceSession> {
        if self.has_vault() {
            return Err(VaultError::AlreadyExists);
        }
        let identity = DeviceIdentity::generate();
        let device_id = DeviceId::generate();
        let dp = device_public(
            &device_id,
            &identity,
            device_name.trim(),
            self.cfg.platform,
            MemberRole::Member,
        );
        NewDeviceSession::start(dp, identity, PairingRole::Member, relay_base_url)
    }

    /// New-device side: after `pairing.welcome`, verify `vault.json`, the whole member
    /// chain and the welcome checkpoint from storage, then install the vault locally.
    pub async fn complete_join(
        &self,
        session: &NewDeviceSession,
        welcome: PairingWelcomeInner,
        storage_secret: Option<SecretString>,
    ) -> Result<()> {
        let _op = self.op.lock().await;
        if self.has_vault() {
            return Err(VaultError::AlreadyExists);
        }
        let device = session.device().clone();
        let identity = session.identity().clone();
        let secret = welcome.storage_secret.clone().or(storage_secret);
        let ctx = StoreContext {
            vault_id: welcome.vault_id.clone(),
            device_id: Some(device.device_id.clone()),
            identity: Some(identity.clone()),
        };
        let remote = self
            .factory
            .open(&welcome.storage_profile, secret.as_ref(), &ctx)
            .await?;
        let engine = SyncEngine::new(remote, self.cache_store(), welcome.vault_id.clone());
        let g = engine.genesis_view().await?;
        let (view, _) = engine.pull(&g).await?;
        // the chain must contain the checkpoint the trusted device saw
        if view.seq() < welcome.checkpoint.seq {
            return Err(VaultError::Rollback(
                "storage is older than the trusted device's checkpoint",
            ));
        }
        let mb = FileStore::new(self.cfg.data_dir.join("cache"));
        let at = mb
            .get(&keys::manifest(welcome.checkpoint.seq))
            .await?
            .ok_or(VaultError::Integrity("checkpoint manifest missing"))?;
        if aipass_types::vault::object_hash(&at.bytes) != welcome.checkpoint.hash {
            return Err(VaultError::Rollback(
                "storage does not match the trusted device's checkpoint",
            ));
        }
        let rec = view.member(&device.device_id).ok_or(VaultError::Integrity(
            "this device's member record is missing",
        ))?;
        if rec.rev < welcome.member_rev
            || rec.status != MemberStatus::Active
            || rec.sign_pk != device.sign_pk
            || !rec.role.is_trusted_approver()
        {
            return Err(VaultError::Integrity(
                "this device's member record does not match the pairing",
            ));
        }
        let role = rec.role;
        let mut profile = welcome.storage_profile.clone();
        profile.credential_ref = None;
        self.install_joined(
            &engine,
            view,
            device.device_id.clone(),
            identity,
            role,
            &device.name,
            profile,
            secret,
        )
        .await?;
        let mut st = self.snapshot()?.1;
        st.relay_base_url = Some(welcome.relay_base_url.clone());
        self.save_state(&st)?;
        self.lock_inner().state = Some(st);
        Ok(())
    }
}

fn rotation_reason() -> Localized {
    Localized::new(
        "已撤销的设备可能读取过此凭证，建议在对应服务上更换密码或 Key",
        "A revoked device may have read this credential; consider changing it at the service.",
    )
}

/// Executor principal of a member device id (re-export for convenience).
pub fn executor_principal(device: &DeviceId) -> ExecutorId {
    member_executor_id(device)
}
