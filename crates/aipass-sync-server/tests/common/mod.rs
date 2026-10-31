// SPDX-License-Identifier: Apache-2.0
//! Test fixtures: real signed vault objects, an in-process server (sync + relay routers on
//! 127.0.0.1:0) and helpers. Servers live inside the test runtime and stop with it.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use aipass_crypto::{DeviceIdentity, SecretString};
use aipass_storage::http::DeviceSigner;
use aipass_storage::{HttpSyncStore, MemoryStore, ObjectStore};
use aipass_sync_server::relay::{
    MemoryRelayStore, PushNotifier, RelayDirectory, RelayStore, SyncDirectory,
};
use aipass_sync_server::sync::{EnrollTokenAdmission, QuotaPolicy, StaticQuota};
use aipass_sync_server::{
    Clock, ManualClock, RelayConfig, RelayState, SyncConfig, SyncState, relay_router, sync_router,
};
use aipass_types::ids::{DeviceId, EntryId, ExecutorId, PrincipalId, VaultId};
use aipass_types::relay::PushHint;
use aipass_types::vault::{
    EntryVersion, Manifest, ManifestEntry, ManifestMember, MemberRecord, MemberRole, MemberStatus,
    Platform, SignedObject, VaultHeader, keys, object_hash,
};
use async_trait::async_trait;

pub struct Device {
    pub id: DeviceId,
    pub ident: Arc<DeviceIdentity>,
}

impl Device {
    pub fn new() -> Self {
        Self {
            id: DeviceId::generate(),
            ident: Arc::new(DeviceIdentity::generate()),
        }
    }

    /// An executor: member id `dev_U` and executor principal `exe_U` share the ULID.
    pub fn executor_principal(&self) -> PrincipalId {
        let (_, u) = aipass_types::ids::split(self.id.as_str()).unwrap();
        PrincipalId::Executor(ExecutorId::parse(&format!("exe_{u}")).unwrap())
    }

    pub fn principal(&self) -> PrincipalId {
        PrincipalId::Device(self.id.clone())
    }

    pub fn signer(&self) -> DeviceSigner {
        self.ident.clone()
    }

    pub fn sign_pk(&self) -> [u8; 32] {
        self.ident.public().sign_pk
    }

    pub fn kem_pk(&self) -> [u8; 32] {
        self.ident.public().kem_pk
    }
}

pub fn now() -> aipass_types::Timestamp {
    aipass_types::time::now()
}

pub fn header_bytes(vault: &VaultId, genesis: &Device) -> Vec<u8> {
    let mut h = VaultHeader {
        format: 1,
        vault_id: vault.clone(),
        created_at: now(),
        genesis_device_id: genesis.id.clone(),
        signature: String::new(),
    };
    h.sign_with(genesis.ident.as_ref()).unwrap();
    serde_json::to_vec(&h).unwrap()
}

pub fn member(
    vault: &VaultId,
    dev: &Device,
    rev: u64,
    role: MemberRole,
    status: MemberStatus,
    signer: &Device,
) -> MemberRecord {
    let mut m = MemberRecord {
        format: 1,
        vault_id: vault.clone(),
        device_id: dev.id.clone(),
        rev,
        name: "Test device".into(),
        platform: if role == MemberRole::Executor {
            Platform::Node
        } else {
            Platform::Cli
        },
        role,
        sign_pk: dev.sign_pk(),
        kem_pk: dev.kem_pk(),
        status,
        key_epoch: 1,
        // owners/members carry a (dummy) VMK wrap so the record can be listed in a manifest
        wrapped_vmk: (role != MemberRole::Executor && status == MemberStatus::Active).then(|| {
            aipass_crypto::SealedBox {
                enc: vec![7; 32],
                ct: vec![8; 48],
            }
        }),
        added_by: signer.id.clone(),
        created_at: now(),
        signature: String::new(),
    };
    m.sign_with(signer.ident.as_ref()).unwrap();
    m
}

/// Canonical (JCS) bytes, as clients store them (the manifest lists their hash).
pub fn member_bytes(m: &MemberRecord) -> Vec<u8> {
    aipass_vault::encoding::object_bytes(m).unwrap()
}

pub fn manifest(vault: &VaultId, seq: u64, author: &Device, note: &str) -> Vec<u8> {
    let e = EntryId::generate();
    let mut m = Manifest {
        format: 1,
        vault_id: vault.clone(),
        seq,
        prev_hash: if seq == 1 {
            String::new()
        } else {
            format!("prev-{note}")
        },
        key_epoch: 1,
        entries: BTreeMap::from([(
            e,
            ManifestEntry {
                version: 1,
                hash: aipass_crypto::sha256_b64u(note.as_bytes()),
                conflict_versions: vec![],
            },
        )]),
        tombstones: BTreeMap::new(),
        members: BTreeMap::new(),
        author_device_id: author.id.clone(),
        created_at: now(),
        signature: String::new(),
    };
    m.sign_with(author.ident.as_ref()).unwrap();
    serde_json::to_vec(&m).unwrap()
}

pub fn entry(vault: &VaultId, entry_id: &EntryId, version: u64, author: &Device) -> Vec<u8> {
    let e = EntryVersion {
        format: 1,
        vault_id: vault.clone(),
        entry_id: entry_id.clone(),
        version,
        key_epoch: 1,
        dek_nonce: [1; 24],
        wrapped_dek: vec![2; 48],
        nonce: [3; 24],
        ciphertext: vec![4; 100],
        author_device_id: author.id.clone(),
        created_at: now(),
    };
    serde_json::to_vec(&e).unwrap()
}

/// Records every push hint as raw JSON (to prove the payload is minimal).
#[derive(Default)]
pub struct RecordingPush {
    pub hints: Mutex<Vec<serde_json::Value>>,
    pub notify: tokio::sync::Notify,
}

#[async_trait]
impl PushNotifier for RecordingPush {
    async fn notify(&self, hint: PushHint) {
        self.hints
            .lock()
            .unwrap()
            .push(serde_json::to_value(&hint).unwrap());
        self.notify.notify_waiters();
    }
}

pub struct Server {
    pub addr: SocketAddr,
    pub base: url::Url,
    pub sync: SyncState,
    pub relay: RelayState,
    pub blobs: Arc<MemoryStore>,
    pub admission: Arc<EnrollTokenAdmission>,
    pub clock: Arc<ManualClock>,
    pub push: Arc<RecordingPush>,
}

pub struct Options {
    pub quota: Arc<dyn QuotaPolicy>,
    pub relay_store: Arc<dyn RelayStore>,
    pub relay_cfg: RelayConfig,
    pub sync_cfg: SyncConfig,
    pub directory: Option<Arc<dyn RelayDirectory>>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            quota: Arc::new(StaticQuota::unlimited()),
            relay_store: Arc::new(MemoryRelayStore::new()),
            relay_cfg: RelayConfig::default(),
            sync_cfg: SyncConfig::default(),
            directory: None,
        }
    }
}

pub async fn start(opts: Options) -> Server {
    let blobs = Arc::new(MemoryStore::new());
    let clock = Arc::new(ManualClock::starting_now());
    let admission = Arc::new(EnrollTokenAdmission::with_clock(clock.clone()));
    let sync = SyncState::builder(blobs.clone(), admission.clone())
        .quota(opts.quota)
        .clock(clock.clone())
        .config(opts.sync_cfg)
        .build();
    let push = Arc::new(RecordingPush::default());
    let directory = opts
        .directory
        .unwrap_or_else(|| Arc::new(SyncDirectory::new(sync.clone())));
    let relay = RelayState::builder(opts.relay_store, directory)
        .push(push.clone())
        .clock(clock.clone())
        .nonce_cache(sync.nonce_cache())
        .config(opts.relay_cfg)
        .build();
    let app = axum::Router::new()
        .merge(sync_router(sync.clone()))
        .merge(relay_router(relay.clone()));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await;
    });
    let _ = clock.now();
    Server {
        addr,
        base: url::Url::parse(&format!("http://{addr}/")).unwrap(),
        sync,
        relay,
        blobs,
        admission,
        clock,
        push,
    }
}

pub fn http() -> reqwest::Client {
    reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(60))
        .build()
        .unwrap()
}

impl Server {
    pub fn token(&self) -> SecretString {
        self.admission.generate(Some(1), None).unwrap()
    }

    /// Create a vault with `genesis` as owner; returns the vault id.
    pub async fn create_vault(&self, genesis: &Device) -> VaultId {
        let vault = VaultId::generate();
        let h = header_bytes(&vault, genesis);
        let g = member(
            &vault,
            genesis,
            1,
            MemberRole::Owner,
            MemberStatus::Active,
            genesis,
        );
        HttpSyncStore::create_vault(
            &http(),
            &self.base,
            &self.token(),
            &h,
            &member_bytes(&g),
            false,
        )
        .await
        .unwrap();
        vault
    }

    pub fn store_for(&self, vault: &VaultId, dev: &Device) -> HttpSyncStore {
        self.store_as(vault, dev.principal(), dev)
    }

    pub fn store_as(&self, vault: &VaultId, kid: PrincipalId, dev: &Device) -> HttpSyncStore {
        HttpSyncStore::with_client(
            self.base.clone(),
            vault.clone(),
            kid,
            dev.signer(),
            http(),
            false,
        )
        .unwrap()
    }

    /// Build the next **valid** manifest of `vault` signed by `author` (it must be an
    /// active owner/member of the latest manifest): the latest manifest's members plus
    /// `add` (records already uploaded) and one new entry hash. Returns `(seq, bytes)`.
    pub async fn next_manifest(
        &self,
        vault: &VaultId,
        author: &Device,
        add: &[&MemberRecord],
        note: &str,
    ) -> (u64, Vec<u8>) {
        self.next_manifest_epoch(vault, author, add, note, None)
            .await
    }

    /// [`Server::next_manifest`] with an explicit key epoch (rotation).
    pub async fn next_manifest_epoch(
        &self,
        vault: &VaultId,
        author: &Device,
        add: &[&MemberRecord],
        note: &str,
        epoch: Option<u32>,
    ) -> (u64, Vec<u8>) {
        let ns = format!("vaults/{vault}/");
        let blobs: Arc<dyn ObjectStore> = self.blobs.clone();
        let metas = aipass_storage::list_all(blobs.as_ref(), &format!("{ns}manifests/"))
            .await
            .unwrap();
        let latest = metas
            .iter()
            .filter_map(|m| {
                Some((
                    keys::parse_manifest(m.key.strip_prefix(&ns)?)?,
                    m.key.clone(),
                ))
            })
            .max();
        let (seq, prev_hash, mut members, key_epoch, mut entries, tombstones) = match latest {
            Some((seq, k)) => {
                let b = blobs.get(&k).await.unwrap().unwrap().bytes;
                let m: Manifest = serde_json::from_slice(&b).unwrap();
                (
                    seq,
                    object_hash(&b),
                    m.members,
                    m.key_epoch,
                    m.entries,
                    m.tombstones,
                )
            }
            None => {
                let hb = blobs
                    .get(&format!("{ns}{}", keys::VAULT_HEADER))
                    .await
                    .unwrap()
                    .unwrap()
                    .bytes;
                let h: VaultHeader = serde_json::from_slice(&hb).unwrap();
                let gb = blobs
                    .get(&format!("{ns}{}", keys::member(&h.genesis_device_id, 1)))
                    .await
                    .unwrap()
                    .unwrap()
                    .bytes;
                let members = BTreeMap::from([(
                    h.genesis_device_id.clone(),
                    ManifestMember {
                        rev: 1,
                        hash: object_hash(&gb),
                        status: MemberStatus::Active,
                        role: MemberRole::Owner,
                    },
                )]);
                (
                    0,
                    String::new(),
                    members,
                    1,
                    BTreeMap::new(),
                    BTreeMap::new(),
                )
            }
        };
        for r in add {
            members.insert(
                r.device_id.clone(),
                ManifestMember {
                    rev: r.rev,
                    hash: object_hash(&member_bytes(r)),
                    status: r.status,
                    role: r.role,
                },
            );
        }
        entries.insert(
            EntryId::generate(),
            ManifestEntry {
                version: 1,
                hash: aipass_crypto::sha256_b64u(note.as_bytes()),
                conflict_versions: vec![],
            },
        );
        let mut m = Manifest {
            format: 1,
            vault_id: vault.clone(),
            seq: seq + 1,
            prev_hash,
            key_epoch: epoch.unwrap_or(key_epoch),
            entries,
            tombstones,
            members,
            author_device_id: author.id.clone(),
            created_at: now(),
            signature: String::new(),
        };
        m.sign_with(author.ident.as_ref()).unwrap();
        (seq + 1, serde_json::to_vec(&m).unwrap())
    }

    /// Upload the next valid manifest (see [`Server::next_manifest`]) as `author`.
    pub async fn commit(&self, vault: &VaultId, author: &Device, add: &[&MemberRecord]) -> u64 {
        let (seq, bytes) = self.next_manifest(vault, author, add, "commit").await;
        let out = self
            .store_for(vault, author)
            .put(
                &keys::manifest(seq),
                bytes,
                aipass_storage::PutCondition::IfAbsent,
            )
            .await
            .unwrap();
        assert!(
            matches!(out, aipass_storage::PutOutcome::Written { .. }),
            "commit failed"
        );
        seq
    }

    /// Add `dev` to `vault` (record signed by `by`, uploaded by `by`); returns the record.
    pub async fn add_member(
        &self,
        vault: &VaultId,
        dev: &Device,
        rev: u64,
        role: MemberRole,
        status: MemberStatus,
        by: &Device,
    ) -> MemberRecord {
        let m = member(vault, dev, rev, role, status, by);
        let s = self.store_for(vault, by);
        let out = s
            .put(
                &keys::member(&dev.id, rev),
                member_bytes(&m),
                aipass_storage::PutCondition::IfAbsent,
            )
            .await
            .unwrap();
        assert!(
            matches!(out, aipass_storage::PutOutcome::Written { .. }),
            "add member failed"
        );
        m
    }

    pub async fn raw_blob_count(&self) -> usize {
        self.blobs.len().await
    }

    pub fn blob_store(&self) -> Arc<dyn ObjectStore> {
        self.blobs.clone()
    }
}
