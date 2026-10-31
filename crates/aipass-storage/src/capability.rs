// SPDX-License-Identifier: Apache-2.0
//! Storage capability test (CONTRACTS §3.1, design doc §10.1–§10.2, A15).
//!
//! Exercises read, write, binary roundtrip, paginated list, conditional create (including
//! a concurrent race), conditional update and delete under a dedicated scratch prefix, then
//! cleans up. A backend is `sync_capable` only when read, write, list, roundtrip,
//! conditional create **and** conditional update all behave correctly; otherwise it is
//! `backup_only` (UI: 仅可备份). Details never contain credentials or object contents.

use serde::{Deserialize, Serialize};

use crate::{ObjectStore, PutCondition, PutOutcome, StorageVerdict};

/// Number of concurrent create-only writers raced against one key.
pub const RACE_WRITERS: usize = 8;

/// Capability test result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityReport {
    /// Objects can be read back.
    pub read: bool,
    /// Objects can be written.
    pub write: bool,
    /// Listing is lexicographic, prefix-filtered and paginates with `start_after`.
    pub list: bool,
    /// `IfAbsent` creates once and refuses afterwards, also under concurrency.
    pub conditional_create: bool,
    /// `IfMatch` succeeds with the current ETag and refuses stale / absent.
    pub conditional_update: bool,
    /// Objects can be deleted.
    pub delete: bool,
    /// Binary content survives unchanged.
    pub roundtrip: bool,
    /// Overall verdict.
    pub verdict: StorageVerdict,
    /// Human-readable step log (no secrets).
    pub details: Vec<String>,
}

impl CapabilityReport {
    /// Verdict rule.
    pub fn compute_verdict(&self) -> StorageVerdict {
        if self.read
            && self.write
            && self.list
            && self.roundtrip
            && self.conditional_create
            && self.conditional_update
        {
            StorageVerdict::SyncCapable
        } else {
            StorageVerdict::BackupOnly
        }
    }
}

fn run_id() -> String {
    // lowercase hex keeps the key within the strict key alphabet
    aipass_crypto::rng::random_array::<8>()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Run the capability test under `scratch_prefix` (e.g. `"_aipass_captest"`).
pub async fn capability_test(store: &dyn ObjectStore, scratch_prefix: &str) -> CapabilityReport {
    let mut r = CapabilityReport {
        read: false,
        write: false,
        list: false,
        conditional_create: false,
        conditional_update: false,
        delete: false,
        roundtrip: false,
        verdict: StorageVerdict::BackupOnly,
        details: Vec::new(),
    };
    let desc = store.describe();
    r.details.push(format!(
        "backend: {}{}",
        desc.kind,
        desc.endpoint
            .as_deref()
            .map(|e| format!(" ({e})"))
            .unwrap_or_default()
    ));
    let base = format!("{}/{}", scratch_prefix.trim_end_matches('/'), run_id());
    let mut created: Vec<String> = Vec::new();

    // 1. write + read + roundtrip (all 256 byte values, repeated)
    let k_probe = format!("{base}/probe.bin");
    let payload: Vec<u8> = (0..4096u32).map(|i| (i % 256) as u8).collect();
    match store
        .put(&k_probe, payload.clone(), PutCondition::None)
        .await
    {
        Ok(PutOutcome::Written { .. }) => {
            r.write = true;
            created.push(k_probe.clone());
            r.details.push("write: ok".into());
        }
        Ok(PutOutcome::PreconditionFailed) => r
            .details
            .push("write: unconditional write was refused".into()),
        Err(e) => r.details.push(format!("write: failed ({e})")),
    }
    if r.write {
        match store.get(&k_probe).await {
            Ok(Some(o)) => {
                r.read = true;
                r.roundtrip = o.bytes == payload;
                r.details.push(if r.roundtrip {
                    "read: ok, binary roundtrip ok".into()
                } else {
                    "read: ok, but content changed".into()
                });
            }
            Ok(None) => r.details.push("read: object written but not found".into()),
            Err(e) => r.details.push(format!("read: failed ({e})")),
        }
        match store.get(&format!("{base}/missing.bin")).await {
            Ok(None) => {}
            Ok(Some(_)) => {
                r.read = false;
                r.details
                    .push("read: missing object returned content".into());
            }
            Err(e) => {
                r.read = false;
                r.details
                    .push(format!("read: missing object errored ({e})"));
            }
        }
    }

    // 2. list with pagination
    if r.write {
        let names = ["list-a.json", "list-b.json", "list-c.json"];
        let mut ok = true;
        for n in names {
            let k = format!("{base}/l/{n}");
            match store.put(&k, b"{}".to_vec(), PutCondition::None).await {
                Ok(PutOutcome::Written { .. }) => created.push(k),
                _ => ok = false,
            }
        }
        if ok {
            let prefix = format!("{base}/l/");
            let first = store.list(&prefix, None, 2).await;
            let rest = match &first {
                Ok(p) if p.len() == 2 => store.list(&prefix, Some(&p[1].key), 10).await.map(Some),
                _ => Ok(None),
            };
            match (first, rest) {
                (Ok(p1), Ok(Some(p2))) => {
                    let keys: Vec<String> =
                        p1.iter().chain(p2.iter()).map(|m| m.key.clone()).collect();
                    let expected: Vec<String> =
                        names.iter().map(|n| format!("{prefix}{n}")).collect();
                    r.list = keys == expected
                        && p1
                            .iter()
                            .chain(p2.iter())
                            .all(|m| m.size == 2 && !m.etag.is_empty());
                    r.details.push(if r.list {
                        "list: ok (ordered, paginated)".into()
                    } else {
                        format!("list: unexpected result ({} keys)", keys.len())
                    });
                }
                (Ok(p1), Ok(None)) => r.details.push(format!(
                    "list: first page returned {} keys, expected 2",
                    p1.len()
                )),
                (Err(e), _) | (_, Err(e)) => r.details.push(format!("list: failed ({e})")),
            }
        } else {
            r.details.push("list: could not write list probes".into());
        }
    }

    // 3. conditional create, including a concurrent race
    if r.write {
        let k = format!("{base}/create.json");
        let first = store
            .put(&k, b"first".to_vec(), PutCondition::IfAbsent)
            .await;
        let second = store
            .put(&k, b"second".to_vec(), PutCondition::IfAbsent)
            .await;
        let content = store.get(&k).await;
        let mut ok = matches!(first, Ok(PutOutcome::Written { .. }))
            && matches!(second, Ok(PutOutcome::PreconditionFailed))
            && matches!(&content, Ok(Some(o)) if o.bytes == b"first");
        if matches!(first, Ok(PutOutcome::Written { .. })) {
            created.push(k.clone());
        }
        if !ok {
            r.details
                .push("conditional create: second create-only write was not refused".into());
        }
        let race_key = format!("{base}/race.json");
        let futs = (0..RACE_WRITERS).map(|i| {
            let k = race_key.clone();
            async move {
                store
                    .put(
                        &k,
                        format!("writer-{i}").into_bytes(),
                        PutCondition::IfAbsent,
                    )
                    .await
            }
        });
        let results = futures::future::join_all(futs).await;
        let winners = results
            .iter()
            .filter(|r| matches!(r, Ok(PutOutcome::Written { .. })))
            .count();
        let errors = results.iter().filter(|r| r.is_err()).count();
        if winners > 0 {
            created.push(race_key.clone());
        }
        if winners != 1 || errors != 0 {
            ok = false;
            r.details.push(format!("conditional create race: {winners} of {RACE_WRITERS} writers succeeded, {errors} errors (expected exactly 1)"));
        }
        r.conditional_create = ok;
        if ok {
            r.details
                .push("conditional create: ok (incl. concurrent race)".into());
        }
    }

    // 4. conditional update
    if r.write {
        let k = format!("{base}/update.json");
        match store.put(&k, b"v1".to_vec(), PutCondition::None).await {
            Ok(PutOutcome::Written { etag: e1 }) => {
                created.push(k.clone());
                let up = store
                    .put(&k, b"v2".to_vec(), PutCondition::IfMatch(e1.clone()))
                    .await;
                let stale = store
                    .put(&k, b"v3".to_vec(), PutCondition::IfMatch(e1.clone()))
                    .await;
                let absent = store
                    .put(
                        &format!("{base}/absent.json"),
                        b"x".to_vec(),
                        PutCondition::IfMatch(e1.clone()),
                    )
                    .await;
                let content = store.get(&k).await;
                let ok = matches!(&up, Ok(PutOutcome::Written { etag }) if *etag != e1)
                    && matches!(stale, Ok(PutOutcome::PreconditionFailed))
                    && matches!(absent, Ok(PutOutcome::PreconditionFailed))
                    && matches!(&content, Ok(Some(o)) if o.bytes == b"v2");
                if matches!(absent, Ok(PutOutcome::Written { .. })) {
                    created.push(format!("{base}/absent.json"));
                }
                r.conditional_update = ok;
                r.details.push(if ok {
                    "conditional update: ok".into()
                } else {
                    "conditional update: stale or absent If-Match was not refused".into()
                });
            }
            Ok(PutOutcome::PreconditionFailed) => r
                .details
                .push("conditional update: setup write refused".into()),
            Err(e) => r.details.push(format!("conditional update: failed ({e})")),
        }
    }

    // 5. delete (also cleanup)
    let mut delete_ok = !created.is_empty();
    for k in &created {
        if store.delete(k).await.is_err() {
            delete_ok = false;
        }
    }
    if delete_ok {
        match store.get(&k_probe).await {
            Ok(None) => {}
            _ => delete_ok = false,
        }
    }
    r.delete = delete_ok;
    r.details.push(if delete_ok {
        "delete: ok (scratch objects removed)".into()
    } else {
        "delete: failed or not verified; scratch objects may remain".into()
    });

    r.verdict = r.compute_verdict();
    r.details.push(match r.verdict {
        StorageVerdict::SyncCapable => "verdict: sync_capable (加密同步可用)".into(),
        StorageVerdict::BackupOnly => "verdict: backup_only (仅可备份)".into(),
    });
    r
}
