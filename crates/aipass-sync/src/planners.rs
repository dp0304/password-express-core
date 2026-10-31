// SPDX-License-Identifier: Apache-2.0
//! Commit planners: outbox application with rebase + 3-way merge, member changes, key
//! rotation and conflict resolution. Every planner rebuilds its changes from the view it
//! is given, so it can be re-run after a lost race.

use aipass_types::ids::{DeviceId, EntryId};
use aipass_types::vault::{DevicePublic, EntryPayload};
use aipass_vault::manifest::ManifestDraft;
use aipass_vault::member::SignedMember;
use aipass_vault::vault::{stage_add_member, stage_replace_recovery_key, stage_revocation};
use aipass_vault::{PendingEpoch, RecoveryKey, Result, VaultError};
use async_trait::async_trait;

use crate::engine::{CommitPlanner, PlanContext};
use crate::merge::merge3;
use crate::outbox::{ChangeOp, PendingChange};

/// What applying the outbox did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ApplyReport {
    /// Changes written (or already satisfied).
    pub applied: Vec<EntryId>,
    /// Entries where a secret-bearing field conflicted (local version kept as a conflict
    /// version; automatic use paused).
    pub conflicts: Vec<EntryId>,
    /// Edits refused because the entry was deleted elsewhere: `(entry, tombstone version)`.
    pub rejected: Vec<(EntryId, u64)>,
    /// Deletes skipped because the entry was edited elsewhere (the edit wins; no data loss).
    pub delete_skipped: Vec<EntryId>,
}

/// Applies pending outbox changes.
pub struct OutboxPlanner {
    changes: Vec<PendingChange>,
    /// Result of the last (committed) plan.
    pub report: ApplyReport,
}

impl OutboxPlanner {
    /// Planner for `changes`.
    pub fn new(changes: Vec<PendingChange>) -> Self {
        Self {
            changes,
            report: ApplyReport::default(),
        }
    }
}

fn write_current(
    ctx: &PlanContext<'_>,
    draft: &mut ManifestDraft,
    id: &EntryId,
    payload: &EntryPayload,
    conflicts: Vec<u64>,
) -> Result<u64> {
    let v = draft.next_version(id);
    let sealed = ctx.vault.encrypt_entry(id, v, payload, &ctx.now)?;
    draft.set_current(&sealed, conflicts);
    Ok(v)
}

#[async_trait]
impl CommitPlanner for OutboxPlanner {
    async fn plan(&mut self, ctx: &PlanContext<'_>, draft: &mut ManifestDraft) -> Result<()> {
        let mut report = ApplyReport::default();
        for ch in &self.changes {
            let id = &ch.entry_id;
            let cur = draft.entries.get(id).cloned();
            let tomb = draft.tombstones.get(id).cloned();
            match &ch.op {
                ChangeOp::Upsert { payload } => {
                    if let Some(t) = tomb {
                        // writes for a tombstoned entry are rejected; restore is explicit
                        report.rejected.push((id.clone(), t.version));
                        continue;
                    }
                    match cur {
                        None => {
                            write_current(ctx, draft, id, payload, Vec::new())?;
                        }
                        Some(ce) if Some(ce.version) == ch.base_version => {
                            write_current(ctx, draft, id, payload, ce.conflict_versions.clone())?;
                        }
                        Some(ce) => {
                            let remote = ctx.payload(id, ce.version).await?;
                            let base = match ch.base_version {
                                Some(b) => ctx.payload(id, b).await?,
                                None => remote.clone(),
                            };
                            let m = merge3(&base, payload, &remote);
                            let mut conflicts = ce.conflict_versions.clone();
                            if m.merged != remote {
                                write_current(ctx, draft, id, &m.merged, conflicts.clone())?;
                            }
                            if m.secret_conflict {
                                let v = draft.next_version(id);
                                let sealed = ctx.vault.encrypt_entry(id, v, payload, &ctx.now)?;
                                draft.add_version_object(&sealed);
                                conflicts.push(v);
                                draft.set_conflicts(id, conflicts)?;
                                report.conflicts.push(id.clone());
                            }
                        }
                    }
                    report.applied.push(id.clone());
                }
                ChangeOp::Delete => {
                    if tomb.is_some() {
                        report.applied.push(id.clone());
                        continue;
                    }
                    match cur {
                        None => report.applied.push(id.clone()),
                        Some(ce) if ch.base_version.is_none_or(|b| b == ce.version) => {
                            draft.tombstone(id, &ctx.now)?;
                            report.applied.push(id.clone());
                        }
                        Some(_) => report.delete_skipped.push(id.clone()),
                    }
                }
                ChangeOp::Restore { payload } => {
                    let conflicts = cur.map(|c| c.conflict_versions).unwrap_or_default();
                    // next_version is above the tombstone version → explicit restore
                    write_current(ctx, draft, id, payload, conflicts)?;
                    report.applied.push(id.clone());
                }
            }
        }
        self.report = report;
        Ok(())
    }
}

/// Adds a member (pairing confirmed on this trusted device).
pub struct AddMemberPlanner {
    device: DevicePublic,
    /// The committed member record.
    pub record: Option<SignedMember>,
}

impl AddMemberPlanner {
    /// Planner for `device`.
    pub fn new(device: DevicePublic) -> Self {
        Self {
            device,
            record: None,
        }
    }
}

#[async_trait]
impl CommitPlanner for AddMemberPlanner {
    async fn plan(&mut self, ctx: &PlanContext<'_>, draft: &mut ManifestDraft) -> Result<()> {
        self.record = Some(stage_add_member(
            ctx.vault,
            ctx.view,
            draft,
            &self.device,
            &ctx.now,
        )?);
        Ok(())
    }
}

/// Revokes a device (+ key rotation for owners/members).
pub struct RevokePlanner {
    target: DeviceId,
    /// Epoch to install after a successful commit.
    pub pending: Option<PendingEpoch>,
}

impl RevokePlanner {
    /// Planner for `target`.
    pub fn new(target: DeviceId) -> Self {
        Self {
            target,
            pending: None,
        }
    }
}

#[async_trait]
impl CommitPlanner for RevokePlanner {
    async fn plan(&mut self, ctx: &PlanContext<'_>, draft: &mut ManifestDraft) -> Result<()> {
        self.pending = stage_revocation(ctx.vault, ctx.view, draft, &self.target, &ctx.now)?;
        Ok(())
    }
}

/// Replaces the recovery key (revokes the old recovery member with rotation).
pub struct ReplaceRecoveryPlanner {
    key: RecoveryKey,
    /// Epoch to install after a successful commit.
    pub pending: Option<PendingEpoch>,
}

impl ReplaceRecoveryPlanner {
    /// Planner for `key`.
    pub fn new(key: RecoveryKey) -> Self {
        Self { key, pending: None }
    }
}

#[async_trait]
impl CommitPlanner for ReplaceRecoveryPlanner {
    async fn plan(&mut self, ctx: &PlanContext<'_>, draft: &mut ManifestDraft) -> Result<()> {
        self.pending = stage_replace_recovery_key(ctx.vault, ctx.view, draft, &self.key, &ctx.now)?;
        Ok(())
    }
}

/// Resolves a conflict by keeping one version (written as a new current version, conflict
/// list cleared). Fails if the entry changed since the user looked at it.
pub struct ResolvePlanner {
    entry: EntryId,
    keep_version: u64,
    expected_version: u64,
    expected_conflicts: Vec<u64>,
}

impl ResolvePlanner {
    /// Planner.
    pub fn new(
        entry: EntryId,
        keep_version: u64,
        expected_version: u64,
        expected_conflicts: Vec<u64>,
    ) -> Self {
        Self {
            entry,
            keep_version,
            expected_version,
            expected_conflicts,
        }
    }
}

#[async_trait]
impl CommitPlanner for ResolvePlanner {
    async fn plan(&mut self, ctx: &PlanContext<'_>, draft: &mut ManifestDraft) -> Result<()> {
        let ce = draft
            .entries
            .get(&self.entry)
            .cloned()
            .ok_or(VaultError::NotFound("entry"))?;
        if ce.version != self.expected_version || ce.conflict_versions != self.expected_conflicts {
            return Err(VaultError::PreconditionFailed(
                "the entry changed on another device; review the versions again",
            ));
        }
        if ce.conflict_versions.is_empty() {
            return Ok(());
        }
        if self.keep_version != ce.version && !ce.conflict_versions.contains(&self.keep_version) {
            return Err(VaultError::InvalidInput(
                "version is not part of this conflict",
            ));
        }
        let mut payload = ctx.payload(&self.entry, self.keep_version).await?;
        payload.updated_at = ctx.now;
        write_current(ctx, draft, &self.entry, &payload, Vec::new())?;
        Ok(())
    }
}
