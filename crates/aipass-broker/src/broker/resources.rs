// SPDX-License-Identifier: Apache-2.0
//! Projects and resources. Resources never contain secrets — the credential is a vault
//! entry reference, and configs are scanned for credential-looking material on write.

use std::sync::Arc;

use aipass_types::error::{ApiError, Lang};
use aipass_types::exec::{OperationSpec, Stage};
use aipass_types::ids::{EntryId, ProjectId, ResourceId};
use aipass_types::models::{
    AdminResourcesResponse, CreateProjectRequest, ExecutorStatus, OperationView, Project,
    ProjectsResponse, ProtectionLevel, Resource, ResourceInput, ResourcePatch, ResourceStatus,
    ResourceView, ResourcesResponse, RevocationLevel,
};
use serde_json::{Value, json};

use super::{Broker, ExecutorSlot};
use crate::audit::{self, Audit};
use crate::db::{enum_str, unix};
use crate::principal::{Actor, ConnectionPrincipal};
use crate::redact::config_contains_secret;
use crate::store::{self, ResourceRow};
use crate::types::EntryConflictResponse;

fn bounded_text(field: &str, v: &str, max: usize) -> Result<String, ApiError> {
    let t = v.trim();
    if t.is_empty() || t.chars().count() > max || t.chars().any(char::is_control) {
        return Err(ApiError::invalid_request(
            format!("{field} 长度必须为 1 到 {max} 个可打印字符"),
            format!("{field} must be 1 to {max} printable characters"),
        )
        .with_detail("field", field.to_owned()));
    }
    Ok(t.to_owned())
}

impl Broker {
    pub(crate) fn stage_allowed(&self, s: Stage) -> bool {
        s == Stage::V1 || self.cfg.experimental
    }

    /// Specs of `connector` offered by the executor, filtered by stage.
    pub(crate) fn specs_for(&self, slot: &ExecutorSlot, connector: &str) -> Vec<OperationSpec> {
        slot.backend
            .operation_specs(connector)
            .into_iter()
            .filter(|s| self.stage_allowed(s.stage))
            .collect()
    }

    /// Displayed status of a resource (conflict / executor state folded in).
    pub(crate) fn effective_status(&self, row: &ResourceRow) -> ResourceStatus {
        let r = &row.resource;
        if r.status == ResourceStatus::Disabled {
            return ResourceStatus::Disabled;
        }
        if row.entry_conflict || r.status == ResourceStatus::SyncConflict {
            return ResourceStatus::SyncConflict;
        }
        match self.executor_slot(&r.executor_id) {
            Some(s) if s.is_online() => {}
            _ => return ResourceStatus::ExecutorOffline,
        }
        r.status
    }

    // ------------------------------------------------------------- projects

    /// `GET /v1/projects`.
    pub async fn list_projects(&self) -> Result<ProjectsResponse, ApiError> {
        let projects = self.db.call(|c| store::list_projects(c)).await?;
        Ok(ProjectsResponse { projects })
    }

    /// `POST /v1/projects`.
    pub async fn create_project(&self, actor: &Actor, req: CreateProjectRequest) -> Result<Project, ApiError> {
        let name = bounded_text("name", &req.name, 100)?;
        let project = Project {
            project_id: ProjectId::generate(),
            name,
        };
        self.import_project_as(actor, project.clone()).await?;
        Ok(project)
    }

    /// Insert or rename a project with a known id (state import / restore).
    pub async fn import_project(&self, project: Project) -> Result<(), ApiError> {
        self.import_project_as(&Actor::Admin, project).await
    }

    async fn import_project_as(&self, actor: &Actor, project: Project) -> Result<(), ApiError> {
        let now = self.now();
        let actor = actor.audit_name();
        self.db
            .call(move |c| {
                let tx = c.transaction()?;
                tx.execute(
                    "INSERT INTO projects (project_id, name, created_at) VALUES (?1, ?2, ?3)
                     ON CONFLICT(project_id) DO UPDATE SET name = excluded.name",
                    rusqlite::params![project.project_id.as_str(), project.name, unix(&now)],
                )?;
                audit::append(
                    &tx,
                    now,
                    Audit::new(actor, "project.created").detail(json!({ "project_id": project.project_id.as_str() })),
                )?;
                tx.commit()?;
                Ok(())
            })
            .await
    }

    // ------------------------------------------------------------- admin resources

    /// `GET /v1/admin/resources` (status reflects conflicts and executor state).
    pub async fn admin_list_resources(&self) -> Result<AdminResourcesResponse, ApiError> {
        let rows = self.db.call(|c| store::list_resources(c)).await?;
        Ok(AdminResourcesResponse {
            resources: rows
                .iter()
                .map(|r| {
                    let mut res = r.resource.clone();
                    res.status = self.effective_status(r);
                    res
                })
                .collect(),
        })
    }

    /// One resource (admin view).
    pub async fn get_resource(&self, id: &ResourceId) -> Result<Resource, ApiError> {
        let id = id.clone();
        let row = self
            .db
            .call(move |c| store::get_resource(c, &id))
            .await?
            .ok_or_else(ApiError::not_found)?;
        let mut r = row.resource.clone();
        r.status = self.effective_status(&row);
        Ok(r)
    }

    fn validate_resource(&self, r: &Resource) -> Result<(), ApiError> {
        if !r.config.is_object() {
            return Err(ApiError::invalid_request("config 必须是对象", "config must be an object").with_detail("field", "config"));
        }
        if config_contains_secret(&r.config) {
            return Err(ApiError::invalid_request(
                "资源配置中不能包含密码、令牌或密钥；凭证请保存在账号库条目中",
                "Resource config must not contain passwords, tokens or keys; keep the credential in a vault entry.",
            )
            .with_detail("field", "config"));
        }
        let slot = self.executor_slot(&r.executor_id).ok_or_else(|| {
            ApiError::invalid_request("执行设备未注册", "The executor is not registered with this broker.")
                .with_detail("field", "executor_id")
        })?;
        let info = slot.backend.info();
        if !info.capabilities.contains(&r.connector) {
            return Err(ApiError::invalid_request("执行设备不支持该连接器", "The executor does not offer this connector.")
                .with_detail("field", "connector"));
        }
        let specs = self.specs_for(&slot, r.connector.as_str());
        if r.operations.is_empty() {
            return Err(ApiError::invalid_request("至少需要一个操作", "At least one operation is required.").with_detail("field", "operations"));
        }
        for op in &r.operations {
            if !specs.iter().any(|s| &s.name == op) {
                return Err(ApiError::invalid_request("连接器不提供该操作", "The connector does not offer this operation.")
                    .with_detail("operation", op.clone()));
            }
        }
        Ok(())
    }

    /// `POST /v1/admin/resources`.
    pub async fn create_resource(&self, actor: &Actor, input: ResourceInput) -> Result<Resource, ApiError> {
        let alias = bounded_text("alias", &input.alias, 100)?;
        let service = bounded_text("service", &input.service, 64)?;
        let operations = match input.operations {
            Some(ops) => {
                let mut ops = ops;
                ops.sort();
                ops.dedup();
                ops
            }
            None => {
                let slot = self.executor_slot(&input.executor_id).ok_or_else(|| {
                    ApiError::invalid_request("执行设备未注册", "The executor is not registered with this broker.")
                        .with_detail("field", "executor_id")
                })?;
                self.specs_for(&slot, input.connector.as_str())
                    .into_iter()
                    .map(|s| s.name)
                    .collect()
            }
        };
        let resource = Resource {
            resource_id: ResourceId::generate(),
            alias,
            service,
            connector: input.connector,
            project_id: input.project_id,
            environment: input.environment,
            config: input.config,
            credential_entry_id: input.credential_entry_id,
            executor_id: input.executor_id,
            operations,
            status: ResourceStatus::Available,
            created_at: self.now(),
        };
        self.validate_resource(&resource)?;
        self.save_resource(actor, &resource, "resource.created", false).await?;
        Ok(resource)
    }

    /// Persist a resource. With `disable_policies`, every standing rule on it is disabled
    /// in the same transaction: a signed rule never silently carries over to a changed
    /// credential, target or executor (A05, design §8.3) — the owner must re-sign.
    async fn save_resource(&self, actor: &Actor, r: &Resource, action: &'static str, disable_policies: bool) -> Result<(), ApiError> {
        let now = self.now();
        let (r, actor) = (r.clone(), actor.audit_name());
        self.db
            .call(move |c| {
                let tx = c.transaction()?;
                if !store::project_exists(&tx, &r.project_id)? {
                    return Err(ApiError::invalid_request("项目不存在", "unknown project").with_detail("field", "project_id").into());
                }
                store::upsert_resource(&tx, &r)?;
                if disable_policies {
                    let n = store::disable_policies(&tx, "resource_id", r.resource_id.as_str(), &now)?;
                    if n > 0 {
                        audit::append(
                            &tx,
                            now,
                            Audit::new(actor.clone(), "policy.disabled")
                                .resource(&r.resource_id)
                                .detail(json!({ "reason": "resource_changed", "count": n })),
                        )?;
                    }
                }
                audit::append(
                    &tx,
                    now,
                    Audit::new(actor, action).resource(&r.resource_id).detail(json!({
                        "connector": r.connector.as_str(),
                        "environment": enum_str(&r.environment),
                        "executor_id": r.executor_id.as_str(),
                        "operations": r.operations,
                        "status": enum_str(&r.status),
                    })),
                )?;
                tx.commit()?;
                Ok(())
            })
            .await
    }

    /// Insert or replace a resource verbatim (state import / restore, tests). Validated
    /// like a create.
    pub async fn import_resource(&self, resource: Resource) -> Result<(), ApiError> {
        self.validate_resource(&resource)?;
        self.save_resource(&Actor::Admin, &resource, "resource.imported", false).await
    }

    /// `PATCH /v1/admin/resources/{id}`. Any security-relevant change (environment,
    /// config, credential entry, executor, operations, disabling) revokes the resource's
    /// grants and cancels its pending approvals: an approval never silently carries over
    /// to a changed target (A05).
    pub async fn update_resource(self: &Arc<Self>, actor: &Actor, id: &ResourceId, patch: ResourcePatch) -> Result<Resource, ApiError> {
        let rid = id.clone();
        let row = self
            .db
            .call(move |c| store::get_resource(c, &rid))
            .await?
            .ok_or_else(ApiError::not_found)?;
        let before = row.resource.clone();
        let mut r = before.clone();
        if let Some(a) = &patch.alias {
            r.alias = bounded_text("alias", a, 100)?;
        }
        if let Some(e) = patch.environment {
            r.environment = e;
        }
        if let Some(cfg) = patch.config {
            r.config = cfg;
        }
        if let Some(e) = patch.credential_entry_id {
            r.credential_entry_id = e;
        }
        if let Some(e) = patch.executor_id {
            r.executor_id = e;
        }
        if let Some(mut ops) = patch.operations {
            ops.sort();
            ops.dedup();
            r.operations = ops;
        }
        if let Some(s) = patch.status {
            if matches!(s, ResourceStatus::ExecutorOffline) {
                return Err(ApiError::invalid_request("该状态由系统维护", "This status is maintained by the broker.").with_detail("field", "status"));
            }
            r.status = s;
        }
        self.validate_resource(&r)?;
        let security_change = r.environment != before.environment
            || r.config != before.config
            || r.credential_entry_id != before.credential_entry_id
            || r.executor_id != before.executor_id
            || r.operations != before.operations
            || (r.status == ResourceStatus::Disabled && before.status != ResourceStatus::Disabled);
        self.save_resource(actor, &r, "resource.updated", security_change).await?;
        if security_change {
            self.revoke_resource_access(actor, id, "resource_changed").await?;
        }
        Ok(r)
    }

    /// `DELETE /v1/admin/resources/{id}` (soft delete; grants revoked, policies disabled).
    pub async fn delete_resource(self: &Arc<Self>, actor: &Actor, id: &ResourceId) -> Result<(), ApiError> {
        let now = self.now();
        let (rid, act) = (id.clone(), actor.audit_name());
        self.db
            .call(move |c| {
                let tx = c.transaction()?;
                let n = tx.execute(
                    "UPDATE resources SET deleted_at = ?2 WHERE resource_id = ?1 AND deleted_at IS NULL",
                    rusqlite::params![rid.as_str(), unix(&now)],
                )?;
                if n == 0 {
                    return Err(ApiError::not_found().into());
                }
                store::disable_policies(&tx, "resource_id", rid.as_str(), &now)?;
                audit::append(&tx, now, Audit::new(act, "resource.deleted").resource(&rid))?;
                tx.commit()?;
                Ok(())
            })
            .await?;
        self.revoke_resource_access(actor, id, "resource_deleted").await
    }

    pub(crate) async fn revoke_resource_access(self: &Arc<Self>, actor: &Actor, id: &ResourceId, reason: &str) -> Result<(), ApiError> {
        self.cancel_pending_approvals_for_resource(id, reason).await;
        let rid = id.clone();
        let grants = self
            .db
            .call(move |c| store::query_grants(c, "resource_id = ?1 AND status IN ('active', 'exhausted')", &[&rid.as_str()]))
            .await?;
        self.revoke_grants(actor, grants.into_iter().map(|g| g.grant.grant_id).collect(), RevocationLevel::EndSessions)
            .await?;
        Ok(())
    }

    /// Record whether a vault entry has unresolved sync conflicts (trusted client). While
    /// set, operations on resources using the entry fail with `SYNC_CONFLICT`.
    pub async fn set_entry_conflict(&self, actor: &Actor, entry: &EntryId, conflict: bool) -> Result<EntryConflictResponse, ApiError> {
        let now = self.now();
        let (e, act) = (entry.clone(), actor.audit_name());
        let n = self
            .db
            .call(move |c| {
                let tx = c.transaction()?;
                let n = store::set_entry_conflict(&tx, &e, conflict)?;
                audit::append(
                    &tx,
                    now,
                    Audit::new(act, "resource.conflict_set").detail(json!({
                        "entry_id": e.as_str(),
                        "conflict": conflict,
                        "resources_affected": n,
                    })),
                )?;
                tx.commit()?;
                Ok(n)
            })
            .await?;
        Ok(EntryConflictResponse {
            entry_id: entry.clone(),
            conflict,
            resources_affected: n,
        })
    }

    // ------------------------------------------------------------- C: resources.list

    /// `GET /v1/resources` — only resources in the connection's allowed projects, as
    /// [`ResourceView`]s (no config, no host names, no credential references).
    pub async fn list_resources(
        &self,
        p: &ConnectionPrincipal,
        project_id: Option<&ProjectId>,
        service: Option<&str>,
        lang: Lang,
    ) -> Result<ResourcesResponse, ApiError> {
        let conn = self.active_connection(p).await?;
        let rows = self.db.call(|c| store::list_resources(c)).await?;
        let mut resources = Vec::new();
        for row in rows {
            let r = &row.resource;
            if !store::visible(&conn, &r.project_id) {
                continue;
            }
            if project_id.is_some_and(|pid| pid != &r.project_id) {
                continue;
            }
            if service.is_some_and(|s| !s.eq_ignore_ascii_case(&r.service)) {
                continue;
            }
            resources.push(self.resource_view(&row, lang));
        }
        Ok(ResourcesResponse { resources })
    }

    pub(crate) fn resource_view(&self, row: &ResourceRow, lang: Lang) -> ResourceView {
        let r = &row.resource;
        let slot = self.executor_slot(&r.executor_id);
        let (protection_level, executor_status, specs) = match &slot {
            Some(s) => (
                s.backend.info().protection_level,
                if s.is_online() { ExecutorStatus::Online } else { ExecutorStatus::Offline },
                self.specs_for(s, r.connector.as_str()),
            ),
            None => (ProtectionLevel::Compatible, ExecutorStatus::Offline, Vec::new()),
        };
        let operations = r
            .operations
            .iter()
            .filter_map(|name| specs.iter().find(|s| &s.name == name))
            .map(|s| OperationView {
                name: s.name.clone(),
                description: match lang {
                    Lang::ZhCn => s.description_zh.clone(),
                    Lang::En => s.description_en.clone(),
                },
                side_effect: s.side_effect,
                parameters_schema: if s.parameters_schema.is_null() { Value::Object(Default::default()) } else { s.parameters_schema.clone() },
            })
            .collect();
        ResourceView {
            resource_id: r.resource_id.clone(),
            alias: r.alias.clone(),
            service: r.service.clone(),
            project_id: r.project_id.clone(),
            environment: r.environment,
            operations,
            status: self.effective_status(row),
            protection_level,
            executor_status,
        }
    }
}
