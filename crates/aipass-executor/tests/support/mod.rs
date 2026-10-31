// SPDX-License-Identifier: Apache-2.0
//! Shared helpers for the executor integration tests.
#![allow(dead_code)]

pub mod certs;
pub mod demo_site;
pub mod pg;
pub mod tls_server;

use std::sync::Arc;

use aipass_crypto::{DeviceIdentity, SecretString};
use aipass_executor::{Executor, ExecutorBuilder};
use aipass_types::exec::{CredentialMaterial, ExecutionOutcome, ExecutionRequest, ExecutorBackend};
use aipass_types::models::{Connector, Environment, Limits, Resource, ResourceStatus};
use aipass_types::vault::{DatabaseInfo, EntryKind};
use aipass_types::{ApiError, EntryId, ExecutorId, GrantId, OperationId, ProjectId, ResourceId};
use serde_json::Value;
use tokio_util::sync::CancellationToken;

/// Builder for a test executor (random identity).
pub fn builder() -> ExecutorBuilder {
    Executor::builder(
        ExecutorId::generate(),
        "test-executor",
        DeviceIdentity::generate(),
    )
}

/// Default test executor.
pub fn executor() -> Arc<Executor> {
    Arc::new(builder().build().expect("executor"))
}

/// A resource bound to `exec`.
pub fn resource(
    exec: &Executor,
    connector: Connector,
    config: Value,
    operations: &[&str],
) -> Resource {
    Resource {
        resource_id: ResourceId::generate(),
        alias: "test resource".into(),
        service: connector.as_str().into(),
        connector,
        project_id: ProjectId::generate(),
        environment: Environment::Test,
        config,
        credential_entry_id: EntryId::generate(),
        executor_id: exec.executor_id().clone(),
        operations: operations.iter().map(|s| (*s).to_owned()).collect(),
        status: ResourceStatus::Available,
        created_at: aipass_types::time::now(),
    }
}

/// Credential material for `resource`.
pub fn material(
    resource: &Resource,
    kind: EntryKind,
    username: Option<&str>,
    secret: &str,
    ttl_secs: i64,
) -> CredentialMaterial {
    CredentialMaterial {
        entry_id: resource.credential_entry_id.clone(),
        version: 1,
        kind,
        username: username.map(str::to_owned),
        secret: SecretString::from(secret),
        database: None,
        expires_at: chrono::Utc::now() + chrono::Duration::seconds(ttl_secs),
    }
}

/// Database credential with `DatabaseInfo`.
pub fn db_material(
    resource: &Resource,
    user: &str,
    password: &str,
    host: &str,
    port: u16,
) -> CredentialMaterial {
    let mut m = material(resource, EntryKind::Database, Some(user), password, 600);
    m.database = Some(DatabaseInfo {
        engine: "postgres".into(),
        host: host.into(),
        port,
        dbname: "lure".into(),
        sslmode: "disable".into(),
    });
    m
}

/// Generous limits.
pub fn limits() -> Limits {
    Limits::default()
}

/// Install a plaintext credential for a fresh grant.
pub async fn grant_with(exec: &Executor, m: CredentialMaterial) -> GrantId {
    let g = GrantId::generate();
    exec.install_plain_credential(g.as_str(), m)
        .await
        .expect("install");
    g
}

/// Normalize + execute.
pub async fn run(
    exec: &Executor,
    resource: &Resource,
    grant: &GrantId,
    operation: &str,
    params: Value,
    remaining: Limits,
) -> Result<ExecutionOutcome, ApiError> {
    run_with(
        exec,
        resource,
        grant,
        operation,
        params,
        remaining,
        OperationId::generate(),
        CancellationToken::new(),
    )
    .await
}

/// Normalize + execute with an explicit operation id and token.
#[allow(clippy::too_many_arguments)]
pub async fn run_with(
    exec: &Executor,
    resource: &Resource,
    grant: &GrantId,
    operation: &str,
    params: Value,
    remaining: Limits,
    operation_id: OperationId,
    cancel: CancellationToken,
) -> Result<ExecutionOutcome, ApiError> {
    let normalized = exec.normalize(resource, operation, &params)?;
    exec.execute(ExecutionRequest {
        operation_id,
        grant_id: grant.clone(),
        resource: resource.clone(),
        normalized,
        remaining,
        cancel,
    })
    .await
}

/// Every text an error can surface (code, messages, details, Debug).
pub fn error_text(e: &ApiError) -> String {
    format!(
        "{e:?} {} {} {}",
        e.message(aipass_types::Lang::ZhCn),
        e.message(aipass_types::Lang::En),
        serde_json::to_string(&e.to_body(aipass_types::Lang::En)).unwrap_or_default()
    )
}

/// Assert `needle` appears nowhere in an outcome / error.
pub fn assert_no_leak<T: std::fmt::Debug>(
    r: &Result<ExecutionOutcome, ApiError>,
    needle: &str,
    ctx: T,
) {
    match r {
        Ok(o) => {
            let s = format!("{o:?} {}", serde_json::to_string(o).unwrap_or_default());
            assert!(
                !s.contains(needle),
                "{ctx:?}: secret leaked into outcome: {s}"
            );
        }
        Err(e) => {
            let s = error_text(e);
            assert!(
                !s.contains(needle),
                "{ctx:?}: secret leaked into error: {s}"
            );
        }
    }
}
