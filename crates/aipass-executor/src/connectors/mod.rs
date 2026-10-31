// SPDX-License-Identifier: Apache-2.0
//! Connector registry and the internal driver interface.
//!
//! Connector kinds are fixed by [`aipass_types::models::Connector`] (`postgres`, `github`,
//! `http_api`): there is no plug-in marketplace (design doc §12.5). A [`ConnectorDriver`]
//! owns parameter validation, scope mapping, execution and session teardown for its kind.

use std::collections::BTreeSet;
use std::sync::Arc;

use aipass_types::exec::{ExecutionOutcome, NormalizedRequest, OperationSpec};
use aipass_types::models::{Connector, GrantScope, Limits, Resource, SideEffects};
use aipass_types::{ApiError, GrantId, OperationId};
use async_trait::async_trait;
use serde_json::Value;
use tokio_util::sync::CancellationToken;

use crate::custody::{CredentialCustody, InstalledCredential};
use crate::errors;
use crate::filter::OutputFilter;

pub mod github;
pub mod http_api;
pub mod postgres;

/// Everything a driver needs for one execution.
pub struct ExecContext {
    /// Operation.
    pub operation_id: OperationId,
    /// Grant.
    pub grant_id: GrantId,
    /// Resource (config without secrets).
    pub resource: Resource,
    /// Normalized request (already re-validated by the executor).
    pub normalized: NormalizedRequest,
    /// Remaining budget.
    pub remaining: Limits,
    /// Cancellation (operation cancel, end_sessions, broker token).
    pub cancel: CancellationToken,
    /// Installed credential of the grant.
    pub credential: Arc<InstalledCredential>,
    /// Output filter armed with the credential.
    pub filter: Arc<OutputFilter>,
    /// Custody (rotation swaps the grant's credential).
    pub custody: Arc<CredentialCustody>,
}

/// Result of closing a grant's sessions.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SessionsClosed {
    /// Sessions closed.
    pub closed: usize,
    /// Running statements a cancel request was sent for.
    pub cancelled: usize,
    /// Cancel requests that could not be delivered.
    pub cancel_failures: usize,
}

/// A connector implementation.
#[async_trait]
pub trait ConnectorDriver: Send + Sync {
    /// Connector kind.
    fn connector(&self) -> Connector;
    /// Static operation specs of this connector.
    fn operation_specs(&self) -> Vec<OperationSpec>;
    /// Specs as offered by one resource (declared operations for `http_api`, filtered by
    /// `resource.operations`).
    fn resource_operation_specs(&self, resource: &Resource) -> Vec<OperationSpec> {
        self.operation_specs()
            .into_iter()
            .filter(|s| resource.operations.iter().any(|o| o == &s.name))
            .collect()
    }
    /// Validate a (trusted) resource configuration.
    fn validate_config(&self, config: &Value) -> Result<(), ApiError>;
    /// Schema validation + allowlist + scope mapping.
    fn normalize(
        &self,
        resource: &Resource,
        operation: &str,
        params: &Value,
    ) -> Result<NormalizedRequest, ApiError>;
    /// Execute an authorized operation.
    async fn execute(&self, ctx: ExecContext) -> Result<ExecutionOutcome, ApiError>;
    /// Close the grant's connector sessions.
    async fn end_sessions(&self, grant_id: &GrantId) -> SessionsClosed;
    /// Revoke upstream leases of the grant.
    async fn revoke_upstream(&self, grant_id: &GrantId) -> aipass_types::exec::LevelReport;
    /// Periodic maintenance (idle sessions, expired leases).
    async fn sweep(&self) {}
}

// ======================================================================================
// Shared helpers
// ======================================================================================

/// The operation must be offered by the resource (`SCOPE_DENIED` otherwise).
pub(crate) fn require_offered(resource: &Resource, operation: &str) -> Result<(), ApiError> {
    if resource.operations.iter().any(|o| o == operation) {
        Ok(())
    } else {
        Err(errors::scope_denied(
            "该资源未提供此操作",
            "This resource does not offer that operation.",
        )
        .with_detail("operation", operation.to_owned()))
    }
}

/// Build a [`NormalizedRequest`] (digest over the normalized params).
pub(crate) fn normalized(
    operation: &str,
    params: Value,
    required_scope: GrantScope,
) -> Result<NormalizedRequest, ApiError> {
    let parameters_digest =
        aipass_types::exec::parameters_digest(operation, &params).map_err(|_| {
            errors::invalid(
                "参数中含有不支持的数值（例如小数或超大整数）",
                "Parameters contain unsupported numbers (floats or unsafe integers).",
            )
        })?;
    Ok(NormalizedRequest {
        operation: operation.to_owned(),
        params,
        required_scope: aipass_types::approval::normalize_scope(&required_scope),
        parameters_digest,
    })
}

/// Row cap for one operation = min(requested, connector/config cap, grant per-op limit,
/// remaining grant rows). Zero → `BUDGET_EXHAUSTED`.
pub(crate) fn row_cap(
    requested: Option<u64>,
    config_cap: u64,
    remaining: &Limits,
) -> Result<u64, ApiError> {
    let mut cap = config_cap
        .min(remaining.max_rows_per_operation)
        .min(remaining.max_rows_per_grant);
    if let Some(r) = requested {
        cap = cap.min(r);
    }
    if remaining.max_rows_per_grant == 0 || remaining.max_result_bytes == 0 {
        return Err(errors::budget_exhausted());
    }
    if cap == 0 {
        return Err(errors::budget_exhausted());
    }
    Ok(cap)
}

/// Serialized size of a JSON value.
pub(crate) fn json_len(v: &Value) -> u64 {
    serde_json::to_vec(v)
        .map(|b| b.len() as u64)
        .unwrap_or(u64::MAX)
}

/// Drop trailing items until `wrap(items)` fits into `cap` bytes. Returns true when items
/// were dropped.
pub(crate) fn fit_items<F>(items: &mut Vec<Value>, cap: u64, wrap: F) -> bool
where
    F: Fn(&[Value]) -> Value,
{
    let empty = json_len(&wrap(&[]));
    let mut total = empty;
    let mut keep = 0usize;
    for (i, it) in items.iter().enumerate() {
        let add = json_len(it) + u64::from(i > 0);
        if total + add > cap {
            break;
        }
        total += add;
        keep += 1;
    }
    let truncated = keep < items.len();
    items.truncate(keep);
    truncated
}

/// Final assembly: byte accounting + the serialized-output leak sweep.
pub(crate) fn finish(
    filter: &OutputFilter,
    data: Value,
    rows: Option<u64>,
    truncated: bool,
    restricted: BTreeSet<String>,
    side_effects: SideEffects,
    max_bytes: u64,
) -> Result<ExecutionOutcome, ApiError> {
    if filter.leaks(&data) {
        return Err(errors::result_restricted("secret_detected"));
    }
    let bytes = json_len(&data);
    if bytes > max_bytes {
        return Err(errors::result_restricted("result_too_large"));
    }
    Ok(ExecutionOutcome {
        data,
        rows,
        bytes,
        truncated,
        restricted_fields: restricted.into_iter().collect(),
        side_effects,
    })
}

/// Byte cap for one result: min(grant per-op bytes) — the remaining budget carries it.
pub(crate) fn byte_cap(remaining: &Limits) -> u64 {
    remaining.max_result_bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn row_cap_takes_minimum_and_exhausts() {
        let l = Limits {
            max_rows_per_operation: 100,
            max_rows_per_grant: 7,
            max_requests_per_grant: 3,
            max_result_bytes: 1000,
        };
        assert_eq!(row_cap(Some(50), 1000, &l).unwrap(), 7);
        assert_eq!(row_cap(Some(2), 1000, &l).unwrap(), 2);
        assert_eq!(row_cap(None, 5, &l).unwrap(), 5);
        let none = Limits {
            max_rows_per_grant: 0,
            ..l
        };
        assert_eq!(
            row_cap(None, 5, &none).unwrap_err().code,
            aipass_types::ErrorCode::BudgetExhausted
        );
    }

    #[test]
    fn fit_items_respects_cap() {
        let mut items: Vec<Value> = (0..10).map(|i| json!({"n": i})).collect();
        let wrap = |xs: &[Value]| json!({"rows": xs});
        let cap = json_len(&wrap(&items[..3]));
        assert!(fit_items(&mut items, cap, wrap));
        assert_eq!(items.len(), 3);
        let mut all: Vec<Value> = (0..2).map(|i| json!({"n": i})).collect();
        assert!(!fit_items(&mut all, 10_000, wrap));
    }
}
