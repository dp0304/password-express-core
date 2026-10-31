// SPDX-License-Identifier: Apache-2.0
//! Shared test helpers: an in-process `BrokerApi` fake and a minimal JSON-Schema checker for
//! the subset of keywords our tool schemas use.

#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::Mutex;

use aipass_client::BrokerApi;
use aipass_client::testing::demo_resource;
use aipass_types::models::{
    AccessRequest, AccessRequestResponse, ApprovalStatus, CancelResponse, GrantStatus,
    OperationRequest, OperationResponse, OperationResult, OperationStatus, ReleaseResponse,
    ResourcesResponse, SideEffects,
};
use aipass_types::{
    ApiError, ApprovalRequestId, ErrorCode, GrantId, Lang, OperationId, ProjectId,
};
use async_trait::async_trait;
use serde_json::{Value, json};

/// Programmable in-process broker.
pub struct FakeBroker {
    pub resources: ResourcesResponse,
    pub ops: Mutex<HashMap<String, OperationResponse>>,
    pub fail_with: Mutex<Option<ApiError>>,
    pub calls: Mutex<Vec<String>>,
}

impl FakeBroker {
    pub fn new() -> Self {
        Self {
            resources: ResourcesResponse {
                resources: vec![demo_resource(&ProjectId::generate())],
            },
            ops: Mutex::new(HashMap::new()),
            fail_with: Mutex::new(None),
            calls: Mutex::new(Vec::new()),
        }
    }

    pub fn fail(&self, e: Option<ApiError>) {
        *self.fail_with.lock().unwrap() = e;
    }

    fn check(&self, call: &str) -> Result<(), ApiError> {
        self.calls.lock().unwrap().push(call.to_owned());
        match self.fail_with.lock().unwrap().clone() {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    /// Complete every waiting operation.
    pub fn approve_all(&self) {
        for r in self.ops.lock().unwrap().values_mut() {
            if r.status == OperationStatus::AwaitingApproval {
                *r = OperationResponse {
                    status: OperationStatus::Succeeded,
                    operation_id: r.operation_id.clone(),
                    approval_request_id: None,
                    expires_in_seconds: None,
                    message: None,
                    result: Some(OperationResult {
                        data: json!([{"day": "2026-10-01", "plan": "pro", "subscriptions": 42}]),
                        rows: Some(1),
                        truncated: false,
                        restricted: true,
                        restricted_fields: vec!["email".into()],
                    }),
                    error: None,
                };
            }
        }
    }
}

#[async_trait]
impl BrokerApi for FakeBroker {
    async fn list_resources(&self, project_id: Option<&ProjectId>, service: Option<&str>) -> Result<ResourcesResponse, ApiError> {
        self.check("list_resources")?;
        let mut r = self.resources.clone();
        r.resources.retain(|x| project_id.is_none_or(|p| &x.project_id == p) && service.is_none_or(|s| x.service == s));
        Ok(r)
    }
    async fn request_operation(&self, req: &OperationRequest) -> Result<OperationResponse, ApiError> {
        self.check("request_operation")?;
        if !self.resources.resources.iter().any(|r| r.resource_id == req.resource_id) {
            return Err(ApiError::not_found());
        }
        let id = OperationId::generate();
        let resp = OperationResponse::approval_required(id.clone(), ApprovalRequestId::generate(), 120);
        self.ops.lock().unwrap().insert(id.as_str().to_owned(), resp.clone());
        Ok(resp)
    }
    async fn get_operation(&self, id: &OperationId) -> Result<OperationResponse, ApiError> {
        self.check("get_operation")?;
        self.ops.lock().unwrap().get(id.as_str()).cloned().ok_or_else(ApiError::not_found)
    }
    async fn cancel_operation(&self, id: &OperationId) -> Result<CancelResponse, ApiError> {
        self.check("cancel_operation")?;
        let mut ops = self.ops.lock().unwrap();
        let op = ops.get_mut(id.as_str()).ok_or_else(ApiError::not_found)?;
        let cancelled = !op.status.is_terminal();
        if cancelled {
            op.status = OperationStatus::Cancelled;
        }
        Ok(CancelResponse {
            operation_id: id.clone(),
            status: op.status,
            cancelled,
            side_effects: SideEffects::None,
            message: "ok".into(),
        })
    }
    async fn request_access(&self, _req: &AccessRequest) -> Result<AccessRequestResponse, ApiError> {
        self.check("request_access")?;
        Ok(AccessRequestResponse {
            approval_request_id: ApprovalRequestId::generate(),
            status: ApprovalStatus::Pending,
            grant_id: None,
        })
    }
    async fn get_access_request(&self, id: &ApprovalRequestId) -> Result<AccessRequestResponse, ApiError> {
        self.check("get_access_request")?;
        Ok(AccessRequestResponse {
            approval_request_id: id.clone(),
            status: ApprovalStatus::Approved,
            grant_id: Some(GrantId::generate()),
        })
    }
    async fn release_grant(&self, id: &GrantId) -> Result<ReleaseResponse, ApiError> {
        self.check("release_grant")?;
        Ok(ReleaseResponse {
            grant_id: id.clone(),
            status: GrantStatus::Released,
        })
    }
}

pub fn scope_denied() -> ApiError {
    ApiError::new(ErrorCode::ScopeDenied)
}

pub fn lang() -> Lang {
    Lang::ZhCn
}

/// Validate `v` against the JSON-Schema subset used by our tool schemas
/// (type, properties, required, enum, items, minimum, minItems, maxItems, additionalProperties).
pub fn validate(schema: &Value, v: &Value, path: &str) -> Result<(), String> {
    if let Some(t) = schema.get("type").and_then(Value::as_str) {
        let ok = match t {
            "object" => v.is_object(),
            "array" => v.is_array(),
            "string" => v.is_string(),
            "integer" => v.is_i64() || v.is_u64(),
            "number" => v.is_number(),
            "boolean" => v.is_boolean(),
            "null" => v.is_null(),
            _ => true,
        };
        if !ok {
            return Err(format!("{path}: expected {t}, got {v}"));
        }
    }
    if let Some(e) = schema.get("enum").and_then(Value::as_array)
        && !e.contains(v)
    {
        return Err(format!("{path}: {v} not in enum {e:?}"));
    }
    if let (Some(min), Some(n)) = (schema.get("minimum").and_then(Value::as_i64), v.as_i64())
        && n < min
    {
        return Err(format!("{path}: {n} < {min}"));
    }
    if let Some(obj) = v.as_object() {
        if let Some(req) = schema.get("required").and_then(Value::as_array) {
            for r in req {
                let k = r.as_str().unwrap();
                if !obj.contains_key(k) {
                    return Err(format!("{path}: missing required {k}"));
                }
            }
        }
        let props = schema.get("properties").and_then(Value::as_object);
        for (k, val) in obj {
            match props.and_then(|p| p.get(k)) {
                Some(s) => validate(s, val, &format!("{path}.{k}"))?,
                None => {
                    if schema.get("additionalProperties") == Some(&Value::Bool(false)) {
                        return Err(format!("{path}: unexpected property {k}"));
                    }
                }
            }
        }
    }
    if let Some(arr) = v.as_array() {
        if let Some(items) = schema.get("items") {
            for (i, it) in arr.iter().enumerate() {
                validate(items, it, &format!("{path}[{i}]"))?;
            }
        }
        if let Some(min) = schema.get("minItems").and_then(Value::as_u64)
            && (arr.len() as u64) < min
        {
            return Err(format!("{path}: fewer than {min} items"));
        }
    }
    Ok(())
}
