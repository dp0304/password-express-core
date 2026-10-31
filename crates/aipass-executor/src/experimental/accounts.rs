// SPDX-License-Identifier: Apache-2.0
//! `SiteAdapter`, the pending-registration store and the idempotent account-creation flow.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::{Arc, Mutex};

use aipass_crypto::SecretString;
use aipass_types::error::Localized;
use aipass_types::vault::PasswordRules;
use aipass_types::{ApiError, ErrorCode, Timestamp};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::errors;
use crate::filter::{FieldTree, OutputFilter};

/// Static description of an adapted site (shown on the approval screen).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SiteAdapterInfo {
    /// Adapter id, e.g. `demo`.
    pub id: String,
    /// Site origin (the domain the account belongs to).
    pub origin: String,
    /// Display name.
    pub display_name: Localized,
    /// The site may ask for e-mail verification.
    pub may_require_email_verification: bool,
    /// Fees (none for the demo). Fees are never approved by the model.
    pub fees: Option<Localized>,
    /// Adapted actions for `browser.start_task`.
    pub actions: Vec<SiteAction>,
}

/// An adapted, fixed action on a site.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SiteAction {
    /// Action name.
    pub name: String,
    /// Read-only.
    pub read_only: bool,
    /// Fields that may be returned.
    pub allowed_fields: Vec<String>,
    /// Description.
    pub description: Localized,
}

/// User-visible sign-up data supplied by the model (never secrets).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignupProfile {
    /// Desired username.
    pub username: String,
    /// E-mail for the account.
    pub email: String,
    /// Display name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
}

/// Outcome of a sign-up submission.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignupOutcome {
    /// Account exists and is usable.
    Created,
    /// Account created, but the site requires e-mail (or other) verification by the user.
    NeedsVerification,
    /// The site may or may not have created the account.
    Unknown,
}

/// Login material for adapted actions.
pub struct SiteLogin {
    /// Username.
    pub username: String,
    /// Password.
    pub password: SecretString,
}

impl fmt::Debug for SiteLogin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SiteLogin")
            .field("username", &"[REDACTED]")
            .field("password", &"[REDACTED]")
            .finish()
    }
}

/// An adapter for one supported site.
#[async_trait]
pub trait SiteAdapter: Send + Sync {
    /// Description.
    fn info(&self) -> SiteAdapterInfo;
    /// Password rules of the site.
    fn password_rules(&self) -> PasswordRules {
        PasswordRules::default()
    }
    /// Whether `username` already exists. `Ok(None)` = the site cannot tell.
    async fn account_exists(&self, username: &str) -> Result<Option<bool>, ApiError>;
    /// Submit the sign-up. `Err` means the account was definitely **not** created.
    async fn submit_signup(
        &self,
        profile: &SignupProfile,
        password: &SecretString,
        idempotency_key: &str,
    ) -> Result<SignupOutcome, ApiError>;
    /// Whether the credentials log in.
    async fn verify_login(&self, username: &str, password: &SecretString)
    -> Result<bool, ApiError>;
    /// Run an adapted action as the logged-in account. Output is filtered by the caller.
    async fn run_action(
        &self,
        action: &str,
        login: &SiteLogin,
        params: &Value,
    ) -> Result<Value, ApiError>;
}

/// Status of a pending registration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationStatus {
    /// Persisted, not yet (or not knowingly) submitted.
    Pending,
    /// Created and verified.
    Created,
    /// Created; user must complete verification.
    NeedsVerification,
    /// Outcome unknown; check before retrying.
    Unknown,
    /// Definitely not created.
    Failed,
}

/// The encrypted pending record the trusted client stores (vault entry with
/// `lifecycle: pending_registration`). `Debug` is redacted.
#[derive(Clone)]
pub struct PendingRegistration {
    /// Record id (also the account reference given to the AI).
    pub pending_id: String,
    /// Adapter.
    pub adapter: String,
    /// Origin.
    pub origin: String,
    /// Idempotency key of the request.
    pub idempotency_key: String,
    /// Digest of the normalized request (adapter + profile).
    pub request_digest: String,
    /// Profile.
    pub profile: SignupProfile,
    /// Generated password.
    pub password: SecretString,
    /// Status.
    pub status: RegistrationStatus,
    /// Created.
    pub created_at: Timestamp,
}

impl fmt::Debug for PendingRegistration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PendingRegistration")
            .field("pending_id", &self.pending_id)
            .field("adapter", &self.adapter)
            .field("status", &self.status)
            .field("password", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

/// Durable store for pending registrations, implemented by the trusted client (it encrypts
/// the record into the vault). `persist_pending` must only return `Ok` once the record is
/// durable — the adapter submits nothing before that.
#[async_trait]
pub trait PendingRegistrationStore: Send + Sync {
    /// Look up by idempotency key.
    async fn get(&self, idempotency_key: &str) -> Result<Option<PendingRegistration>, ApiError>;
    /// Persist a new pending record (durably).
    async fn persist_pending(&self, record: &PendingRegistration) -> Result<(), ApiError>;
    /// Update the status.
    async fn update_status(
        &self,
        pending_id: &str,
        status: RegistrationStatus,
    ) -> Result<(), ApiError>;
}

/// In-memory store (development / tests). Records an event log and can be told to fail.
#[derive(Default)]
pub struct MemoryPendingStore {
    records: Mutex<BTreeMap<String, PendingRegistration>>,
    events: Mutex<Vec<String>>,
    fail_persist: std::sync::atomic::AtomicBool,
}

impl MemoryPendingStore {
    /// New empty store.
    pub fn new() -> Self {
        Self::default()
    }
    /// Make `persist_pending` fail.
    pub fn set_fail_persist(&self, fail: bool) {
        self.fail_persist
            .store(fail, std::sync::atomic::Ordering::SeqCst);
    }
    /// Event log (`persist:<id>`, `status:<id>:<status>`).
    pub fn events(&self) -> Vec<String> {
        self.events
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }
    /// Push an external event (tests interleave submit markers).
    pub fn note(&self, e: impl Into<String>) {
        self.events
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push(e.into());
    }
    /// The stored password of a record (trusted-client side only).
    pub fn password_of(&self, idempotency_key: &str) -> Option<SecretString> {
        self.records
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(idempotency_key)
            .map(|r| r.password.clone())
    }
}

#[async_trait]
impl PendingRegistrationStore for MemoryPendingStore {
    async fn get(&self, idempotency_key: &str) -> Result<Option<PendingRegistration>, ApiError> {
        Ok(self
            .records
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(idempotency_key)
            .cloned())
    }
    async fn persist_pending(&self, record: &PendingRegistration) -> Result<(), ApiError> {
        if self.fail_persist.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(ApiError::new(ErrorCode::SecretUnavailable).with_message(
                "无法保存待注册记录（账号库已锁定或不可写）",
                "Could not save the pending registration (vault locked or not writable).",
            ));
        }
        self.records
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(record.idempotency_key.clone(), record.clone());
        self.note(format!("persist:{}", record.pending_id));
        Ok(())
    }
    async fn update_status(
        &self,
        pending_id: &str,
        status: RegistrationStatus,
    ) -> Result<(), ApiError> {
        let mut g = self.records.lock().unwrap_or_else(|p| p.into_inner());
        for r in g.values_mut() {
            if r.pending_id == pending_id {
                r.status = status;
            }
        }
        drop(g);
        self.note(format!("status:{pending_id}:{status:?}"));
        Ok(())
    }
}

/// `accounts.create` request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountCreateRequest {
    /// Adapter id.
    pub adapter: String,
    /// Idempotency key (required, 1..=128).
    pub idempotency_key: String,
    /// Profile.
    pub profile: SignupProfile,
}

/// `accounts.create` result given to the AI — never contains the password.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountCreateResult {
    /// `created` | `needs_verification` | `unknown`.
    pub status: SignupOutcome,
    /// Account reference (pending record id). Not a capability.
    pub account_ref: String,
    /// Adapter.
    pub adapter: String,
    /// Origin.
    pub origin: String,
    /// Username (alias).
    pub username: String,
    /// Explanation.
    pub message: Localized,
}

/// `browser.start_task` result (filtered).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SiteTaskResult {
    /// Action.
    pub action: String,
    /// Filtered data.
    pub data: Value,
    /// Redacted fields.
    pub restricted_fields: Vec<String>,
}

/// Orchestrates adapted sign-ups and actions.
pub struct AccountCreator {
    adapters: BTreeMap<String, Arc<dyn SiteAdapter>>,
    store: Arc<dyn PendingRegistrationStore>,
    lock: tokio::sync::Mutex<()>,
}

impl fmt::Debug for AccountCreator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AccountCreator")
            .field("adapters", &self.adapters.keys().collect::<Vec<_>>())
            .finish()
    }
}

fn valid_username(s: &str) -> bool {
    (3..=64).contains(&s.len())
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || "_.-".contains(c))
}

fn valid_email(s: &str) -> bool {
    let Some((local, domain)) = s.split_once('@') else {
        return false;
    };
    !local.is_empty()
        && local.len() <= 64
        && domain.contains('.')
        && domain.len() <= 253
        && !s.chars().any(|c| c.is_whitespace() || c.is_control())
        && !domain.starts_with('.')
        && !domain.ends_with('.')
}

fn message(status: SignupOutcome) -> Localized {
    match status {
        SignupOutcome::Created => Localized::new(
            "账号已创建并验证可登录；密码已保存在账号库中，不会提供给 AI。",
            "The account was created and verified; its password is stored in the vault and is never given to the AI.",
        ),
        SignupOutcome::NeedsVerification => Localized::new(
            "账号已提交创建，网站要求验证（例如邮箱确认），请在可信设备上完成。",
            "The account was submitted; the site requires verification (e.g. e-mail confirmation). Complete it on a trusted device.",
        ),
        SignupOutcome::Unknown => Localized::new(
            "无法确认网站是否已创建账号，状态为“需要核对”。请勿重复注册；用相同的幂等标识重试会先核对账号是否存在。",
            "Could not confirm whether the site created the account (needs checking). Do not register again; retrying with the same idempotency key first checks whether the account exists.",
        ),
    }
}

impl AccountCreator {
    /// New creator with a trusted-client store.
    pub fn new(store: Arc<dyn PendingRegistrationStore>) -> Self {
        Self {
            adapters: BTreeMap::new(),
            store,
            lock: tokio::sync::Mutex::new(()),
        }
    }

    /// Register an adapter.
    pub fn register_adapter(&mut self, adapter: Arc<dyn SiteAdapter>) {
        self.adapters.insert(adapter.info().id, adapter);
    }

    /// Adapters offered.
    pub fn adapters(&self) -> Vec<SiteAdapterInfo> {
        self.adapters.values().map(|a| a.info()).collect()
    }

    fn adapter(&self, id: &str) -> Result<&Arc<dyn SiteAdapter>, ApiError> {
        self.adapters.get(id).ok_or_else(|| {
            errors::not_supported(
                "该网站没有可用的适配器；请由用户自行注册",
                "No adapter for this site; the user has to register manually.",
            )
        })
    }

    fn result(rec: &PendingRegistration, status: SignupOutcome) -> AccountCreateResult {
        AccountCreateResult {
            status,
            account_ref: rec.pending_id.clone(),
            adapter: rec.adapter.clone(),
            origin: rec.origin.clone(),
            username: rec.profile.username.clone(),
            message: message(status),
        }
    }

    async fn settle(
        &self,
        rec: &PendingRegistration,
        status: RegistrationStatus,
    ) -> Result<(), ApiError> {
        self.store.update_status(&rec.pending_id, status).await
    }

    async fn submit(
        &self,
        adapter: &dyn SiteAdapter,
        rec: &PendingRegistration,
    ) -> Result<AccountCreateResult, ApiError> {
        match adapter
            .submit_signup(&rec.profile, &rec.password, &rec.idempotency_key)
            .await
        {
            Ok(SignupOutcome::Created) => {
                let ok = adapter
                    .verify_login(&rec.profile.username, &rec.password)
                    .await
                    .unwrap_or(false);
                let (st, out) = if ok {
                    (RegistrationStatus::Created, SignupOutcome::Created)
                } else {
                    (RegistrationStatus::Unknown, SignupOutcome::Unknown)
                };
                self.settle(rec, st).await?;
                Ok(Self::result(rec, out))
            }
            Ok(SignupOutcome::NeedsVerification) => {
                self.settle(rec, RegistrationStatus::NeedsVerification)
                    .await?;
                Ok(Self::result(rec, SignupOutcome::NeedsVerification))
            }
            Ok(SignupOutcome::Unknown) => {
                self.settle(rec, RegistrationStatus::Unknown).await?;
                Ok(Self::result(rec, SignupOutcome::Unknown))
            }
            Err(e) => {
                self.settle(rec, RegistrationStatus::Failed).await?;
                Err(e)
            }
        }
    }

    /// `accounts.create`.
    pub async fn create_account(
        &self,
        req: AccountCreateRequest,
    ) -> Result<AccountCreateResult, ApiError> {
        if req.idempotency_key.is_empty() || req.idempotency_key.len() > 128 {
            return Err(errors::invalid_param(
                "idempotency_key",
                "注册请求必须带有幂等标识（1 到 128 个字符）",
                "A sign-up needs an idempotency key (1 to 128 characters).",
            ));
        }
        if !valid_username(&req.profile.username) {
            return Err(errors::invalid_param(
                "profile.username",
                "用户名无效",
                "Invalid username.",
            ));
        }
        if !valid_email(&req.profile.email) {
            return Err(errors::invalid_param(
                "profile.email",
                "邮箱无效",
                "Invalid e-mail.",
            ));
        }
        if req
            .profile
            .display_name
            .as_ref()
            .is_some_and(|d| d.chars().count() > 100)
        {
            return Err(errors::invalid_param(
                "profile.display_name",
                "显示名称过长",
                "Display name too long.",
            ));
        }
        let adapter = self.adapter(&req.adapter)?.clone();
        let info = adapter.info();
        let digest = aipass_types::canonical::jcs_sha256_b64u(&serde_json::json!({
            "adapter": req.adapter, "profile": req.profile
        }))
        .map_err(|_| ApiError::internal())?;
        // One sign-up flow at a time per creator: makes the idempotency check-then-act atomic.
        let _g = self.lock.lock().await;

        if let Some(existing) = self.store.get(&req.idempotency_key).await? {
            if existing.request_digest != digest {
                return Err(ApiError::new(ErrorCode::IdempotencyConflict));
            }
            return match existing.status {
                RegistrationStatus::Created => Ok(Self::result(&existing, SignupOutcome::Created)),
                RegistrationStatus::NeedsVerification => {
                    Ok(Self::result(&existing, SignupOutcome::NeedsVerification))
                }
                RegistrationStatus::Pending | RegistrationStatus::Unknown => {
                    // Reconcile before anything else — never blindly register again.
                    match adapter.account_exists(&existing.profile.username).await? {
                        Some(true) => {
                            let ok = adapter
                                .verify_login(&existing.profile.username, &existing.password)
                                .await
                                .unwrap_or(false);
                            if ok {
                                self.settle(&existing, RegistrationStatus::Created).await?;
                                Ok(Self::result(&existing, SignupOutcome::Created))
                            } else {
                                // Exists but our password does not log in: may be someone
                                // else's account or pending verification — needs a human.
                                self.settle(&existing, RegistrationStatus::Unknown).await?;
                                Ok(Self::result(&existing, SignupOutcome::Unknown))
                            }
                        }
                        Some(false) => self.submit(adapter.as_ref(), &existing).await,
                        None => Ok(Self::result(&existing, SignupOutcome::Unknown)),
                    }
                }
                RegistrationStatus::Failed => self.submit(adapter.as_ref(), &existing).await,
            };
        }

        let password = super::password::generate(&adapter.password_rules())?;
        let rec = PendingRegistration {
            pending_id: format!(
                "reg_{}",
                aipass_crypto::b64u::encode(
                    aipass_crypto::rng::try_random_array::<12>()
                        .map_err(|_| ApiError::internal())?
                )
            ),
            adapter: req.adapter.clone(),
            origin: info.origin.clone(),
            idempotency_key: req.idempotency_key.clone(),
            request_digest: digest,
            profile: req.profile,
            password,
            status: RegistrationStatus::Pending,
            created_at: aipass_types::time::now(),
        };
        // Persist BEFORE submitting (§6.3 step 3). Failure → nothing is sent to the site.
        self.store.persist_pending(&rec).await?;
        tracing::info!(adapter = %rec.adapter, pending_id = %rec.pending_id, "pending registration persisted; submitting");
        self.submit(adapter.as_ref(), &rec).await
    }

    /// `browser.start_task` (adapted action as the stored account). `login` comes from the
    /// vault via the trusted client; the result is filtered by the action's field allowlist
    /// and the secret detectors.
    pub async fn start_task(
        &self,
        adapter: &str,
        action: &str,
        login: SiteLogin,
        params: &Value,
    ) -> Result<SiteTaskResult, ApiError> {
        let adapter = self.adapter(adapter)?;
        let info = adapter.info();
        let spec = info
            .actions
            .iter()
            .find(|a| a.name == action)
            .ok_or_else(|| {
                errors::scope_denied(
                    "该网站适配器不提供此动作",
                    "The site adapter does not offer this action.",
                )
            })?;
        let raw = adapter.run_action(action, &login, params).await?;
        let mut filter = OutputFilter::new();
        filter.add_secret(login.password.expose());
        let out = crate::filter::filter_value(
            &filter,
            &raw,
            Some(&FieldTree::from_paths(&spec.allowed_fields)),
        );
        if filter.leaks(&out.data) {
            return Err(errors::result_restricted("secret_detected"));
        }
        Ok(SiteTaskResult {
            action: action.to_owned(),
            data: out.data,
            restricted_fields: out.restricted_fields,
        })
    }
}
