// SPDX-License-Identifier: Apache-2.0
//! Experimental `accounts.create` / `browser.start_task` through the `demo` SiteAdapter and
//! the bundled demo site (A19): pending record persisted before submit, idempotency,
//! created | needs_verification | unknown outcomes, reconciliation without duplicate
//! sign-ups, and no password in any AI-facing result.
#![cfg(feature = "experimental")]

mod support;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use aipass_executor::experimental::{
    AccountCreateRequest, AccountCreator, DemoSiteAdapter, MemoryPendingStore, PendingRegistration,
    PendingRegistrationStore, RegistrationStatus, SignupOutcome, SignupProfile, SiteLogin,
};
use aipass_types::{ApiError, ErrorCode};
use async_trait::async_trait;
use serde_json::json;
use support::demo_site::{DemoSite, SiteState};

/// Wraps the memory store and checks that no sign-up for the request reached the site before
/// its pending record was persisted.
struct OrderedStore {
    inner: MemoryPendingStore,
    site: Arc<SiteState>,
    violations: AtomicUsize,
}

#[async_trait]
impl PendingRegistrationStore for OrderedStore {
    async fn get(&self, k: &str) -> Result<Option<PendingRegistration>, ApiError> {
        self.inner.get(k).await
    }
    async fn persist_pending(&self, r: &PendingRegistration) -> Result<(), ApiError> {
        if self.site.saw_key(&r.idempotency_key) {
            self.violations.fetch_add(1, Ordering::SeqCst);
        }
        self.inner.persist_pending(r).await
    }
    async fn update_status(&self, id: &str, s: RegistrationStatus) -> Result<(), ApiError> {
        self.inner.update_status(id, s).await
    }
}

fn req(key: &str, user: &str, email: &str) -> AccountCreateRequest {
    AccountCreateRequest {
        adapter: "demo".into(),
        idempotency_key: key.into(),
        profile: SignupProfile {
            username: user.into(),
            email: email.into(),
            display_name: Some("Demo".into()),
        },
    }
}

#[tokio::test]
async fn demo_site_account_creation() {
    let site = DemoSite::start_on("127.0.0.1:0").await.unwrap();
    site.state.slow_ms.store(2500, Ordering::SeqCst);
    let store = Arc::new(OrderedStore {
        inner: MemoryPendingStore::new(),
        site: site.state.clone(),
        violations: AtomicUsize::new(0),
    });
    let mut creator = AccountCreator::new(store.clone());
    creator.register_adapter(Arc::new(
        DemoSiteAdapter::new(&site.base_url(), Duration::from_secs(1)).unwrap(),
    ));
    assert_eq!(creator.adapters()[0].id, "demo");

    // created
    let r = creator
        .create_account(req("k1", "alice", "alice@example.com"))
        .await
        .unwrap();
    assert_eq!(r.status, SignupOutcome::Created);
    assert_eq!(site.state.signups.load(Ordering::SeqCst), 1);
    let pw = store.inner.password_of("k1").unwrap();
    assert!(pw.expose().chars().count() >= 20);
    let ai_view = serde_json::to_string(&r).unwrap();
    assert!(
        !ai_view.contains(pw.expose()),
        "password must not be in the AI-facing result"
    );
    assert!(!format!("{r:?}").contains(pw.expose()));
    let events = store.inner.events();
    assert!(
        events[0].starts_with("persist:") && events[1].contains(":Created"),
        "{events:?}"
    );

    // idempotent replay: no second sign-up
    let again = creator
        .create_account(req("k1", "alice", "alice@example.com"))
        .await
        .unwrap();
    assert_eq!(again, r);
    assert_eq!(site.state.signups.load(Ordering::SeqCst), 1);
    // same key, different request → conflict
    let e = creator
        .create_account(req("k1", "mallory", "m@example.com"))
        .await
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::IdempotencyConflict);

    // needs_verification
    let r = creator
        .create_account(req("k2", "bob", "bob@verify.example"))
        .await
        .unwrap();
    assert_eq!(r.status, SignupOutcome::NeedsVerification);

    // unknown (client timeout after the site created the account) → reconcile, no duplicate
    let r = creator
        .create_account(req("k3", "slowpoke", "slow@example.com"))
        .await
        .unwrap();
    assert_eq!(r.status, SignupOutcome::Unknown);
    assert!(r.message.en.contains("Do not register again"));
    let created_before = site.state.signups.load(Ordering::SeqCst);
    let requests_before = site.state.signup_requests.load(Ordering::SeqCst);
    let r = creator
        .create_account(req("k3", "slowpoke", "slow@example.com"))
        .await
        .unwrap();
    assert_eq!(
        r.status,
        SignupOutcome::Created,
        "reconciled via exists + login"
    );
    assert_eq!(site.state.signups.load(Ordering::SeqCst), created_before);
    assert_eq!(
        site.state.signup_requests.load(Ordering::SeqCst),
        requests_before,
        "no blind re-registration"
    );

    // persisting fails → nothing is submitted
    store.inner.set_fail_persist(true);
    let before = site.state.signup_requests.load(Ordering::SeqCst);
    let e = creator
        .create_account(req("k4", "carol", "carol@example.com"))
        .await
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::SecretUnavailable);
    assert_eq!(site.state.signup_requests.load(Ordering::SeqCst), before);
    assert!(!site.state.has_account("carol"));
    store.inner.set_fail_persist(false);

    // username taken → failed, explained
    let e = creator
        .create_account(req("k5", "alice", "other@example.com"))
        .await
        .unwrap_err();
    assert_eq!(e.details["reason"], "username_taken");

    // invalid input, unknown adapter, missing idempotency key
    assert_eq!(
        creator
            .create_account(req("k6", "a b", "x@example.com"))
            .await
            .unwrap_err()
            .code,
        ErrorCode::InvalidRequest
    );
    assert_eq!(
        creator
            .create_account(req("", "dave", "d@example.com"))
            .await
            .unwrap_err()
            .code,
        ErrorCode::InvalidRequest
    );
    let mut other = req("k7", "erin", "e@example.com");
    other.adapter = "bank".into();
    assert_eq!(
        creator.create_account(other).await.unwrap_err().code,
        ErrorCode::NotSupported
    );

    assert_eq!(
        store.violations.load(Ordering::SeqCst),
        0,
        "pending record always persisted before submit"
    );

    // browser.start_task: adapted action only, output filtered (no password / session).
    let login = SiteLogin {
        username: "alice".into(),
        password: store.inner.password_of("k1").unwrap(),
    };
    let t = creator
        .start_task("demo", "account.profile", login, &json!({}))
        .await
        .unwrap();
    assert_eq!(
        t.data,
        json!({"username": "alice", "plan": "free", "created_at": "2026-10-30T12:00:00Z"})
    );
    let login = SiteLogin {
        username: "alice".into(),
        password: store.inner.password_of("k1").unwrap(),
    };
    assert_eq!(
        creator
            .start_task("demo", "account.delete", login, &json!({}))
            .await
            .unwrap_err()
            .code,
        ErrorCode::ScopeDenied
    );
    let bad = SiteLogin {
        username: "alice".into(),
        password: aipass_crypto::SecretString::from("wrong-password-123"),
    };
    assert_eq!(
        creator
            .start_task("demo", "account.profile", bad, &json!({}))
            .await
            .unwrap_err()
            .code,
        ErrorCode::InteractiveAuthRequired
    );

    // The adapter refuses non-loopback plain http.
    assert!(DemoSiteAdapter::new("http://demo.example.com", Duration::from_secs(1)).is_err());
}
