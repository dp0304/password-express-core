// SPDX-License-Identifier: Apache-2.0
//! GitHub connector against a local mock (test-only base override). Covers allowlisted
//! repos, per-operation output field allowlists, pagination bounds and budget caps,
//! 401 → INTERACTIVE_AUTH_REQUIRED (A17), rate limits, redirects never followed, and the
//! token never echoed back (A18).

mod support;

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use aipass_types::ErrorCode;
use aipass_types::exec::ExecutorBackend;
use aipass_types::models::{Connector, Limits};
use aipass_types::vault::EntryKind;
use axum::Router;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use base64::Engine as _;
use serde_json::{Value, json};
use support::*;

const TOKEN: &str = "ghp_TestTokenAbcdefghijklmnopqrstuvwxyz0123";

/// (path, sorted query, authorization header)
type Hits = Arc<Mutex<Vec<(String, String, Option<String>)>>>;

#[derive(Clone, Default)]
struct Mock {
    hits: Hits,
    evil_port: Arc<Mutex<u16>>,
}

fn auth_ok(h: &HeaderMap) -> bool {
    h.get("authorization").and_then(|v| v.to_str().ok()) == Some(&format!("Bearer {TOKEN}"))
}

fn record(m: &Mock, path: String, q: &std::collections::HashMap<String, String>, h: &HeaderMap) {
    let mut qs: Vec<String> = q.iter().map(|(k, v)| format!("{k}={v}")).collect();
    qs.sort();
    m.hits.lock().unwrap().push((
        path,
        qs.join("&"),
        h.get("authorization")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned),
    ));
}

fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        axum::Json(json!({"message": "Bad credentials"})),
    )
        .into_response()
}

async fn repo(
    State(m): State<Mock>,
    Path((owner, name)): Path<(String, String)>,
    Query(q): Query<std::collections::HashMap<String, String>>,
    h: HeaderMap,
) -> Response {
    record(&m, format!("/repos/{owner}/{name}"), &q, &h);
    if !auth_ok(&h) {
        return unauthorized();
    }
    match name.as_str() {
        "app" => axum::Json(json!({
            "id": 42, "name": "app", "full_name": "octo/app", "private": true,
            "description": format!("deploy with {TOKEN}"),
            "default_branch": "main", "language": "Rust", "topics": ["ai"],
            "owner": {"login": "octo", "email": "owner@example.com", "id": 1},
            "permissions": {"admin": true}, "secret_scanning": "enabled",
            "clone_url": "https://x-access-token:abc123@github.com/octo/app.git"
        }))
        .into_response(),
        "limited" => {
            let reset = aipass_types::time::unix_now() + 60;
            (
                StatusCode::FORBIDDEN,
                [
                    ("x-ratelimit-remaining", "0".to_owned()),
                    ("x-ratelimit-reset", reset.to_string()),
                ],
                axum::Json(json!({"message": "API rate limit exceeded"})),
            )
                .into_response()
        }
        "moved" => {
            let port = *m.evil_port.lock().unwrap();
            (
                StatusCode::MOVED_PERMANENTLY,
                [("location", format!("http://127.0.0.1:{port}/steal"))],
                "",
            )
                .into_response()
        }
        "echo" => {
            let auth = h
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_owned();
            axum::Json(json!({"name": "echo", "description": format!("you sent: {auth}")}))
                .into_response()
        }
        _ => (
            StatusCode::NOT_FOUND,
            axum::Json(json!({"message": "Not Found"})),
        )
            .into_response(),
    }
}

async fn contents(
    State(m): State<Mock>,
    Path((owner, name, path)): Path<(String, String, String)>,
    Query(q): Query<std::collections::HashMap<String, String>>,
    h: HeaderMap,
) -> Response {
    record(&m, format!("/repos/{owner}/{name}/contents/{path}"), &q, &h);
    if !auth_ok(&h) {
        return unauthorized();
    }
    let b64 = |b: &[u8]| {
        let s = base64::engine::general_purpose::STANDARD.encode(b);
        // GitHub wraps at 60 columns.
        s.as_bytes()
            .chunks(60)
            .map(|c| String::from_utf8_lossy(c).to_string())
            .collect::<Vec<_>>()
            .join("\n")
    };
    match path.as_str() {
        "README.md" => axum::Json(json!({"type": "file", "name": "README.md", "path": "README.md", "sha": "abc", "size": 12,
            "encoding": "base64", "content": b64(b"# Hello AI\n"), "download_url": "https://raw.example/README.md?token=zzz"}))
        .into_response(),
        "src/config.rs" => axum::Json(json!({"type": "file", "name": "config.rs", "path": "src/config.rs", "sha": "def", "size": 50,
            "encoding": "base64", "content": b64(format!("const T: &str = \"{TOKEN}\";\n").as_bytes())}))
        .into_response(),
        "big.txt" => {
            let text = "0123456789abcdef\n".repeat(20_000);
            axum::Json(json!({"type": "file", "name": "big.txt", "path": "big.txt", "sha": "big", "size": text.len(),
                "encoding": "base64", "content": b64(text.as_bytes())}))
            .into_response()
        }
        "bin.dat" => axum::Json(json!({"type": "file", "name": "bin.dat", "path": "bin.dat", "sha": "bin", "size": 4,
            "encoding": "base64", "content": b64(&[0xff, 0xfe, 0x00, 0x80])}))
        .into_response(),
        "docs" => axum::Json(json!([
            {"type": "file", "name": "a.md", "path": "docs/a.md", "size": 3, "sha": "1", "url": "https://api/x", "_links": {}},
            {"type": "dir", "name": "img", "path": "docs/img", "size": 0, "sha": "2"}
        ]))
        .into_response(),
        _ => (StatusCode::NOT_FOUND, axum::Json(json!({"message": "Not Found"}))).into_response(),
    }
}

async fn list(
    State(m): State<Mock>,
    Path((owner, name, kind)): Path<(String, String, String)>,
    Query(q): Query<std::collections::HashMap<String, String>>,
    h: HeaderMap,
) -> Response {
    record(&m, format!("/repos/{owner}/{name}/{kind}"), &q, &h);
    if !auth_ok(&h) {
        return unauthorized();
    }
    let per_page: usize = q.get("per_page").and_then(|v| v.parse().ok()).unwrap_or(30);
    let n = per_page.min(50);
    let items: Vec<Value> = (1..=n)
        .map(|i| match kind.as_str() {
            "issues" => {
                let mut v = json!({"number": i, "title": format!("issue {i}"), "state": "open",
                    "user": {"login": "dev", "email": "dev@example.com", "site_admin": false},
                    "labels": [{"name": "bug", "color": "f00", "id": 9}], "body": if i == 2 { format!("token: {TOKEN}") } else { "ok".into() },
                    "reactions": {"+1": 3}, "node_id": "X"});
                if i % 2 == 0 {
                    v["pull_request"] = json!({"url": "https://api/pr"});
                }
                v
            }
            "pulls" => json!({"number": i, "title": "pr", "state": "open", "draft": false, "user": {"login": "dev", "email": "e"},
                "head": {"ref": "feature", "sha": "aaa", "repo": {"full_name": "fork/app"}}, "base": {"ref": "main"},
                "merge_commit_sha": "bbb", "body": "desc"}),
            _ => json!({"sha": format!("{i:040}"), "commit": {"message": "fix", "author": {"name": "Dev", "email": "dev@example.com", "date": "2026-10-01T00:00:00Z"},
                "committer": {"name": "Dev", "email": "dev@example.com", "date": "2026-10-01T00:00:00Z"}, "verification": {"payload": "x"}},
                "author": {"login": "dev", "email": "dev@example.com"}}),
        })
        .collect();
    axum::Json(Value::Array(items)).into_response()
}

async fn serve(router: Router) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    addr
}

#[tokio::test]
async fn github_connector_against_mock() {
    let mock = Mock::default();
    let router = Router::new()
        .route("/repos/{owner}/{name}", get(repo))
        .route("/repos/{owner}/{name}/contents/{*path}", get(contents))
        .route("/repos/{owner}/{name}/{kind}", get(list))
        .with_state(mock.clone());
    let addr = serve(router).await;
    let evil_hits = Arc::new(Mutex::new(0usize));
    let eh = evil_hits.clone();
    let evil = serve(Router::new().fallback(move || {
        let eh = eh.clone();
        async move {
            *eh.lock().unwrap() += 1;
            "stolen"
        }
    }))
    .await;
    *mock.evil_port.lock().unwrap() = evil.port();

    let exec = Arc::new(
        builder()
            .github_api_base_override_for_tests(
                url::Url::parse(&format!("http://{addr}/")).unwrap(),
            )
            .build()
            .unwrap(),
    );
    let ops = [
        "github.repo.get",
        "github.contents.get",
        "github.issues.list",
        "github.pulls.list",
        "github.commits.list",
    ];
    let r = resource(
        &exec,
        Connector::Github,
        json!({"allowed_repos": ["octo/app", "octo/limited", "octo/moved", "octo/echo"]}),
        &ops,
    );
    let g = grant_with(&exec, material(&r, EntryKind::ApiKey, None, TOKEN, 600)).await;

    // repo.get: allowlisted fields only, token in data redacted, never echoed.
    let res = run(
        &exec,
        &r,
        &g,
        "github.repo.get",
        json!({"repo": "Octo/App"}),
        limits(),
    )
    .await;
    assert_no_leak(&res, TOKEN, "repo.get");
    assert_no_leak(&res, "abc123", "clone url creds");
    let out = res.unwrap();
    let repo = &out.data["repo"];
    assert_eq!(repo["full_name"], "octo/app");
    assert_eq!(repo["description"], "[REDACTED]");
    assert_eq!(repo["owner"], json!({"login": "octo"}));
    for forbidden in ["permissions", "secret_scanning", "clone_url"] {
        assert!(
            repo.get(forbidden).is_none(),
            "{forbidden} must not be returned"
        );
    }
    assert_eq!(out.restricted_fields, vec!["description".to_owned()]);
    {
        let hits = mock.hits.lock().unwrap();
        let (path, _, auth) = hits.last().unwrap();
        assert_eq!(path, "/repos/octo/app");
        assert_eq!(auth.as_deref(), Some(format!("Bearer {TOKEN}").as_str()));
    }

    // Repos outside the allowlist never reach GitHub.
    let before = mock.hits.lock().unwrap().len();
    for repo in ["octo/other", "evil/app", "octo/app/../other", "octo"] {
        let e = run(
            &exec,
            &r,
            &g,
            "github.repo.get",
            json!({"repo": repo}),
            limits(),
        )
        .await
        .unwrap_err();
        assert!(
            matches!(e.code, ErrorCode::ScopeDenied | ErrorCode::InvalidRequest),
            "{repo}: {e:?}"
        );
    }
    assert_eq!(mock.hits.lock().unwrap().len(), before);

    // contents.get
    let out = run(
        &exec,
        &r,
        &g,
        "github.contents.get",
        json!({"repo": "octo/app", "path": "README.md"}),
        limits(),
    )
    .await
    .unwrap();
    assert_eq!(out.data["text"], "# Hello AI\n");
    assert!(out.data.get("download_url").is_none());
    let res = run(
        &exec,
        &r,
        &g,
        "github.contents.get",
        json!({"repo": "octo/app", "path": "src/config.rs"}),
        limits(),
    )
    .await;
    assert_no_leak(&res, TOKEN, "contents with token");
    assert_eq!(res.unwrap().restricted_fields, vec!["text".to_owned()]);
    let out = run(
        &exec,
        &r,
        &g,
        "github.contents.get",
        json!({"repo": "octo/app", "path": "big.txt"}),
        limits(),
    )
    .await
    .unwrap();
    assert!(out.truncated);
    assert_eq!(out.data["text_truncated"], true);
    assert!(out.bytes <= 262_144);
    let out = run(
        &exec,
        &r,
        &g,
        "github.contents.get",
        json!({"repo": "octo/app", "path": "bin.dat"}),
        limits(),
    )
    .await
    .unwrap();
    assert_eq!(out.data["binary"], true);
    assert!(out.data["text"].is_null());
    let out = run(
        &exec,
        &r,
        &g,
        "github.contents.get",
        json!({"repo": "octo/app", "path": "docs"}),
        limits(),
    )
    .await
    .unwrap();
    assert_eq!(out.data["entries"].as_array().unwrap().len(), 2);
    assert!(out.data["entries"][0].get("url").is_none());
    for bad in ["../secrets", "/etc/passwd", "a/../../b", "docs/./x", ""] {
        let e = run(
            &exec,
            &r,
            &g,
            "github.contents.get",
            json!({"repo": "octo/app", "path": bad}),
            limits(),
        )
        .await
        .unwrap_err();
        assert_eq!(e.code, ErrorCode::InvalidRequest, "{bad}");
    }
    let e = run(
        &exec,
        &r,
        &g,
        "github.contents.get",
        json!({"repo": "octo/app", "path": "README.md", "ref": "main..evil"}),
        limits(),
    )
    .await
    .unwrap_err();
    assert_eq!(e.code, ErrorCode::InvalidRequest);

    // issues.list: page bounds, budget-capped per_page, field allowlist.
    let five = Limits {
        max_rows_per_grant: 5,
        ..limits()
    };
    let res = run(
        &exec,
        &r,
        &g,
        "github.issues.list",
        json!({"repo": "octo/app", "per_page": 100, "labels": ["bug"]}),
        five,
    )
    .await;
    assert_no_leak(&res, TOKEN, "issues");
    let out = res.unwrap();
    assert_eq!(out.rows, Some(5));
    assert!(out.truncated);
    {
        let hits = mock.hits.lock().unwrap();
        let (path, q, _) = hits.last().unwrap();
        assert_eq!(path, "/repos/octo/app/issues");
        assert_eq!(
            q, "labels=bug&page=1&per_page=5",
            "per_page capped by the remaining grant budget"
        );
    }
    let first = &out.data["items"][0];
    assert_eq!(first["user"], json!({"login": "dev"}));
    assert_eq!(first["labels"], json!([{"name": "bug"}]));
    assert!(first.get("reactions").is_none() && first.get("node_id").is_none());
    assert_eq!(out.data["items"][1]["is_pull_request"], true);
    assert_eq!(out.data["items"][1]["body"], "[REDACTED]");
    for bad in [
        json!({"repo": "octo/app", "page": 101}),
        json!({"repo": "octo/app", "per_page": 0}),
        json!({"repo": "octo/app", "per_page": 101}),
        json!({"repo": "octo/app", "state": "merged"}),
        json!({"repo": "octo/app", "sha": "main"}),
        json!({"repo": "octo/app", "q": "x"}),
    ] {
        let e = run(&exec, &r, &g, "github.issues.list", bad.clone(), limits())
            .await
            .unwrap_err();
        assert_eq!(e.code, ErrorCode::InvalidRequest, "{bad}");
    }
    let none = Limits {
        max_rows_per_grant: 0,
        ..limits()
    };
    let e = run(
        &exec,
        &r,
        &g,
        "github.issues.list",
        json!({"repo": "octo/app"}),
        none,
    )
    .await
    .unwrap_err();
    assert_eq!(e.code, ErrorCode::BudgetExhausted);

    let out = run(
        &exec,
        &r,
        &g,
        "github.pulls.list",
        json!({"repo": "octo/app", "state": "all", "per_page": 3}),
        limits(),
    )
    .await
    .unwrap();
    assert_eq!(out.rows, Some(3));
    let pr = &out.data["items"][0];
    assert_eq!(pr["head"], json!({"ref": "feature"}));
    assert!(pr.get("merge_commit_sha").is_none());
    let out = run(
        &exec,
        &r,
        &g,
        "github.commits.list",
        json!({"repo": "octo/app", "sha": "main", "path": "src/lib.rs", "per_page": 2, "page": 2}),
        limits(),
    )
    .await
    .unwrap();
    let c0 = &out.data["items"][0];
    assert_eq!(
        c0["commit"]["author"],
        json!({"name": "Dev", "date": "2026-10-01T00:00:00Z"})
    );
    assert!(c0["commit"].get("verification").is_none());
    assert_eq!(c0["author"], json!({"login": "dev"}));
    assert!(
        !out.data.to_string().contains("dev@example.com"),
        "emails are not in the allowlist"
    );

    // Upstream errors.
    let e = run(
        &exec,
        &r,
        &g,
        "github.repo.get",
        json!({"repo": "octo/limited"}),
        limits(),
    )
    .await
    .unwrap_err();
    assert_eq!(e.code, ErrorCode::RateLimited);
    assert!(e.details.get("retry_after_seconds").is_some());
    let res = run(
        &exec,
        &r,
        &g,
        "github.repo.get",
        json!({"repo": "octo/moved"}),
        limits(),
    )
    .await;
    let e = res.unwrap_err();
    assert_eq!(e.code, ErrorCode::UpstreamError);
    assert_eq!(e.details["reason"], "redirect_not_followed");
    assert_eq!(
        *evil_hits.lock().unwrap(),
        0,
        "redirect target must never be contacted"
    );
    let res = run(
        &exec,
        &r,
        &g,
        "github.repo.get",
        json!({"repo": "octo/echo"}),
        limits(),
    )
    .await;
    assert_no_leak(&res, TOKEN, "echoed auth header");
    assert_eq!(res.unwrap().data["repo"]["description"], "[REDACTED]");

    // A17: revoked / wrong token → re-authorise on a trusted device, never in chat.
    let g_bad = grant_with(
        &exec,
        material(
            &r,
            EntryKind::ApiKey,
            None,
            "ghp_WrongTokenWrongTokenWrongToken01",
            600,
        ),
    )
    .await;
    let res = run(
        &exec,
        &r,
        &g_bad,
        "github.repo.get",
        json!({"repo": "octo/app"}),
        limits(),
    )
    .await;
    assert_no_leak(&res, "ghp_WrongTokenWrongTokenWrongToken01", "401");
    let e = res.unwrap_err();
    assert_eq!(e.code, ErrorCode::InteractiveAuthRequired);
    assert!(
        e.message(aipass_types::Lang::ZhCn)
            .contains("不要在聊天中提供")
    );
    assert!(e.message(aipass_types::Lang::En).contains("never paste"));

    // Wrong credential kind.
    let g_db = grant_with(
        &exec,
        material(&r, EntryKind::Database, Some("u"), "pw-123456", 600),
    )
    .await;
    let e = run(
        &exec,
        &r,
        &g_db,
        "github.repo.get",
        json!({"repo": "octo/app"}),
        limits(),
    )
    .await
    .unwrap_err();
    assert_eq!(e.code, ErrorCode::SecretUnavailable);

    // The test override cannot be set from resource config; http / private bases are refused.
    for cfg in [
        json!({"allowed_repos": ["octo/app"], "test_base_override": format!("http://{addr}/")}),
        json!({"allowed_repos": ["octo/app"], "api_base": format!("http://{addr}/")}),
    ] {
        let rr = resource(&exec, Connector::Github, cfg.clone(), &ops);
        let e = exec
            .normalize(&rr, "github.repo.get", &json!({"repo": "octo/app"}))
            .unwrap_err();
        assert_eq!(e.code, ErrorCode::InvalidRequest, "{cfg}");
    }
    // Without the override, GitHub traffic goes through the egress guard (GHES on a private
    // address needs allow_private_network).
    let plain = Arc::new(builder().build().unwrap());
    let rr = resource(
        &plain,
        Connector::Github,
        json!({"allowed_repos": ["octo/app"], "api_base": "https://10.20.30.40/api/v3"}),
        &ops,
    );
    let gg = grant_with(&plain, material(&rr, EntryKind::ApiKey, None, TOKEN, 600)).await;
    let e = run(
        &plain,
        &rr,
        &gg,
        "github.repo.get",
        json!({"repo": "octo/app"}),
        limits(),
    )
    .await
    .unwrap_err();
    assert_eq!(e.code, ErrorCode::ScopeDenied);
    assert_eq!(e.details["reason"], "blocked_address");
    assert!(!support::error_text(&e).contains(TOKEN));

    // Specs: five read operations, retry-safe, zh/en descriptions.
    let specs = <aipass_executor::Executor as aipass_types::exec::ExecutorBackend>::operation_specs(
        &exec, "github",
    );
    assert_eq!(specs.len(), 5);
    assert!(
        specs
            .iter()
            .all(|s| s.retry_safe && !s.description_zh.is_empty() && !s.description_en.is_empty())
    );
    let rep = <aipass_executor::Executor as aipass_types::exec::ExecutorBackend>::revoke_upstream(
        &exec,
        g.as_str(),
    )
    .await;
    assert_eq!(rep.status, aipass_types::models::LevelStatus::NotApplicable);
    assert!(
        !exec.has_credential(g.as_str()),
        "revocation includes end_sessions"
    );
}
