// SPDX-License-Identifier: Apache-2.0
//! The approval card (design doc §5.3): who asks, for what, where it runs, where results
//! go and for how long — never secrets.

use aipass_types::error::Lang;
use aipass_types::models::{ApprovalRequest, Environment, ProtectionLevel};

fn env_label(e: Environment, lang: Lang) -> &'static str {
    match (e, lang) {
        (Environment::Production, Lang::En) => "PRODUCTION",
        (Environment::Production, _) => "生产环境 production",
        (Environment::Test, Lang::En) => "test",
        (Environment::Test, _) => "测试环境 test",
    }
}

fn level_label(p: ProtectionLevel) -> &'static str {
    match p {
        ProtectionLevel::Isolated => "隔离执行 / isolated",
        ProtectionLevel::Compatible => "兼容连接 / compatible",
    }
}

fn human_duration(secs: u64, lang: Lang) -> String {
    let (n, zh, en) = if secs.is_multiple_of(3600) && secs >= 3600 {
        (secs / 3600, "小时", "h")
    } else if secs.is_multiple_of(60) && secs >= 60 {
        (secs / 60, "分钟", "min")
    } else {
        (secs, "秒", "s")
    };
    if lang == Lang::En { format!("{n} {en}") } else { format!("{n} {zh}") }
}

/// Render the card as terminal text.
pub fn render(r: &ApprovalRequest, lang: Lang, now: &aipass_types::time::Timestamp) -> String {
    let en = lang == Lang::En;
    let mut o = String::new();
    let line = |o: &mut String, zh: &str, enl: &str, v: String| {
        o.push_str(&format!("  {:<16} {v}\n", if en { enl } else { zh }));
    };
    o.push_str(&format!(
        "━━ {} {} ━━\n",
        if en { "Access request" } else { "访问请求" },
        r.approval_request_id
    ));
    line(&mut o, "请求方", "Requested by", format!(
        "{} ({}) {}",
        r.connection.display_name,
        serde_json::to_value(r.connection.host_type).ok().and_then(|v| v.as_str().map(String::from)).unwrap_or_default(),
        if r.connection.verified { if en { "· paired & verified" } else { "· 已配对验证" } } else { "" }
    ));
    line(&mut o, "资源", "Resource", format!("{} · {} · {}", r.resource.alias, r.resource.service, env_label(r.resource.environment, lang)));
    line(&mut o, "内容", "Summary", if en { r.summary.en.clone() } else { r.summary.zh.clone() });
    line(&mut o, "操作", "Operations", r.requested.operations.join(", "));
    if let Some(pg) = &r.requested.scope.postgres {
        for (view, fields) in &pg.views {
            line(&mut o, "视图与字段", "View & fields", format!("{view}: {}", fields.join(", ")));
        }
    }
    if let Some(gh) = &r.requested.scope.github {
        line(&mut o, "仓库", "Repositories", gh.repos.join(", "));
    }
    if let Some(h) = &r.requested.scope.http_api {
        line(&mut o, "API 操作", "API operations", h.operations.join(", "));
    }
    for (view, fields) in &r.excluded_fields {
        line(&mut o, "不包含", "Not included", format!("{view}: {}", fields.join(", ")));
    }
    let l = &r.requested.limits;
    line(&mut o, "限制", "Limits", if en {
        format!("≤{} rows/op, ≤{} rows total, ≤{} requests, ≤{} bytes/result", l.max_rows_per_operation, l.max_rows_per_grant, l.max_requests_per_grant, l.max_result_bytes)
    } else {
        format!("每次 ≤{} 行，共 ≤{} 行，≤{} 次请求，单次结果 ≤{} 字节", l.max_rows_per_operation, l.max_rows_per_grant, l.max_requests_per_grant, l.max_result_bytes)
    });
    line(&mut o, "有效期", "Duration", format!(
        "{} ({})",
        human_duration(r.requested.duration_seconds, lang),
        serde_json::to_value(r.requested.mode).ok().and_then(|v| v.as_str().map(String::from)).unwrap_or_default()
    ));
    line(&mut o, "执行设备", "Runs on", format!("{} · {}", r.executor.name, level_label(r.executor.protection_level)));
    line(&mut o, "结果发送给", "Results go to", r.recipients.iter().map(|x| x.display_name.clone()).collect::<Vec<_>>().join(", "));
    let left = (r.expires_at - *now).num_seconds().max(0);
    line(&mut o, "等待批准", "Expires in", if en { format!("{left} s (never auto-approved)") } else { format!("{left} 秒（超时不会自动批准）") });
    o.push_str(if en {
        "  ⚠ If an AI agent can control or read this terminal, it can see this card and type here.\n    For production data approve on your phone or another trusted device.\n"
    } else {
        "  ⚠ 如果有 AI 代理能控制或读取本终端，它能看到此卡片并在此输入。\n    生产数据请在手机或其他可信设备上批准。\n"
    });
    o
}
