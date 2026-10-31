// SPDX-License-Identifier: Apache-2.0
//! Human summaries for approval requests, in the field order of design doc §5.3:
//! requester (verified) → resource → operation → data fields (and excluded fields) →
//! scope / limits / duration → execution location → result recipients.
//!
//! The approving client renders the structured fields; this text is a convenience (push
//! previews never contain it — they carry only `{mailbox, message_id}`).

use std::collections::BTreeMap;

use aipass_types::error::Localized;
use aipass_types::models::{
    AccessSpec, ApprovalMode, Connector, Environment, GrantScope, ProtectionLevel, Resource,
};
use serde_json::Value;

/// One operation as shown to the user.
pub(crate) struct OpLabel {
    pub name: String,
    pub zh: String,
    pub en: String,
}

/// Inputs of [`approval_summary`].
pub(crate) struct SummaryInput<'a> {
    pub connection_name: &'a str,
    pub resource: &'a Resource,
    pub ops: &'a [OpLabel],
    pub spec: &'a AccessSpec,
    pub excluded: &'a BTreeMap<String, Vec<String>>,
    pub executor_name: &'a str,
    pub protection: ProtectionLevel,
    pub reason: Option<&'a str>,
}

pub(crate) fn approval_summary(i: &SummaryInput<'_>) -> Localized {
    let env = match i.resource.environment {
        Environment::Test => ("测试环境", "test"),
        Environment::Production => ("生产环境", "production"),
    };
    let ops_zh = join(i.ops.iter().map(|o| format!("{}（{}）", o.zh, o.name)), "、");
    let ops_en = join(i.ops.iter().map(|o| format!("{} ({})", o.en, o.name)), ", ");
    let (data_zh, data_en) = data_lines(&i.spec.scope, i.excluded);
    let (mode_zh, mode_en) = match i.spec.mode {
        ApprovalMode::Once => ("仅本次操作", "this operation only"),
        ApprovalMode::Task => ("本次任务", "this task"),
        ApprovalMode::Rule => ("持续规则", "standing rule"),
    };
    let l = &i.spec.limits;
    let prot = i.protection.label();
    let mut zh = format!(
        "「{conn}」（已配对的连接；名称由应用自报）请求访问「{alias}」（{env_zh}）\n操作：{ops_zh}\n数据：{data_zh}\n范围：{mode_zh}，最长 {dur_zh}，每次最多返回 {rows} 行，累计最多 {total} 行、{reqs} 次请求\n执行位置：{exe}（{prot_zh}）\n结果接收方：{conn} 及其模型服务",
        conn = i.connection_name,
        alias = i.resource.alias,
        env_zh = env.0,
        dur_zh = duration_zh(i.spec.duration_seconds),
        rows = thousands(l.max_rows_per_operation),
        total = thousands(l.max_rows_per_grant),
        reqs = thousands(l.max_requests_per_grant),
        exe = i.executor_name,
        prot_zh = prot.zh,
    );
    let mut en = format!(
        "\"{conn}\" (paired connection; name self-reported by the app) requests access to \"{alias}\" ({env_en})\nOperation: {ops_en}\nData: {data_en}\nScope: {mode_en}, up to {dur_en}, at most {rows} rows per request, {total} rows and {reqs} requests in total\nRuns on: {exe} ({prot_en})\nResults go to: {conn} and its model provider",
        conn = i.connection_name,
        alias = i.resource.alias,
        env_en = env.1,
        dur_en = duration_en(i.spec.duration_seconds),
        rows = thousands(l.max_rows_per_operation),
        total = thousands(l.max_rows_per_grant),
        reqs = thousands(l.max_requests_per_grant),
        exe = i.executor_name,
        prot_en = prot.en,
    );
    if let Some(r) = i.reason.map(str::trim).filter(|r| !r.is_empty()) {
        let r: String = r.chars().filter(|c| !c.is_control()).take(200).collect();
        zh.push_str(&format!("\n说明（AI 自述，未经验证）：{r}"));
        en.push_str(&format!("\nReason (self-declared by the AI, unverified): {r}"));
    }
    Localized::new(zh, en)
}

fn data_lines(scope: &GrantScope, excluded: &BTreeMap<String, Vec<String>>) -> (String, String) {
    let mut zh = Vec::new();
    let mut en = Vec::new();
    if let Some(pg) = &scope.postgres {
        for (view, fields) in &pg.views {
            let mut z = format!("{view}：{}", join(fields.iter().cloned(), "、"));
            let mut e = format!("{view}: {}", join(fields.iter().cloned(), ", "));
            if let Some(ex) = excluded.get(view).filter(|x| !x.is_empty()) {
                z.push_str(&format!("（不含 {}）", join(ex.iter().cloned(), "、")));
                e.push_str(&format!(" (excluding {})", join(ex.iter().cloned(), ", ")));
            }
            zh.push(z);
            en.push(e);
        }
    }
    if let Some(gh) = &scope.github {
        zh.push(format!("仓库 {}", join(gh.repos.iter().cloned(), "、")));
        en.push(format!("repositories {}", join(gh.repos.iter().cloned(), ", ")));
    }
    if let Some(h) = &scope.http_api {
        zh.push(format!("接口 {}", join(h.operations.iter().cloned(), "、")));
        en.push(format!("API operations {}", join(h.operations.iter().cloned(), ", ")));
    }
    if zh.is_empty() {
        ("按操作定义的固定输出字段".into(), "the operation's fixed output fields".into())
    } else {
        (zh.join("；"), en.join("; "))
    }
}

/// For PostgreSQL resources: fields that the resource exposes for a view but the request
/// does not include (UI: "不含客户邮箱"). Best effort from the CONTRACTS §8 config shape
/// `allowed_views: {"schema.view": {fields: [...]}}`.
pub(crate) fn excluded_fields(resource: &Resource, scope: &GrantScope) -> BTreeMap<String, Vec<String>> {
    let mut out = BTreeMap::new();
    if resource.connector != Connector::Postgres {
        return out;
    }
    let (Some(pg), Some(Value::Object(views))) =
        (&scope.postgres, resource.config.get("allowed_views"))
    else {
        return out;
    };
    for (view, requested) in &pg.views {
        let Some(Value::Array(all)) = views.get(view).and_then(|v| v.get("fields")) else {
            continue;
        };
        let ex: Vec<String> = all
            .iter()
            .filter_map(Value::as_str)
            .filter(|f| !requested.iter().any(|r| r == f))
            .map(str::to_owned)
            .collect();
        if !ex.is_empty() {
            out.insert(view.clone(), ex);
        }
    }
    out
}

fn join(items: impl Iterator<Item = String>, sep: &str) -> String {
    items.collect::<Vec<_>>().join(sep)
}

pub(crate) fn thousands(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::with_capacity(s.len() + s.len() / 3);
    for (idx, ch) in s.chars().enumerate() {
        if idx > 0 && (s.len() - idx).is_multiple_of(3) {
            out.push(',');
        }
        out.push(ch);
    }
    out
}

pub(crate) fn duration_zh(secs: u64) -> String {
    if secs < 60 {
        format!("{secs} 秒")
    } else if secs < 3600 {
        format!("{} 分钟", secs.div_ceil(60))
    } else if secs.is_multiple_of(3600) {
        format!("{} 小时", secs / 3600)
    } else {
        format!("{} 小时 {} 分钟", secs / 3600, (secs % 3600).div_ceil(60))
    }
}

pub(crate) fn duration_en(secs: u64) -> String {
    let plural = |n: u64, w: &str| if n == 1 { format!("1 {w}") } else { format!("{n} {w}s") };
    if secs < 60 {
        plural(secs, "second")
    } else if secs < 3600 {
        plural(secs.div_ceil(60), "minute")
    } else if secs.is_multiple_of(3600) {
        plural(secs / 3600, "hour")
    } else {
        format!(
            "{} {}",
            plural(secs / 3600, "hour"),
            plural((secs % 3600).div_ceil(60), "minute")
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats() {
        assert_eq!(thousands(1000), "1,000");
        assert_eq!(thousands(262_144), "262,144");
        assert_eq!(thousands(20), "20");
        assert_eq!(duration_zh(900), "15 分钟");
        assert_eq!(duration_en(900), "15 minutes");
        assert_eq!(duration_zh(86_400), "24 小时");
        assert_eq!(duration_en(3600), "1 hour");
        assert_eq!(duration_en(5400), "1 hour 30 minutes");
    }
}
