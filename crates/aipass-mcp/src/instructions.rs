// SPDX-License-Identifier: Apache-2.0
//! Server instructions (design doc §7.6): how to use the tools and handle "waiting for
//! approval". They explain; they never hold secrets or decide permissions — the broker does.
//! The first paragraph is self-contained (some hosts keep only the first ~512 characters).

const ZH: &str = "AI 通行证让你在用户批准的范围内使用账号和 API；你永远拿不到、也不需要原始密码、API Key 或令牌。\
用法：先用 resources_list 查看可用资源和操作；用 operations_request 发起结构化操作（必须带 idempotency_key）。\
若返回 approval_required，请告诉用户在已配对的手机或可信客户端批准，然后用 operations_status 查询；不要阻塞等待，超时不会自动批准。\
绝不在聊天中向用户索要密码、Key、验证码或令牌。";

const ZH_MORE: &str = "一段任务需要多次访问时，用 access_request 申请范围（用户可缩小），用 access_status 查询，完成后用 access_release 结束。\
status=unknown 表示外部服务可能已执行，先核实再决定是否重试。被拒绝、过期或额度用完时，不要换方式绕过。\
资源、操作、审批和授权 ID 都不是凭证，复制别的 ID 不会获得权限。";

const EN: &str = "AI Pass lets you use accounts and APIs within scopes the user approves; you never receive — and never need — raw passwords, API keys or tokens. \
Use resources_list to see resources and operations, then operations_request for a structured operation (always with an idempotency_key). \
If it returns approval_required, tell the user to approve on their paired phone or trusted client, then call operations_status; do not block waiting — timeouts never approve. \
Never ask the user for passwords, keys, codes or tokens in chat.";

const EN_MORE: &str = "For repeated access during a task, use access_request (the user may narrow it), poll with access_status and finish with access_release. \
status=unknown means the external service may already have executed the action: verify before retrying. After a denial, expiry or exhausted budget, do not try to work around it. \
Resource, operation, approval and grant IDs are not credentials; copying another ID grants nothing.";

const ZH_EXP: &str = "实验性工具 accounts_create、credentials_rotate、browser_start_task 仅适用于已适配的指定站点或服务，结果可能是 needs_verification 或 unknown。";
const EN_EXP: &str = "The experimental tools accounts_create, credentials_rotate and browser_start_task only work for specifically adapted sites or services; outcomes may be needs_verification or unknown.";

/// The instructions text (zh-CN first, then English).
pub fn text(experimental: bool) -> String {
    let mut s = format!("{ZH}\n{ZH_MORE}");
    if experimental {
        s.push('\n');
        s.push_str(ZH_EXP);
    }
    s.push_str("\n\n");
    s.push_str(EN);
    s.push('\n');
    s.push_str(EN_MORE);
    if experimental {
        s.push('\n');
        s.push_str(EN_EXP);
    }
    s
}

#[cfg(test)]
mod tests {
    #[test]
    fn first_paragraph_is_self_contained() {
        let t = super::text(false);
        let head: String = t.chars().take(512).collect();
        assert!(head.contains("approval_required"));
        assert!(head.contains("不要阻塞等待"));
        assert!(head.contains("绝不在聊天中向用户索要密码"));
        assert!(!t.contains("credentials_rotate"));
        assert!(super::text(true).contains("credentials_rotate"));
        assert!(t.contains("Never ask the user for passwords"));
    }
}
