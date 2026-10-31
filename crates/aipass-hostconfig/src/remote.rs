// SPDX-License-Identifier: Apache-2.0
//! Remote hosts (ChatGPT, Claude custom connectors): instructions as data — server URL and
//! OAuth steps. Nothing is written locally. Product UIs change often; the steps name the
//! entry points current at the time of writing and point at the official docs.

use aipass_types::Localized;
use serde::Serialize;

use crate::HostConfigError;
use crate::model::{CompatLabel, Host, label_for, Os};

/// Where the remote MCP endpoint lives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoteTarget {
    /// Official remote MCP gateway (OAuth 2.1 + PKCE, tunnel to your node). Base URL, e.g.
    /// `https://cloud.aipass.example`.
    OfficialGateway(String),
    /// A self-hosted `aipass-node` reachable over HTTPS (Bearer `aipc_…` connection token).
    SelfHostNode(String),
}

/// Instructions for one remote host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RemoteInstructions {
    /// Host.
    pub host: Host,
    /// Label (`standard_protocol`; availability also depends on the host's plan/workspace).
    pub label: CompatLabel,
    /// MCP server URL to paste into the host.
    pub server_url: String,
    /// OAuth protected-resource metadata URL (official gateway only).
    pub protected_resource_metadata: Option<String>,
    /// Authentication mode to choose in the host.
    pub auth: Localized,
    /// OAuth scope (official gateway only).
    pub oauth_scope: Option<String>,
    /// Step-by-step instructions.
    pub steps: Vec<Localized>,
    /// Caveats (honesty rules: no E2E-blind claim, no "verified" claim).
    pub notes: Vec<Localized>,
    /// Official documentation.
    pub docs: Vec<String>,
}

fn base_url(s: &str) -> Result<String, HostConfigError> {
    let u = url::Url::parse(s.trim())
        .map_err(|_| HostConfigError::InvalidEntry(format!("{s:?} is not a URL")))?;
    if u.scheme() != "https" && !(u.scheme() == "http" && matches!(u.host_str(), Some("127.0.0.1" | "localhost"))) {
        return Err(HostConfigError::InvalidEntry(
            "remote MCP servers must use https://".into(),
        ));
    }
    if !u.username().is_empty() || u.password().is_some() || u.query().is_some() {
        return Err(HostConfigError::SecretInEntry);
    }
    Ok(u.as_str().trim_end_matches('/').to_owned())
}

fn l(zh: &str, en: &str) -> Localized {
    Localized::new(zh, en)
}

/// Build the instructions for `host` (must be [`Host::Chatgpt`] or [`Host::ClaudeConnector`]).
pub fn remote_instructions(host: Host, target: &RemoteTarget) -> Result<RemoteInstructions, HostConfigError> {
    if !host.is_remote() {
        return Err(HostConfigError::Unsupported {
            host,
            reason: "local hosts are configured with plan()/apply()".into(),
        });
    }
    let (base, official) = match target {
        RemoteTarget::OfficialGateway(b) => (base_url(b)?, true),
        RemoteTarget::SelfHostNode(b) => (base_url(b)?, false),
    };
    let server_url = format!("{base}/mcp");
    let mut notes = vec![
        l(
            "AI 宿主拿到的只是 AI 通行证的有限访问令牌，不是数据库密码或 GitHub 令牌；每项业务资源仍需在手机或可信客户端单独批准。",
            "The AI host only receives a limited AI Pass access token — never your database password or GitHub token; every business resource still needs approval on your phone or trusted client.",
        ),
        l(
            "此接入方式为“标准协议可接入”，尚未完成本产品的逐版本验收；可用性还取决于宿主的套餐和工作区权限。",
            "This path is labelled “standard protocol”: it has not passed our per-version acceptance run, and availability depends on the host's plan and workspace permissions.",
        ),
    ];
    if official {
        notes.push(l(
            "官方远程网关会转发 MCP 请求和允许返回的结果，它不是端到端不可见的中继；凭证仍只在你的执行设备上使用。",
            "The official remote gateway forwards MCP requests and permitted results; it is not an end-to-end-blind relay. Credentials are still only used on your executor.",
        ));
    } else {
        notes.push(l(
            "自托管节点直接接收远程宿主的请求，请只通过 HTTPS 公开 /mcp，并妥善保管连接令牌（aipc_…）；令牌只能访问本连接被批准的范围。",
            "A self-hosted node receives the remote host's requests directly: expose /mcp over HTTPS only and keep the connection token (aipc_…) safe; it can only reach what this connection has been approved for.",
        ));
    }
    let consent = l(
        "在 AI 通行证的授权页登录，选择在线的执行设备和允许的项目；页面显示配对码后，在手机或桌面 App 核对并确认此连接。",
        "On the AI Pass consent page, sign in and pick an online executor and the allowed projects; when the page shows a pairing code, compare and confirm the connection on your phone or desktop app.",
    );
    let (steps, auth, docs) = match (host, official) {
        (Host::Chatgpt, true) => (
            vec![
                l("在 ChatGPT 网页版打开“Plugins”（旧界面为“设置 → Apps/Connectors”，可能需要先开启 Developer Mode）。", "In ChatGPT on the web, open Plugins (older UIs: Settings → Apps/Connectors; Developer Mode may need to be enabled first)."),
                l("点击“+”，选择“Add custom MCP server”，填写名称，例如“AI 通行证”。", "Click “+”, choose “Add custom MCP server” and enter a name such as “AI Pass”."),
                l(&format!("在 Connection 中填入服务地址：{server_url}"), &format!("Under Connection, enter the server URL: {server_url}")),
                l("Authentication 选择 OAuth，阅读风险提示后确认并创建。", "Choose OAuth for Authentication, review the risk warning, confirm and create."),
                consent.clone(),
                l("安装后在对话中输入 @ 选择它。需要批准的操作会提示你在手机或可信客户端处理。", "After installing, type @ in a conversation to select it. Operations that need approval will ask you to approve on your phone or trusted client."),
            ],
            l("OAuth（PKCE S256）", "OAuth (PKCE S256)"),
            vec![
                "https://help.openai.com/en/articles/12584461-creating-custom-mcp-apps-in-chatgpt".to_owned(),
                "https://developers.openai.com/api/docs/guides/custom-mcp-server".to_owned(),
            ],
        ),
        (Host::ClaudeConnector, true) => (
            vec![
                l("个人 Pro / Max：打开“Customize → Connectors”，点击“+ Add”→“Add custom connector”。Team / Enterprise：由所有者在“Organization settings → Connectors”添加。", "Pro / Max: open Customize → Connectors, click “+ Add” → “Add custom connector”. Team / Enterprise: an owner adds it under Organization settings → Connectors."),
                l(&format!("填写名称和远程 MCP 服务地址：{server_url}，点击 Continue。"), &format!("Enter a name and the remote MCP server URL: {server_url}, then click Continue.")),
                l("认证选择“Sign in now”（OAuth），OAuth 客户端可使用推荐选项，然后点击 Add。", "Choose “Sign in now” (OAuth); the recommended OAuth client option works. Click Add."),
                l("点击 Connect 完成登录授权。", "Click Connect to sign in."),
                consent.clone(),
            ],
            l("OAuth（PKCE S256）", "OAuth (PKCE S256)"),
            vec!["https://support.claude.com/en/articles/11175166-get-started-with-custom-connectors-using-remote-mcp".to_owned()],
        ),
        (Host::Chatgpt, false) => {
            notes.push(l(
                "ChatGPT 的自定义 MCP 需要 OAuth 或无认证；自托管节点不提供 OAuth 授权服务器，请改用官方远程网关（节点通过出站隧道连接），或使用支持自定义请求头的宿主。",
                "ChatGPT custom MCP servers need OAuth or no authentication. A self-hosted node does not run an OAuth authorization server, so use the official remote gateway (your node connects through the outbound tunnel) or a host that supports custom request headers.",
            ));
            (
                vec![l("请改用官方远程网关地址，或选择支持请求头认证的宿主。", "Use the official remote gateway URL instead, or a host that supports request-header authentication.")],
                l("不适用", "Not applicable"),
                vec!["https://developers.openai.com/api/docs/guides/custom-mcp-server".to_owned()],
            )
        }
        (Host::ClaudeConnector, false) => (
            vec![
                l("在自托管节点上为此 AI 应用创建连接并取得连接令牌（aipc_…），在手机或可信客户端批准此连接。", "Create a connection for this AI app on your self-hosted node, obtain its connection token (aipc_…) and approve the connection on your phone or trusted client."),
                l("在 Claude 中添加自定义连接器（Customize → Connectors → Add custom connector），服务地址填写：", "In Claude, add a custom connector (Customize → Connectors → Add custom connector) with the server URL:"),
                l(&server_url, &server_url),
                l("认证选择“No sign-in”，在 Request headers 中添加 Authorization: Bearer <连接令牌>。", "Choose “No sign-in” and add the request header Authorization: Bearer <connection token>."),
            ],
            l("请求头 Bearer 连接令牌", "Request header with the Bearer connection token"),
            vec!["https://claude.com/docs/connectors/custom/remote-mcp".to_owned()],
        ),
        _ => unreachable_remote(host)?,
    };
    Ok(RemoteInstructions {
        host,
        label: label_for(host, None, Os::current()),
        protected_resource_metadata: official
            .then(|| format!("{base}/.well-known/oauth-protected-resource/mcp")),
        oauth_scope: official.then(|| "aipass.tools".to_owned()),
        server_url,
        auth,
        steps,
        notes,
        docs,
    })
}

fn unreachable_remote(host: Host) -> Result<(Vec<Localized>, Localized, Vec<String>), HostConfigError> {
    Err(HostConfigError::Unsupported {
        host,
        reason: "not a remote host".into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn official_gateway() {
        let r = remote_instructions(Host::Chatgpt, &RemoteTarget::OfficialGateway("https://cloud.aipass.example/".into())).unwrap();
        assert_eq!(r.server_url, "https://cloud.aipass.example/mcp");
        assert_eq!(
            r.protected_resource_metadata.as_deref(),
            Some("https://cloud.aipass.example/.well-known/oauth-protected-resource/mcp")
        );
        assert_eq!(r.label, CompatLabel::StandardProtocol);
        let all: String = r.steps.iter().chain(r.notes.iter()).map(|s| format!("{}{}", s.zh, s.en)).collect();
        assert!(all.contains("不是端到端不可见"));
        assert!(!all.contains("已验证连接"));
        let c = remote_instructions(Host::ClaudeConnector, &RemoteTarget::OfficialGateway("https://cloud.aipass.example".into())).unwrap();
        assert!(c.steps.iter().any(|s| s.en.contains("https://cloud.aipass.example/mcp")));
    }

    #[test]
    fn self_host_and_errors() {
        let r = remote_instructions(Host::ClaudeConnector, &RemoteTarget::SelfHostNode("https://node.example.com".into())).unwrap();
        assert_eq!(r.server_url, "https://node.example.com/mcp");
        assert!(r.protected_resource_metadata.is_none());
        assert!(remote_instructions(Host::Chatgpt, &RemoteTarget::SelfHostNode("http://node.example.com".into())).is_err());
        assert!(remote_instructions(Host::Chatgpt, &RemoteTarget::OfficialGateway("https://a:b@x.example".into())).is_err());
        assert!(remote_instructions(Host::Codex, &RemoteTarget::OfficialGateway("https://x.example".into())).is_err());
    }
}
