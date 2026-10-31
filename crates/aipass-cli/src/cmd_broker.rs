// SPDX-License-Identifier: Apache-2.0
//! Broker-facing commands. This CLI is a **trusted device**: every request is signed with
//! the device key (`AIPass-Sig kid=dev_…`) and approvals carry a device signature over the
//! approval digest; the credential is sealed end-to-end to the executor.

use std::collections::BTreeSet;
use std::path::PathBuf;

use aipass_client::{BrokerClient, ConnectionAction};
use aipass_hostconfig::{Host, McpEntry, PlanAction, Scope};
use aipass_types::error::ApiError;
use aipass_types::ids::{ApprovalRequestId, ConnectionId, EntryId, GrantId, PolicyId, ProjectId, ResourceId};
use aipass_types::models::{AccessSpec, AllowedProjects, ApprovalRequest, ApproveConnectionRequest, ConnectionStatus, ConnectionView, Decision, GrantStatus, Policy, Resource, ResourceInput, RevocationLevel};
use aipass_types::relay::{ControlAction, RelayMessage};
use aipass_types::vault::DevicePublic;
use anyhow::{Context, bail};
use serde_json::json;

use crate::args::*;
use crate::ctx::{Ctx, Pick, confirm, parse_enum, read_line, stdin_is_tty};

fn api(e: aipass_client::ClientError) -> anyhow::Error {
    let a: ApiError = e.to_api_error();
    let msg = a.message.as_ref().map(|m| format!("{} / {}", m.zh, m.en)).unwrap_or_default();
    anyhow::anyhow!("{} {}", a.code.as_str(), msg)
}

fn allowed_projects(s: &str) -> anyhow::Result<AllowedProjects> {
    if s.trim() == "*" {
        return Ok(AllowedProjects::All);
    }
    let mut set = BTreeSet::new();
    for p in s.split(',').map(str::trim).filter(|p| !p.is_empty()) {
        set.insert(ProjectId::parse(p).map_err(|_| anyhow::anyhow!("invalid project id {p}"))?);
    }
    Ok(AllowedProjects::Only(set))
}

/// `connect <host>`
pub async fn connect(ctx: &mut Ctx, a: ConnectArgs) -> anyhow::Result<()> {
    let host = Host::parse(&a.host).context("unknown host (codex, claude_code, cursor, claude_desktop, vscode, windsurf)")?;
    if host.is_remote() {
        bail!("{}", ctx.t("此主机是远程连接，请在其设置中添加 MCP 连接器（见 docs）", "this host connects remotely; add the MCP connector in its settings (see docs)"));
    }
    let scope = match &a.scope {
        Some(s) => match s.as_str() {
            "user" => Scope::User,
            "project" => Scope::Project,
            _ => bail!("--scope must be user or project"),
        },
        None => host.default_scope(),
    };
    let mut env = aipass_hostconfig::HostEnv::from_system().map_err(|e| anyhow::anyhow!("{e}"))?;
    if let Some(d) = &a.project_dir {
        env = env.project(d.clone());
    }
    let plan = if a.remove {
        aipass_hostconfig::plan_remove_in(&env, host, scope).map_err(|e| anyhow::anyhow!("{e}"))?
    } else {
        let cid = ConnectionId::parse(a.connection.as_deref().context("--connection conn_… is required (pair first with `aipass-mcp pair`)")?)
            .map_err(|_| anyhow::anyhow!("invalid connection id"))?;
        let bin = match &a.mcp_bin {
            Some(b) => b.clone(),
            None => std::env::current_exe()?.with_file_name("aipass-mcp"),
        };
        let mut entry = McpEntry::stdio(bin, &cid).map_err(|e| anyhow::anyhow!("{e}"))?;
        if let Some(b) = &ctx.broker_flag {
            entry = entry.with_broker(b).map_err(|e| anyhow::anyhow!("{e}"))?;
        }
        aipass_hostconfig::plan_in(&env, host, scope, &entry).map_err(|e| anyhow::anyhow!("{e}"))?
    };
    if plan.action == PlanAction::Unchanged {
        println!("{}", ctx.t("配置已是最新，无需修改", "already configured; nothing to change"));
        return Ok(());
    }
    println!("{}: {}", ctx.t("将修改", "Will modify"), plan.path.display());
    println!("{}", plan.unified_diff);
    if !a.yes && !confirm(ctx.t("应用此修改？（会先备份原文件）", "Apply this change? (the original is backed up first)"))? {
        bail!("cancelled");
    }
    let out = aipass_hostconfig::apply(&plan).map_err(|e| anyhow::anyhow!("{e}"))?;
    println!("{} {}", ctx.t("已写入", "written"), out.path.display());
    if let Some(b) = out.backup_path {
        println!("{} {}", ctx.t("备份", "backup"), b.display());
    }
    Ok(())
}

/// `connections …`
pub async fn connections(ctx: &mut Ctx, cmd: ConnectionsCmd) -> anyhow::Result<()> {
    let id = |s: &str| ConnectionId::parse(s).map_err(|_| anyhow::anyhow!("invalid connection id"));
    if matches!(cmd, ConnectionsCmd::Approve { .. }) {
        ctx.ensure_approval_terminal(("批准连接", "approving a connection"))?;
    }
    // the phone path: device-signed control messages through the end-to-end relay (§4)
    let relay_action = match &cmd {
        ConnectionsCmd::Approve { id: c, projects, code, via_relay: true } => {
            Some((id(c)?, RelayControl::Approve(allowed_projects(projects)?, code.clone())))
        }
        ConnectionsCmd::Deny { id: c, via_relay: true } => Some((id(c)?, RelayControl::Decision(Decision::Deny, AllowedProjects::All))),
        ConnectionsCmd::Pause { id: c, via_relay: true } => Some((id(c)?, RelayControl::Control(ControlAction::Pause))),
        ConnectionsCmd::Resume { id: c, via_relay: true } => Some((id(c)?, RelayControl::Control(ControlAction::Resume))),
        ConnectionsCmd::Remove { id: c, via_relay: true } => Some((id(c)?, RelayControl::Control(ControlAction::Remove))),
        _ => None,
    };
    if let Some((cid, ctl)) = relay_action {
        return connection_via_relay(ctx, &cid, ctl).await;
    }
    let b = ctx.device_broker().await?;
    match cmd {
        ConnectionsCmd::List => {
            let r = b.list_connections().await.map_err(api)?;
            if ctx.json {
                return ctx.print_json(&r);
            }
            // the display name is self-declared: approve the id that `aipass-mcp pair`
            // printed, not a row picked by its name
            for c in r.connections {
                println!(
                    "{}  {:<8} {:<16} {:<24} {}  {}",
                    c.connection_id,
                    serde_json::to_value(c.status)?.as_str().unwrap_or(""),
                    serde_json::to_value(c.host_type)?.as_str().unwrap_or(""),
                    c.display_name,
                    aipass_types::time::format_rfc3339(&c.created_at),
                    serde_json::to_string(&c.allowed_projects)?
                );
            }
        }
        ConnectionsCmd::Approve { id: c, projects, code, .. } => {
            let cid = id(&c)?;
            let req = ApproveConnectionRequest { allowed_projects: allowed_projects(&projects)? };
            // the broker only shows the code to trusted devices (D/A principals, CONTRACTS §6.3)
            let view: ConnectionView = b.get_json(&format!("/v1/connections/{cid}")).await.map_err(api)?;
            print_pending(ctx, &view.connection)?;
            verify_pairing_code(ctx, view.pairing_code.as_deref(), code.as_deref())?;
            ctx.require_human_approval(("批准连接", "approving a connection"), ("批准此连接？", "Approve this connection?"), true)?;
            let r = b.approve_connection(&cid, &req).await.map_err(api)?;
            println!("{} {} → {}", ctx.t("已批准连接", "connection approved"), r.connection_id, serde_json::to_string(&r.allowed_projects)?);
        }
        ConnectionsCmd::Deny { id: c, .. } => action(ctx, &b, &id(&c)?, ConnectionAction::Deny).await?,
        ConnectionsCmd::Pause { id: c, .. } => action(ctx, &b, &id(&c)?, ConnectionAction::Pause).await?,
        ConnectionsCmd::Resume { id: c, .. } => action(ctx, &b, &id(&c)?, ConnectionAction::Resume).await?,
        ConnectionsCmd::Remove { id: c, .. } => action(ctx, &b, &id(&c)?, ConnectionAction::Remove).await?,
    }
    Ok(())
}

/// A connection change sent as a device-signed relay control message.
enum RelayControl {
    /// Approve, with the pairing code the user typed (if given on the command line).
    Approve(AllowedProjects, Option<String>),
    Decision(Decision, AllowedProjects),
    Control(ControlAction),
}

/// Show the pending connection being approved (its name is self-declared, never identity).
fn print_pending(ctx: &Ctx, c: &aipass_types::models::AppConnection) -> anyhow::Result<()> {
    eprintln!(
        "{}: {}  {} \"{}\" ({})",
        ctx.t("待批准连接", "pending connection"),
        c.connection_id,
        ctx.t("自称", "self-declared name"),
        c.display_name,
        serde_json::to_value(c.host_type)?.as_str().unwrap_or("")
    );
    Ok(())
}

/// Check the pairing code the user read off the AI host against the code the broker holds
/// for the pending connection (constant-time). `typed` comes from `--code`; without it the
/// code is asked for on the terminal. No open pairing (expired, already decided, or a
/// broker that does not expose it) is a refusal, never a pass.
fn verify_pairing_code(ctx: &Ctx, expected: Option<&str>, typed: Option<&str>) -> anyhow::Result<()> {
    let Some(expected) = expected else {
        bail!(
            "{}",
            ctx.t(
                "此连接没有进行中的配对（已过期、已处理或经纪服务未提供配对码），无法核对配对码；请在 AI 端重新运行配对",
                "this connection has no open pairing (expired, already decided, or the broker does not expose its code), so the pairing code cannot be checked; pair again on the AI host"
            )
        );
    };
    let typed = match typed {
        Some(t) => t.trim().to_owned(),
        None if stdin_is_tty() => read_line(ctx.t("AI 端显示的 6 位配对码: ", "6-digit pairing code shown by the AI host: "))?.trim().to_owned(),
        None => bail!(
            "{}",
            ctx.t(
                "请用 --code 传入 AI 端显示的 6 位配对码",
                "pass the 6-digit pairing code shown by the AI host with --code"
            )
        ),
    };
    if typed.len() != 6 || !typed.bytes().all(|b| b.is_ascii_digit()) {
        bail!("{}", ctx.t("配对码应为 6 位数字", "the pairing code is 6 digits"));
    }
    if !aipass_crypto::ct_eq(typed.as_bytes(), expected.as_bytes()) {
        bail!(
            "{}",
            ctx.t(
                "配对码不一致，已拒绝批准：这可能不是你刚才在 AI 端发起的连接",
                "pairing code mismatch; refusing to approve — this may not be the connection you just started on the AI host"
            )
        );
    }
    Ok(())
}

/// The pairing code of `cid` from the sealed `connection.pair_request` messages that `exe`
/// (the executor this device is paired with) sent to this device's relay mailbox.
async fn relay_pairing_code(
    v: &aipass_sync::VaultClient,
    relay: &aipass_storage::RelayClient,
    exe: &aipass_types::ids::ExecutorId,
    cid: &ConnectionId,
    lang: aipass_types::Lang,
) -> anyhow::Result<Option<String>> {
    let mut cursor = None;
    let mut code: Option<String> = None;
    loop {
        let (msgs, next) = v.fetch_inbox(relay, cursor.as_ref(), 0).await.map_err(|e| anyhow::anyhow!("{}", e.localized().pick(lang)))?;
        for (_, sender, m) in &msgs {
            if let RelayMessage::ConnectionPairRequest(r) = m {
                if &r.connection.connection_id != cid || sender != exe {
                    continue;
                }
                match &code {
                    None => code = Some(r.pairing_code.clone()),
                    // differing copies for one connection: trust neither
                    Some(c) if c != &r.pairing_code => bail!(
                        "{}",
                        if lang == aipass_types::Lang::En {
                            "the relay holds differing pairing requests for this connection; refusing to approve"
                        } else {
                            "中继里有此连接的不同配对请求，已拒绝批准"
                        }
                    ),
                    Some(_) => {}
                }
            }
        }
        if msgs.is_empty() || next == cursor {
            return Ok(code);
        }
        cursor = next;
    }
}

/// How long to wait for the broker's answer on the relay.
const RELAY_CONFIRM_SECS: u64 = 20;

/// Newest message id in this device's relay mailbox (so later reads see only replies).
async fn inbox_cursor(v: &aipass_sync::VaultClient, relay: &aipass_storage::RelayClient, lang: aipass_types::Lang) -> anyhow::Result<Option<aipass_types::ids::MessageId>> {
    let mut cursor = None;
    loop {
        let (msgs, next) = v.fetch_inbox(relay, cursor.as_ref(), 0).await.map_err(|e| anyhow::anyhow!("{}", e.localized().pick(lang)))?;
        if msgs.is_empty() && next == cursor {
            return Ok(cursor);
        }
        cursor = next;
    }
}

/// Wait for the first relay reply after `cursor` that `want` accepts.
async fn await_relay_reply<T>(
    v: &aipass_sync::VaultClient,
    relay: &aipass_storage::RelayClient,
    mut cursor: Option<aipass_types::ids::MessageId>,
    lang: aipass_types::Lang,
    mut want: impl FnMut(RelayMessage) -> Option<T>,
) -> anyhow::Result<Option<T>> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(RELAY_CONFIRM_SECS);
    while std::time::Instant::now() < deadline {
        let left = deadline.saturating_duration_since(std::time::Instant::now()).as_secs().clamp(1, 5);
        let (msgs, next) = v.fetch_inbox(relay, cursor.as_ref(), left).await.map_err(|e| anyhow::anyhow!("{}", e.localized().pick(lang)))?;
        cursor = next.or(cursor);
        for (_, _, m) in msgs {
            if let Some(t) = want(m) {
                return Ok(Some(t));
            }
        }
    }
    Ok(None)
}

async fn connection_via_relay(ctx: &mut Ctx, cid: &ConnectionId, ctl: RelayControl) -> anyhow::Result<()> {
    let lang = ctx.lang;
    let (relay, exe) = device_relay(ctx, None)?;
    let v = ctx.unlocked().await?;
    let err = |e: aipass_vault::VaultError| anyhow::anyhow!("{} ({})", e.localized().pick(lang), e.code().as_str());
    let (msg, expect) = match ctl {
        RelayControl::Approve(projects, typed) => {
            let expected = relay_pairing_code(&v, &relay, &exe, cid, lang).await?;
            verify_pairing_code(ctx, expected.as_deref(), typed.as_deref())?;
            ctx.require_human_approval(("批准连接", "approving a connection"), ("批准此连接？", "Approve this connection?"), true)?;
            (RelayMessage::ConnectionDecision(v.sign_connection_decision(cid, Decision::Approve, projects).map_err(err)?), ConnectionStatus::Active)
        }
        RelayControl::Decision(d, projects) => {
            let expect = if d == Decision::Approve { ConnectionStatus::Active } else { ConnectionStatus::Removed };
            (RelayMessage::ConnectionDecision(v.sign_connection_decision(cid, d, projects).map_err(err)?), expect)
        }
        RelayControl::Control(a) => {
            let expect = match a {
                ControlAction::Pause => ConnectionStatus::Paused,
                ControlAction::Resume => ConnectionStatus::Active,
                _ => ConnectionStatus::Removed,
            };
            (RelayMessage::ConnectionControl(v.sign_connection_control(cid, a).map_err(err)?), expect)
        }
    };
    let cursor = inbox_cursor(&v, &relay, lang).await?;
    let mid = v.send_to_executor(&relay, &exe, &msg).await.map_err(err)?;
    // ask for a signed-and-sealed state snapshot to confirm the change was applied (the
    // broker processes a mailbox in order, so the snapshot reflects the control message)
    v.send_to_executor(&relay, &exe, &RelayMessage::StateRequest(aipass_types::relay::StateRequest {})).await.map_err(err)?;
    let status = await_relay_reply(&v, &relay, cursor, lang, |m| match m {
        RelayMessage::StateSnapshot(s) => Some(s.connections.into_iter().find(|c| &c.connection_id == cid).map(|c| c.status)),
        _ => None,
    })
    .await?;
    let confirmed = matches!(status, Some(Some(s)) if s == expect)
        // a denied pending connection may disappear from the snapshot altogether
        || (expect == ConnectionStatus::Removed && matches!(status, Some(None)));
    if ctx.json {
        return ctx.print_json(&json!({
            "connection_id": cid,
            "message_id": mid,
            "via": "relay",
            "confirmed": confirmed,
            "status": status.flatten(),
        }));
    }
    println!("{} ({mid})", ctx.t("已通过端到端中继发送签名指令", "signed control message sent through the end-to-end relay"));
    if !confirmed {
        bail!(
            "{}",
            ctx.t(
                "执行设备未确认此更改（中继未返回匹配的状态），请稍后用 `aipass connections list` 检查",
                "the executor did not confirm this change (no matching state on the relay); check with `aipass connections list`"
            )
        );
    }
    println!("{}", ctx.t("执行设备已确认", "confirmed by the executor"));
    Ok(())
}

async fn grant_revoke_via_relay(ctx: &mut Ctx, grant: &GrantId, level: RevocationLevel) -> anyhow::Result<()> {
    let lang = ctx.lang;
    let (relay, exe) = device_relay(ctx, None)?;
    let v = ctx.unlocked().await?;
    let err = |e: aipass_vault::VaultError| anyhow::anyhow!("{} ({})", e.localized().pick(lang), e.code().as_str());
    let msg = RelayMessage::GrantRevoke(v.sign_grant_revoke(grant, level).map_err(err)?);
    let cursor = inbox_cursor(&v, &relay, lang).await?;
    let mid = v.send_to_executor(&relay, &exe, &msg).await.map_err(err)?;
    let report = await_relay_reply(&v, &relay, cursor, lang, |m| match m {
        RelayMessage::RevokeReport(r) if &r.grant_id == grant => Some(r),
        _ => None,
    })
    .await?;
    let Some(r) = report else {
        // never claim a revocation the broker did not report
        if ctx.json {
            return ctx.print_json(&json!({"grant_id": grant, "message_id": mid, "via": "relay", "confirmed": false}));
        }
        bail!(
            "{}",
            ctx.t(
                "撤销指令已发送，但执行设备未返回撤销报告；不能确认已撤销",
                "the revocation was sent but the executor returned no revoke report; it is NOT confirmed"
            )
        );
    };
    if ctx.json {
        return ctx.print_json(&r);
    }
    print_revoke_report(ctx, &r)
}

fn print_revoke_report(ctx: &Ctx, r: &aipass_types::models::RevocationReport) -> anyhow::Result<()> {
    for (n, l) in [("stop_access", &r.stop_access), ("end_sessions", &r.end_sessions), ("revoke_upstream", &r.revoke_upstream)] {
        println!("  {n:<16} {:<15} {}", serde_json::to_value(l.status)?.as_str().unwrap_or(""), l.detail.clone().unwrap_or_default());
    }
    println!("{}", r.summary_label().pick(ctx.lang));
    Ok(())
}

async fn action(ctx: &Ctx, b: &BrokerClient, id: &ConnectionId, a: ConnectionAction) -> anyhow::Result<()> {
    let v = b.connection_action(id, a).await.map_err(api)?;
    if ctx.json {
        return ctx.print_json(&v);
    }
    println!("ok");
    Ok(())
}

/// `projects …`
pub async fn projects(ctx: &mut Ctx, cmd: ProjectsCmd) -> anyhow::Result<()> {
    let b = ctx.device_broker().await?;
    match cmd {
        ProjectsCmd::List => {
            let r = b.list_projects().await.map_err(api)?;
            for p in r.projects {
                println!("{}  {}", p.project_id, p.name);
            }
        }
        ProjectsCmd::Add { name } => {
            let p = b.create_project(&name).await.map_err(api)?;
            println!("{}", p.project_id);
        }
    }
    Ok(())
}

async fn project_id(b: &BrokerClient, s: &str) -> anyhow::Result<ProjectId> {
    if let Ok(p) = ProjectId::parse(s) {
        return Ok(p);
    }
    let list = b.list_projects().await.map_err(api)?;
    if let Some(p) = list.projects.iter().find(|p| p.name == s) {
        return Ok(p.project_id.clone());
    }
    Ok(b.create_project(s).await.map_err(api)?.project_id)
}

/// `resource …`
pub async fn resource(ctx: &mut Ctx, cmd: ResourceCmd) -> anyhow::Result<()> {
    let lang = ctx.lang;
    match cmd {
        ResourceCmd::Add { alias, service, connector, project, environment, entry, config, executor } => {
            let entry = EntryId::parse(&entry).map_err(|_| anyhow::anyhow!("invalid entry id"))?;
            let executor = ctx.executor(executor.as_deref())?;
            let cfg: serde_json::Value = serde_json::from_slice(&std::fs::read(&config).with_context(|| format!("cannot read {}", config.display()))?)
                .context("config is not JSON")?;
            let b = ctx.device_broker().await?;
            {
                // the entry must exist in this vault; only its id is sent
                let v = ctx.unlocked().await?;
                v.get_item(&entry).map_err(|e| anyhow::anyhow!("{}", e.localized().pick(lang)))?;
            }
            let project_id = project_id(&b, &project).await?;
            let input: ResourceInput = serde_json::from_value(json!({
                "alias": alias,
                "service": service.unwrap_or_else(|| connector.clone()),
                "connector": connector,
                "project_id": project_id,
                "environment": environment,
                "config": cfg,
                "credential_entry_id": entry,
                "executor_id": executor,
            }))
            .context("invalid resource")?;
            let r = b.admin_create_resource(&input).await.map_err(api)?;
            let v = ctx.unlocked().await?;
            v.bind_resource(&r.resource_id, &entry).map_err(|e| anyhow::anyhow!("{}", e.localized().pick(lang)))?;
            println!("{}", r.resource_id);
            Ok(())
        }
        ResourceCmd::List => {
            let b = ctx.device_broker().await?;
            let r = b.admin_list_resources().await.map_err(api)?;
            if ctx.json {
                return ctx.print_json(&r);
            }
            for x in r.resources {
                println!(
                    "{}  {:<18} {:<9} {:<10} {}",
                    x.resource_id,
                    x.alias,
                    serde_json::to_value(x.connector)?.as_str().unwrap_or(""),
                    serde_json::to_value(x.environment)?.as_str().unwrap_or(""),
                    x.operations.join(",")
                );
            }
            Ok(())
        }
    }
}

/// `policy …`
pub async fn policy(ctx: &mut Ctx, cmd: PolicyCmd) -> anyhow::Result<()> {
    if matches!(cmd, PolicyCmd::Add { .. }) {
        ctx.ensure_approval_terminal(("添加访问规则", "adding a policy"))?;
    }
    let b = ctx.device_broker().await?;
    match cmd {
        PolicyCmd::Add { resource, connection, operations, views, repos, mode, auto_approve, ttl } => {
            let rid = ResourceId::parse(&resource).map_err(|_| anyhow::anyhow!("invalid resource id"))?;
            let res: Resource = b.get_json(&format!("/v1/admin/resources/{rid}")).await.map_err(api)?;
            let ops: Vec<String> = operations.split(',').map(str::trim).filter(|s| !s.is_empty()).map(String::from).collect();
            let mut view_map = serde_json::Map::new();
            let mut all_views = Vec::new();
            let mut all_fields = Vec::new();
            for v in &views {
                let (name, fields) = v.split_once(':').context("--view must be schema.view:field1,field2")?;
                let fields: Vec<String> = fields.split(',').map(str::trim).filter(|s| !s.is_empty()).map(String::from).collect();
                all_views.push(name.to_string());
                all_fields.extend(fields.iter().map(|f| format!("{name}.{f}")));
                view_map.insert(name.to_string(), json!(fields));
            }
            let mut scope = json!({ "operations": ops });
            if !view_map.is_empty() {
                scope["postgres"] = json!({ "views": view_map });
            }
            if !repos.is_empty() {
                scope["github"] = json!({ "repos": repos });
            }
            let (dev, identity) = ctx.device_identity()?;
            let mut p: Policy = serde_json::from_value(json!({
                "policy_id": PolicyId::generate(),
                "version": 1,
                "subject_connection_id": connection,
                "project_id": res.project_id,
                "resource_id": res.resource_id,
                "executor_id": res.executor_id,
                "allowed_operations": ops,
                "allowed_views": all_views,
                "allowed_fields": all_fields,
                "scope": scope,
                "limits": aipass_types::models::Limits::default(),
                "grant_ttl_seconds": ttl,
                "approval_mode": mode,
                "auto_approve": auto_approve,
                "on_control_channel_lost": "deny_new_operations",
                "output_recipients": [connection],
                "status": "active",
                "created_at": aipass_types::time::format_rfc3339(&aipass_types::time::now()),
                "signed_by": dev,
                "signature": "",
            }))
            .context("invalid policy")?;
            eprintln!(
                "{}: {} → {}  {} [{}]  auto_approve={}",
                ctx.t("新规则", "new policy"),
                p.subject_connection_id,
                p.resource_id,
                ctx.t("操作", "operations"),
                p.allowed_operations.join(", "),
                p.auto_approve
            );
            ctx.require_human_approval(("添加访问规则", "adding a policy"), ("签名并添加此规则？", "Sign and add this policy?"), false)?;
            aipass_types::policy::sign_policy(&mut p, identity.as_ref()).map_err(|e| anyhow::anyhow!("sign: {e:?}"))?;
            let out = b.create_policy(&p).await.map_err(api)?;
            println!("{}", out.policy_id);
        }
        PolicyCmd::List => {
            let r = b.list_policies().await.map_err(api)?;
            ctx.print_json(&r)?;
        }
        PolicyCmd::Disable { id } => {
            let id = PolicyId::parse(&id).map_err(|_| anyhow::anyhow!("invalid policy id"))?;
            let r = b.disable_policy(&id).await.map_err(api)?;
            ctx.print_json(&r)?;
        }
    }
    Ok(())
}

fn narrowed(req: &ApprovalRequest, narrow: &[String], duration: Option<u64>, max_rows: Option<u64>) -> anyhow::Result<Option<AccessSpec>> {
    if narrow.is_empty() && duration.is_none() && max_rows.is_none() {
        return Ok(None);
    }
    let mut spec = req.requested.clone();
    for n in narrow {
        let (view, fields) = n.split_once(':').context("--narrow must be schema.view:field1,field2")?;
        let pg = spec.scope.postgres.as_mut().context("this request has no postgres views to narrow")?;
        let cur = pg.views.get_mut(view).with_context(|| format!("view {view} is not part of the request"))?;
        let keep: Vec<String> = fields.split(',').map(str::trim).filter(|s| !s.is_empty()).map(String::from).collect();
        if keep.iter().any(|f| !cur.contains(f)) {
            bail!("narrowing can only remove fields");
        }
        *cur = keep;
    }
    if let Some(d) = duration {
        if d > spec.duration_seconds || d == 0 {
            bail!("--duration can only shorten the request");
        }
        spec.duration_seconds = d;
    }
    if let Some(m) = max_rows {
        spec.limits.max_rows_per_operation = spec.limits.max_rows_per_operation.min(m);
        spec.limits.max_rows_per_grant = spec.limits.max_rows_per_grant.min(m.max(spec.limits.max_rows_per_operation));
    }
    Ok(Some(spec))
}

/// `approvals …`
pub async fn approvals(ctx: &mut Ctx, cmd: ApprovalsCmd) -> anyhow::Result<()> {
    let lang = ctx.lang;
    match &cmd {
        ApprovalsCmd::Approve { .. } => ctx.ensure_approval_terminal(("批准访问请求", "approving an access request"))?,
        ApprovalsCmd::Deny { .. } => ctx.ensure_approval_terminal(("拒绝访问请求", "denying an access request"))?,
        _ => {}
    }
    let b = ctx.device_broker().await?;
    let get = |id: &str| -> anyhow::Result<ApprovalRequestId> { ApprovalRequestId::parse(id).map_err(|_| anyhow::anyhow!("invalid approval request id")) };
    match cmd {
        ApprovalsCmd::List => {
            let r = b.list_approvals(None).await.map_err(api)?;
            if ctx.json {
                return ctx.print_json(&r);
            }
            if r.approvals.is_empty() {
                println!("{}", ctx.t("没有待处理的请求", "no pending requests"));
            }
            let now = aipass_types::time::now();
            for a in &r.approvals {
                println!("{}", crate::card::render(a, lang, &now));
            }
        }
        ApprovalsCmd::Show { id } => {
            let a: ApprovalRequest = b.get_json(&format!("/v1/approvals/{}", get(&id)?)).await.map_err(api)?;
            if ctx.json {
                return ctx.print_json(&a);
            }
            println!("{}", crate::card::render(&a, lang, &aipass_types::time::now()));
        }
        ApprovalsCmd::Approve { id, narrow, duration, max_rows, yes, via_relay: true } => {
            let want = get(&id)?;
            let (relay, _) = device_relay(ctx, None)?;
            let v = ctx.unlocked().await?;
            let (msgs, _) = v.fetch_inbox(&relay, None, 0).await.map_err(|e| anyhow::anyhow!("{}", e.localized().pick(lang)))?;
            // only the executor named in the request may ask for it (CONTRACTS §12)
            let copies: Vec<(aipass_types::ids::ExecutorId, ApprovalRequest)> = msgs
                .into_iter()
                .filter_map(|(_, exe, m)| match m {
                    RelayMessage::ApprovalRequest(r) if r.approval_request_id == want && r.executor.executor_id == exe => Some((exe, *r)),
                    _ => None,
                })
                .collect();
            let (exe, a) = copies.first().cloned().context("this approval request is not in the relay inbox")?;
            // a second, different copy of the same id is never trusted over the first
            let digest = |r: &ApprovalRequest| aipass_types::approval::request_digest(r).map_err(|e| anyhow::anyhow!("request digest: {e:?}"));
            let first = digest(&a)?;
            if copies.iter().map(|(_, c)| digest(c)).collect::<anyhow::Result<Vec<_>>>()?.iter().any(|d| d != &first) {
                bail!(
                    "{}",
                    ctx.t(
                        "中继里有同一请求的不同副本，已拒绝批准；请在执行设备上查看",
                        "the relay holds differing copies of this request; refusing to approve (check it on the executor)"
                    )
                );
            }
            println!("{}", crate::card::render(&a, lang, &aipass_types::time::now()));
            let spec = narrowed(&a, &narrow, duration, max_rows)?;
            ctx.require_human_approval(("批准访问请求", "approving an access request"), ("批准此访问？", "Approve this access?"), yes)?;
            let decision = v.approve(&a, spec).await.map_err(|e| anyhow::anyhow!("{} ({})", e.localized().pick(lang), e.code().as_str()))?;
            let mid = v
                .send_to_executor(&relay, &exe, &RelayMessage::ApprovalDecision(Box::new(decision)))
                .await
                .map_err(|e| anyhow::anyhow!("{}", e.localized().pick(lang)))?;
            println!("{} ({mid})", ctx.t("已通过端到端中继发送批准", "approval sent through the end-to-end relay"));
        }
        ApprovalsCmd::Approve { id, narrow, duration, max_rows, yes, via_relay: false } => {
            let a: ApprovalRequest = b.get_json(&format!("/v1/approvals/{}", get(&id)?)).await.map_err(api)?;
            println!("{}", crate::card::render(&a, lang, &aipass_types::time::now()));
            let spec = narrowed(&a, &narrow, duration, max_rows)?;
            ctx.require_human_approval(("批准访问请求", "approving an access request"), ("批准此访问？", "Approve this access?"), yes)?;
            let v = ctx.unlocked().await?;
            let decision = v.approve(&a, spec).await.map_err(|e| anyhow::anyhow!("{} ({})", e.localized().pick(lang), e.code().as_str()))?;
            let r = b.post_decision(&decision).await.map_err(api)?;
            println!(
                "{}: {}{}",
                ctx.t("已批准", "approved"),
                serde_json::to_value(r.status)?.as_str().unwrap_or(""),
                r.grant_id.map(|g| format!("  grant {g}")).unwrap_or_default()
            );
        }
        ApprovalsCmd::Deny { id } => {
            let a: ApprovalRequest = b.get_json(&format!("/v1/approvals/{}", get(&id)?)).await.map_err(api)?;
            println!("{}", crate::card::render(&a, lang, &aipass_types::time::now()));
            ctx.require_human_approval(("拒绝访问请求", "denying an access request"), ("拒绝此访问？", "Deny this access?"), false)?;
            let v = ctx.unlocked().await?;
            let decision = v.deny(&a).map_err(|e| anyhow::anyhow!("{}", e.localized().pick(lang)))?;
            let r = b.post_decision(&decision).await.map_err(api)?;
            println!("{}: {}", ctx.t("已拒绝", "denied"), serde_json::to_value(r.status)?.as_str().unwrap_or(""));
        }
    }
    Ok(())
}

/// Relay client for this device's own mailbox at the executor's relay.
fn device_relay(ctx: &mut Ctx, executor: Option<&str>) -> anyhow::Result<(aipass_storage::RelayClient, aipass_types::ids::ExecutorId)> {
    let exe = ctx.executor(executor)?;
    let cfg = ctx.config()?;
    let base = cfg
        .executors
        .iter()
        .find(|x| x.executor_id == exe)
        .map(|x| x.relay_url.clone())
        .filter(|u| !u.is_empty())
        .context("no relay known for this executor (pair it with `aipass device pair`)")?;
    let url = url::Url::parse(&base)?;
    let allow_http = aipass_node::config::is_loopback_url(&url);
    let (kid, identity) = ctx.device_identity()?;
    let dev = aipass_types::ids::DeviceId::parse(&kid).map_err(|_| anyhow::anyhow!("device id"))?;
    let http = reqwest_client()?;
    let signer: aipass_storage::http::DeviceSigner = identity;
    let auth = aipass_storage::relay_client::RelayAuth::Signed { kid: aipass_types::ids::PrincipalId::Device(dev), signer };
    let c = aipass_storage::RelayClient::with_client(url, auth, http, allow_http).map_err(|e| anyhow::anyhow!("relay: {e}"))?;
    Ok((c, exe))
}

fn reqwest_client() -> anyhow::Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(40))
        .redirect(reqwest::redirect::Policy::none())
        .build()?)
}

/// `inbox`
pub async fn inbox(ctx: &mut Ctx, wait: u64, executor: Option<String>) -> anyhow::Result<()> {
    let lang = ctx.lang;
    ctx.unlocked().await?;
    let (relay, _) = device_relay(ctx, executor.as_deref())?;
    let v = ctx.unlocked().await?;
    let (msgs, _) = v.fetch_inbox(&relay, None, wait.min(25)).await.map_err(|e| anyhow::anyhow!("{}", e.localized().pick(lang)))?;
    let mut out = Vec::new();
    for (mid, exe, m) in msgs {
        let (kind, subject) = match &m {
            RelayMessage::ApprovalRequest(r) => ("approval.request", r.approval_request_id.to_string()),
            RelayMessage::ApprovalCancelled(c) => ("approval.cancelled", serde_json::to_value(c)?.get("approval_request_id").and_then(|x| x.as_str()).unwrap_or("").to_string()),
            RelayMessage::ConnectionPairRequest(p) => ("connection.pair_request", p.connection.connection_id.to_string()),
            RelayMessage::RevokeReport(r) => ("revoke.report", r.grant_id.to_string()),
            other => (other.message_type().as_str(), String::new()),
        };
        out.push(json!({"message_id": mid, "from": exe, "type": kind, "subject": subject}));
    }
    if ctx.json {
        return ctx.print_json(&json!({ "messages": out }));
    }
    for m in &out {
        println!("{}  {:<24} {}", m["message_id"].as_str().unwrap_or(""), m["type"].as_str().unwrap_or(""), m["subject"].as_str().unwrap_or(""));
    }
    Ok(())
}

/// `grants …`
pub async fn grants(ctx: &mut Ctx, cmd: GrantsCmd) -> anyhow::Result<()> {
    if let GrantsCmd::Revoke { id, level, via_relay: true } = &cmd {
        let id = GrantId::parse(id).map_err(|_| anyhow::anyhow!("invalid grant id"))?;
        let level: RevocationLevel = parse_enum("level", level)?;
        return grant_revoke_via_relay(ctx, &id, level).await;
    }
    let b = ctx.device_broker().await?;
    match cmd {
        GrantsCmd::List { status } => {
            let st: Option<GrantStatus> = status.as_deref().map(|s| parse_enum("status", s)).transpose()?;
            let r = b.list_grants(st).await.map_err(api)?;
            if ctx.json {
                return ctx.print_json(&r);
            }
            for g in r.grants {
                println!(
                    "{}  {:<9} {} → {}  used {}/{} req, {} rows  until {}",
                    g.grant_id,
                    serde_json::to_value(g.status)?.as_str().unwrap_or(""),
                    g.connection_id,
                    g.resource_id,
                    g.usage.requests,
                    g.limits.max_requests_per_grant,
                    g.usage.rows,
                    aipass_types::time::format_rfc3339(&g.expires_at)
                );
            }
        }
        GrantsCmd::Revoke { id, level, .. } => {
            let id = GrantId::parse(&id).map_err(|_| anyhow::anyhow!("invalid grant id"))?;
            let level: RevocationLevel = parse_enum("level", &level)?;
            let r = b.revoke_grant(&id, level).await.map_err(api)?;
            if ctx.json {
                return ctx.print_json(&r);
            }
            print_revoke_report(ctx, &r)?;
        }
    }
    Ok(())
}

/// `activity`
pub async fn activity(ctx: &mut Ctx, since: Option<String>) -> anyhow::Result<()> {
    let b = ctx.device_broker().await?;
    let since = since.map(|s| aipass_types::time::parse_rfc3339(&s)).transpose().map_err(|_| anyhow::anyhow!("--since must be RFC 3339"))?;
    let r = b.activity_summary(since.as_ref()).await.map_err(api)?;
    ctx.print_json(&r)
}

/// `audit …`
pub async fn audit(ctx: &mut Ctx, cmd: AuditCmd) -> anyhow::Result<()> {
    let b = ctx.device_broker().await?;
    match cmd {
        AuditCmd::Verify => {
            let r = b.audit_verify().await.map_err(api)?;
            ctx.print_json(&r)?;
            if !r.valid {
                bail!("{}", ctx.t("审计链校验失败", "audit chain verification failed"));
            }
        }
        AuditCmd::List { after, limit } => {
            let r = b.audit(Some(after), Some(limit)).await.map_err(api)?;
            ctx.print_json(&r)?;
        }
    }
    Ok(())
}

/// `node run` — embedded broker + executor for this computer (desktop-like, `compatible`).
pub async fn node_run(ctx: &mut Ctx, tcp: Option<String>, name: String) -> anyhow::Result<()> {
    let lang = ctx.lang;
    let node_dir: PathBuf = ctx.home.join("node");
    let mut cfg = aipass_node::NodeConfig::new(name.clone(), node_dir);
    cfg.sync.enabled = false;
    cfg.relay.enabled = true;
    cfg.mcp.enabled = false;
    if let Some(t) = &tcp {
        cfg.node.listen = t.clone();
    }
    let sock = ctx.home.join("run").join("broker.sock");
    let opts = aipass_node::StartOptions { connection_socket: Some(sock.clone()), no_tcp: tcp.is_none(), local_only: true };
    // the device must be unlocked to register itself as the approver
    let (_, identity) = {
        ctx.unlocked().await?;
        ctx.device_identity()?
    };
    let node = aipass_node::start(cfg, opts).await?;
    let v = ctx.unlocked().await?;
    let me = v.devices().map_err(|e| anyhow::anyhow!("{}", e.localized().pick(lang)))?.into_iter().find(|d| d.is_this_device).context("this device")?;
    let pk = identity.public();
    let dp = DevicePublic { device_id: me.device_id.clone(), name: me.name.clone(), platform: me.platform, role: me.role, sign_pk: pk.sign_pk, kem_pk: pk.kem_pk };
    match node.broker.add_trusted_device(&aipass_broker::Actor::System, dp).await {
        Ok(_) => {}
        Err(e) if e.code == aipass_types::error::ErrorCode::PreconditionFailed => {}
        Err(e) => bail!("cannot register this device as approver: {}", e.code.as_str()),
    }
    let exe = node.identity.executor_id.clone();
    let epk = node.identity.identity.public();
    v.register_executor(&exe, aipass_sync::models::KnownExecutor { name, sign_pk: epk.sign_pk, kem_pk: epk.kem_pk })
        .map_err(|e| anyhow::anyhow!("{}", e.localized().pick(lang)))?;
    let mut c = ctx.config()?;
    c.executors.retain(|x| x.executor_id != exe);
    c.executors.push(crate::ctx::PairedExecutor { executor_id: exe.clone(), name: "embedded".into(), relay_url: String::new() });
    ctx.save_config(&c)?;
    println!("broker: unix://{}", sock.display());
    if let Some(a) = node.local_addr {
        println!("broker: http://{a}");
    }
    println!("executor: {exe} ({})", ctx.t("兼容连接", "compatible"));
    println!("{}", ctx.t("按 Ctrl+C 停止", "press Ctrl+C to stop"));
    let _ = tokio::signal::ctrl_c().await;
    node.shutdown().await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allowed_projects_parse() {
        assert_eq!(allowed_projects("*").expect("all"), AllowedProjects::All);
        let p = ProjectId::generate();
        match allowed_projects(&format!("{p}, ")).expect("one") {
            AllowedProjects::Only(s) => assert!(s.contains(&p)),
            AllowedProjects::All => panic!("expected Only"),
        }
        assert!(allowed_projects("not-an-id").is_err());
    }

    /// MNC-04: approving a connection never grants every project implicitly.
    #[test]
    fn approve_requires_explicit_projects() {
        use clap::Parser;
        let id = aipass_types::ids::ConnectionId::generate().to_string();
        assert!(crate::args::Cli::try_parse_from(["aipass", "connections", "approve", id.as_str()]).is_err());
        assert!(crate::args::Cli::try_parse_from(["aipass", "connections", "approve", id.as_str(), "--via-relay"]).is_err());
        let p = ProjectId::generate().to_string();
        assert!(crate::args::Cli::try_parse_from(["aipass", "connections", "approve", id.as_str(), "--projects", p.as_str()]).is_ok());
    }

    #[test]
    fn enums_parse_snake_case() {
        let l: RevocationLevel = parse_enum("level", "end_sessions").expect("level");
        assert_eq!(l, RevocationLevel::EndSessions);
        assert!(parse_enum::<RevocationLevel>("level", "everything").is_err());
    }
}

#[cfg(test)]
mod pairing_code_tests {
    use super::*;

    fn ctx() -> Ctx {
        Ctx::new(Some(std::env::temp_dir().join("aipass-cli-unit-none")), None, false, "en").expect("ctx")
    }

    #[test]
    fn pairing_code_must_match_the_brokers() {
        let c = ctx();
        assert!(verify_pairing_code(&c, Some("123456"), Some("123456")).is_ok());
        assert!(verify_pairing_code(&c, Some("123456"), Some(" 123456 ")).is_ok());
        let e = verify_pairing_code(&c, Some("123456"), Some("123457")).unwrap_err().to_string();
        assert!(e.contains("mismatch"), "{e}");
        let e = verify_pairing_code(&c, Some("123456"), Some("12345")).unwrap_err().to_string();
        assert!(e.contains("6 digits"), "{e}");
        let e = verify_pairing_code(&c, Some("123456"), Some("12345a")).unwrap_err().to_string();
        assert!(e.contains("6 digits"), "{e}");
    }

    #[test]
    fn no_open_pairing_is_a_refusal_not_a_pass() {
        let c = ctx();
        let e = verify_pairing_code(&c, None, Some("123456")).unwrap_err().to_string();
        assert!(e.contains("no open pairing"), "{e}");
    }
}
