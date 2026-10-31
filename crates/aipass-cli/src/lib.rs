// SPDX-License-Identifier: Apache-2.0
//! # aipass-cli — reference CLI / trusted client (`aipass`)
//!
//! Vault creation and unlock, items, generator, TOTP, import/export, sync, recovery,
//! device pairing, and — as a **trusted device** — connection approval, resources,
//! signed policies, approvals (with the §5.3 card), grants and revocation against a
//! broker (`aipass-node` or the embedded `aipass node run`).
//!
//! Revealing a raw secret is a human-only action that re-asks the passphrase on a
//! terminal; nothing here is reachable by AI principals.

pub mod args;
pub mod card;
pub mod cmd_broker;
pub mod cmd_vault;
pub mod ctx;

use args::{Cli, Cmd};

/// Run one invocation.
pub async fn run(cli: Cli) -> anyhow::Result<()> {
    let mut ctx = ctx::Ctx::new(cli.home, cli.broker, cli.json, &cli.lang)?;
    match cli.cmd {
        Cmd::Vault(c) => cmd_vault::vault(&mut ctx, c).await,
        Cmd::Storage(c) => cmd_vault::storage(&mut ctx, c).await,
        Cmd::Item(c) => cmd_vault::item(&mut ctx, c).await,
        Cmd::Import { format, file } => cmd_vault::import(&mut ctx, &format, &file).await,
        Cmd::Export { encrypted, csv, yes } => cmd_vault::export(&mut ctx, encrypted, csv, yes).await,
        Cmd::Sync => cmd_vault::sync(&mut ctx).await,
        Cmd::Conflicts(c) => cmd_vault::conflicts(&mut ctx, c).await,
        Cmd::Recovery(c) => cmd_vault::recovery(&mut ctx, c).await,
        Cmd::Device(c) => cmd_vault::device(&mut ctx, c).await,
        Cmd::Rotation(c) => cmd_vault::rotation(&mut ctx, c).await,
        Cmd::Node(args::NodeCmd::Run { tcp, name }) => cmd_broker::node_run(&mut ctx, tcp, name).await,
        Cmd::Connect(a) => cmd_broker::connect(&mut ctx, a).await,
        Cmd::Connections(c) => cmd_broker::connections(&mut ctx, c).await,
        Cmd::Projects(c) => cmd_broker::projects(&mut ctx, c).await,
        Cmd::Resource(c) => cmd_broker::resource(&mut ctx, c).await,
        Cmd::Policy(c) => cmd_broker::policy(&mut ctx, c).await,
        Cmd::Approvals(c) => cmd_broker::approvals(&mut ctx, c).await,
        Cmd::Grants(c) => cmd_broker::grants(&mut ctx, c).await,
        Cmd::Activity { since } => cmd_broker::activity(&mut ctx, since).await,
        Cmd::Audit(c) => cmd_broker::audit(&mut ctx, c).await,
        Cmd::Inbox { wait, executor } => cmd_broker::inbox(&mut ctx, wait, executor).await,
        Cmd::UseBroker { url } => {
            aipass_client::BrokerEndpoint::parse(&url).map_err(|e| anyhow::anyhow!("{e}"))?;
            let mut c = ctx.config()?;
            c.broker_url = Some(url);
            ctx.save_config(&c)?;
            println!("ok");
            Ok(())
        }
    }
}
