// SPDX-License-Identifier: Apache-2.0
//! `aipass` binary entry point.

use clap::Parser;

#[tokio::main]
async fn main() {
    let cli = aipass_cli::args::Cli::parse();
    let filter = std::env::var("AIPASS_LOG").unwrap_or_else(|_| "warn".into());
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_new(filter).unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")))
        .with_writer(std::io::stderr)
        .with_target(false)
        .try_init();
    if let Err(e) = aipass_cli::run(cli).await {
        eprintln!("aipass: {e:#}");
        std::process::exit(1);
    }
}
