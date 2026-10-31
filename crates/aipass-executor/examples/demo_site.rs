// SPDX-License-Identifier: Apache-2.0
//! Run the bundled demo site used by the experimental `demo` SiteAdapter:
//!
//! ```sh
//! cargo run -p aipass-executor --example demo_site            # 127.0.0.1:8090
//! AIPASS_DEMO_SITE_ADDR=127.0.0.1:9000 cargo run -p aipass-executor --example demo_site
//! ```
//!
//! Local testing only: accounts live in memory and the site deliberately over-shares in
//! `/api/profile` so the adapter's output filter can be exercised.

#[path = "../tests/support/demo_site.rs"]
mod demo_site;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let addr =
        std::env::var("AIPASS_DEMO_SITE_ADDR").unwrap_or_else(|_| "127.0.0.1:8090".to_owned());
    let site = demo_site::DemoSite::start_on(&addr).await?;
    eprintln!(
        "AI 通行证演示网站 / AI Pass demo site: {} (Ctrl-C to stop)",
        site.base_url()
    );
    tokio::signal::ctrl_c().await?;
    Ok(())
}
