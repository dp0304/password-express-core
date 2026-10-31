// SPDX-License-Identifier: Apache-2.0
//! Temporary PostgreSQL cluster (Homebrew `initdb` / `pg_ctl`) on a fixed port, with TLS
//! enabled (test CA) and SCRAM authentication. Stopped and deleted on drop; a watchdog
//! process also stops it if the test process dies without unwinding.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use tokio_postgres::{Client, NoTls};

use super::certs::TestPki;

/// Superuser password of the temp cluster.
pub const SUPER_PASSWORD: &str = "super-Pw-0f3c9a2e";

/// A running temporary cluster.
pub struct TempCluster {
    dir: Option<tempfile::TempDir>,
    bin: PathBuf,
    /// Port.
    pub port: u16,
    /// PKI whose CA signed the server certificate (SANs: localhost, 127.0.0.1).
    pub pki: TestPki,
    watchdog: Option<std::process::Child>,
}

fn find_bin() -> PathBuf {
    for p in [
        "/opt/homebrew/opt/postgresql@17/bin",
        "/opt/homebrew/bin",
        "/usr/local/opt/postgresql@17/bin",
        "/usr/local/bin",
        "/usr/lib/postgresql/17/bin",
    ] {
        if Path::new(p).join("pg_ctl").exists() && Path::new(p).join("initdb").exists() {
            return PathBuf::from(p);
        }
    }
    panic!("PostgreSQL binaries (initdb, pg_ctl) not found");
}

fn port_in_use(port: u16) -> bool {
    std::net::TcpStream::connect_timeout(
        &std::net::SocketAddr::from(([127, 0, 0, 1], port)),
        Duration::from_millis(200),
    )
    .is_ok()
}

impl TempCluster {
    /// initdb + start on `port`.
    pub fn start(port: u16) -> Self {
        assert!(
            !port_in_use(port),
            "port {port} is already in use (a leftover test cluster?)"
        );
        let bin = find_bin();
        let dir = tempfile::Builder::new()
            .prefix("aipass-exec-pg-")
            .tempdir()
            .expect("tempdir");
        let data = dir.path().join("data");
        let pwfile = dir.path().join("pw");
        std::fs::write(&pwfile, SUPER_PASSWORD).expect("pwfile");
        let st = Command::new(bin.join("initdb"))
            .env("LC_ALL", "C")
            .env("LANG", "C")
            .arg("-D")
            .arg(&data)
            .args([
                "-U",
                "postgres",
                "--auth=scram-sha-256",
                "-E",
                "UTF8",
                "--no-locale",
                "--no-instructions",
            ])
            .arg(format!("--pwfile={}", pwfile.display()))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("initdb");
        assert!(st.success(), "initdb failed");
        std::fs::remove_file(&pwfile).ok();

        let pki = TestPki::new(&["localhost", "127.0.0.1"]);
        std::fs::write(data.join("server.crt"), &pki.leaf_pem).expect("crt");
        let key = data.join("server.key");
        std::fs::write(&key, &pki.key_pem).expect("key");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).expect("chmod");
        }
        let conf = format!(
            "\nport = {port}\nlisten_addresses = '127.0.0.1'\nunix_socket_directories = '{}'\n\
             ssl = on\nssl_cert_file = 'server.crt'\nssl_key_file = 'server.key'\n\
             max_connections = 60\nfsync = off\nsynchronous_commit = off\nfull_page_writes = off\n\
             password_encryption = 'scram-sha-256'\nlog_min_messages = warning\n",
            dir.path().display()
        );
        let mut existing = std::fs::read_to_string(data.join("postgresql.conf")).expect("conf");
        existing.push_str(&conf);
        std::fs::write(data.join("postgresql.conf"), existing).expect("conf write");

        let st = Command::new(bin.join("pg_ctl"))
            .env("LC_ALL", "C")
            .env("LANG", "C")
            .arg("-D")
            .arg(&data)
            .arg("-l")
            .arg(dir.path().join("server.log"))
            .args(["-w", "-t", "60", "start"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("pg_ctl start");
        if !st.success() {
            let log = std::fs::read_to_string(dir.path().join("server.log")).unwrap_or_default();
            panic!("pg_ctl start failed:\n{log}");
        }
        // Watchdog: stop + delete the cluster if this process disappears without Drop.
        let watchdog = Command::new("/bin/sh")
            .env("LC_ALL", "C")
            .arg("-c")
            .arg(format!(
                "while kill -0 {pid} 2>/dev/null; do sleep 1; done; '{pg_ctl}' -D '{data}' -m immediate stop >/dev/null 2>&1; rm -rf '{dir}'",
                pid = std::process::id(),
                pg_ctl = bin.join("pg_ctl").display(),
                data = data.display(),
                dir = dir.path().display(),
            ))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .ok();
        Self {
            dir: Some(dir),
            bin,
            port,
            pki,
            watchdog,
        }
    }

    /// Superuser connection to `db`.
    pub async fn superuser(&self, db: &str) -> Client {
        Self::connect_as(self.port, db, "postgres", SUPER_PASSWORD)
            .await
            .expect("superuser connect")
    }

    /// Plain connection as `user`.
    pub async fn connect_as(
        port: u16,
        db: &str,
        user: &str,
        password: &str,
    ) -> Result<Client, tokio_postgres::Error> {
        let mut cfg = tokio_postgres::Config::new();
        cfg.host("127.0.0.1")
            .port(port)
            .dbname(db)
            .user(user)
            .password(password)
            .connect_timeout(Duration::from_secs(5));
        let (client, conn) = cfg.connect(NoTls).await?;
        tokio::spawn(async move {
            let _ = conn.await;
        });
        Ok(client)
    }

    /// Server log (for diagnostics).
    pub fn log(&self) -> String {
        self.dir
            .as_ref()
            .map(|d| std::fs::read_to_string(d.path().join("server.log")).unwrap_or_default())
            .unwrap_or_default()
    }
}

impl Drop for TempCluster {
    fn drop(&mut self) {
        if let Some(dir) = self.dir.take() {
            let _ = Command::new(self.bin.join("pg_ctl"))
                .arg("-D")
                .arg(dir.path().join("data"))
                .args(["-m", "immediate", "-w", "stop"])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
            drop(dir);
        }
        if let Some(mut w) = self.watchdog.take() {
            let _ = w.kill();
            let _ = w.wait();
        }
    }
}
