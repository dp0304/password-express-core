// SPDX-License-Identifier: Apache-2.0
//! Serving helpers: Unix domain socket (mode 0600, inside a 0700 directory) and TCP.
//!
//! **UDS admin peers.** With [`UdsOptions::admin_peers`], a peer whose uid equals the
//! socket owner's uid is the local admin (`A`). Same-user processes can also read
//! `<data>/admin.token`, so this grants nothing beyond what the token already does — in
//! the `compatible` protection level the product does not claim to resist same-user code
//! (design doc §9.3). Approval *decisions* always need a device signature, whoever relays
//! them. Embedders that expose the socket to AI bridges may prefer a separate admin
//! socket (`admin_peers: true`) and a connections socket (`admin_peers: false`).

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::path::Path;

use axum::Router;
use axum::extract::connect_info::Connected;
use axum::serve::IncomingStream;
use tokio::net::{TcpListener, UnixListener};

use super::UdsAdminUid;

/// Options for [`serve_uds`].
#[derive(Debug, Clone, Copy, Default)]
pub struct UdsOptions {
    /// Treat same-uid peers of this socket as the local admin (principal class `A`).
    pub admin_peers: bool,
}

/// Connect info of a UDS peer.
#[derive(Debug, Clone)]
pub struct UdsPeer {
    /// Peer uid from the kernel (`SO_PEERCRED` / `getpeereid`).
    pub uid: Option<u32>,
}

impl Connected<IncomingStream<'_, UnixListener>> for UdsPeer {
    fn connect_info(stream: IncomingStream<'_, UnixListener>) -> Self {
        Self {
            uid: stream.io().peer_cred().ok().map(|c| c.uid()),
        }
    }
}

/// Bind a Unix socket at `path`: creates the parent directory with mode 0700 when
/// missing, replaces a stale socket file (never a regular file), and sets the socket to
/// mode 0600.
pub fn bind_uds(path: &Path) -> io::Result<UnixListener> {
    use std::os::unix::fs::{DirBuilderExt, FileTypeExt, PermissionsExt};
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty() && !parent.exists() {
            std::fs::DirBuilder::new().recursive(true).mode(0o700).create(parent)?;
        }
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_socket() => std::fs::remove_file(path)?,
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "refusing to replace a non-socket file at the broker socket path",
            ));
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let listener = UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}

/// Bind and serve `router` on a Unix socket until `shutdown` resolves; removes the socket
/// file afterwards.
pub async fn serve_uds<F>(router: Router, path: &Path, opts: UdsOptions, shutdown: F) -> io::Result<()>
where
    F: Future<Output = ()> + Send + 'static,
{
    let listener = bind_uds(path)?;
    let r = serve_uds_listener(listener, path, router, opts, shutdown).await;
    let _ = std::fs::remove_file(path);
    r
}

/// Serve on an already bound socket (`path` is used to learn the owner uid).
pub async fn serve_uds_listener<F>(
    listener: UnixListener,
    path: &Path,
    router: Router,
    opts: UdsOptions,
    shutdown: F,
) -> io::Result<()>
where
    F: Future<Output = ()> + Send + 'static,
{
    use std::os::unix::fs::MetadataExt;
    let app = if opts.admin_peers {
        let uid = std::fs::metadata(path)?.uid();
        router.layer(axum::Extension(UdsAdminUid(uid)))
    } else {
        router
    };
    axum::serve(listener, app.into_make_service_with_connect_info::<UdsPeer>())
        .with_graceful_shutdown(shutdown)
        .await
}

/// Serve `router` on a TCP listener (peer addresses feed the public-endpoint rate limit).
/// TCP peers are never admin; use the admin token.
pub async fn serve_tcp<F>(router: Router, listener: TcpListener, shutdown: F) -> io::Result<()>
where
    F: Future<Output = ()> + Send + 'static,
{
    axum::serve(listener, router.into_make_service_with_connect_info::<SocketAddr>())
        .with_graceful_shutdown(shutdown)
        .await
}
