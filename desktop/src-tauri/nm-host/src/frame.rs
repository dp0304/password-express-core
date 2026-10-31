// SPDX-License-Identifier: Apache-2.0
//! Chrome native-messaging framing: a 4-byte little-endian length followed by that many
//! bytes of UTF-8 JSON. Chrome limits host→browser messages to 1 MB; we apply the same
//! cap in both directions because no legitimate message of ours comes close.

use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Maximum frame we read or write (1 MiB, Chrome's host→browser limit).
pub const MAX_FRAME: usize = 1024 * 1024;

/// Errors while reading a frame.
#[derive(Debug)]
pub enum FrameError {
    /// Underlying I/O failed.
    Io(io::Error),
    /// The announced length exceeds [`MAX_FRAME`] (the stream cannot be resynchronised).
    TooLarge(usize),
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "i/o error: {e}"),
            Self::TooLarge(n) => write!(f, "frame of {n} bytes exceeds the {MAX_FRAME} byte limit"),
        }
    }
}

impl std::error::Error for FrameError {}

impl From<io::Error> for FrameError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

/// Read one frame. `Ok(None)` means a clean end of stream before a new frame started.
pub async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> Result<Option<Vec<u8>>, FrameError> {
    let mut len = [0u8; 4];
    let mut got = 0;
    while got < 4 {
        let n = r.read(&mut len[got..]).await?;
        if n == 0 {
            if got == 0 {
                return Ok(None);
            }
            return Err(FrameError::Io(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "truncated length prefix",
            )));
        }
        got += n;
    }
    let n = u32::from_le_bytes(len) as usize;
    if n > MAX_FRAME {
        return Err(FrameError::TooLarge(n));
    }
    let mut buf = vec![0u8; n];
    r.read_exact(&mut buf).await?;
    Ok(Some(buf))
}

/// Write one frame and flush.
pub async fn write_frame<W: AsyncWrite + Unpin>(w: &mut W, body: &[u8]) -> io::Result<()> {
    if body.len() > MAX_FRAME {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "frame too large"));
    }
    let len = u32::try_from(body.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "frame too large"))?;
    w.write_all(&len.to_le_bytes()).await?;
    w.write_all(body).await?;
    w.flush().await
}

/// Serialize `v` and write it as one frame.
pub async fn write_json<W: AsyncWrite + Unpin>(w: &mut W, v: &serde_json::Value) -> io::Result<()> {
    let bytes = serde_json::to_vec(v).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    write_frame(w, &bytes).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn roundtrip_and_eof() {
        let mut buf = Vec::new();
        write_frame(&mut buf, br#"{"id":"1","type":"status"}"#).await.unwrap();
        write_frame(&mut buf, b"{}").await.unwrap();
        assert_eq!(&buf[..4], &26u32.to_le_bytes());
        let mut r = &buf[..];
        assert_eq!(read_frame(&mut r).await.unwrap().unwrap(), br#"{"id":"1","type":"status"}"#);
        assert_eq!(read_frame(&mut r).await.unwrap().unwrap(), b"{}");
        assert!(read_frame(&mut r).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn rejects_oversized_and_truncated() {
        let big = ((MAX_FRAME + 1) as u32).to_le_bytes();
        let mut r = &big[..];
        assert!(matches!(read_frame(&mut r).await, Err(FrameError::TooLarge(_))));
        let mut r = &[3u8, 0][..];
        assert!(matches!(read_frame(&mut r).await, Err(FrameError::Io(_))));
        let mut r = &[5u8, 0, 0, 0, b'{'][..];
        assert!(matches!(read_frame(&mut r).await, Err(FrameError::Io(_))));
        let mut sink = Vec::new();
        assert!(write_frame(&mut sink, &vec![0u8; MAX_FRAME + 1]).await.is_err());
    }
}
