//! The iohr extension token socket (RFC 0028): when the agent runs as `iohr agent …`,
//! iohr passes `IOHR_EXT_TOKEN_SOCKET` (a 0600 Unix socket, a named pipe on Windows) and
//! the agent asks it for a short-lived access token narrowed to the scopes it needs. The
//! refresh token never leaves iohr.

use std::path::Path;

use serde::Deserialize;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use zeroize::Zeroizing;

use crate::error::{Error, Result};

/// The socket variable.
pub const SOCKET_ENV: &str = "IOHR_EXT_TOKEN_SOCKET";
/// The API base variable.
pub const API_ENV: &str = "IOHR_EXT_API";
const MAX_ANSWER: usize = 64 * 1024;

#[derive(Deserialize)]
struct TokenAnswer {
    access_token: String,
}

/// Asks iohr for an access token with `scopes`.
///
/// # Errors
/// When the socket cannot be reached or refuses.
pub async fn fetch_token(socket: &Path, scopes: &[&str]) -> Result<Zeroizing<String>> {
    #[cfg(unix)]
    {
        let s = tokio::net::UnixStream::connect(socket)
            .await
            .map_err(|e| Error::Platform(format!("iohr token socket {}: {e}", socket.display())))?;
        exchange(s, scopes).await
    }
    #[cfg(windows)]
    {
        let s = tokio::net::windows::named_pipe::ClientOptions::new()
            .open(socket)
            .map_err(|e| Error::Platform(format!("iohr token pipe {}: {e}", socket.display())))?;
        exchange(s, scopes).await
    }
}

/// One HTTP/1.1 request over the socket.
async fn exchange<S: AsyncRead + AsyncWrite + Unpin>(
    mut s: S,
    scopes: &[&str],
) -> Result<Zeroizing<String>> {
    let body = serde_json::json!({ "scopes": scopes }).to_string();
    let req = format!(
        "POST /token HTTP/1.1\r\nHost: iohr\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    s.write_all(req.as_bytes())
        .await
        .map_err(|e| Error::Platform(format!("iohr token socket: {e}")))?;
    let mut raw = Zeroizing::new(Vec::new());
    let mut limited = (&mut s).take(MAX_ANSWER as u64 + 1);
    limited
        .read_to_end(&mut raw)
        .await
        .map_err(|e| Error::Platform(format!("iohr token socket: {e}")))?;
    if raw.len() > MAX_ANSWER {
        return Err(Error::Platform(
            "iohr token socket: answer too large".into(),
        ));
    }
    let (status, headers, body) = split_response(&raw)
        .ok_or_else(|| Error::Platform("iohr token socket: malformed answer".into()))?;
    if status != 200 {
        return Err(Error::Platform(format!(
            "iohr refused the token request ({status}); the extension's scopes may not include {scopes:?}"
        )));
    }
    let body = if headers
        .to_ascii_lowercase()
        .contains("transfer-encoding: chunked")
    {
        Zeroizing::new(
            dechunk(body)
                .ok_or_else(|| Error::Platform("iohr token socket: bad chunked body".into()))?,
        )
    } else {
        Zeroizing::new(body.to_vec())
    };
    let answer: TokenAnswer = serde_json::from_slice(&body)
        .map_err(|_| Error::Platform("iohr token socket: answer is not a token".into()))?;
    Ok(Zeroizing::new(answer.access_token))
}

fn split_response(raw: &[u8]) -> Option<(u16, String, &[u8])> {
    let end = raw.windows(4).position(|w| w == b"\r\n\r\n")?;
    let head = std::str::from_utf8(raw.get(..end)?).ok()?;
    let status = head.split(' ').nth(1)?.parse().ok()?;
    Some((status, head.to_owned(), raw.get(end + 4..)?))
}

fn dechunk(mut body: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let line_end = body.windows(2).position(|w| w == b"\r\n")?;
        let size_str = std::str::from_utf8(body.get(..line_end)?).ok()?;
        let size = usize::from_str_radix(size_str.split(';').next()?.trim(), 16).ok()?;
        body = body.get(line_end + 2..)?;
        if size == 0 {
            return Some(out);
        }
        out.extend_from_slice(body.get(..size)?);
        body = body.get(size + 2..)?;
    }
}

#[cfg(test)]
#[cfg(unix)]
mod tests {
    use super::*;

    fn fake_iohr(answer: &'static str) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tok.sock");
        let l = tokio::net::UnixListener::bind(&path).unwrap();
        tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let n = s.read(&mut buf).await.unwrap();
            let req = String::from_utf8_lossy(&buf[..n]).to_string();
            assert!(req.starts_with("POST /token HTTP/1.1"));
            assert!(req.contains("\"scopes\":[\"agents:write\"]"));
            s.write_all(answer.as_bytes()).await.unwrap();
        });
        (dir, path)
    }

    #[tokio::test]
    async fn content_length_and_chunked() {
        let (_d, p) = fake_iohr(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"access_token\":\"at\",\"expires_at\":\"x\"}",
        );
        assert_eq!(
            fetch_token(&p, &["agents:write"]).await.unwrap().as_str(),
            "at"
        );
        let (_d, p) = fake_iohr(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n10\r\n{\"access_token\":\r\n5\r\n\"at2\"\r\n1\r\n}\r\n0\r\n\r\n",
        );
        assert_eq!(
            fetch_token(&p, &["agents:write"]).await.unwrap().as_str(),
            "at2"
        );
        let (_d, p) = fake_iohr("HTTP/1.1 403 Forbidden\r\n\r\n");
        assert!(fetch_token(&p, &["agents:write"]).await.is_err());
    }
}
