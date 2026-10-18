//! One bounded process: argv only, a cleared environment, no stdin, a deadline and a cap
//! on what is read. Never a shell.

use std::collections::BTreeMap;
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt as _};
use tokio::process::Command;

/// What a process left.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Output {
    /// The exit code; `None` when it was killed (deadline or signal).
    pub code: Option<i32>,
    /// Standard output, cut at the cap.
    pub stdout: Vec<u8>,
    /// Standard error, cut at the cap.
    pub stderr: Vec<u8>,
    /// Either stream was cut.
    pub truncated: bool,
    /// The deadline passed and the process was killed.
    pub timed_out: bool,
}

async fn read_capped<R: AsyncRead + Unpin>(mut r: R, cap: usize) -> (Vec<u8>, bool) {
    let mut buf = Vec::new();
    let mut chunk = vec![0u8; 8192];
    let mut cut = false;
    loop {
        match r.read(&mut chunk).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if buf.len() < cap {
                    let take = n.min(cap - buf.len());
                    buf.extend_from_slice(&chunk[..take]);
                    cut |= take < n;
                } else {
                    cut = true; // keep draining so the child never blocks on a full pipe
                }
            }
        }
    }
    (buf, cut)
}

/// Runs `bin args` in `cwd` with exactly `env`, for at most `timeout`, keeping at most
/// `cap` bytes of each stream.
///
/// # Errors
/// The process could not be started.
pub async fn run(
    bin: &Path,
    args: &[String],
    cwd: &Path,
    env: &BTreeMap<String, String>,
    timeout: Duration,
    cap: usize,
) -> std::io::Result<Output> {
    let mut cmd = Command::new(bin);
    cmd.args(args)
        .current_dir(cwd)
        .env_clear()
        .envs(env)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let mut child = cmd.spawn()?;
    let (Some(out), Some(err)) = (child.stdout.take(), child.stderr.take()) else {
        return Err(std::io::Error::other("no pipes"));
    };
    let work = async {
        let ((o, oc), (e, ec)) = tokio::join!(read_capped(out, cap), read_capped(err, cap));
        let status = child.wait().await?;
        Ok::<_, std::io::Error>((o, e, oc || ec, status.code()))
    };
    match tokio::time::timeout(timeout, work).await {
        Ok(r) => {
            let (stdout, stderr, truncated, code) = r?;
            Ok(Output {
                code,
                stdout,
                stderr,
                truncated,
                timed_out: false,
            })
        }
        Err(_) => Ok(Output {
            code: None,
            stdout: Vec::new(),
            stderr: Vec::new(),
            truncated: false,
            timed_out: true,
        }),
    }
}
