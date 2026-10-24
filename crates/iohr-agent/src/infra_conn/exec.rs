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
    // Its own process group, so a deadline stops everything it started, not only it.
    #[cfg(unix)]
    cmd.process_group(0);
    let mut child = cmd.spawn()?;
    let (Some(out), Some(err)) = (child.stdout.take(), child.stderr.take()) else {
        return Err(std::io::Error::other("no pipes"));
    };
    let pid = child.id();
    let readers = tokio::spawn(async move {
        let ((o, oc), (e, ec)) = tokio::join!(read_capped(out, cap), read_capped(err, cap));
        (o, e, oc || ec)
    });
    let deadline = tokio::time::sleep(timeout);
    tokio::pin!(deadline);
    let status = tokio::select! {
        s = child.wait() => Some(s?),
        () = &mut deadline => None,
    };
    let Some(status) = status else {
        stop(&mut child, pid).await;
        readers.abort();
        return Ok(Output {
            code: None,
            stdout: Vec::new(),
            stderr: Vec::new(),
            truncated: false,
            timed_out: true,
        });
    };
    // The child is gone, and so is anything it left running in its group: a background
    // process must not outlive the command (or keep a pipe open to the end of the deadline).
    kill_group(pid);
    // A grandchild that somehow still holds a pipe gets what is left of the deadline.
    match tokio::time::timeout_at(deadline.deadline(), readers).await {
        Ok(Ok((stdout, stderr, truncated))) => Ok(Output {
            code: status.code(),
            stdout,
            stderr,
            truncated,
            timed_out: false,
        }),
        Ok(Err(e)) => Err(std::io::Error::other(e)),
        Err(_) => {
            stop(&mut child, pid).await;
            Ok(Output {
                code: None,
                stdout: Vec::new(),
                stderr: Vec::new(),
                truncated: false,
                timed_out: true,
            })
        }
    }
}

/// Kills what is left of the child's process group at once. The child has exited, so
/// the group holds only what it started; an empty group makes this a no-op.
#[cfg(unix)]
fn kill_group(pid: Option<u32>) {
    use rustix::process::{Pid, Signal, kill_process_group};
    if let Some(g) = pid
        .and_then(|p| i32::try_from(p).ok())
        .and_then(Pid::from_raw)
    {
        let _ = kill_process_group(g, Signal::KILL);
    }
}

#[cfg(not(unix))]
fn kill_group(_pid: Option<u32>) {}

/// Stops the process group: TERM, two seconds to exit, then KILL.
#[cfg(unix)]
async fn stop(child: &mut tokio::process::Child, pid: Option<u32>) {
    use rustix::process::{Pid, Signal, kill_process_group};
    let group = pid
        .and_then(|p| i32::try_from(p).ok())
        .and_then(Pid::from_raw);
    if let Some(g) = group {
        let _ = kill_process_group(g, Signal::TERM);
        tokio::time::sleep(Duration::from_secs(2)).await;
        let _ = kill_process_group(g, Signal::KILL);
    } else {
        let _ = child.start_kill();
    }
    let _ = child.wait().await;
}

#[cfg(not(unix))]
async fn stop(child: &mut tokio::process::Child, _pid: Option<u32>) {
    let _ = child.kill().await;
}
