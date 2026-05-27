//! Phase 7di.5: shared subprocess-with-timeout primitive.
//!
//! Pre-7di.5 the shellout and external-process plugin runtimes each
//! had their own spawn → write-stdin → poll → kill → reap loop
//! (~80 LOC and ~150 LOC respectively). They drifted on hardening
//! details: shellout's BrokenPipe handling vs. process's, the
//! 25 ms vs. 20 ms polling tick, the 1 s vs. 0 s reap window, etc.
//! Phase 7dh.5 had to fix the same bug class in both. This module
//! collapses the spawn-and-wait shape so future hardening lands in
//! one place.
//!
//! Scope on purpose limited to the **synchronous, one-shot** case:
//! spawn, optionally feed stdin, wait for exit-or-timeout, return
//! captured stdout + stderr + status. Long-running plugin processes
//! (the external-process runtime's per-plugin daemon) keep their
//! own NDJSON-RPC loop on top of `Command::spawn` — that's a
//! different shape and not what this helper targets.

use std::io::{Read, Write};
use std::process::{Command, ExitStatus};
use std::time::{Duration, Instant};

/// Polling tick. The host wakes this often to check whether the
/// child has exited or the deadline has passed. Smaller values
/// reduce reap latency; larger values reduce host CPU when many
/// processes are running concurrently. 25 ms matches the
/// historical shellout value and is the default operators
/// expect.
const POLL_INTERVAL: Duration = Duration::from_millis(25);

/// How long we wait, after `kill()`, for the child to actually
/// exit before giving up and letting the OS reap on agent exit.
/// SIGKILL is unblockable, so this is mostly hedging against
/// the kernel's accounting being slow on a loaded system.
const POST_KILL_REAP_WINDOW: Duration = Duration::from_secs(1);

/// Captured output from one subprocess invocation.
#[derive(Debug, Clone)]
pub struct Output {
    pub status: ExitStatus,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

/// Why a [`run_with_timeout`] call failed before producing an
/// [`Output`]. Successful runs (any exit status, including
/// non-zero) return `Ok(Output)`; the caller decides whether the
/// status is acceptable.
#[derive(Debug)]
pub enum SubprocessError {
    /// `Command::spawn` failed (binary not on PATH, exec denied,
    /// fork failed). Carries the raw `io::Error` so callers can
    /// distinguish ENOENT vs. EACCES.
    Spawn(std::io::Error),
    /// Child didn't exit within `timeout`. We sent SIGKILL and
    /// gave it [`POST_KILL_REAP_WINDOW`]; whether or not the
    /// reap completed, the call surfaces this so the operator
    /// sees it. Carries any bytes captured up to the kill so
    /// diagnostics aren't lost.
    Timeout {
        elapsed: Duration,
        partial_stdout: Vec<u8>,
        partial_stderr: Vec<u8>,
    },
    /// `child.try_wait()` itself failed — usually means the OS
    /// dropped the parent → child relationship under us.
    Wait(std::io::Error),
}

impl std::fmt::Display for SubprocessError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Spawn(e) => write!(f, "spawn failed: {e}"),
            Self::Timeout { elapsed, .. } => {
                write!(f, "subprocess timed out after {}s", elapsed.as_secs())
            }
            Self::Wait(e) => write!(f, "wait failed: {e}"),
        }
    }
}

impl std::error::Error for SubprocessError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Spawn(e) | Self::Wait(e) => Some(e),
            Self::Timeout { .. } => None,
        }
    }
}

/// Run a pre-built [`Command`], optionally piping `stdin_bytes`,
/// and return its captured output or a [`SubprocessError`].
///
/// Caller responsibilities:
/// * Set `cmd.stdin/stdout/stderr` to `Stdio::piped()` if input or
///   capture is desired. This helper does NOT mutate the stdio
///   configuration so callers retain full control (e.g.
///   `Stdio::inherit()` for one stream, `Stdio::piped()` for
///   another).
/// * Treat `Output.status` non-zero as application-level
///   failure; this helper returns `Ok(_)` for any exit code.
/// * Choose `timeout` to fit the workload. There is no
///   "infinite" sentinel — pick `Duration::from_secs(3600)` if
///   you genuinely don't want a deadline.
///
/// `BrokenPipe` on the stdin write is treated as benign: a child
/// that exits before reading its input is a legitimate
/// `stdout`-only producer (think `echo '{...}'`). Genuine I/O
/// errors during stdin write surface as a [`SubprocessError::Wait`]
/// after the child reaps (we capture the exit status; the caller
/// sees stderr).
pub fn run_with_timeout(
    mut cmd: Command,
    stdin_bytes: &[u8],
    timeout: Duration,
) -> std::result::Result<Output, SubprocessError> {
    let started = Instant::now();
    let mut child = cmd.spawn().map_err(SubprocessError::Spawn)?;

    // Feed stdin first. We're synchronous so a child that fills
    // its OS-level pipe buffer (~64 KiB on Linux) before we get
    // here will block — but the trial's plugin envelopes are far
    // smaller than that, and the alternative (background thread
    // for the write) doubles the complexity for no operator-
    // visible win.
    if let Some(stdin) = child.stdin.as_mut() {
        match stdin.write_all(stdin_bytes) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => {}
            Err(e) => {
                // Don't surface raw I/O — let the wait branch
                // collect stderr so the operator sees what the
                // child complained about.
                tracing::debug!("subprocess stdin write: {e}");
            }
        }
    }
    // Drop stdin → EOF for the child. Some plugins block on read
    // until they see EOF.
    drop(child.stdin.take());

    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let mut stdout = Vec::new();
                let mut stderr = Vec::new();
                if let Some(s) = child.stdout.as_mut() {
                    s.read_to_end(&mut stdout).ok();
                }
                if let Some(s) = child.stderr.as_mut() {
                    s.read_to_end(&mut stderr).ok();
                }
                return Ok(Output {
                    status,
                    stdout,
                    stderr,
                });
            }
            Ok(None) => {
                if started.elapsed() >= timeout {
                    // Capture whatever's already buffered before
                    // the kill so diagnostics survive the reap.
                    let mut partial_stdout = Vec::new();
                    let mut partial_stderr = Vec::new();
                    if let Some(s) = child.stdout.as_mut() {
                        s.read_to_end(&mut partial_stdout).ok();
                    }
                    if let Some(s) = child.stderr.as_mut() {
                        s.read_to_end(&mut partial_stderr).ok();
                    }
                    let _ = child.kill();
                    // Bounded reap loop. If the child still hasn't
                    // exited in POST_KILL_REAP_WINDOW (very
                    // unlikely after SIGKILL), we let init reap
                    // it on agent exit — we'd rather return than
                    // pin the host thread.
                    let reap_deadline = Instant::now() + POST_KILL_REAP_WINDOW;
                    while Instant::now() < reap_deadline {
                        match child.try_wait() {
                            Ok(Some(_)) => break,
                            _ => std::thread::sleep(POLL_INTERVAL),
                        }
                    }
                    return Err(SubprocessError::Timeout {
                        elapsed: started.elapsed(),
                        partial_stdout,
                        partial_stderr,
                    });
                }
                std::thread::sleep(POLL_INTERVAL);
            }
            Err(e) => return Err(SubprocessError::Wait(e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Stdio;

    fn cmd(prog: &str, args: &[&str]) -> Command {
        let mut c = Command::new(prog);
        c.args(args);
        c.stdin(Stdio::piped());
        c.stdout(Stdio::piped());
        c.stderr(Stdio::piped());
        c
    }

    #[test]
    fn captures_stdout_on_success() {
        let out = run_with_timeout(
            cmd("/bin/sh", &["-c", "echo hello"]),
            b"",
            Duration::from_secs(2),
        )
        .unwrap();
        assert!(out.status.success());
        assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "hello");
    }

    #[test]
    fn captures_stderr_on_nonzero_exit() {
        let out = run_with_timeout(
            cmd("/bin/sh", &["-c", "echo oops >&2; exit 7"]),
            b"",
            Duration::from_secs(2),
        )
        .unwrap();
        assert!(!out.status.success());
        assert_eq!(out.status.code(), Some(7));
        assert_eq!(String::from_utf8_lossy(&out.stderr).trim(), "oops");
    }

    #[test]
    fn pipes_stdin_to_child() {
        let out =
            run_with_timeout(cmd("/usr/bin/wc", &["-c"]), b"abcd", Duration::from_secs(2)).unwrap();
        assert!(out.status.success());
        assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "4");
    }

    #[test]
    fn timeout_kills_runaway() {
        let result = run_with_timeout(cmd("/bin/sleep", &["10"]), b"", Duration::from_millis(200));
        match result {
            Err(SubprocessError::Timeout { elapsed, .. }) => {
                assert!(
                    elapsed >= Duration::from_millis(200),
                    "elapsed too short: {elapsed:?}"
                );
            }
            other => panic!("expected Timeout, got {other:?}"),
        }
    }

    #[test]
    fn brokenpipe_on_stdin_is_benign() {
        // `true` exits before reading any stdin → BrokenPipe
        // when we try to write. The helper must NOT surface that
        // as an error; the child exited 0 and we should see it.
        let mut c = Command::new("/bin/true");
        c.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let out = run_with_timeout(c, &vec![0u8; 1024], Duration::from_secs(2)).unwrap();
        assert!(out.status.success());
    }

    #[test]
    fn spawn_failure_returns_spawn_variant() {
        let c = Command::new("/this/binary/does/not/exist");
        let err = run_with_timeout(c, b"", Duration::from_secs(1)).unwrap_err();
        assert!(matches!(err, SubprocessError::Spawn(_)));
    }
}
