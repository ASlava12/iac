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
use std::sync::mpsc;
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
/// errors during stdin write are logged at debug; the caller still
/// sees the child's stderr/exit.
///
/// ## Concurrency model
///
/// stdout, stderr and stdin are each handled by a dedicated thread
/// so no single pipe buffer can ever deadlock the wait:
///
/// * Pre-fix, the parent only drained stdout/stderr *after* the
///   child exited. A child that wrote more than the ~64 KiB OS pipe
///   buffer before exiting blocked on `write()` forever; the parent
///   never saw the exit and the call burned the full `timeout` then
///   SIGKILLed a perfectly healthy process.
/// * Pre-fix, the timeout branch did a blocking `read_to_end`
///   *before* `kill()`. If the child held the pipe open (e.g. a
///   `sleep` with inherited stdout), that read blocked until the
///   child exited on its own — so the timeout never fired. We now
///   `kill()` first, which closes the write ends, lets the reader
///   threads finish, and collects whatever was buffered with a hard
///   [`POST_KILL_REAP_WINDOW`] bound.
pub fn run_with_timeout(
    mut cmd: Command,
    stdin_bytes: &[u8],
    timeout: Duration,
) -> std::result::Result<Output, SubprocessError> {
    let started = Instant::now();
    let mut child = cmd.spawn().map_err(SubprocessError::Spawn)?;

    // Drain stdout/stderr on their own threads so the child can
    // never block on a full pipe buffer while we wait for exit.
    let stdout_rx = child.stdout.take().map(spawn_reader);
    let stderr_rx = child.stderr.take().map(spawn_reader);

    // Feed stdin on its own thread too: a child that fills its stdin
    // pipe buffer before reading would otherwise deadlock the parent
    // here. The thread drops the handle on completion → child sees EOF.
    if let Some(mut stdin) = child.stdin.take() {
        let bytes = stdin_bytes.to_vec();
        std::thread::spawn(move || match stdin.write_all(&bytes) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => {}
            Err(e) => tracing::debug!("subprocess stdin write: {e}"),
        });
    }

    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                // Child exited → write ends are closed, so the reader
                // threads finish promptly. recv() blocks only until
                // they flush their final buffer.
                let stdout = stdout_rx.and_then(|rx| rx.recv().ok()).unwrap_or_default();
                let stderr = stderr_rx.and_then(|rx| rx.recv().ok()).unwrap_or_default();
                return Ok(Output {
                    status,
                    stdout,
                    stderr,
                });
            }
            Ok(None) => {
                if started.elapsed() >= timeout {
                    // Kill FIRST so the write ends close and the
                    // reader threads can complete; then collect their
                    // partial output with a hard deadline so a
                    // grandchild holding the pipe can't pin us.
                    let _ = child.kill();
                    let reap_deadline = Instant::now() + POST_KILL_REAP_WINDOW;
                    while Instant::now() < reap_deadline {
                        match child.try_wait() {
                            Ok(Some(_)) => break,
                            _ => std::thread::sleep(POLL_INTERVAL),
                        }
                    }
                    let partial_stdout = stdout_rx
                        .and_then(|rx| rx.recv_timeout(POST_KILL_REAP_WINDOW).ok())
                        .unwrap_or_default();
                    let partial_stderr = stderr_rx
                        .and_then(|rx| rx.recv_timeout(POST_KILL_REAP_WINDOW).ok())
                        .unwrap_or_default();
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

/// Spawn a thread that drains `reader` to EOF and ships the bytes
/// back over a channel. Errors are swallowed: a read error yields
/// whatever was captured so far (diagnostics-grade output).
fn spawn_reader<R: Read + Send + 'static>(mut reader: R) -> mpsc::Receiver<Vec<u8>> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = reader.read_to_end(&mut buf);
        let _ = tx.send(buf);
    });
    rx
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

    #[test]
    fn large_stdout_does_not_deadlock() {
        // Regression: a child that writes far more than the ~64 KiB
        // OS pipe buffer before exiting used to deadlock — the parent
        // didn't drain stdout until after exit, but the child blocked
        // on write() before it could exit. With reader threads the
        // full output comes back and the child exits cleanly.
        let out = run_with_timeout(
            cmd("/bin/sh", &["-c", "yes abcdefgh | head -c 1000000"]),
            b"",
            Duration::from_secs(10),
        )
        .unwrap();
        assert!(out.status.success());
        assert_eq!(out.stdout.len(), 1_000_000);
    }

    #[test]
    fn timeout_fires_promptly_when_child_holds_pipe_open() {
        // Regression: the timeout branch used to `read_to_end` before
        // `kill()`. A child that keeps stdout open (here `sleep`, whose
        // inherited stdout fd stays open) made that read block until
        // the child exited on its own (10 s), so the 200 ms deadline
        // never fired. Now we kill first; the call must return well
        // before the natural 10 s exit.
        let started = Instant::now();
        let result = run_with_timeout(
            cmd("/bin/sh", &["-c", "sleep 10"]),
            b"",
            Duration::from_millis(200),
        );
        let elapsed = started.elapsed();
        assert!(
            matches!(result, Err(SubprocessError::Timeout { .. })),
            "expected Timeout, got {result:?}"
        );
        assert!(
            elapsed < Duration::from_secs(5),
            "timeout did not fire promptly: {elapsed:?}"
        );
    }
}
