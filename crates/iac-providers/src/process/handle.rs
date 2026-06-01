//! Phase 7db.2: long-running plugin process supervisor.
//!
//! `PluginHandle` owns a child process + a synchronous request/response
//! pump over its stdin/stdout. One handle per kind, all calls serialised
//! through an internal mutex — plugin parallelism is the plugin's own
//! responsibility (cache pools, internal worker threads).
//!
//! Crash recovery: if the child dies between calls, the next call sees
//! a write or read error, the handle marks itself dead, and the
//! `ExternalProvider` re-spawns transparently (when `restart_on_crash`).

use super::proto::{Frame, Hello, PROTOCOL_VERSION, Request, Response};
use super::spec::ExternalProviderSpec;
use iac_core::{Error, Result};
use parking_lot::Mutex;
use serde_json::Value as Json;
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc;
use std::time::Instant;

pub struct PluginHandle {
    spec: ExternalProviderSpec,
    state: Mutex<State>,
}

struct State {
    proc: Option<RunningProc>,
    next_id: u64,
    /// Hello message captured from the last successful spawn. Cached
    /// so callers can read `capability_keys` / `methods` without
    /// crossing the wire on every request.
    hello: Option<Hello>,
    /// Phase 7dh.5: tracks consecutive crashes for the restart-on-
    /// crash cool-off. Reset to 0 after a successful spawn-and-call.
    /// Increments each time we observe a transport-shaped failure.
    consecutive_crashes: u32,
    /// Phase 7dh.5: the earliest instant the next spawn is allowed.
    /// While `Instant::now() < spawn_blocked_until`, calls fail
    /// fast with a clear "in cool-off" error instead of forking yet
    /// another doomed child.
    spawn_blocked_until: Option<Instant>,
}

struct RunningProc {
    child: Child,
    stdin: ChildStdin,
    /// Complete NDJSON lines delivered by a dedicated reader thread.
    /// Reading through a channel (rather than a blocking `fill_buf`
    /// on the calling thread) is what makes the per-call deadline
    /// real: `BufRead::fill_buf` blocks until a byte arrives, so a
    /// plugin that never writes (and never closes stdout) would
    /// otherwise hang the worker past any timeout. The reader thread
    /// exits when the child's stdout closes (i.e. on kill/exit).
    lines: mpsc::Receiver<std::io::Result<String>>,
}

impl PluginHandle {
    pub fn new(spec: ExternalProviderSpec) -> Self {
        Self {
            spec,
            state: Mutex::new(State {
                proc: None,
                next_id: 1,
                hello: None,
                consecutive_crashes: 0,
                spawn_blocked_until: None,
            }),
        }
    }

    pub fn kind(&self) -> &str {
        &self.spec.kind
    }

    /// Cached `hello` from the most recent spawn. Returns `None`
    /// before the first successful call.
    pub fn hello(&self) -> Option<Hello> {
        self.state.lock().hello.clone()
    }

    /// Issue a request. Spawns the plugin lazily; respawns on crash
    /// when `restart_on_crash`. Errors carry kind for log triage.
    ///
    /// Phase 7dh.5: per-handle restart cool-off. After 3
    /// consecutive transport-shaped failures, further spawns are
    /// blocked for an exponentially-growing window (capped at 5
    /// minutes). Stops the "plugin crashes on every call" pattern
    /// from looking like a fork bomb.
    pub fn call(&self, method: &str, params: Json) -> Result<Json> {
        let mut tries = 0;
        loop {
            tries += 1;
            let outcome = self.call_once(method, &params);
            match outcome {
                Ok(v) => {
                    // Reset crash counter on success — sustained good
                    // calls clear the cool-off entirely.
                    let mut state = self.state.lock();
                    state.consecutive_crashes = 0;
                    state.spawn_blocked_until = None;
                    return Ok(v);
                }
                Err(e) => {
                    // On a transport-shaped error we may retry once
                    // by respawning. We do not retry application
                    // errors (those come back as `Response.error`).
                    let transport = matches!(
                        &e,
                        Error::Provider { message, .. }
                            if message.contains("EOF")
                                || message.contains("write:")
                                || message.contains("read:")
                                || message.contains("not running")
                                || message.contains("ndjson line exceeded")
                    );
                    if transport {
                        let mut state = self.state.lock();
                        state.consecutive_crashes = state.consecutive_crashes.saturating_add(1);
                        // Threshold + backoff: after 3 in a row, set
                        // a cool-off of 2^(n-3) seconds, capped at
                        // 300 s (5 min). 4th = 2 s, 5th = 4 s, …,
                        // 11th and beyond = 300 s.
                        if state.consecutive_crashes >= 3 {
                            let extra = state.consecutive_crashes - 3;
                            let secs = 2u64.saturating_pow(extra.min(8)).min(300);
                            state.spawn_blocked_until =
                                Some(Instant::now() + std::time::Duration::from_secs(secs));
                        }
                        // Drop the dead child; next call_once will
                        // try to respawn (subject to cool-off).
                        state.proc = None;
                        drop(state);
                        if tries == 1 && self.spec.restart_on_crash {
                            continue;
                        }
                    }
                    return Err(e);
                }
            }
        }
    }

    fn call_once(&self, method: &str, params: &Json) -> Result<Json> {
        let mut state = self.state.lock();
        if state.proc.is_none() {
            self.spawn_locked(&mut state)?;
        }
        let id = {
            let n = state.next_id;
            state.next_id = state.next_id.wrapping_add(1).max(1);
            n
        };
        let req = Request {
            id,
            method: method.into(),
            params: params.clone(),
        };
        let line = serde_json::to_string(&req)
            .map_err(|e| Error::provider(&self.spec.kind, format!("encode request: {e}")))?;

        // Borrow the child's pipes via the lock for the duration of the
        // round-trip. Writes are small (one JSON line); reads are bounded
        // by `call_timeout_secs` — we enforce it by polling the child
        // and checking elapsed time.
        let proc = state
            .proc
            .as_mut()
            .ok_or_else(|| Error::provider(&self.spec.kind, "plugin not running"))?;
        write_line(&mut proc.stdin, &line)
            .map_err(|e| Error::provider(&self.spec.kind, format!("write: {e}")))?;

        let deadline = Instant::now() + self.spec.call_timeout();
        let resp = read_response_until(proc, deadline)
            .map_err(|e| Error::provider(&self.spec.kind, format!("read: {e}")))?;
        if resp.id != id {
            return Err(Error::provider(
                &self.spec.kind,
                format!("response id mismatch: expected {id}, got {}", resp.id),
            ));
        }
        if let Some(err) = resp.error {
            return Err(Error::provider(&self.spec.kind, err));
        }
        Ok(resp.result.unwrap_or(Json::Null))
    }

    fn spawn_locked(&self, state: &mut State) -> Result<()> {
        // Phase 7dh.5: cool-off gate. If the plugin has been
        // crashing in tight succession, refuse to spawn until the
        // backoff window expires. Caller sees a clear error rather
        // than yet-another-doomed-fork.
        if let Some(until) = state.spawn_blocked_until {
            let now = Instant::now();
            if now < until {
                let remaining = until - now;
                return Err(Error::provider(
                    &self.spec.kind,
                    format!(
                        "plugin in restart cool-off after {} consecutive crashes; \
                         retry in {}s",
                        state.consecutive_crashes,
                        remaining.as_secs() + 1
                    ),
                ));
            }
            // Window expired — clear it so the next failure starts a
            // fresh count; success will fully reset.
            state.spawn_blocked_until = None;
        }
        // Phase 7dh.4: optional content-hash pin. Read the binary
        // and verify its SHA-256 before spawning. There's still a
        // TOCTOU between the read and the exec — an attacker who
        // can swap the binary between these two operations could
        // bypass the check. That's acceptable: the *real* defence
        // is an immutable filesystem (read-only mount, IPE, dm-
        // verity); this pin catches the common case of "binary
        // got swapped on operator's host overnight" without doing
        // anything heroic.
        if let Some(expected) = self.spec.binary_sha256.as_deref() {
            let bytes = std::fs::read(&self.spec.binary).map_err(|e| {
                Error::provider(
                    &self.spec.kind,
                    format!("read binary {}: {e}", self.spec.binary.display()),
                )
            })?;
            crate::sha256_pin::verify_sha256(&bytes, expected, "binary")
                .map_err(|e| Error::provider(&self.spec.kind, e))?;
        }
        let mut cmd = Command::new(&self.spec.binary);
        cmd.args(&self.spec.args);
        for kv in &self.spec.env {
            if let Some((k, v)) = kv.split_once('=') {
                cmd.env(k, v);
            }
        }
        cmd.stdin(Stdio::piped());
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::inherit());
        let mut child = cmd.spawn().map_err(|e| {
            Error::provider(
                &self.spec.kind,
                format!("spawn {}: {e}", self.spec.binary.display()),
            )
        })?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| Error::provider(&self.spec.kind, "child stdin missing after spawn"))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| Error::provider(&self.spec.kind, "child stdout missing after spawn"))?;
        // Drain stdout on a dedicated thread so a per-call deadline can
        // actually fire even when the plugin goes silent without closing
        // the pipe. The thread ends when stdout closes (kill/exit).
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || reader_loop(stdout, &tx));

        let mut proc = RunningProc {
            child,
            stdin,
            lines: rx,
        };
        // Read the first line as the hello message.
        let deadline = Instant::now() + self.spec.handshake_timeout();
        let line = read_line_until(&mut proc, deadline)
            .map_err(|e| Error::provider(&self.spec.kind, format!("handshake read: {e}")))?;
        let hello: Hello = match serde_json::from_str::<Frame>(&line) {
            Ok(Frame::Hello { hello }) => hello,
            Ok(other) => {
                return Err(Error::provider(
                    &self.spec.kind,
                    format!("expected hello, got {other:?}"),
                ));
            }
            Err(e) => {
                return Err(Error::provider(
                    &self.spec.kind,
                    format!("hello parse: {e}: {line:?}"),
                ));
            }
        };
        if hello.protocol_version != PROTOCOL_VERSION {
            return Err(Error::provider(
                &self.spec.kind,
                format!(
                    "plugin protocol_version={} != agent protocol_version={}",
                    hello.protocol_version, PROTOCOL_VERSION
                ),
            ));
        }
        if hello.kind != self.spec.kind {
            return Err(Error::provider(
                &self.spec.kind,
                format!(
                    "plugin announces kind={:?} but config expects {:?}",
                    hello.kind, self.spec.kind
                ),
            ));
        }
        state.hello = Some(hello);
        state.proc = Some(proc);
        Ok(())
    }
}

impl Drop for PluginHandle {
    fn drop(&mut self) {
        // Best-effort: nudge the child via stdin EOF, give it a tick
        // to exit cleanly, then kill if still alive.
        let mut state = self.state.lock();
        if let Some(mut proc) = state.proc.take() {
            // Send a shutdown notification — the plugin can flush
            // caches if it wants. We don't read a response; we don't
            // care about ordering at drop time.
            let _ = write_line(
                &mut proc.stdin,
                &serde_json::to_string(&Request {
                    id: 0,
                    method: super::proto::methods::SHUTDOWN.into(),
                    params: Json::Null,
                })
                .unwrap_or_default(),
            );
            // Drop stdin → EOF.
            drop(proc.stdin);
            let deadline = Instant::now() + std::time::Duration::from_millis(500);
            while Instant::now() < deadline {
                match proc.child.try_wait() {
                    Ok(Some(_)) => break,
                    _ => std::thread::sleep(std::time::Duration::from_millis(20)),
                }
            }
            let _ = proc.child.kill();
            let _ = proc.child.wait();
        }
    }
}

// Small I/O helpers. `write_line` is a fail-soft "newline-delimited
// JSON" writer; `read_line_until` polls so we don't pin the thread
// indefinitely on a misbehaving plugin.

fn write_line<W: Write>(w: &mut W, line: &str) -> std::io::Result<()> {
    w.write_all(line.as_bytes())?;
    w.write_all(b"\n")?;
    w.flush()
}

/// Phase 7dh.5: hard cap on a single NDJSON line. A misbehaving
/// or malicious plugin can drip-feed bytes for the full call
/// timeout without ever emitting `\n`; without this cap the host
/// would buffer the whole tail in memory. 16 MiB is generous for
/// any legitimate plugin response — bigger than that means
/// "something is wrong" and we'd rather error than OOM.
const MAX_NDJSON_LINE_BYTES: usize = 16 * 1024 * 1024;

fn read_line_until(proc: &mut RunningProc, deadline: Instant) -> std::io::Result<String> {
    // The reader thread delivers complete lines (or a terminal error)
    // over the channel; we just wait for the next one up to the
    // deadline. `recv_timeout(0)` returns immediately, so a deadline
    // already in the past surfaces as a clean TimedOut rather than a
    // hang — the bug this replaced (`fill_buf` blocked before the
    // deadline check ever ran).
    let remaining = deadline.saturating_duration_since(Instant::now());
    match proc.lines.recv_timeout(remaining) {
        Ok(line) => line,
        Err(mpsc::RecvTimeoutError::Timeout) => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "deadline",
        )),
        // Sender dropped → reader thread ended → stdout closed (the
        // child exited or was killed). Surface as EOF; the caller's
        // transport classifier treats "read: EOF" as a crash and
        // respawns when `restart_on_crash` is set.
        Err(mpsc::RecvTimeoutError::Disconnected) => Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "EOF",
        )),
    }
}

/// Reader-thread body: pull newline-delimited lines off the child's
/// stdout and hand each one (trimmed) to the channel. Enforces
/// [`MAX_NDJSON_LINE_BYTES`] *incrementally* — a plugin that drip-feeds
/// bytes without ever emitting `\n` is cut off before it can OOM the
/// host (the previous on-thread `read_line` would have buffered the
/// whole tail first). Exits on EOF, send error (receiver gone), or a
/// read error.
fn reader_loop(stdout: std::process::ChildStdout, tx: &mpsc::Sender<std::io::Result<String>>) {
    let mut reader = BufReader::new(stdout);
    let mut line: Vec<u8> = Vec::new();
    loop {
        line.clear();
        let mut capped = false;
        loop {
            let available = match reader.fill_buf() {
                Ok(b) => b,
                Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => {
                    let _ = tx.send(Err(e));
                    return;
                }
            };
            if available.is_empty() {
                // EOF. Flush a trailing partial line if any, then stop.
                if !line.is_empty() && !capped {
                    let _ = tx.send(Ok(String::from_utf8_lossy(&line).into_owned()));
                }
                return; // dropping tx disconnects the channel
            }
            if let Some(nl) = available.iter().position(|&b| b == b'\n') {
                if !capped {
                    line.extend_from_slice(&available[..nl]);
                }
                reader.consume(nl + 1);
                break;
            }
            let take = available.len();
            if !capped {
                line.extend_from_slice(available);
                if line.len() > MAX_NDJSON_LINE_BYTES {
                    let _ = tx.send(Err(std::io::Error::other(format!(
                        "ndjson line exceeded {MAX_NDJSON_LINE_BYTES} bytes \
                         without newline; refusing to buffer further"
                    ))));
                    // Keep draining-and-discarding this line until its
                    // newline so the stream re-syncs, but never buffer more.
                    capped = true;
                    line.clear();
                }
            }
            reader.consume(take);
        }
        if capped {
            // We already reported the over-length error; skip emitting
            // this (now-discarded) line and move to the next.
            continue;
        }
        if tx
            .send(Ok(String::from_utf8_lossy(&line).into_owned()))
            .is_err()
        {
            return; // receiver gone
        }
    }
}

fn read_response_until(proc: &mut RunningProc, deadline: Instant) -> std::io::Result<Response> {
    let line = read_line_until(proc, deadline)?;
    serde_json::from_str::<Response>(&line)
        .map_err(|e| std::io::Error::other(format!("parse response: {e}: {line:?}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SPAWN_LOCK;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::TempDir;

    fn mk_plugin_script(dir: &std::path::Path, body: &str) -> std::path::PathBuf {
        let p = dir.join("plugin.sh");
        {
            let mut f = std::fs::File::create(&p).unwrap();
            writeln!(f, "#!/bin/sh").unwrap();
            f.write_all(body.as_bytes()).unwrap();
            f.sync_all().unwrap();
        }
        let mut perm = std::fs::metadata(&p).unwrap().permissions();
        perm.set_mode(0o755);
        std::fs::set_permissions(&p, perm).unwrap();
        p
    }

    #[test]
    fn handshake_then_one_call() {
        let _guard = SPAWN_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = TempDir::new().unwrap();
        // Plugin emits hello, then echoes one observe response.
        let plugin = mk_plugin_script(
            tmp.path(),
            r#"
echo '{"hello":{"protocol_version":1,"kind":"t.k","capability_keys":["{{ name }}"],"methods":["observe","apply"]}}'
read REQ
echo '{"id":1,"result":{"present":true,"spec":{"name":"x"}}}'
"#,
        );
        let spec = ExternalProviderSpec {
            kind: "t.k".into(),
            binary: plugin,
            args: vec![],
            env: vec![],
            restart_on_crash: false,
            handshake_timeout_secs: 3,
            call_timeout_secs: 3,
            binary_sha256: None,
        };
        let handle = PluginHandle::new(spec);
        let resp = handle
            .call("observe", serde_json::json!({"spec": {"name":"x"}}))
            .unwrap();
        assert_eq!(resp["present"], serde_json::json!(true));
        let hello = handle.hello().unwrap();
        assert_eq!(hello.kind, "t.k");
        assert_eq!(hello.capability_keys, vec!["{{ name }}"]);
    }

    #[test]
    fn call_times_out_when_plugin_goes_silent() {
        // Regression (security): a plugin that completes the handshake,
        // reads the request, then goes silent WITHOUT closing stdout
        // used to hang the worker forever — the blocking `fill_buf`
        // ran before the deadline check. The reader-thread + recv_timeout
        // design must surface a read timeout within ~call_timeout.
        let _guard = SPAWN_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = TempDir::new().unwrap();
        let plugin = mk_plugin_script(
            tmp.path(),
            r#"
echo '{"hello":{"protocol_version":1,"kind":"t.k","capability_keys":[],"methods":["observe"]}}'
read REQ
sleep 30
"#,
        );
        let spec = ExternalProviderSpec {
            kind: "t.k".into(),
            binary: plugin,
            args: vec![],
            env: vec![],
            restart_on_crash: false,
            handshake_timeout_secs: 10,
            call_timeout_secs: 1,
            binary_sha256: None,
        };
        let handle = PluginHandle::new(spec);
        let start = Instant::now();
        let err = handle
            .call("observe", serde_json::json!({"spec": {"name": "x"}}))
            .unwrap_err();
        let elapsed = start.elapsed();
        let msg = format!("{err:?}");
        assert!(
            msg.contains("read"),
            "expected read/timeout error, got: {msg}"
        );
        assert!(
            elapsed < std::time::Duration::from_secs(10),
            "call did not time out promptly: {elapsed:?}"
        );
    }

    #[test]
    fn protocol_version_mismatch_fails_handshake() {
        let _guard = SPAWN_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = TempDir::new().unwrap();
        let plugin = mk_plugin_script(
            tmp.path(),
            r#"
echo '{"hello":{"protocol_version":99,"kind":"t.k"}}'
sleep 5
"#,
        );
        let spec = ExternalProviderSpec {
            kind: "t.k".into(),
            binary: plugin,
            args: vec![],
            env: vec![],
            restart_on_crash: false,
            // 10s, not 2s: CI runners (ARM, Windows-on-ARM, FreeBSD
            // QEMU) periodically take >2s to spawn `sh` and pipe the
            // first echo back, which used to surface as a handshake
            // timeout, masking the assertion we actually want to test.
            handshake_timeout_secs: 10,
            call_timeout_secs: 10,
            binary_sha256: None,
        };
        let handle = PluginHandle::new(spec);
        let err = handle.call("observe", serde_json::Value::Null).unwrap_err();
        let msg = format!("{err:?}");
        assert!(msg.contains("protocol_version"), "unexpected error: {msg}");
    }

    #[test]
    fn kind_mismatch_fails_handshake() {
        let _guard = SPAWN_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = TempDir::new().unwrap();
        let plugin = mk_plugin_script(
            tmp.path(),
            r#"
echo '{"hello":{"protocol_version":1,"kind":"other.kind"}}'
sleep 5
"#,
        );
        let spec = ExternalProviderSpec {
            kind: "t.k".into(),
            binary: plugin,
            args: vec![],
            env: vec![],
            restart_on_crash: false,
            handshake_timeout_secs: 10,
            call_timeout_secs: 10,
            binary_sha256: None,
        };
        let handle = PluginHandle::new(spec);
        let err = handle.call("observe", serde_json::Value::Null).unwrap_err();
        let msg = format!("{err:?}");
        assert!(msg.contains("other.kind"), "{msg}");
    }

    #[test]
    fn application_error_round_trips() {
        let _guard = SPAWN_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = TempDir::new().unwrap();
        let plugin = mk_plugin_script(
            tmp.path(),
            r#"
echo '{"hello":{"protocol_version":1,"kind":"t.k"}}'
read REQ
echo '{"id":1,"error":"backend down"}'
"#,
        );
        let spec = ExternalProviderSpec {
            kind: "t.k".into(),
            binary: plugin,
            args: vec![],
            env: vec![],
            restart_on_crash: false,
            handshake_timeout_secs: 3,
            call_timeout_secs: 3,
            binary_sha256: None,
        };
        let handle = PluginHandle::new(spec);
        let err = handle.call("observe", serde_json::Value::Null).unwrap_err();
        assert!(format!("{err:?}").contains("backend down"));
    }

    /// Phase 7dh.5: a plugin that crashes immediately on every spawn
    /// must NOT be re-forked unbounded. After 3 consecutive
    /// transport-shaped failures the cool-off blocks further spawns.
    #[test]
    fn restart_cooloff_kicks_in_after_repeated_crashes() {
        let _guard = SPAWN_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = TempDir::new().unwrap();
        // Plugin that exits 1 immediately, before sending hello.
        let plugin = mk_plugin_script(tmp.path(), "exit 1\n");
        let spec = ExternalProviderSpec {
            kind: "t.k".into(),
            binary: plugin,
            args: vec![],
            env: vec![],
            restart_on_crash: true,
            handshake_timeout_secs: 1,
            call_timeout_secs: 1,
            binary_sha256: None,
        };
        let handle = PluginHandle::new(spec);
        // First three calls each see a transport error and are
        // allowed (consecutive_crashes 1, 2, 3).
        for _ in 0..3 {
            let _ = handle.call("observe", serde_json::Value::Null).unwrap_err();
        }
        // Fourth call now hits the cool-off gate at spawn time.
        let err = handle.call("observe", serde_json::Value::Null).unwrap_err();
        let msg = format!("{err:?}");
        assert!(
            msg.contains("cool-off"),
            "expected cool-off error, got: {msg}"
        );
    }
}
