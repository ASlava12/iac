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

use super::proto::{Frame, Hello, Request, Response, PROTOCOL_VERSION};
use super::spec::ExternalProviderSpec;
use iac_core::{Error, Result};
use parking_lot::Mutex;
use serde_json::Value as Json;
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
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
    stdout: BufReader<std::process::ChildStdout>,
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
                        state.consecutive_crashes =
                            state.consecutive_crashes.saturating_add(1);
                        // Threshold + backoff: after 3 in a row, set
                        // a cool-off of 2^(n-3) seconds, capped at
                        // 300 s (5 min). 4th = 2 s, 5th = 4 s, …,
                        // 11th and beyond = 300 s.
                        if state.consecutive_crashes >= 3 {
                            let extra = state.consecutive_crashes - 3;
                            let secs = 2u64
                                .saturating_pow(extra.min(8))
                                .min(300);
                            state.spawn_blocked_until = Some(
                                Instant::now()
                                    + std::time::Duration::from_secs(secs),
                            );
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
        let line = serde_json::to_string(&req).map_err(|e| {
            Error::provider(&self.spec.kind, format!("encode request: {e}"))
        })?;

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
        let resp = read_response_until(proc, deadline).map_err(|e| {
            Error::provider(&self.spec.kind, format!("read: {e}"))
        })?;
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
            crate::wasm::spec::verify_sha256(&bytes, expected, "binary").map_err(|e| {
                Error::provider(&self.spec.kind, e)
            })?;
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
        let stdin = child.stdin.take().ok_or_else(|| {
            Error::provider(&self.spec.kind, "child stdin missing after spawn")
        })?;
        let stdout = BufReader::new(child.stdout.take().ok_or_else(|| {
            Error::provider(&self.spec.kind, "child stdout missing after spawn")
        })?);

        let mut proc = RunningProc { child, stdin, stdout };
        // Read the first line as the hello message.
        let deadline = Instant::now() + self.spec.handshake_timeout();
        let line = read_line_until(&mut proc, deadline).map_err(|e| {
            Error::provider(
                &self.spec.kind,
                format!("handshake read: {e}"),
            )
        })?;
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

fn read_line_until(
    proc: &mut RunningProc,
    deadline: Instant,
) -> std::io::Result<String> {
    // BufRead::read_line is blocking. To enforce a deadline without
    // pulling in a runtime, we run a polling loop using available()
    // bytes plus a short sleep. We accept a bit of latency on bursts
    // — plugin handshakes are small, calls are small, this is fine.
    let mut accumulated = String::new();
    loop {
        // Cheap "anything to read?" probe: try a non-blocking peek
        // through fill_buf. If the buffer has data, drain a line.
        let buf = proc.stdout.fill_buf()?;
        if !buf.is_empty() {
            let n = proc.stdout.read_line(&mut accumulated)?;
            if n == 0 && accumulated.is_empty() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "EOF",
                ));
            }
            // `read_line` returns the bytes including the trailing
            // `\n` if it found one. Without `\n` it returns whatever
            // was in the buffer and we loop. Cap before looping.
            if accumulated.len() > MAX_NDJSON_LINE_BYTES {
                return Err(std::io::Error::other(format!(
                    "ndjson line exceeded {MAX_NDJSON_LINE_BYTES} bytes \
                     without newline; refusing to buffer further"
                )));
            }
            if accumulated.ends_with('\n') {
                return Ok(accumulated.trim_end_matches('\n').to_string());
            }
            // No newline yet — keep polling for more data.
            continue;
        }
        if Instant::now() >= deadline {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "deadline",
            ));
        }
        // Has the child exited?
        match proc.child.try_wait() {
            Ok(Some(status)) => {
                return Err(std::io::Error::other(format!(
                    "child exited: {status}"
                )));
            }
            Ok(None) => {}
            Err(e) => return Err(e),
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
}

fn read_response_until(
    proc: &mut RunningProc,
    deadline: Instant,
) -> std::io::Result<Response> {
    let line = read_line_until(proc, deadline)?;
    serde_json::from_str::<Response>(&line)
        .map_err(|e| std::io::Error::other(format!("parse response: {e}: {line:?}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::TempDir;

    fn mk_plugin_script(dir: &std::path::Path, body: &str) -> std::path::PathBuf {
        let p = dir.join("plugin.sh");
        let mut f = std::fs::File::create(&p).unwrap();
        writeln!(f, "#!/bin/sh").unwrap();
        f.write_all(body.as_bytes()).unwrap();
        let mut perm = std::fs::metadata(&p).unwrap().permissions();
        perm.set_mode(0o755);
        std::fs::set_permissions(&p, perm).unwrap();
        p
    }

    #[test]
    fn handshake_then_one_call() {
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
    fn protocol_version_mismatch_fails_handshake() {
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
            handshake_timeout_secs: 2,
            call_timeout_secs: 2,
            binary_sha256: None,
        };
        let handle = PluginHandle::new(spec);
        let err = handle.call("observe", serde_json::Value::Null).unwrap_err();
        assert!(format!("{err:?}").contains("protocol_version"));
    }

    #[test]
    fn kind_mismatch_fails_handshake() {
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
            handshake_timeout_secs: 2,
            call_timeout_secs: 2,
            binary_sha256: None,
        };
        let handle = PluginHandle::new(spec);
        let err = handle.call("observe", serde_json::Value::Null).unwrap_err();
        let msg = format!("{err:?}");
        assert!(msg.contains("other.kind"), "{msg}");
    }

    #[test]
    fn application_error_round_trips() {
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
        let err = handle
            .call("observe", serde_json::Value::Null)
            .unwrap_err();
        assert!(format!("{err:?}").contains("backend down"));
    }

    /// Phase 7dh.5: a plugin that crashes immediately on every spawn
    /// must NOT be re-forked unbounded. After 3 consecutive
    /// transport-shaped failures the cool-off blocks further spawns.
    #[test]
    fn restart_cooloff_kicks_in_after_repeated_crashes() {
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
        let err = handle
            .call("observe", serde_json::Value::Null)
            .unwrap_err();
        let msg = format!("{err:?}");
        assert!(
            msg.contains("cool-off"),
            "expected cool-off error, got: {msg}"
        );
    }
}
