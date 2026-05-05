//! Phase 7di.6: provider-side wrapper around
//! [`iac_core::subprocess::run_with_timeout`].
//!
//! The core helper returns a structured [`SubprocessError`] that
//! every provider needs to convert into its own
//! `Error::provider(provider_kind, ...)` shape. Doing the conversion
//! in one place means a fix to the error message format lands in
//! every provider at once. Per-call timeout choice still belongs
//! to the caller — there's no one-size-fits-all (an `iptables -L`
//! is bounded by tens of seconds, an `apt-get install` by tens of
//! minutes).
//!
//! ### Phase 7dh.10 (defence in depth)
//!
//! Subprocess error messages are stored verbatim in the audit log
//! (`assignment.completed` payload + downstream rollups). Some
//! providers wrap third-party CLIs (lego, sops, kubectl) that have
//! historically had bug versions which echoed credentials or env
//! to stderr. The audit log is `Approver`-gated, but a leak there
//! is permanent — operators retain audit data for compliance.
//!
//! Truncation here caps the blast radius: the first 512 bytes of
//! each stream go to the error message; the rest is summarised as
//! `…[truncated, N more bytes]`. Operators investigating a real
//! failure can still re-run the underlying command interactively
//! to see full output; this is purely about what enters durable
//! state.

use iac_core::subprocess::{run_with_timeout, SubprocessError};
use iac_core::{Error, Result};
use std::process::Command;
use std::time::Duration;

/// Cap on how much of a subprocess's captured stdout / stderr
/// makes it into an `Error::Provider` message. The full streams
/// remain available to the caller via `run_with_timeout` directly
/// when forensic detail matters; the wrappers below truncate as
/// defence in depth against credential / env leakage through the
/// audit log.
const ERR_BYTES_PER_STREAM: usize = 512;

/// Render a captured byte stream into an audit-safe slice. Long
/// streams get the first [`ERR_BYTES_PER_STREAM`] bytes plus a
/// `…[truncated, N more bytes]` marker. UTF-8 lossy so non-text
/// output (e.g. binary tools, garbled locale) doesn't crash the
/// formatter.
fn truncate_for_error(bytes: &[u8]) -> String {
    if bytes.len() <= ERR_BYTES_PER_STREAM {
        return String::from_utf8_lossy(bytes).into_owned();
    }
    let mut head = String::from_utf8_lossy(&bytes[..ERR_BYTES_PER_STREAM]).into_owned();
    head.push_str(&format!(
        "…[truncated, {} more bytes]",
        bytes.len() - ERR_BYTES_PER_STREAM
    ));
    head
}

/// Map a `SubprocessError` into the provider-shaped `Error::Provider`
/// using the same truncation rules across every wrapper. Pulled out
/// so all three public helpers share one path.
fn map_subprocess_error(
    err: SubprocessError,
    provider_kind: &str,
    label: &str,
) -> Error {
    match err {
        SubprocessError::Timeout { elapsed, partial_stderr, .. } => Error::provider(
            provider_kind,
            format!(
                "{label} timed out after {}s (stderr={})",
                elapsed.as_secs(),
                truncate_for_error(&partial_stderr)
            ),
        ),
        SubprocessError::Spawn(e) => Error::provider(
            provider_kind,
            format!("{label}: spawn failed: {e}"),
        ),
        SubprocessError::Wait(e) => Error::provider(
            provider_kind,
            format!("{label}: wait failed: {e}"),
        ),
    }
}

/// Format the non-zero-exit error consistently across wrappers.
fn nonzero_exit_error(
    out: &iac_core::subprocess::Output,
    provider_kind: &str,
    label: &str,
) -> Error {
    Error::provider(
        provider_kind,
        format!(
            "{label} exit={:?} stderr={} stdout={}",
            out.status.code(),
            truncate_for_error(&out.stderr),
            truncate_for_error(&out.stdout),
        ),
    )
}

/// Run `cmd` with a hard timeout, capture stdout as UTF-8, map
/// every failure mode (non-zero exit, timeout, spawn error,
/// wait error) into a single `Error::Provider` carrying both
/// `provider_kind` (audit-log shape) and `label` (human-readable
/// description of what was being run).
///
/// Caller responsibilities:
/// * Set `cmd.stdin/stdout/stderr` to `Stdio::piped()` if input
///   or capture is desired (we forward exactly what the caller
///   configures — no implicit piping).
/// * Choose a timeout that fits the underlying operation.
pub(crate) fn run_capture_stdout(
    cmd: Command,
    stdin: &[u8],
    timeout: Duration,
    provider_kind: &str,
    label: &str,
) -> Result<String> {
    match run_with_timeout(cmd, stdin, timeout) {
        Ok(out) => {
            if !out.status.success() {
                return Err(nonzero_exit_error(&out, provider_kind, label));
            }
            String::from_utf8(out.stdout).map_err(|e| {
                Error::provider(
                    provider_kind,
                    format!("{label}: response not utf-8: {e}"),
                )
            })
        }
        Err(e) => Err(map_subprocess_error(e, provider_kind, label)),
    }
}

/// Same as [`run_capture_stdout`] but the caller doesn't need
/// stdout (only success/failure matters). Returns `Ok(())` on
/// any successful exit; non-zero exit / timeout / spawn errors
/// surface as `Error::Provider` per the same mapping.
pub(crate) fn run_check_status(
    cmd: Command,
    stdin: &[u8],
    timeout: Duration,
    provider_kind: &str,
    label: &str,
) -> Result<()> {
    run_capture_stdout(cmd, stdin, timeout, provider_kind, label).map(|_| ())
}

/// Phase 7dh.10 / 7di.6 follow-up: returns `(success_bool, stdout,
/// stderr)` regardless of exit
/// code, with subprocess transport errors (timeout/spawn/wait) still
/// mapped into `Error::Provider`. Used where the caller decides
/// per-call whether a non-zero exit is a real error or a domain-
/// level signal (e.g. `docker inspect` returning "No such object").
pub(crate) fn run_with_status(
    cmd: Command,
    stdin: &[u8],
    timeout: Duration,
    provider_kind: &str,
    label: &str,
) -> Result<(bool, String, String)> {
    match run_with_timeout(cmd, stdin, timeout) {
        Ok(out) => {
            let success = out.status.success();
            let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
            let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
            Ok((success, stdout, stderr))
        }
        Err(e) => Err(map_subprocess_error(e, provider_kind, label)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncate_short_stream_returns_full() {
        let s = b"hello world";
        assert_eq!(truncate_for_error(s), "hello world");
    }

    #[test]
    fn truncate_long_stream_caps_and_marks() {
        let s = vec![b'a'; ERR_BYTES_PER_STREAM + 100];
        let out = truncate_for_error(&s);
        assert!(out.contains("…[truncated, 100 more bytes]"));
        assert!(out.starts_with(&"a".repeat(ERR_BYTES_PER_STREAM)));
    }

    #[test]
    fn truncate_at_exact_boundary_returns_full() {
        let s = vec![b'a'; ERR_BYTES_PER_STREAM];
        let out = truncate_for_error(&s);
        assert_eq!(out, "a".repeat(ERR_BYTES_PER_STREAM));
        assert!(!out.contains("truncated"));
    }
}
