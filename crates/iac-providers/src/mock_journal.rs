// Phase 7cz.16: this entire module is mock test infrastructure shared
// across the pluggable providers. The internal `expect("poisoned")`
// calls cannot fire in practice (the locked sections do not panic),
// so the strict-clippy lints are noise here.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Phase 7cz.18: shared mock-backend bookkeeping.
//!
//! Pre-7cz the three pluggable providers (`compose`, `dns`, `acme`)
//! each implemented their `Mock<X>` test harness from scratch:
//! `Mutex<Inner>` wrapping, `calls: Vec<String>` recording, per-op
//! `fail_next_*: Option<String>` setters. The bookkeeping was
//! identical across the three; the differences were the provider-
//! specific state (records map, services map, expiry timestamps).
//!
//! `MockJournal<S>` extracts that bookkeeping into one place. Each
//! mock embeds a `MockJournal<TheirState>` instead of rolling its
//! own Mutex+inner. The provider-specific state lives in `S`; the
//! universal `calls` / `failures` machinery is shared.
//!
//! Adoption is opt-in — older mocks (`MockDocker`, `MockSystemctl`,
//! etc.) keep their hand-rolled shape until they organically need
//! the same affordance.

use std::collections::HashMap;
use std::sync::Mutex;

/// Shared mock harness. Wraps provider-specific state `S` with a
/// recording of every call and a per-op failure-injection map.
///
/// Concurrency: the inner Mutex serialises every access. Tests
/// that don't need true concurrency just clone the journal via
/// the inherent accessors below; tests that exercise concurrent
/// backends should pass `Arc<MockJournal<S>>`.
pub struct MockJournal<S: Default> {
    inner: Mutex<JournalInner<S>>,
}

struct JournalInner<S> {
    state: S,
    calls: Vec<String>,
    /// Per-operation arming. The key is an operation name the mock
    /// chooses (e.g. `"issue"`, `"up"`); the value is the error
    /// message to return on the next call to that op.
    failures: HashMap<&'static str, String>,
}

impl<S: Default> Default for MockJournal<S> {
    fn default() -> Self {
        Self {
            inner: Mutex::new(JournalInner {
                state: S::default(),
                calls: Vec::new(),
                failures: HashMap::new(),
            }),
        }
    }
}

impl<S: Default> MockJournal<S> {
    /// Snapshot of every recorded call in arrival order.
    pub fn calls(&self) -> Vec<String> {
        self.inner.lock().expect("mock journal mutex poisoned").calls.clone()
    }

    /// Arm `op` to fail on the next call with `msg`. The next
    /// `take_failure(op)` clears the arming.
    pub fn fail_next(&self, op: &'static str, msg: impl Into<String>) {
        self.inner
            .lock()
            .expect("mock journal mutex poisoned")
            .failures
            .insert(op, msg.into());
    }

    /// Record a call line + atomically check for an armed failure.
    /// The closure runs under the same lock so call-recording and
    /// state mutation can't observe a torn intermediate state. The
    /// closure receives a mutable handle on the provider-specific
    /// state so it can read/mutate as needed; returns whatever the
    /// closure returns, after which the lock is released.
    ///
    /// If `op` had a failure armed, returns `Err(msg)` BEFORE
    /// invoking the closure — the call is still recorded. This
    /// matches the pre-7cz mock semantics: every call gets logged,
    /// failure injection only suppresses the side-effect.
    pub fn record<R>(
        &self,
        op: &'static str,
        line: String,
        f: impl FnOnce(&mut S) -> R,
    ) -> Result<R, String> {
        let mut g = self.inner.lock().expect("mock journal mutex poisoned");
        g.calls.push(line);
        if let Some(msg) = g.failures.remove(op) {
            return Err(msg);
        }
        Ok(f(&mut g.state))
    }

    /// Read-only inspection of the underlying state. Use sparingly —
    /// most tests should reach into state via the mock's domain
    /// methods (e.g. `MockDns::find_record`) rather than poking at
    /// internals.
    pub fn with_state<R>(&self, f: impl FnOnce(&S) -> R) -> R {
        let g = self.inner.lock().expect("mock journal mutex poisoned");
        f(&g.state)
    }

    /// Mutable inspection — for test setup that pre-populates state
    /// before exercising the mock.
    pub fn with_state_mut<R>(&self, f: impl FnOnce(&mut S) -> R) -> R {
        let mut g = self.inner.lock().expect("mock journal mutex poisoned");
        f(&mut g.state)
    }
}

impl<S: Default + std::fmt::Debug> std::fmt::Debug for MockJournal<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let g = self.inner.lock();
        match g {
            Ok(g) => f
                .debug_struct("MockJournal")
                .field("calls", &g.calls.len())
                .field("armed_failures", &g.failures.keys().collect::<Vec<_>>())
                .field("state", &g.state)
                .finish(),
            Err(_) => f.write_str("MockJournal { <poisoned> }"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default, Debug)]
    struct DemoState {
        counter: u32,
    }

    #[test]
    fn record_runs_closure_when_no_failure_armed() {
        let j: MockJournal<DemoState> = MockJournal::default();
        let r = j
            .record("inc", "inc(by=2)".into(), |s| {
                s.counter += 2;
                s.counter
            })
            .unwrap();
        assert_eq!(r, 2);
        assert_eq!(j.calls(), vec!["inc(by=2)".to_string()]);
        assert_eq!(j.with_state(|s| s.counter), 2);
    }

    #[test]
    fn record_returns_armed_failure_and_logs_call() {
        let j: MockJournal<DemoState> = MockJournal::default();
        j.fail_next("inc", "boom");
        let err = j
            .record("inc", "inc(armed)".into(), |s| {
                s.counter += 1;
                s.counter
            })
            .unwrap_err();
        assert_eq!(err, "boom");
        // The call is still recorded — only the closure was suppressed.
        assert_eq!(j.calls(), vec!["inc(armed)".to_string()]);
        // State unchanged.
        assert_eq!(j.with_state(|s| s.counter), 0);
    }

    #[test]
    fn fail_next_only_fires_once() {
        let j: MockJournal<DemoState> = MockJournal::default();
        j.fail_next("inc", "first");
        j.record("inc", "a".into(), |_| ()).unwrap_err();
        j.record("inc", "b".into(), |_| ()).unwrap();
        assert_eq!(j.calls(), vec!["a", "b"]);
    }
}
