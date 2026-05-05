// Phase 7cz.16: this file mixes a real-CLI backend (uses ? everywhere)
// with a Mock for tests. The Mock relies on Mutex::lock().unwrap()
// in trait-bound code where Mutex poisoning is impossible because
// the locked sections never panic. Module-level allow keeps the
// strict-clippy lint useful in spec.rs/ops.rs without false-
// positives here.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Phase 7ca: monitoring check backend — pure `std::net` HTTP/TCP.
//!
//! No third-party HTTP client to keep binary size small (matters for
//! agents on network gear / embedded boxes). HTTP/1.0 over plain TCP
//! is sufficient for the "GET /healthz" pattern; HTTPS would require
//! pulling in rustls + cert chain config and is deferred to v2.

use super::spec::{CheckType, MonitoringCheckSpec};
use iac_core::Result;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Mutex;
use std::time::Duration;

/// Result of running one health check. The provider's diff /
/// observe pipeline turns these into ObservedState.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckOutcome {
    /// Check passed. For HTTP, status matched expected; for TCP,
    /// connect succeeded within timeout.
    Healthy,
    /// Check failed for an actionable reason. Operators reading the
    /// audit log get exactly what went wrong.
    Unhealthy(String),
}

impl CheckOutcome {
    pub fn is_healthy(&self) -> bool {
        matches!(self, Self::Healthy)
    }

    pub fn message(&self) -> &str {
        match self {
            Self::Healthy => "healthy",
            Self::Unhealthy(m) => m,
        }
    }
}

pub trait CheckBackend: Send + Sync + std::fmt::Debug {
    fn run(&self, spec: &MonitoringCheckSpec) -> Result<CheckOutcome>;
}

/// Real backend — pure-std HTTP/TCP probes. Handles connect timeout,
/// read timeout, and simple HTTP status parsing. No HTTPS, no
/// redirects, no chunked-encoding parsing — these are intentional
/// scope cuts for the v1 "is the endpoint up" use case.
#[derive(Debug, Default)]
pub struct StdNetBackend;

impl CheckBackend for StdNetBackend {
    fn run(&self, spec: &MonitoringCheckSpec) -> Result<CheckOutcome> {
        let timeout = Duration::from_secs(spec.timeout_secs);
        match spec.check_type {
            CheckType::Tcp => Ok(check_tcp(&spec.target, timeout)),
            CheckType::Http => {
                let expected = spec.expected_status.unwrap_or(200);
                Ok(check_http(&spec.target, expected, timeout))
            }
        }
    }
}

/// Try to TCP-connect to `host:port` within `timeout`. Returns
/// `Healthy` on accepted connection, `Unhealthy(reason)` otherwise.
pub(crate) fn check_tcp(target: &str, timeout: Duration) -> CheckOutcome {
    let addrs: Vec<_> = match target.to_socket_addrs() {
        Ok(it) => it.collect(),
        Err(e) => return CheckOutcome::Unhealthy(format!("DNS resolve {target}: {e}")),
    };
    if addrs.is_empty() {
        return CheckOutcome::Unhealthy(format!("DNS resolve {target}: no addresses"));
    }
    // Try each resolved address (e.g. dual-stack hostname). First
    // success wins; otherwise return the last error.
    let mut last_err = String::new();
    for addr in addrs {
        match TcpStream::connect_timeout(&addr, timeout) {
            Ok(_) => return CheckOutcome::Healthy,
            Err(e) => last_err = format!("connect {addr}: {e}"),
        }
    }
    CheckOutcome::Unhealthy(last_err)
}

/// HTTP/1.0 GET to `url`. Returns `Healthy` iff the response status
/// matches `expected_status`. Pure std::net — no TLS, no chunked.
pub(crate) fn check_http(url: &str, expected_status: u16, timeout: Duration) -> CheckOutcome {
    let parsed = match parse_http_url(url) {
        Ok(p) => p,
        Err(e) => return CheckOutcome::Unhealthy(e),
    };
    let target = format!("{}:{}", parsed.host, parsed.port);
    let addrs: Vec<_> = match target.to_socket_addrs() {
        Ok(it) => it.collect(),
        Err(e) => return CheckOutcome::Unhealthy(format!("DNS {target}: {e}")),
    };
    if addrs.is_empty() {
        return CheckOutcome::Unhealthy(format!("DNS {target}: no addresses"));
    }
    let addr = addrs[0];
    let mut stream = match TcpStream::connect_timeout(&addr, timeout) {
        Ok(s) => s,
        Err(e) => return CheckOutcome::Unhealthy(format!("connect {addr}: {e}")),
    };
    if let Err(e) = stream.set_read_timeout(Some(timeout)) {
        return CheckOutcome::Unhealthy(format!("set_read_timeout: {e}"));
    }
    if let Err(e) = stream.set_write_timeout(Some(timeout)) {
        return CheckOutcome::Unhealthy(format!("set_write_timeout: {e}"));
    }
    // HTTP/1.0 GET — no keep-alive, no chunked, predictable parse.
    // Connection: close ensures the server closes the socket so we
    // can read until EOF without parsing Content-Length.
    let req = format!(
        "GET {path} HTTP/1.0\r\nHost: {host}\r\nUser-Agent: iac-monitoring-check/1.0\r\nConnection: close\r\n\r\n",
        path = parsed.path,
        host = parsed.host,
    );
    if let Err(e) = stream.write_all(req.as_bytes()) {
        return CheckOutcome::Unhealthy(format!("write: {e}"));
    }
    let mut buf = Vec::with_capacity(1024);
    // Cap response at 64 KiB — we only need the status line, and a
    // misbehaving server shouldn't be able to OOM the agent.
    let mut limited = stream.take(64 * 1024);
    if let Err(e) = limited.read_to_end(&mut buf) {
        return CheckOutcome::Unhealthy(format!("read: {e}"));
    }
    let status_line = match buf
        .split(|&b| b == b'\n')
        .next()
        .map(|s| std::str::from_utf8(s).unwrap_or("").trim_end_matches('\r'))
    {
        Some(s) if !s.is_empty() => s,
        _ => return CheckOutcome::Unhealthy("empty response".into()),
    };
    // Status line: "HTTP/1.x <code> <reason>". We only need the code.
    let code = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok());
    match code {
        Some(c) if c == expected_status => CheckOutcome::Healthy,
        Some(c) => {
            CheckOutcome::Unhealthy(format!("status {c} (expected {expected_status})"))
        }
        None => CheckOutcome::Unhealthy(format!("malformed status line: {status_line:?}")),
    }
}

#[derive(Debug)]
pub(crate) struct ParsedUrl<'a> {
    pub host: &'a str,
    pub port: u16,
    pub path: &'a str,
}

/// Minimal URL parser for `http://host[:port]/path`. We don't pull in
/// the `url` crate — this is the only place we'd use it, and the
/// shape is mechanical. Validation already runs in spec.rs so we can
/// trust the input is roughly well-formed.
pub(crate) fn parse_http_url(url: &str) -> std::result::Result<ParsedUrl<'_>, String> {
    let after = url
        .strip_prefix("http://")
        .ok_or_else(|| format!("not an http:// URL: {url:?}"))?;
    let (authority, path) = match after.find('/') {
        Some(i) => (&after[..i], &after[i..]),
        None => (after, "/"),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => {
            let port: u16 = p
                .parse()
                .map_err(|_| format!("invalid port {p:?} in URL {url:?}"))?;
            (h, port)
        }
        None => (authority, 80),
    };
    if host.is_empty() {
        return Err(format!("empty host in URL {url:?}"));
    }
    Ok(ParsedUrl { host, port, path })
}

/// Mock backend — for unit tests. Allows queueing a sequence of
/// outcomes; each `run()` pops the next. Useful for testing
/// "transient failure then recovery" flows.
#[derive(Debug)]
pub struct MockCheck {
    queue: Mutex<Vec<CheckOutcome>>,
    pub calls: Mutex<u32>,
    /// When `queue` is empty, this is what `run()` returns. Defaults
    /// to `Healthy` so tests can build minimal cases.
    pub default_outcome: Mutex<CheckOutcome>,
}

impl Default for MockCheck {
    fn default() -> Self {
        Self::new()
    }
}

impl MockCheck {
    pub fn new() -> Self {
        Self {
            queue: Mutex::new(Vec::new()),
            calls: Mutex::new(0),
            default_outcome: Mutex::new(CheckOutcome::Healthy),
        }
    }

    pub fn always_healthy() -> Self {
        Self::new()
    }

    pub fn always_unhealthy(reason: &str) -> Self {
        let m = Self::new();
        *m.default_outcome.lock().unwrap() = CheckOutcome::Unhealthy(reason.into());
        m
    }

    pub fn queue_outcome(&self, outcome: CheckOutcome) {
        self.queue.lock().unwrap().insert(0, outcome);
    }

    pub fn call_count(&self) -> u32 {
        *self.calls.lock().unwrap()
    }
}

impl CheckBackend for MockCheck {
    fn run(&self, _spec: &MonitoringCheckSpec) -> Result<CheckOutcome> {
        *self.calls.lock().unwrap() += 1;
        let queued = self.queue.lock().unwrap().pop();
        Ok(queued.unwrap_or_else(|| self.default_outcome.lock().unwrap().clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_http_url_with_port_and_path() {
        let p = parse_http_url("http://localhost:8080/healthz").unwrap();
        assert_eq!(p.host, "localhost");
        assert_eq!(p.port, 8080);
        assert_eq!(p.path, "/healthz");
    }

    #[test]
    fn parse_http_url_default_port_80() {
        let p = parse_http_url("http://example.com/").unwrap();
        assert_eq!(p.port, 80);
        assert_eq!(p.path, "/");
    }

    #[test]
    fn parse_http_url_no_path_defaults_root() {
        let p = parse_http_url("http://example.com").unwrap();
        assert_eq!(p.path, "/");
    }

    #[test]
    fn parse_http_url_rejects_non_http() {
        let err = parse_http_url("ftp://x/").unwrap_err();
        assert!(err.contains("http://"));
    }

    #[test]
    fn check_tcp_unhealthy_on_no_listener() {
        // Bind a port, then close the listener; the port is now closed.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let outcome = check_tcp(&format!("127.0.0.1:{port}"), Duration::from_secs(1));
        assert!(!outcome.is_healthy(), "should fail to connect: {outcome:?}");
    }

    #[test]
    fn check_tcp_healthy_when_listener_accepts() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let target = format!("127.0.0.1:{port}");
        let h = std::thread::spawn(move || {
            // Accept one connection then drop it.
            if let Ok((s, _)) = listener.accept() {
                drop(s);
            }
        });
        let outcome = check_tcp(&target, Duration::from_secs(2));
        let _ = h.join();
        assert!(outcome.is_healthy(), "should succeed: {outcome:?}");
    }

    #[test]
    fn check_http_unhealthy_on_unreachable() {
        // Use a deliberately unbound port. set_connect_timeout forces
        // a quick failure.
        let outcome = check_http("http://127.0.0.1:1/", 200, Duration::from_secs(1));
        assert!(!outcome.is_healthy());
    }

    #[test]
    fn check_http_healthy_when_status_matches() {
        // Spin up a tiny server that responds 200 OK.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let h = std::thread::spawn(move || {
            if let Ok((mut s, _)) = listener.accept() {
                let mut req = [0u8; 1024];
                let _ = s.read(&mut req);
                let _ = s.write_all(
                    b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK",
                );
            }
        });
        let outcome = check_http(
            &format!("http://127.0.0.1:{port}/healthz"),
            200,
            Duration::from_secs(2),
        );
        let _ = h.join();
        assert!(outcome.is_healthy(), "outcome: {outcome:?}");
    }

    #[test]
    fn check_http_unhealthy_when_status_mismatches() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let h = std::thread::spawn(move || {
            if let Ok((mut s, _)) = listener.accept() {
                let mut req = [0u8; 1024];
                let _ = s.read(&mut req);
                let _ = s.write_all(b"HTTP/1.0 503 Service Unavailable\r\n\r\n");
            }
        });
        let outcome = check_http(
            &format!("http://127.0.0.1:{port}/"),
            200,
            Duration::from_secs(2),
        );
        let _ = h.join();
        assert!(!outcome.is_healthy());
        assert!(outcome.message().contains("503"));
    }

    #[test]
    fn mock_check_default_healthy() {
        let m = MockCheck::always_healthy();
        let spec = MonitoringCheckSpec {
            name: "t".into(),
            check_type: CheckType::Http,
            target: "http://x/".into(),
            expected_status: None,
            timeout_secs: 5,
            state: super::super::spec::CheckState::Present,
            retries: 0,
            retry_interval_secs: 1,
        };
        let outcome = m.run(&spec).unwrap();
        assert!(outcome.is_healthy());
    }

    #[test]
    fn mock_check_queue_consumed_in_order() {
        let m = MockCheck::new();
        // Queued outcomes pop FIFO via insert-at-0.
        m.queue_outcome(CheckOutcome::Unhealthy("first".into()));
        m.queue_outcome(CheckOutcome::Healthy);
        let spec = MonitoringCheckSpec {
            name: "t".into(),
            check_type: CheckType::Http,
            target: "http://x/".into(),
            expected_status: None,
            timeout_secs: 5,
            state: super::super::spec::CheckState::Present,
            retries: 0,
            retry_interval_secs: 1,
        };
        // queued ordering: insert(0) means LAST pushed becomes head, pop() takes from end.
        // To document behavior precisely:
        let first = m.run(&spec).unwrap();
        let second = m.run(&spec).unwrap();
        // queue_outcome inserts at front; pop() takes from back. So
        // earliest-queued is popped first.
        assert!(matches!(first, CheckOutcome::Unhealthy(_)));
        assert!(matches!(second, CheckOutcome::Healthy));
        assert_eq!(m.call_count(), 2);
    }
}
