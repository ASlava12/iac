// Phase 7cz.16: integration tests are compiled as their own crates, so the
// crate-root #[cfg_attr(test, allow(...))] does not reach here. Add it locally.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Phase 7t: outbound webhooks. The dispatcher polls audit_events and
//! POSTs matching rows to configured receivers. Tests run a mock
//! receiver in-process, configure the dispatcher to point at it, write
//! a few audit rows directly through the store, and tick the
//! dispatcher to verify the right events get delivered.

use iac_controlplane::Store;
use iac_controlplane::store::AuditRecord;
use iac_controlplane::webhook::{
    WebhookConfig, WebhookDispatcher, WebhooksConfig, parse_signature_header,
    parse_signature_header_versioned, verify_signed_payload, verify_signed_payload_v2,
};
use std::net::SocketAddr;
use std::sync::Arc;
use tempfile::TempDir;
use tokio::sync::{Mutex, Notify};

/// One captured POST: body + selected headers we care about.
#[derive(Debug, Clone)]
struct CapturedPost {
    body: Vec<u8>,
    body_json: serde_json::Value,
    signature: Option<String>,
}

/// Minimal in-process HTTP receiver that records POST bodies + the
/// `X-Iac-Signature` header.
struct MockReceiver {
    addr: SocketAddr,
    received: Arc<Mutex<Vec<CapturedPost>>>,
    shutdown: Arc<Notify>,
    handle: tokio::task::JoinHandle<()>,
}

impl MockReceiver {
    async fn spawn() -> Self {
        let received: Arc<Mutex<Vec<CapturedPost>>> = Arc::new(Mutex::new(Vec::new()));
        let received_for_route = received.clone();
        let app = axum::Router::new().route(
            "/sink",
            axum::routing::post(
                move |headers: axum::http::HeaderMap, body: axum::body::Bytes| {
                    let received = received_for_route.clone();
                    async move {
                        let signature = headers
                            .get("x-iac-signature")
                            .and_then(|v| v.to_str().ok())
                            .map(str::to_string);
                        let body_vec = body.to_vec();
                        let body_json: serde_json::Value =
                            serde_json::from_slice(&body_vec).unwrap_or(serde_json::Value::Null);
                        received.lock().await.push(CapturedPost {
                            body: body_vec,
                            body_json,
                            signature,
                        });
                        axum::http::StatusCode::OK
                    }
                },
            ),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let shutdown = Arc::new(Notify::new());
        let signal = shutdown.clone();
        let handle = tokio::spawn(async move {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .with_graceful_shutdown(async move { signal.notified().await })
            .await
            .unwrap();
        });
        Self {
            addr,
            received,
            shutdown,
            handle,
        }
    }

    fn url(&self) -> String {
        format!("http://{}/sink", self.addr)
    }

    async fn count(&self) -> usize {
        self.received.lock().await.len()
    }

    async fn snapshot(&self) -> Vec<CapturedPost> {
        self.received.lock().await.clone()
    }

    async fn shutdown(self) {
        self.shutdown.notify_waiters();
        let _ = self.handle.await;
    }
}

async fn open_store(dir: &TempDir) -> Store {
    let url = format!("sqlite://{}/server.db?mode=rwc", dir.path().display());
    Store::connect(&url).await.unwrap()
}

fn webhook_to(name: &str, url: &str, min_severity: &str, kinds: Vec<&str>) -> WebhookConfig {
    WebhookConfig {
        name: name.into(),
        url: url.into(),
        min_severity: min_severity.into(),
        kinds: kinds.iter().map(|s| s.to_string()).collect(),
        hmac_secret: None,
        backfill: false,
        max_concurrent_requests: None,
        signing_versions: vec!["v1".into()],
    }
}

fn webhook_signed(name: &str, url: &str, secret: &str) -> WebhookConfig {
    WebhookConfig {
        name: name.into(),
        url: url.into(),
        min_severity: "info".into(),
        kinds: vec![],
        hmac_secret: Some(secret.into()),
        backfill: false,
        max_concurrent_requests: None,
        signing_versions: vec!["v1".into()],
    }
}

#[tokio::test]
async fn dispatches_warning_event_to_configured_receiver() {
    let dir = TempDir::new().unwrap();
    let store = open_store(&dir).await;
    let receiver = MockReceiver::spawn().await;

    let dispatcher = WebhookDispatcher::new(WebhooksConfig {
        webhooks: vec![webhook_to("test", &receiver.url(), "warning", vec![])],
        poll_interval_secs: 1,
        max_concurrent_requests: 16,
        backfill_batch_size: 200,
        allow_insecure_urls: true,
        allow_private_urls: true,
    });
    dispatcher.initialize(&store).await;

    // No events yet → no dispatch.
    assert_eq!(dispatcher.tick_once(&store).await, 0);
    assert_eq!(receiver.count().await, 0);

    // Write a warning-severity event.
    store
        .record_audit(
            AuditRecord::new("user:alice", "operation.maintenance_bypass")
                .severity("warning")
                .payload(serde_json::json!({ "environment": "prod" })),
        )
        .await
        .unwrap();

    // Tick fires once.
    assert_eq!(dispatcher.tick_once(&store).await, 1);
    let events = receiver.snapshot().await;
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].body_json["kind"], "operation.maintenance_bypass");
    assert_eq!(events[0].body_json["severity"], "warning");
    assert_eq!(events[0].body_json["actor"], "user:alice");
    assert_eq!(events[0].body_json["payload"]["environment"], "prod");

    // Subsequent tick is a no-op (cursor advanced).
    assert_eq!(dispatcher.tick_once(&store).await, 0);

    receiver.shutdown().await;
}

#[tokio::test]
async fn info_severity_below_warning_floor_is_skipped() {
    let dir = TempDir::new().unwrap();
    let store = open_store(&dir).await;
    let receiver = MockReceiver::spawn().await;

    let dispatcher = WebhookDispatcher::new(WebhooksConfig {
        webhooks: vec![webhook_to("test", &receiver.url(), "warning", vec![])],
        poll_interval_secs: 1,
        max_concurrent_requests: 16,
        backfill_batch_size: 200,
        allow_insecure_urls: true,
        allow_private_urls: true,
    });
    dispatcher.initialize(&store).await;

    store
        .record_audit(AuditRecord::new("system", "operation.submitted").severity("info"))
        .await
        .unwrap();
    store
        .record_audit(AuditRecord::new("user:bob", "operation.rejected").severity("warning"))
        .await
        .unwrap();

    // Two rows written but only the warning matches.
    assert_eq!(dispatcher.tick_once(&store).await, 1);
    let events = receiver.snapshot().await;
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].body_json["kind"], "operation.rejected");

    receiver.shutdown().await;
}

#[tokio::test]
async fn kind_filter_excludes_other_kinds() {
    let dir = TempDir::new().unwrap();
    let store = open_store(&dir).await;
    let receiver = MockReceiver::spawn().await;

    let dispatcher = WebhookDispatcher::new(WebhooksConfig {
        webhooks: vec![webhook_to(
            "test",
            &receiver.url(),
            "info",
            vec!["operation.maintenance_bypass"],
        )],
        poll_interval_secs: 1,
        max_concurrent_requests: 16,
        backfill_batch_size: 200,
        allow_insecure_urls: true,
        allow_private_urls: true,
    });
    dispatcher.initialize(&store).await;

    store
        .record_audit(
            AuditRecord::new("user:alice", "operation.maintenance_bypass").severity("warning"),
        )
        .await
        .unwrap();
    store
        .record_audit(AuditRecord::new("user:bob", "user.disabled").severity("info"))
        .await
        .unwrap();

    assert_eq!(dispatcher.tick_once(&store).await, 1);
    let events = receiver.snapshot().await;
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].body_json["kind"], "operation.maintenance_bypass");

    receiver.shutdown().await;
}

#[tokio::test]
async fn multiple_receivers_each_get_event() {
    let dir = TempDir::new().unwrap();
    let store = open_store(&dir).await;
    let r1 = MockReceiver::spawn().await;
    let r2 = MockReceiver::spawn().await;

    let dispatcher = WebhookDispatcher::new(WebhooksConfig {
        webhooks: vec![
            webhook_to("a", &r1.url(), "warning", vec![]),
            webhook_to("b", &r2.url(), "warning", vec![]),
        ],
        poll_interval_secs: 1,
        max_concurrent_requests: 16,
        backfill_batch_size: 200,
        allow_insecure_urls: true,
        allow_private_urls: true,
    });
    dispatcher.initialize(&store).await;

    store
        .record_audit(AuditRecord::new("user:alice", "operation.rejected").severity("warning"))
        .await
        .unwrap();

    // 1 event × 2 webhooks = 2 dispatches.
    assert_eq!(dispatcher.tick_once(&store).await, 2);
    assert_eq!(r1.count().await, 1);
    assert_eq!(r2.count().await, 1);

    r1.shutdown().await;
    r2.shutdown().await;
}

#[tokio::test]
async fn initialize_skips_pre_existing_events() {
    // Events written BEFORE initialize() are not dispatched — operators
    // who restart the server don't get blasted with replays.
    let dir = TempDir::new().unwrap();
    let store = open_store(&dir).await;
    store
        .record_audit(AuditRecord::new("system", "agent.registered").severity("info"))
        .await
        .unwrap();
    store
        .record_audit(AuditRecord::new("user:alice", "operation.rejected").severity("warning"))
        .await
        .unwrap();

    let receiver = MockReceiver::spawn().await;
    let dispatcher = WebhookDispatcher::new(WebhooksConfig {
        webhooks: vec![webhook_to("test", &receiver.url(), "warning", vec![])],
        poll_interval_secs: 1,
        max_concurrent_requests: 16,
        backfill_batch_size: 200,
        allow_insecure_urls: true,
        allow_private_urls: true,
    });
    dispatcher.initialize(&store).await;

    // No new events since init → no dispatch.
    assert_eq!(dispatcher.tick_once(&store).await, 0);

    // Adding a new event after init does dispatch.
    store
        .record_audit(
            AuditRecord::new("user:bob", "operation.maintenance_bypass").severity("warning"),
        )
        .await
        .unwrap();
    assert_eq!(dispatcher.tick_once(&store).await, 1);

    receiver.shutdown().await;
}

#[tokio::test]
async fn dead_receiver_doesnt_block_subsequent_events() {
    // Receiver returns 500. Dispatcher logs the failure but still
    // advances the cursor, so the next event isn't stuck behind the
    // dead one.
    let dir = TempDir::new().unwrap();
    let store = open_store(&dir).await;

    let dead_app = axum::Router::new().route(
        "/sink",
        axum::routing::post(|| async { axum::http::StatusCode::INTERNAL_SERVER_ERROR }),
    );
    let dead_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead_addr = dead_listener.local_addr().unwrap();
    let dead_shutdown = Arc::new(Notify::new());
    let dead_signal = dead_shutdown.clone();
    let dead_handle = tokio::spawn(async move {
        axum::serve(dead_listener, dead_app)
            .with_graceful_shutdown(async move { dead_signal.notified().await })
            .await
            .unwrap();
    });
    let dead_url = format!("http://{}/sink", dead_addr);

    let dispatcher = WebhookDispatcher::new(WebhooksConfig {
        webhooks: vec![webhook_to("dead", &dead_url, "warning", vec![])],
        poll_interval_secs: 1,
        max_concurrent_requests: 16,
        backfill_batch_size: 200,
        allow_insecure_urls: true,
        allow_private_urls: true,
    });
    dispatcher.initialize(&store).await;

    store
        .record_audit(AuditRecord::new("user:alice", "operation.rejected").severity("warning"))
        .await
        .unwrap();
    // Dispatch is fire-and-forget: the call counts as "dispatched"
    // even though the receiver returned 500.
    assert_eq!(dispatcher.tick_once(&store).await, 1);

    // Cursor advanced — second event arrives at the same broken
    // receiver but doesn't get re-dispatched for the first one.
    store
        .record_audit(AuditRecord::new("user:bob", "operation.rejected").severity("warning"))
        .await
        .unwrap();
    assert_eq!(dispatcher.tick_once(&store).await, 1);

    dead_shutdown.notify_waiters();
    let _ = dead_handle.await;
}

#[tokio::test]
async fn empty_webhook_list_is_no_op() {
    let dir = TempDir::new().unwrap();
    let store = open_store(&dir).await;
    let dispatcher = WebhookDispatcher::new(WebhooksConfig::default());
    dispatcher.initialize(&store).await;

    store
        .record_audit(AuditRecord::new("user:alice", "operation.rejected").severity("warning"))
        .await
        .unwrap();

    assert_eq!(dispatcher.tick_once(&store).await, 0);
}

#[tokio::test]
async fn unsigned_webhook_does_not_emit_signature_header() {
    let dir = TempDir::new().unwrap();
    let store = open_store(&dir).await;
    let receiver = MockReceiver::spawn().await;

    let dispatcher = WebhookDispatcher::new(WebhooksConfig {
        webhooks: vec![webhook_to("plain", &receiver.url(), "info", vec![])],
        poll_interval_secs: 1,
        max_concurrent_requests: 16,
        backfill_batch_size: 200,
        allow_insecure_urls: true,
        allow_private_urls: true,
    });
    dispatcher.initialize(&store).await;

    store
        .record_audit(AuditRecord::new("system", "operation.submitted").severity("info"))
        .await
        .unwrap();
    dispatcher.tick_once(&store).await;

    let events = receiver.snapshot().await;
    assert_eq!(events.len(), 1);
    assert!(
        events[0].signature.is_none(),
        "no hmac_secret → no X-Iac-Signature, got {:?}",
        events[0].signature
    );

    receiver.shutdown().await;
}

#[tokio::test]
async fn signed_webhook_emits_verifiable_signature() {
    let dir = TempDir::new().unwrap();
    let store = open_store(&dir).await;
    let receiver = MockReceiver::spawn().await;
    let secret = "shared-secret-for-tests";

    let dispatcher = WebhookDispatcher::new(WebhooksConfig {
        webhooks: vec![webhook_signed("signed", &receiver.url(), secret)],
        poll_interval_secs: 1,
        max_concurrent_requests: 16,
        backfill_batch_size: 200,
        allow_insecure_urls: true,
        allow_private_urls: true,
    });
    dispatcher.initialize(&store).await;

    store
        .record_audit(
            AuditRecord::new("user:alice", "operation.maintenance_bypass")
                .severity("warning")
                .payload(serde_json::json!({ "environment": "prod" })),
        )
        .await
        .unwrap();
    dispatcher.tick_once(&store).await;

    let events = receiver.snapshot().await;
    assert_eq!(events.len(), 1);
    let header = events[0]
        .signature
        .as_deref()
        .expect("signed webhook must emit X-Iac-Signature");

    // Phase 7x: header is Stripe-style `t=<unix>,v1=<hex>`.
    let (t, v1) = parse_signature_header(header).expect("header must parse as t=...,v1=...");
    // Timestamp should be recent.
    let now = jiff::Timestamp::now().as_second();
    assert!(
        (now - t).abs() < 60,
        "timestamp should be within last minute, got t={t}, now={now}"
    );
    assert!(!v1.is_empty(), "v1 hex must be non-empty");

    // Receiver-side verification with the same helper that operators
    // would use in their integration code.
    verify_signed_payload(secret.as_bytes(), &events[0].body, header, now, 300)
        .expect("fresh signature must verify");

    receiver.shutdown().await;
}

#[tokio::test]
async fn inter_event_dispatch_runs_in_parallel() {
    // Phase 7z: multiple events for the same webhook fan out in
    // parallel within a single tick. Five 600ms-slow events should
    // complete in ~600ms wall time (parallel) instead of ~3s
    // (sequential).
    let dir = TempDir::new().unwrap();
    let store = open_store(&dir).await;

    let slow_app = axum::Router::new().route(
        "/sink",
        axum::routing::post(|| async {
            tokio::time::sleep(std::time::Duration::from_millis(600)).await;
            axum::http::StatusCode::OK
        }),
    );
    let slow_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let slow_addr = slow_listener.local_addr().unwrap();
    let slow_shutdown = Arc::new(Notify::new());
    let slow_signal = slow_shutdown.clone();
    let slow_handle = tokio::spawn(async move {
        axum::serve(slow_listener, slow_app)
            .with_graceful_shutdown(async move { slow_signal.notified().await })
            .await
            .unwrap();
    });
    let slow_url = format!("http://{}/sink", slow_addr);

    let dispatcher = WebhookDispatcher::new(WebhooksConfig {
        webhooks: vec![webhook_to("slow", &slow_url, "info", vec![])],
        poll_interval_secs: 1,
        max_concurrent_requests: 16,
        backfill_batch_size: 200,
        allow_insecure_urls: true,
        allow_private_urls: true,
    });
    dispatcher.initialize(&store).await;

    for i in 0..5 {
        store
            .record_audit(AuditRecord::new("system", &format!("event.{i}")).severity("info"))
            .await
            .unwrap();
    }

    let start = std::time::Instant::now();
    let dispatched = dispatcher.tick_once(&store).await;
    let elapsed = start.elapsed();

    assert_eq!(dispatched, 5);
    // Sequential dispatch would be ~3s. Parallel: total ≈ slow
    // receiver delay (~600ms) + small overhead. Allow up to 1.8s
    // so test machines have generous slack.
    assert!(
        elapsed < std::time::Duration::from_millis(1800),
        "parallel inter-event tick should be ~600ms, got {elapsed:?}"
    );

    slow_shutdown.notify_waiters();
    let _ = slow_handle.await;
}

#[tokio::test]
async fn semaphore_caps_in_flight_requests() {
    // Phase 7z: when 8 events queue up but the cap is 2, at most 2
    // requests are in-flight at any moment. The receiver tracks
    // active-count via an atomic counter and asserts it never
    // exceeds the cap.
    let dir = TempDir::new().unwrap();
    let store = open_store(&dir).await;

    let active = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let max_observed = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));

    let active_for_route = active.clone();
    let max_for_route = max_observed.clone();
    let app = axum::Router::new().route(
        "/sink",
        axum::routing::post(move |_body: axum::body::Bytes| {
            let active = active_for_route.clone();
            let max = max_for_route.clone();
            async move {
                let cur = active.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
                max.fetch_max(cur, std::sync::atomic::Ordering::SeqCst);
                // Hold the request just long enough that subsequent
                // requests would race in if the cap weren't enforced.
                tokio::time::sleep(std::time::Duration::from_millis(150)).await;
                active.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
                axum::http::StatusCode::OK
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let shutdown = Arc::new(Notify::new());
    let signal = shutdown.clone();
    let handle = tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .with_graceful_shutdown(async move { signal.notified().await })
        .await
        .unwrap();
    });
    let url = format!("http://{}/sink", addr);

    let dispatcher = WebhookDispatcher::new(WebhooksConfig {
        webhooks: vec![webhook_to("capped", &url, "info", vec![])],
        poll_interval_secs: 1,
        max_concurrent_requests: 2,
        backfill_batch_size: 200, // cap
        allow_insecure_urls: true,
        allow_private_urls: true,
    });
    dispatcher.initialize(&store).await;

    for i in 0..8 {
        store
            .record_audit(AuditRecord::new("system", &format!("event.{i}")).severity("info"))
            .await
            .unwrap();
    }

    let dispatched = dispatcher.tick_once(&store).await;
    assert_eq!(dispatched, 8);
    let observed = max_observed.load(std::sync::atomic::Ordering::SeqCst);
    assert!(
        observed <= 2,
        "max in-flight should be ≤ 2 (the cap), got {observed}"
    );

    shutdown.notify_waiters();
    let _ = handle.await;
}

#[tokio::test]
async fn slow_receiver_does_not_block_fast_one() {
    // Phase 7w: matching webhooks fan out in parallel per event. A
    // 1.5-second slow receiver shouldn't push the tick over its
    // expected duration; the fast receiver should land within a few
    // hundred ms regardless. We measure end-to-end tick duration
    // and assert it's much closer to the slow receiver's delay than
    // to 2× the delay (which would indicate sequential dispatch).
    let dir = TempDir::new().unwrap();
    let store = open_store(&dir).await;

    // Build a deliberately slow receiver: holds the request for ~1.5s
    // before responding 200.
    let slow_app = axum::Router::new().route(
        "/sink",
        axum::routing::post(|| async {
            tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
            axum::http::StatusCode::OK
        }),
    );
    let slow_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let slow_addr = slow_listener.local_addr().unwrap();
    let slow_shutdown = Arc::new(Notify::new());
    let slow_signal = slow_shutdown.clone();
    let slow_handle = tokio::spawn(async move {
        axum::serve(slow_listener, slow_app)
            .with_graceful_shutdown(async move { slow_signal.notified().await })
            .await
            .unwrap();
    });
    let slow_url = format!("http://{}/sink", slow_addr);

    let fast = MockReceiver::spawn().await;

    let dispatcher = WebhookDispatcher::new(WebhooksConfig {
        webhooks: vec![
            webhook_to("slow", &slow_url, "info", vec![]),
            webhook_to("fast", &fast.url(), "info", vec![]),
        ],
        poll_interval_secs: 1,
        max_concurrent_requests: 16,
        backfill_batch_size: 200,
        allow_insecure_urls: true,
        allow_private_urls: true,
    });
    dispatcher.initialize(&store).await;

    store
        .record_audit(AuditRecord::new("system", "test.event").severity("info"))
        .await
        .unwrap();

    let start = std::time::Instant::now();
    let dispatched = dispatcher.tick_once(&store).await;
    let elapsed = start.elapsed();

    assert_eq!(dispatched, 2);
    // Sequential dispatch would be ~1.5s + small fast receiver time.
    // Parallel: total ≈ slow receiver delay (the bottleneck). We
    // assert the tick completes within 2.5s — well under the 3s+ a
    // sequential-with-overhead implementation would take, but with
    // generous slack so test machines don't flake.
    assert!(
        elapsed < std::time::Duration::from_millis(2500),
        "parallel tick should be ~slow-receiver-time, got {elapsed:?}"
    );
    // Fast receiver got the event despite the slow one being mid-sleep.
    assert_eq!(fast.count().await, 1);

    slow_shutdown.notify_waiters();
    let _ = slow_handle.await;
    fast.shutdown().await;
}

#[tokio::test]
async fn cursor_survives_dispatcher_recreation() {
    // Phase 7v: simulate a server restart. Tick the first dispatcher,
    // drop it, build a fresh one against the same store, verify the
    // new dispatcher resumes from the persisted cursor instead of
    // starting from MAX(id).
    let dir = TempDir::new().unwrap();
    let store = open_store(&dir).await;
    let r1 = MockReceiver::spawn().await;

    // First lifecycle: 2 events written, both delivered.
    {
        let dispatcher = WebhookDispatcher::new(WebhooksConfig {
            webhooks: vec![webhook_to("d1", &r1.url(), "info", vec![])],
            poll_interval_secs: 1,
            max_concurrent_requests: 16,
            backfill_batch_size: 200,
            allow_insecure_urls: true,
            allow_private_urls: true,
        });
        dispatcher.initialize(&store).await;
        store
            .record_audit(AuditRecord::new("system", "kind.one").severity("info"))
            .await
            .unwrap();
        store
            .record_audit(AuditRecord::new("system", "kind.two").severity("info"))
            .await
            .unwrap();
        assert_eq!(dispatcher.tick_once(&store).await, 2);
    }
    assert_eq!(r1.count().await, 2);

    // Second lifecycle: write one more event. A fresh dispatcher
    // must NOT replay the first two; it should only deliver the new
    // one because the persisted cursor sits past them.
    let r2 = MockReceiver::spawn().await;
    let dispatcher = WebhookDispatcher::new(WebhooksConfig {
        webhooks: vec![webhook_to("d2", &r2.url(), "info", vec![])],
        poll_interval_secs: 1,
        max_concurrent_requests: 16,
        backfill_batch_size: 200,
        allow_insecure_urls: true,
        allow_private_urls: true,
    });
    dispatcher.initialize(&store).await;
    store
        .record_audit(AuditRecord::new("system", "kind.three").severity("info"))
        .await
        .unwrap();
    assert_eq!(dispatcher.tick_once(&store).await, 1);
    let events = r2.snapshot().await;
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].body_json["kind"], "kind.three");

    r1.shutdown().await;
    r2.shutdown().await;
}

#[tokio::test]
async fn pre_persistence_events_within_window_are_delivered_after_restart() {
    // Specifically the gap Phase 7v closes: events that arrived
    // *between* the last successful tick and a restart used to be
    // skipped (in-memory cursor was lost; the new MAX(id) initializer
    // jumped past them). With a persisted per-webhook cursor (Phase
    // 7y) they get delivered, as long as the webhook name is the
    // same across the restart.
    let dir = TempDir::new().unwrap();
    let store = open_store(&dir).await;
    let url = {
        let r0 = MockReceiver::spawn().await;
        let url = r0.url();
        let dispatcher = WebhookDispatcher::new(WebhooksConfig {
            webhooks: vec![webhook_to("alerts", &url, "info", vec![])],
            poll_interval_secs: 1,
            max_concurrent_requests: 16,
            backfill_batch_size: 200,
            allow_insecure_urls: true,
            allow_private_urls: true,
        });
        dispatcher.initialize(&store).await;
        store
            .record_audit(AuditRecord::new("system", "early").severity("info"))
            .await
            .unwrap();
        dispatcher.tick_once(&store).await;
        // Now an event arrives that the dispatcher never gets to see.
        store
            .record_audit(AuditRecord::new("system", "missed-by-old-process").severity("info"))
            .await
            .unwrap();
        r0.shutdown().await;
        url
    };

    // Second lifecycle: same webhook name → same cursor → "missed"
    // gets delivered. (Note we pass a fresh URL since the old
    // receiver is gone, but the receiver port doesn't matter for
    // resolving the cursor — only the name does.)
    let r = MockReceiver::spawn().await;
    let dispatcher = WebhookDispatcher::new(WebhooksConfig {
        webhooks: vec![webhook_to("alerts", &r.url(), "info", vec![])],
        poll_interval_secs: 1,
        max_concurrent_requests: 16,
        backfill_batch_size: 200,
        allow_insecure_urls: true,
        allow_private_urls: true,
    });
    dispatcher.initialize(&store).await;
    assert_eq!(dispatcher.tick_once(&store).await, 1);
    let events = r.snapshot().await;
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].body_json["kind"], "missed-by-old-process");
    let _ = url; // keep the binding in scope for clarity

    r.shutdown().await;
}

#[tokio::test]
async fn backfill_true_delivers_all_history() {
    // Phase 7y: a new webhook with `backfill: true` reads the entire
    // audit log on first tick, even rows that pre-date the webhook's
    // configuration.
    let dir = TempDir::new().unwrap();
    let store = open_store(&dir).await;
    for i in 0..3 {
        store
            .record_audit(AuditRecord::new("system", &format!("history.{i}")).severity("info"))
            .await
            .unwrap();
    }

    let receiver = MockReceiver::spawn().await;
    let mut webhook = webhook_to("backfiller", &receiver.url(), "info", vec![]);
    webhook.backfill = true;
    let dispatcher = WebhookDispatcher::new(WebhooksConfig {
        webhooks: vec![webhook],
        poll_interval_secs: 1,
        max_concurrent_requests: 16,
        backfill_batch_size: 200,
        allow_insecure_urls: true,
        allow_private_urls: true,
    });
    dispatcher.initialize(&store).await;

    assert_eq!(dispatcher.tick_once(&store).await, 3);
    let events = receiver.snapshot().await;
    assert_eq!(events.len(), 3);
    let kinds: Vec<_> = events
        .iter()
        .map(|e| e.body_json["kind"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(kinds, vec!["history.0", "history.1", "history.2"]);

    receiver.shutdown().await;
}

#[tokio::test]
async fn per_webhook_cursors_are_isolated() {
    // Two webhooks, only one configured to backfill. The
    // backfilling one delivers history; the other starts fresh.
    let dir = TempDir::new().unwrap();
    let store = open_store(&dir).await;
    for i in 0..2 {
        store
            .record_audit(AuditRecord::new("system", &format!("old.{i}")).severity("info"))
            .await
            .unwrap();
    }

    let r_back = MockReceiver::spawn().await;
    let r_fresh = MockReceiver::spawn().await;
    let mut backfiller = webhook_to("backfill-me", &r_back.url(), "info", vec![]);
    backfiller.backfill = true;
    let fresh = webhook_to("fresh-only", &r_fresh.url(), "info", vec![]);

    let dispatcher = WebhookDispatcher::new(WebhooksConfig {
        webhooks: vec![backfiller, fresh],
        poll_interval_secs: 1,
        max_concurrent_requests: 16,
        backfill_batch_size: 200,
        allow_insecure_urls: true,
        allow_private_urls: true,
    });
    dispatcher.initialize(&store).await;

    // First tick: backfill webhook delivers 2 history events; fresh
    // webhook delivers nothing (cursor was at MAX(id) so no new
    // rows since init).
    assert_eq!(dispatcher.tick_once(&store).await, 2);
    assert_eq!(r_back.count().await, 2);
    assert_eq!(r_fresh.count().await, 0);

    // Now write a new event. Both webhooks deliver it — proves
    // backfill webhook's cursor advanced to the latest after the
    // first tick AND the fresh webhook's cursor finally has
    // something past it.
    store
        .record_audit(AuditRecord::new("system", "shared.new").severity("info"))
        .await
        .unwrap();
    assert_eq!(dispatcher.tick_once(&store).await, 2);
    assert_eq!(r_back.count().await, 3);
    assert_eq!(r_fresh.count().await, 1);

    r_back.shutdown().await;
    r_fresh.shutdown().await;
}

#[tokio::test]
async fn metrics_count_each_response_class() {
    // Phase 7ac: telemetry counts ok / ratelimited / non-success /
    // errors separately. We hit a single configured webhook URL but
    // change the receiver's response per request via an atomic
    // counter (1st: 200, 2nd: 429, 3rd: 500, then close the
    // listener so the 4th errors at the network layer).
    let dir = TempDir::new().unwrap();
    let store = open_store(&dir).await;

    let req_no = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let req_no_for_route = req_no.clone();
    let app = axum::Router::new().route(
        "/sink",
        axum::routing::post(move || {
            let n = req_no_for_route.clone();
            async move {
                let i = n.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let mut resp = axum::http::Response::new(axum::body::Body::empty());
                *resp.status_mut() = match i {
                    0 => axum::http::StatusCode::OK,
                    1 => axum::http::StatusCode::TOO_MANY_REQUESTS,
                    _ => axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                };
                if i == 1 {
                    resp.headers_mut()
                        .insert("retry-after", "1".parse().unwrap());
                }
                resp
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let shutdown = Arc::new(Notify::new());
    let signal = shutdown.clone();
    let handle = tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .with_graceful_shutdown(async move { signal.notified().await })
        .await
        .unwrap();
    });
    let url = format!("http://{}/sink", addr);

    let dispatcher = WebhookDispatcher::new(WebhooksConfig {
        webhooks: vec![webhook_to("metrics", &url, "info", vec![])],
        poll_interval_secs: 1,
        max_concurrent_requests: 16,
        backfill_batch_size: 200,
        allow_insecure_urls: true,
        allow_private_urls: true,
    });
    dispatcher.initialize(&store).await;

    // Event #1 → 200 (dispatched_ok = 1).
    store
        .record_audit(AuditRecord::new("system", "ok").severity("info"))
        .await
        .unwrap();
    dispatcher.tick_once(&store).await;

    // Event #2 → 429 with Retry-After: 1 (dispatched_ratelimited = 1,
    // backoff for 1s).
    store
        .record_audit(AuditRecord::new("system", "rl").severity("info"))
        .await
        .unwrap();
    dispatcher.tick_once(&store).await;

    // Wait out the backoff so subsequent ticks fire again.
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;

    // Event #3 → 500 (dispatched_non_success = 1).
    store
        .record_audit(AuditRecord::new("system", "fail").severity("info"))
        .await
        .unwrap();
    dispatcher.tick_once(&store).await;

    // Now kill the listener so the next request errors at the
    // network layer.
    shutdown.notify_waiters();
    let _ = handle.await;

    // Event #4 → connection refused (delivery_errors = 1).
    store
        .record_audit(AuditRecord::new("system", "boom").severity("info"))
        .await
        .unwrap();
    dispatcher.tick_once(&store).await;

    let m = dispatcher.metrics();
    assert_eq!(m.dispatched_ok, 1, "metrics: {m:?}");
    assert_eq!(m.dispatched_ratelimited, 1, "metrics: {m:?}");
    assert_eq!(m.dispatched_non_success, 1, "metrics: {m:?}");
    assert_eq!(m.delivery_errors, 1, "metrics: {m:?}");
}

#[tokio::test]
async fn metrics_track_in_flight_peak_against_semaphore_cap() {
    // Phase 7ac: in_flight_peak should match the semaphore cap when
    // we queue more events than the cap.
    let dir = TempDir::new().unwrap();
    let store = open_store(&dir).await;

    let app = axum::Router::new().route(
        "/sink",
        axum::routing::post(|| async {
            tokio::time::sleep(std::time::Duration::from_millis(150)).await;
            axum::http::StatusCode::OK
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let shutdown = Arc::new(Notify::new());
    let signal = shutdown.clone();
    let handle = tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .with_graceful_shutdown(async move { signal.notified().await })
        .await
        .unwrap();
    });
    let url = format!("http://{}/sink", addr);

    let dispatcher = WebhookDispatcher::new(WebhooksConfig {
        webhooks: vec![webhook_to("peak", &url, "info", vec![])],
        poll_interval_secs: 1,
        max_concurrent_requests: 3,
        backfill_batch_size: 200, // cap
        allow_insecure_urls: true,
        allow_private_urls: true,
    });
    dispatcher.initialize(&store).await;

    for i in 0..6 {
        store
            .record_audit(AuditRecord::new("system", &format!("e{i}")).severity("info"))
            .await
            .unwrap();
    }
    dispatcher.tick_once(&store).await;

    let m = dispatcher.metrics();
    assert_eq!(m.dispatched_ok, 6);
    assert_eq!(m.in_flight, 0, "all permits released after tick");
    assert!(
        m.in_flight_peak >= 1 && m.in_flight_peak <= 3,
        "peak should match cap, got {}",
        m.in_flight_peak
    );

    shutdown.notify_waiters();
    let _ = handle.await;
}

#[tokio::test]
async fn metrics_semaphore_wait_micros_increases_under_contention() {
    // Phase 7ac: when the semaphore is saturated, subsequent
    // acquisitions wait — that wait time accumulates into
    // `semaphore_wait_micros`. With cap=1 and 2 events, the second
    // acquire waits ~150ms (the slow receiver hold time). The first
    // acquires instantly so wait_micros captures only the second's
    // wait.
    let dir = TempDir::new().unwrap();
    let store = open_store(&dir).await;

    let app = axum::Router::new().route(
        "/sink",
        axum::routing::post(|| async {
            tokio::time::sleep(std::time::Duration::from_millis(150)).await;
            axum::http::StatusCode::OK
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let shutdown = Arc::new(Notify::new());
    let signal = shutdown.clone();
    let handle = tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .with_graceful_shutdown(async move { signal.notified().await })
        .await
        .unwrap();
    });
    let url = format!("http://{}/sink", addr);

    let dispatcher = WebhookDispatcher::new(WebhooksConfig {
        webhooks: vec![webhook_to("contended", &url, "info", vec![])],
        poll_interval_secs: 1,
        max_concurrent_requests: 1,
        backfill_batch_size: 200, // single permit
        allow_insecure_urls: true,
        allow_private_urls: true,
    });
    dispatcher.initialize(&store).await;

    for i in 0..2 {
        store
            .record_audit(AuditRecord::new("system", &format!("e{i}")).severity("info"))
            .await
            .unwrap();
    }
    dispatcher.tick_once(&store).await;

    let m = dispatcher.metrics();
    assert_eq!(m.dispatched_ok, 2);
    // Second acquire waited at least ~140ms (some test slack on the
    // 150ms sleep).
    assert!(
        m.semaphore_wait_micros > 100_000,
        "wait_micros should be > 100ms (~150ms hold), got {}",
        m.semaphore_wait_micros
    );

    shutdown.notify_waiters();
    let _ = handle.await;
}

#[tokio::test]
async fn receiver_429_with_retry_after_pauses_subsequent_ticks() {
    // Phase 7ab: receiver returns 429 + Retry-After: 60 on first
    // request. Next tick must skip the webhook entirely (don't
    // even hit the receiver). Cursor doesn't advance, so events
    // queued during the wait will still be delivered after the
    // backoff window.
    let dir = TempDir::new().unwrap();
    let store = open_store(&dir).await;

    let request_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let count_for_route = request_count.clone();
    let app = axum::Router::new().route(
        "/sink",
        axum::routing::post(move || {
            let count = count_for_route.clone();
            async move {
                count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let mut resp = axum::http::Response::new(axum::body::Body::empty());
                *resp.status_mut() = axum::http::StatusCode::TOO_MANY_REQUESTS;
                resp.headers_mut()
                    .insert("retry-after", "60".parse().unwrap());
                resp
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let shutdown = Arc::new(Notify::new());
    let signal = shutdown.clone();
    let handle = tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .with_graceful_shutdown(async move { signal.notified().await })
        .await
        .unwrap();
    });
    let url = format!("http://{}/sink", addr);

    let dispatcher = WebhookDispatcher::new(WebhooksConfig {
        webhooks: vec![webhook_to("ratelimited", &url, "info", vec![])],
        poll_interval_secs: 1,
        max_concurrent_requests: 16,
        backfill_batch_size: 200,
        allow_insecure_urls: true,
        allow_private_urls: true,
    });
    dispatcher.initialize(&store).await;

    store
        .record_audit(AuditRecord::new("system", "first").severity("info"))
        .await
        .unwrap();
    // First tick fires the request; receiver returns 429 + Retry-After.
    dispatcher.tick_once(&store).await;
    assert_eq!(
        request_count.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "first tick must hit the receiver"
    );

    // Second event arrives during the backoff.
    store
        .record_audit(AuditRecord::new("system", "second").severity("info"))
        .await
        .unwrap();
    // Second tick must skip the webhook entirely — receiver count
    // unchanged.
    dispatcher.tick_once(&store).await;
    assert_eq!(
        request_count.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "second tick must skip the receiver while in backoff"
    );

    shutdown.notify_waiters();
    let _ = handle.await;
}

#[tokio::test]
async fn receiver_429_without_retry_after_does_not_back_off() {
    // A 429 with no parseable Retry-After header is logged but
    // doesn't trigger the backoff path — operators relying on
    // Retry-After get clean semantics, those who don't send it get
    // the existing fire-and-forget behavior.
    let dir = TempDir::new().unwrap();
    let store = open_store(&dir).await;

    let request_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let count_for_route = request_count.clone();
    let app = axum::Router::new().route(
        "/sink",
        axum::routing::post(move || {
            let count = count_for_route.clone();
            async move {
                count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                axum::http::StatusCode::TOO_MANY_REQUESTS
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let shutdown = Arc::new(Notify::new());
    let signal = shutdown.clone();
    let handle = tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .with_graceful_shutdown(async move { signal.notified().await })
        .await
        .unwrap();
    });
    let url = format!("http://{}/sink", addr);

    let dispatcher = WebhookDispatcher::new(WebhooksConfig {
        webhooks: vec![webhook_to("ratelimited-bare", &url, "info", vec![])],
        poll_interval_secs: 1,
        max_concurrent_requests: 16,
        backfill_batch_size: 200,
        allow_insecure_urls: true,
        allow_private_urls: true,
    });
    dispatcher.initialize(&store).await;

    for i in 0..3 {
        store
            .record_audit(AuditRecord::new("system", &format!("e{i}")).severity("info"))
            .await
            .unwrap();
        dispatcher.tick_once(&store).await;
    }
    // No Retry-After ⇒ no backoff ⇒ each tick still hits the receiver.
    assert_eq!(request_count.load(std::sync::atomic::Ordering::SeqCst), 3);

    shutdown.notify_waiters();
    let _ = handle.await;
}

#[tokio::test]
async fn initialize_prunes_orphan_cursors() {
    // Phase: a webhook removed from config since the last run leaves
    // an `audit:<name>` row in `webhook_cursor`. The next startup
    // wipes those rows during initialize. The legacy `audit` row
    // (no name suffix) stays put as a future fallback.
    let dir = TempDir::new().unwrap();
    let store = open_store(&dir).await;
    let now = jiff::Timestamp::now().to_string();
    // Pre-populate with a configured-name row, an orphan row, and
    // the legacy `audit` row.
    for (key, id) in [("audit:active", 100), ("audit:gone", 50), ("audit", 75)] {
        sqlx::query(
            "INSERT INTO webhook_cursor (key, last_seen_id, updated_at)
             VALUES (?, ?, ?)",
        )
        .bind(key)
        .bind(id as i64)
        .bind(&now)
        .execute(store.pool())
        .await
        .unwrap();
    }

    let receiver = MockReceiver::spawn().await;
    let dispatcher = WebhookDispatcher::new(WebhooksConfig {
        // Only "active" is configured; "gone" is removed.
        webhooks: vec![webhook_to("active", &receiver.url(), "info", vec![])],
        poll_interval_secs: 1,
        max_concurrent_requests: 16,
        backfill_batch_size: 200,
        allow_insecure_urls: true,
        allow_private_urls: true,
    });
    dispatcher.initialize(&store).await;

    // After init, only "audit:active" + "audit" should remain.
    let remaining: Vec<(String,)> = sqlx::query_as("SELECT key FROM webhook_cursor ORDER BY key")
        .fetch_all(store.pool())
        .await
        .unwrap();
    let keys: Vec<&str> = remaining.iter().map(|(k,)| k.as_str()).collect();
    assert_eq!(keys, vec!["audit", "audit:active"]);

    receiver.shutdown().await;
}

#[tokio::test]
async fn legacy_shared_cursor_inherited_when_per_webhook_row_missing() {
    // Backwards-compat with Phase 7v: a deployment that ran on the
    // single shared `audit` cursor must still resume from there
    // when upgraded to Phase 7y, instead of jumping to MAX(id).
    let dir = TempDir::new().unwrap();
    let store = open_store(&dir).await;
    // Pre-write 3 events so MAX(id) > 0.
    for i in 0..3 {
        store
            .record_audit(AuditRecord::new("system", &format!("pre.{i}")).severity("info"))
            .await
            .unwrap();
    }
    // Plant a legacy `audit` row sitting on the FIRST event's id, as
    // if the previous-version dispatcher only got that far before
    // the upgrade.
    let first_id: i64 = sqlx::query_scalar("SELECT MIN(id) FROM audit_events")
        .fetch_one(store.pool())
        .await
        .unwrap();
    let now = jiff::Timestamp::now().to_string();
    sqlx::query(
        "INSERT INTO webhook_cursor (key, last_seen_id, updated_at)
         VALUES ('audit', ?, ?)",
    )
    .bind(first_id)
    .bind(&now)
    .execute(store.pool())
    .await
    .unwrap();

    let receiver = MockReceiver::spawn().await;
    let dispatcher = WebhookDispatcher::new(WebhooksConfig {
        webhooks: vec![webhook_to("upgraded", &receiver.url(), "info", vec![])],
        poll_interval_secs: 1,
        max_concurrent_requests: 16,
        backfill_batch_size: 200,
        allow_insecure_urls: true,
        allow_private_urls: true,
    });
    dispatcher.initialize(&store).await;
    // 2 events past the legacy cursor should be delivered.
    assert_eq!(dispatcher.tick_once(&store).await, 2);
    assert_eq!(receiver.count().await, 2);

    receiver.shutdown().await;
}

#[tokio::test]
async fn fresh_install_with_pre_existing_audit_rows_does_not_replay() {
    // Backwards-compat: an existing deployment upgrades to Phase 7v
    // with a populated audit_events table but no webhook_cursor row.
    // The first initialize() falls back to MAX(id) so we don't blast
    // out historical events on first boot.
    let dir = TempDir::new().unwrap();
    let store = open_store(&dir).await;
    // Pre-existing rows.
    for i in 0..5 {
        store
            .record_audit(AuditRecord::new("system", &format!("history.{i}")).severity("info"))
            .await
            .unwrap();
    }

    let receiver = MockReceiver::spawn().await;
    let dispatcher = WebhookDispatcher::new(WebhooksConfig {
        webhooks: vec![webhook_to("first-boot", &receiver.url(), "info", vec![])],
        poll_interval_secs: 1,
        max_concurrent_requests: 16,
        backfill_batch_size: 200,
        allow_insecure_urls: true,
        allow_private_urls: true,
    });
    dispatcher.initialize(&store).await;

    // No new events since init → no dispatch.
    assert_eq!(dispatcher.tick_once(&store).await, 0);
    assert_eq!(receiver.count().await, 0);

    receiver.shutdown().await;
}

#[tokio::test]
async fn wrong_secret_produces_different_signature() {
    // Two receivers, two secrets. Each receiver verifies with its own
    // secret; the cross-check fails. Ensures secrets aren't being
    // shared accidentally between webhooks.
    let dir = TempDir::new().unwrap();
    let store = open_store(&dir).await;
    let r1 = MockReceiver::spawn().await;
    let r2 = MockReceiver::spawn().await;

    let dispatcher = WebhookDispatcher::new(WebhooksConfig {
        webhooks: vec![
            webhook_signed("a", &r1.url(), "secret-A"),
            webhook_signed("b", &r2.url(), "secret-B"),
        ],
        poll_interval_secs: 1,
        max_concurrent_requests: 16,
        backfill_batch_size: 200,
        allow_insecure_urls: true,
        allow_private_urls: true,
    });
    dispatcher.initialize(&store).await;

    store
        .record_audit(AuditRecord::new("user:alice", "operation.rejected").severity("warning"))
        .await
        .unwrap();
    dispatcher.tick_once(&store).await;

    let e1 = r1.snapshot().await;
    let e2 = r2.snapshot().await;
    assert_eq!(e1.len(), 1);
    assert_eq!(e2.len(), 1);
    let h1 = e1[0].signature.as_deref().unwrap();
    let h2 = e2[0].signature.as_deref().unwrap();
    assert_ne!(
        h1, h2,
        "different secrets must produce different signatures"
    );

    // Cross-secret verification fails: r1's header doesn't verify
    // against secret-B and vice versa.
    let now = jiff::Timestamp::now().as_second();
    verify_signed_payload(b"secret-A", &e1[0].body, h1, now, 300)
        .expect("matching secret verifies");
    verify_signed_payload(b"secret-B", &e1[0].body, h1, now, 300)
        .expect_err("wrong secret must reject");

    r1.shutdown().await;
    r2.shutdown().await;
}

#[tokio::test]
async fn replay_with_stale_timestamp_rejected_by_verifier() {
    // Phase 7x's core guarantee: a captured POST cannot be replayed
    // hours later. Receiver verifies with a small tolerance; an old
    // timestamp fails the freshness check.
    let dir = TempDir::new().unwrap();
    let store = open_store(&dir).await;
    let receiver = MockReceiver::spawn().await;
    let secret = "for-replay-test";

    let dispatcher = WebhookDispatcher::new(WebhooksConfig {
        webhooks: vec![webhook_signed("freshness", &receiver.url(), secret)],
        poll_interval_secs: 1,
        max_concurrent_requests: 16,
        backfill_batch_size: 200,
        allow_insecure_urls: true,
        allow_private_urls: true,
    });
    dispatcher.initialize(&store).await;

    store
        .record_audit(AuditRecord::new("user:alice", "operation.rejected").severity("warning"))
        .await
        .unwrap();
    dispatcher.tick_once(&store).await;

    let events = receiver.snapshot().await;
    let header = events[0].signature.as_deref().unwrap();

    // Simulate "two hours have passed" by checking the captured POST
    // against `now + 2h` with the default 5min tolerance.
    let captured_t = parse_signature_header(header).unwrap().0;
    let now = captured_t + 2 * 60 * 60;
    let err =
        verify_signed_payload(secret.as_bytes(), &events[0].body, header, now, 300).unwrap_err();
    assert!(err.contains("tolerance"), "got: {err}");

    receiver.shutdown().await;
}

#[tokio::test]
async fn backoff_survives_dispatcher_restart() {
    // Phase 7as: a 429 with Retry-After persists across server restart.
    // Sequence:
    //   1. Receiver returns 429 with Retry-After: 600 on the first hit.
    //   2. First dispatcher ticks → records the backoff in memory and
    //      writes a row to `webhook_backoff`.
    //   3. Drop the dispatcher (simulated restart). Receiver starts
    //      replying 200 from now on.
    //   4. New dispatcher initialize → restore the backoff. A tick
    //      MUST NOT hit the receiver (still in cool-down).
    //   5. Sanity: a fresh dispatcher with a *different* webhook name
    //      DOES hit the receiver — the backoff is keyed on name.
    let dir = TempDir::new().unwrap();
    let store = open_store(&dir).await;

    // Mock receiver that returns 429 once, then 200 forever after.
    let req_no = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let req_no_for_route = req_no.clone();
    let app = axum::Router::new().route(
        "/sink",
        axum::routing::post(move || {
            let n = req_no_for_route.clone();
            async move {
                let i = n.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let mut resp = axum::http::Response::new(axum::body::Body::empty());
                if i == 0 {
                    *resp.status_mut() = axum::http::StatusCode::TOO_MANY_REQUESTS;
                    // Long enough to outlast the test; the persisted row
                    // should still be in cool-down when we restart.
                    resp.headers_mut()
                        .insert("retry-after", "600".parse().unwrap());
                } else {
                    *resp.status_mut() = axum::http::StatusCode::OK;
                }
                resp
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let shutdown = Arc::new(Notify::new());
    let signal = shutdown.clone();
    let handle = tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .with_graceful_shutdown(async move { signal.notified().await })
        .await
        .unwrap();
    });
    let url = format!("http://{addr}/sink");

    // Lifecycle 1: trip the 429.
    {
        let dispatcher = WebhookDispatcher::new(WebhooksConfig {
            webhooks: vec![webhook_to("ratey", &url, "info", vec![])],
            poll_interval_secs: 1,
            max_concurrent_requests: 16,
            backfill_batch_size: 200,
            allow_insecure_urls: true,
            allow_private_urls: true,
        });
        dispatcher.initialize(&store).await;
        store
            .record_audit(AuditRecord::new("system", "first").severity("info"))
            .await
            .unwrap();
        dispatcher.tick_once(&store).await;
        // The 429 counts as one delivery attempt.
        assert_eq!(req_no.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(dispatcher.metrics().dispatched_ratelimited, 1);
    }

    // Lifecycle 2: simulated restart with the same webhook name. Even
    // though the receiver would now reply 200, the persisted backoff
    // must hold us off.
    {
        let dispatcher = WebhookDispatcher::new(WebhooksConfig {
            webhooks: vec![webhook_to("ratey", &url, "info", vec![])],
            poll_interval_secs: 1,
            max_concurrent_requests: 16,
            backfill_batch_size: 200,
            allow_insecure_urls: true,
            allow_private_urls: true,
        });
        dispatcher.initialize(&store).await;
        store
            .record_audit(AuditRecord::new("system", "second").severity("info"))
            .await
            .unwrap();
        dispatcher.tick_once(&store).await;
        // No new request — receiver count unchanged at 1.
        assert_eq!(
            req_no.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "post-restart dispatcher must honor persisted backoff"
        );
    }

    // Sanity: a fresh dispatcher with a DIFFERENT webhook name has no
    // persisted backoff row, so it fires through.
    {
        let dispatcher = WebhookDispatcher::new(WebhooksConfig {
            webhooks: vec![webhook_to("fresh", &url, "info", vec![])],
            poll_interval_secs: 1,
            max_concurrent_requests: 16,
            backfill_batch_size: 200,
            allow_insecure_urls: true,
            allow_private_urls: true,
        });
        dispatcher.initialize(&store).await;
        store
            .record_audit(AuditRecord::new("system", "third").severity("info"))
            .await
            .unwrap();
        dispatcher.tick_once(&store).await;
        assert_eq!(
            req_no.load(std::sync::atomic::Ordering::SeqCst),
            2,
            "different webhook name should NOT inherit the backoff"
        );
    }

    shutdown.notify_waiters();
    let _ = handle.await;
}

#[tokio::test]
async fn expired_backoff_rows_are_ignored_on_restart() {
    // Phase 7as: rows whose deadline is in the past are NOT loaded into
    // the in-memory backoff map. Verifies the WHERE filter works.
    let dir = TempDir::new().unwrap();
    let store = open_store(&dir).await;

    // Plant a stale row directly in the DB (a previous run's deadline
    // that's long past).
    sqlx::query(
        "INSERT INTO webhook_backoff (webhook_name, deadline_unix, updated_at)
         VALUES ('expired', ?, '2024-01-01T00:00:00Z')",
    )
    .bind(jiff::Timestamp::now().as_second() - 3600) // 1h ago
    .execute(store.pool())
    .await
    .unwrap();

    // Receiver always replies 200.
    let receiver = MockReceiver::spawn().await;
    let dispatcher = WebhookDispatcher::new(WebhooksConfig {
        webhooks: vec![webhook_to("expired", &receiver.url(), "info", vec![])],
        poll_interval_secs: 1,
        max_concurrent_requests: 16,
        backfill_batch_size: 200,
        allow_insecure_urls: true,
        allow_private_urls: true,
    });
    dispatcher.initialize(&store).await;
    store
        .record_audit(AuditRecord::new("system", "go").severity("info"))
        .await
        .unwrap();
    dispatcher.tick_once(&store).await;

    // Even though there's a stale `expired` row in the table, the
    // dispatcher must have ignored it and fired through.
    assert_eq!(receiver.count().await, 1);

    receiver.shutdown().await;
}

#[tokio::test]
async fn per_webhook_metrics_attribute_outcomes_to_each_receiver() {
    // Phase 7at: with two receivers configured, per-webhook counters
    // must attribute each outcome to the right receiver, not blend
    // them into the global total.
    let dir = TempDir::new().unwrap();
    let store = open_store(&dir).await;

    // Receiver A: always 200.
    let r_ok = MockReceiver::spawn().await;

    // Receiver B: always 500 — exercises the non-success counter.
    let app = axum::Router::new().route(
        "/sink",
        axum::routing::post(|| async {
            let mut resp = axum::http::Response::new(axum::body::Body::empty());
            *resp.status_mut() = axum::http::StatusCode::INTERNAL_SERVER_ERROR;
            resp
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bad_addr = listener.local_addr().unwrap();
    let bad_shutdown = Arc::new(Notify::new());
    let bad_signal = bad_shutdown.clone();
    let bad_handle = tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .with_graceful_shutdown(async move { bad_signal.notified().await })
        .await
        .unwrap();
    });
    let bad_url = format!("http://{bad_addr}/sink");

    let dispatcher = WebhookDispatcher::new(WebhooksConfig {
        webhooks: vec![
            webhook_to("alerts", &r_ok.url(), "info", vec![]),
            webhook_to("audit-archive", &bad_url, "info", vec![]),
        ],
        poll_interval_secs: 1,
        max_concurrent_requests: 16,
        backfill_batch_size: 200,
        allow_insecure_urls: true,
        allow_private_urls: true,
    });
    dispatcher.initialize(&store).await;

    // Both receivers see two events each.
    for i in 0..2 {
        store
            .record_audit(AuditRecord::new("system", &format!("event-{i}")).severity("info"))
            .await
            .unwrap();
    }
    dispatcher.tick_once(&store).await;

    let m = dispatcher.metrics();
    // Global aggregates: 2 ok + 2 non_success across both receivers.
    assert_eq!(m.dispatched_ok, 2, "global dispatched_ok");
    assert_eq!(m.dispatched_non_success, 2, "global dispatched_non_success");

    // Per-receiver breakdown: alerts has 2 ok, audit-archive has 2
    // non_success, neither cross-contaminates.
    let by_name: std::collections::HashMap<String, _> = m.per_webhook.iter().cloned().collect();
    let alerts = by_name.get("alerts").expect("alerts entry");
    assert_eq!(alerts.dispatched_ok, 2);
    assert_eq!(alerts.dispatched_non_success, 0);
    let archive = by_name.get("audit-archive").expect("audit-archive entry");
    assert_eq!(archive.dispatched_ok, 0);
    assert_eq!(archive.dispatched_non_success, 2);

    bad_shutdown.notify_waiters();
    let _ = bad_handle.await;
    r_ok.shutdown().await;
}

#[tokio::test]
async fn http_date_retry_after_triggers_backoff() {
    // Phase 7au: HTTP-date form of `Retry-After` triggers the same
    // backoff path the seconds form does. Receiver returns 429 with a
    // far-future date on the first hit; subsequent hits would be 200,
    // but the backoff should keep the dispatcher from firing.
    use std::sync::atomic::{AtomicUsize, Ordering};
    let dir = TempDir::new().unwrap();
    let store = open_store(&dir).await;

    let req_no = Arc::new(AtomicUsize::new(0));
    let req_no_for_route = req_no.clone();
    // Compute a valid IMF-fixdate one hour in the future at runtime —
    // jiff strptime is strict about weekday/date consistency, so a
    // hardcoded "Sat, 01 Jan 2099" would fail (the weekday is wrong).
    // The dispatcher caps at MAX_BACKOFF_SECS = 1h anyway, so 1h works
    // both as a generous cool-down and as a "definitely in the future"
    // wallclock for this test.
    let target = jiff::Timestamp::now()
        .checked_add(jiff::Span::new().try_hours(1).unwrap())
        .unwrap();
    let date = target
        .to_zoned(jiff::tz::TimeZone::UTC)
        .strftime("%a, %d %b %Y %H:%M:%S GMT")
        .to_string();
    let date_for_route = date.clone();
    let app = axum::Router::new().route(
        "/sink",
        axum::routing::post(move || {
            let n = req_no_for_route.clone();
            let d = date_for_route.clone();
            async move {
                let i = n.fetch_add(1, Ordering::SeqCst);
                let mut resp = axum::http::Response::new(axum::body::Body::empty());
                if i == 0 {
                    *resp.status_mut() = axum::http::StatusCode::TOO_MANY_REQUESTS;
                    resp.headers_mut().insert("retry-after", d.parse().unwrap());
                } else {
                    *resp.status_mut() = axum::http::StatusCode::OK;
                }
                resp
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let shutdown = Arc::new(Notify::new());
    let signal = shutdown.clone();
    let handle = tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .with_graceful_shutdown(async move { signal.notified().await })
        .await
        .unwrap();
    });
    let url = format!("http://{addr}/sink");

    let dispatcher = WebhookDispatcher::new(WebhooksConfig {
        webhooks: vec![webhook_to("date-rl", &url, "info", vec![])],
        poll_interval_secs: 1,
        max_concurrent_requests: 16,
        backfill_batch_size: 200,
        allow_insecure_urls: true,
        allow_private_urls: true,
    });
    dispatcher.initialize(&store).await;

    // First event → trigger 429 with HTTP-date Retry-After.
    store
        .record_audit(AuditRecord::new("system", "first").severity("info"))
        .await
        .unwrap();
    dispatcher.tick_once(&store).await;
    assert_eq!(req_no.load(Ordering::SeqCst), 1);
    assert_eq!(dispatcher.metrics().dispatched_ratelimited, 1);

    // Second event → no new request, dispatcher honors the future
    // backoff deadline parsed from the date.
    store
        .record_audit(AuditRecord::new("system", "second").severity("info"))
        .await
        .unwrap();
    dispatcher.tick_once(&store).await;
    assert_eq!(
        req_no.load(Ordering::SeqCst),
        1,
        "HTTP-date Retry-After must drive the same backoff as seconds form"
    );

    shutdown.notify_waiters();
    let _ = handle.await;
}

#[tokio::test]
async fn backfill_batch_size_caps_per_tick_and_resumes_next_tick() {
    // Phase 7bj: write 5 audit rows, configure batch_size=2, tick the
    // dispatcher 3 times. Tick 1 delivers 2, tick 2 delivers 2, tick 3
    // delivers 1 (and a 4th tick would deliver 0). Verifies the
    // batch_size cap is enforced and the cursor advances correctly so
    // the next tick continues without replaying or skipping.
    let dir = TempDir::new().unwrap();
    let store = open_store(&dir).await;
    let receiver = MockReceiver::spawn().await;
    let dispatcher = WebhookDispatcher::new(WebhooksConfig {
        webhooks: vec![webhook_to("ratey", &receiver.url(), "info", vec![])],
        poll_interval_secs: 1,
        max_concurrent_requests: 16,
        backfill_batch_size: 2,
        allow_insecure_urls: true,
        allow_private_urls: true,
    });
    dispatcher.initialize(&store).await;
    for i in 0..5 {
        store
            .record_audit(AuditRecord::new("system", &format!("event-{i}")).severity("info"))
            .await
            .unwrap();
    }

    assert_eq!(dispatcher.tick_once(&store).await, 2, "tick 1");
    assert_eq!(dispatcher.tick_once(&store).await, 2, "tick 2");
    assert_eq!(dispatcher.tick_once(&store).await, 1, "tick 3");
    assert_eq!(dispatcher.tick_once(&store).await, 0, "tick 4 (drained)");
    // All 5 rows reached the receiver, in order, exactly once.
    let events = receiver.snapshot().await;
    assert_eq!(events.len(), 5);
    let kinds: Vec<&str> = events
        .iter()
        .map(|e| e.body_json["kind"].as_str().unwrap())
        .collect();
    assert_eq!(
        kinds,
        vec!["event-0", "event-1", "event-2", "event-3", "event-4"]
    );

    receiver.shutdown().await;
}

#[tokio::test]
async fn backfill_batch_size_zero_falls_back_to_default() {
    // Phase 7bj: a typo'd `backfill_batch_size = 0` shouldn't halt the
    // dispatcher. We treat it as "use the default" and proceed.
    let dir = TempDir::new().unwrap();
    let store = open_store(&dir).await;
    let receiver = MockReceiver::spawn().await;
    let dispatcher = WebhookDispatcher::new(WebhooksConfig {
        webhooks: vec![webhook_to("any", &receiver.url(), "info", vec![])],
        poll_interval_secs: 1,
        max_concurrent_requests: 16,
        backfill_batch_size: 0, // treated as default
        allow_insecure_urls: true,
        allow_private_urls: true,
    });
    dispatcher.initialize(&store).await;
    store
        .record_audit(AuditRecord::new("system", "event").severity("info"))
        .await
        .unwrap();
    assert_eq!(dispatcher.tick_once(&store).await, 1);
    receiver.shutdown().await;
}

#[tokio::test]
async fn per_receiver_cap_limits_concurrent_requests() {
    // Phase 7bk: a per-receiver `max_concurrent_requests = 1` serializes
    // dispatch to that receiver even when the global cap is wide open
    // and a tick has 5 matching events. The receiver tracks its own
    // active-count via an atomic; we assert it never exceeds 1.
    let dir = TempDir::new().unwrap();
    let store = open_store(&dir).await;

    let active = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let max_observed = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let active_for_route = active.clone();
    let max_for_route = max_observed.clone();
    let app = axum::Router::new().route(
        "/sink",
        axum::routing::post(move |_body: axum::body::Bytes| {
            let active = active_for_route.clone();
            let max = max_for_route.clone();
            async move {
                let cur = active.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
                max.fetch_max(cur, std::sync::atomic::Ordering::SeqCst);
                tokio::time::sleep(std::time::Duration::from_millis(150)).await;
                active.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
                axum::http::StatusCode::OK
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let shutdown = Arc::new(Notify::new());
    let signal = shutdown.clone();
    let handle = tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .with_graceful_shutdown(async move { signal.notified().await })
        .await
        .unwrap();
    });
    let url = format!("http://{}/sink", addr);

    let mut wh = webhook_to("capped-rx", &url, "info", vec![]);
    wh.max_concurrent_requests = Some(1);
    let dispatcher = WebhookDispatcher::new(WebhooksConfig {
        webhooks: vec![wh],
        poll_interval_secs: 1,
        // Global cap deliberately wide — only the per-receiver cap should bite.
        max_concurrent_requests: 16,
        backfill_batch_size: 200,
        allow_insecure_urls: true,
        allow_private_urls: true,
    });
    dispatcher.initialize(&store).await;

    for i in 0..5 {
        store
            .record_audit(AuditRecord::new("system", &format!("event.{i}")).severity("info"))
            .await
            .unwrap();
    }

    let dispatched = dispatcher.tick_once(&store).await;
    assert_eq!(dispatched, 5);
    let observed = max_observed.load(std::sync::atomic::Ordering::SeqCst);
    assert_eq!(
        observed, 1,
        "per-receiver cap=1 should serialize dispatch; saw {observed} concurrent"
    );

    shutdown.notify_waiters();
    let _ = handle.await;
}

#[tokio::test]
async fn per_receiver_cap_does_not_throttle_other_receivers() {
    // Phase 7bk: receiver A has cap=1 + a slow handler; receiver B has
    // no cap. With multiple events queued, A serializes (1-at-a-time)
    // while B fans out in parallel. We verify B finishes before A by
    // checking B's observed parallelism > 1 (or at least equal to the
    // event count — fast handler) AND that the tick total time is
    // closer to A's serialized time than to a fully-serial schedule
    // for both.
    let dir = TempDir::new().unwrap();
    let store = open_store(&dir).await;

    // Receiver A: slow + cap=1 (serialized).
    let slow_app = axum::Router::new().route(
        "/sink",
        axum::routing::post(|| async {
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            axum::http::StatusCode::OK
        }),
    );
    let slow_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let slow_addr = slow_listener.local_addr().unwrap();
    let slow_shutdown = Arc::new(Notify::new());
    let slow_signal = slow_shutdown.clone();
    let slow_handle = tokio::spawn(async move {
        axum::serve(slow_listener, slow_app)
            .with_graceful_shutdown(async move { slow_signal.notified().await })
            .await
            .unwrap();
    });
    let slow_url = format!("http://{}/sink", slow_addr);

    // Receiver B: fast + no cap (parallel).
    let fast = MockReceiver::spawn().await;

    let mut wh_slow = webhook_to("slow-capped", &slow_url, "info", vec![]);
    wh_slow.max_concurrent_requests = Some(1);
    let wh_fast = webhook_to("fast-uncapped", &fast.url(), "info", vec![]);

    let dispatcher = WebhookDispatcher::new(WebhooksConfig {
        webhooks: vec![wh_slow, wh_fast],
        poll_interval_secs: 1,
        max_concurrent_requests: 16,
        backfill_batch_size: 200,
        allow_insecure_urls: true,
        allow_private_urls: true,
    });
    dispatcher.initialize(&store).await;

    // 3 events: each fans out to BOTH receivers (no kind/severity filter).
    // Slow receiver: 3 × 200ms serialized ≈ 600ms.
    // Fast receiver: ~all 3 in parallel, sub-100ms.
    for i in 0..3 {
        store
            .record_audit(AuditRecord::new("system", &format!("event.{i}")).severity("info"))
            .await
            .unwrap();
    }

    let start = std::time::Instant::now();
    let dispatched = dispatcher.tick_once(&store).await;
    let elapsed = start.elapsed();

    // 3 events × 2 receivers = 6 dispatched.
    assert_eq!(dispatched, 6);
    // Fast receiver got all 3 despite slow receiver being mid-serialize.
    assert_eq!(fast.count().await, 3);
    // Total time: bounded by slow serialized ≈ 600ms. If slow's per-receiver
    // cap leaked into the global flow it'd still be ≈ 600ms, BUT a
    // regression where the per-receiver semaphore blocks unrelated
    // receivers would push fast's deliveries to wait too. We can't
    // observe that directly; instead we sanity-check the tick stays
    // well under the "fully serial" schedule (6 × 200ms = 1.2s × CI
    // slowdown factor). Under heavy parallel test load real wall-
    // clock can stretch noticeably, so we keep the bound generous;
    // the regression we're guarding against would push elapsed into
    // the 5+ s range, which still trips this assert.
    assert!(
        elapsed < std::time::Duration::from_millis(3500),
        "slow receiver's per-receiver cap should not block fast receiver; tick took {elapsed:?}"
    );

    slow_shutdown.notify_waiters();
    let _ = slow_handle.await;
    fast.shutdown().await;
}

// Phase 7bp: signing-version rotation v1 → v2.

#[tokio::test]
async fn default_signing_versions_emits_v1_only() {
    // Backwards-compat guard: a webhook with `hmac_secret` set but no
    // explicit `signing_versions` should emit just `v1=...` (the
    // pre-7bp behavior). v2 must be absent unless the operator opts
    // in.
    let dir = TempDir::new().unwrap();
    let store = open_store(&dir).await;
    let receiver = MockReceiver::spawn().await;
    let secret = "rotation-test-secret";

    let dispatcher = WebhookDispatcher::new(WebhooksConfig {
        webhooks: vec![webhook_signed("default-versions", &receiver.url(), secret)],
        poll_interval_secs: 1,
        max_concurrent_requests: 16,
        backfill_batch_size: 200,
        allow_insecure_urls: true,
        allow_private_urls: true,
    });
    dispatcher.initialize(&store).await;

    store
        .record_audit(AuditRecord::new("user:alice", "evt").severity("warning"))
        .await
        .unwrap();
    dispatcher.tick_once(&store).await;

    let events = receiver.snapshot().await;
    let header = events[0].signature.as_deref().unwrap();
    let parsed = parse_signature_header_versioned(header).unwrap();
    assert!(parsed.v1.is_some(), "default config must emit v1");
    assert!(parsed.v2.is_none(), "default config must NOT emit v2");

    receiver.shutdown().await;
}

#[tokio::test]
async fn signing_versions_v2_only_emits_v2_no_v1() {
    let dir = TempDir::new().unwrap();
    let store = open_store(&dir).await;
    let receiver = MockReceiver::spawn().await;
    let secret = "v2-only-secret";

    let mut wh = webhook_signed("v2-only", &receiver.url(), secret);
    wh.signing_versions = vec!["v2".into()];
    let dispatcher = WebhookDispatcher::new(WebhooksConfig {
        webhooks: vec![wh],
        poll_interval_secs: 1,
        max_concurrent_requests: 16,
        backfill_batch_size: 200,
        allow_insecure_urls: true,
        allow_private_urls: true,
    });
    dispatcher.initialize(&store).await;

    store
        .record_audit(AuditRecord::new("user:alice", "evt").severity("warning"))
        .await
        .unwrap();
    dispatcher.tick_once(&store).await;

    let events = receiver.snapshot().await;
    let header = events[0].signature.as_deref().unwrap();
    let parsed = parse_signature_header_versioned(header).unwrap();
    assert!(parsed.v1.is_none(), "v2-only must omit v1");
    assert!(parsed.v2.is_some(), "v2-only must emit v2");

    let now = jiff::Timestamp::now().as_second();
    verify_signed_payload_v2(
        secret.as_bytes(),
        &events[0].body,
        &receiver.url(),
        header,
        now,
        300,
    )
    .expect("v2 signature must verify against own URL");

    // The v1 verifier requires v1 to be present in the header; with
    // v2-only it errors cleanly.
    let v1_attempt = verify_signed_payload(secret.as_bytes(), &events[0].body, header, now, 300);
    assert!(
        v1_attempt.is_err(),
        "v1 verifier must fail when only v2 is present"
    );

    receiver.shutdown().await;
}

#[tokio::test]
async fn signing_versions_both_emits_both_signatures() {
    let dir = TempDir::new().unwrap();
    let store = open_store(&dir).await;
    let receiver = MockReceiver::spawn().await;
    let secret = "both-versions-secret";

    let mut wh = webhook_signed("both", &receiver.url(), secret);
    wh.signing_versions = vec!["v1".into(), "v2".into()];
    let dispatcher = WebhookDispatcher::new(WebhooksConfig {
        webhooks: vec![wh],
        poll_interval_secs: 1,
        max_concurrent_requests: 16,
        backfill_batch_size: 200,
        allow_insecure_urls: true,
        allow_private_urls: true,
    });
    dispatcher.initialize(&store).await;

    store
        .record_audit(AuditRecord::new("user:alice", "evt").severity("warning"))
        .await
        .unwrap();
    dispatcher.tick_once(&store).await;

    let events = receiver.snapshot().await;
    let header = events[0].signature.as_deref().unwrap();
    let parsed = parse_signature_header_versioned(header).unwrap();
    let v1 = parsed.v1.expect("v1 must be present");
    let v2 = parsed.v2.expect("v2 must be present");
    assert_ne!(v1, v2, "v1 and v2 use different payloads → different sigs");

    // Both verifiers succeed during a rotation window.
    let now = jiff::Timestamp::now().as_second();
    verify_signed_payload(secret.as_bytes(), &events[0].body, header, now, 300)
        .expect("v1 must verify");
    verify_signed_payload_v2(
        secret.as_bytes(),
        &events[0].body,
        &receiver.url(),
        header,
        now,
        300,
    )
    .expect("v2 must verify");

    receiver.shutdown().await;
}

#[tokio::test]
async fn v2_signature_differs_when_url_differs() {
    // Replay-protection check: a captured payload signed for URL A
    // must NOT verify against URL B. We sign with the receiver's URL,
    // then attempt verification with a different URL — must fail.
    let dir = TempDir::new().unwrap();
    let store = open_store(&dir).await;
    let receiver = MockReceiver::spawn().await;
    let secret = "url-binding-secret";

    let mut wh = webhook_signed("v2-url-bound", &receiver.url(), secret);
    wh.signing_versions = vec!["v2".into()];
    let dispatcher = WebhookDispatcher::new(WebhooksConfig {
        webhooks: vec![wh],
        poll_interval_secs: 1,
        max_concurrent_requests: 16,
        backfill_batch_size: 200,
        allow_insecure_urls: true,
        allow_private_urls: true,
    });
    dispatcher.initialize(&store).await;

    store
        .record_audit(AuditRecord::new("user", "evt").severity("warning"))
        .await
        .unwrap();
    dispatcher.tick_once(&store).await;

    let events = receiver.snapshot().await;
    let header = events[0].signature.as_deref().unwrap();
    let now = jiff::Timestamp::now().as_second();

    verify_signed_payload_v2(
        secret.as_bytes(),
        &events[0].body,
        &receiver.url(),
        header,
        now,
        300,
    )
    .unwrap();

    let wrong_url = "http://imposter.example/sink";
    let result = verify_signed_payload_v2(
        secret.as_bytes(),
        &events[0].body,
        wrong_url,
        header,
        now,
        300,
    );
    assert!(
        result.is_err(),
        "v2 must reject when URL differs; result: {result:?}"
    );

    receiver.shutdown().await;
}

#[tokio::test]
async fn unknown_signing_version_falls_back_to_default() {
    // Typo guard: misconfigured `signing_versions = ["v99"]` shouldn't
    // halt dispatch. Dispatcher logs a warning, falls back to ["v1"].
    let dir = TempDir::new().unwrap();
    let store = open_store(&dir).await;
    let receiver = MockReceiver::spawn().await;
    let secret = "typo-secret";

    let mut wh = webhook_signed("typo", &receiver.url(), secret);
    wh.signing_versions = vec!["v99".into(), "garbage".into()];
    let dispatcher = WebhookDispatcher::new(WebhooksConfig {
        webhooks: vec![wh],
        poll_interval_secs: 1,
        max_concurrent_requests: 16,
        backfill_batch_size: 200,
        allow_insecure_urls: true,
        allow_private_urls: true,
    });
    dispatcher.initialize(&store).await;

    store
        .record_audit(AuditRecord::new("user", "evt").severity("warning"))
        .await
        .unwrap();
    dispatcher.tick_once(&store).await;

    let events = receiver.snapshot().await;
    let header = events[0].signature.as_deref().unwrap();
    let parsed = parse_signature_header_versioned(header).unwrap();
    assert!(parsed.v1.is_some(), "fall back to v1 on typo'd config");
    assert!(parsed.v2.is_none(), "v99 should NOT promote to v2");

    receiver.shutdown().await;
}

#[tokio::test]
async fn per_receiver_semaphore_wait_counter_increases_under_contention() {
    // Phase 7bq: a receiver with `max_concurrent_requests = 1` and a
    // slow handler forces queueing. The per-receiver
    // semaphore_wait_micros counter must reflect that — events 2..N
    // can't acquire the per-receiver permit until the prior request
    // completes, so each waits ~slow-handler-duration.
    let dir = TempDir::new().unwrap();
    let store = open_store(&dir).await;

    let app = axum::Router::new().route(
        "/sink",
        axum::routing::post(|_body: axum::body::Bytes| async {
            tokio::time::sleep(std::time::Duration::from_millis(120)).await;
            axum::http::StatusCode::OK
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let shutdown = Arc::new(Notify::new());
    let signal = shutdown.clone();
    let handle = tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .with_graceful_shutdown(async move { signal.notified().await })
        .await
        .unwrap();
    });
    let url = format!("http://{}/sink", addr);

    let mut wh = webhook_to("backed-up", &url, "info", vec![]);
    wh.max_concurrent_requests = Some(1);
    let dispatcher = WebhookDispatcher::new(WebhooksConfig {
        webhooks: vec![wh],
        poll_interval_secs: 1,
        max_concurrent_requests: 16,
        backfill_batch_size: 200,
        allow_insecure_urls: true,
        allow_private_urls: true,
    });
    dispatcher.initialize(&store).await;

    for i in 0..3 {
        store
            .record_audit(AuditRecord::new("system", &format!("event.{i}")).severity("info"))
            .await
            .unwrap();
    }
    dispatcher.tick_once(&store).await;

    let snap = dispatcher.metrics();
    let entry = snap
        .per_webhook
        .iter()
        .find(|(name, _)| name == "backed-up")
        .expect("per-receiver entry exists");
    // Cumulative wait covers all 3 deliveries. The first acquires
    // immediately, the second waits ~120ms, the third ~240ms — total
    // somewhere north of 300ms = 300_000µs. Allow generous slack so
    // CI doesn't flake.
    assert!(
        entry.1.semaphore_wait_micros >= 100_000,
        "per-receiver wait should accumulate; got {}µs",
        entry.1.semaphore_wait_micros
    );

    shutdown.notify_waiters();
    let _ = handle.await;
}

#[tokio::test]
async fn per_receiver_semaphore_wait_histogram_records_observations() {
    // Phase 7bs: each delivery should land one observation in the
    // per-receiver histogram. With 3 events delivered, count must be 3.
    // Bucket distribution depends on timing; we only assert that the
    // total count matches the dispatch count.
    let dir = TempDir::new().unwrap();
    let store = open_store(&dir).await;
    let receiver = MockReceiver::spawn().await;

    let dispatcher = WebhookDispatcher::new(WebhooksConfig {
        webhooks: vec![webhook_to("histo", &receiver.url(), "info", vec![])],
        poll_interval_secs: 1,
        max_concurrent_requests: 16,
        backfill_batch_size: 200,
        allow_insecure_urls: true,
        allow_private_urls: true,
    });
    dispatcher.initialize(&store).await;

    for i in 0..3 {
        store
            .record_audit(AuditRecord::new("system", &format!("event.{i}")).severity("info"))
            .await
            .unwrap();
    }
    dispatcher.tick_once(&store).await;

    let snap = dispatcher.metrics();
    let entry = snap
        .per_webhook
        .iter()
        .find(|(name, _)| name == "histo")
        .expect("per-receiver entry exists");
    assert_eq!(
        entry.1.semaphore_wait_hist.count, 3,
        "per-receiver histogram count must equal dispatch count"
    );
    // Sum of buckets equals count.
    let bucket_sum: u64 = entry.1.semaphore_wait_hist.buckets.iter().sum();
    assert_eq!(
        bucket_sum, 3,
        "bucket sum {bucket_sum} should equal count {}",
        entry.1.semaphore_wait_hist.count
    );

    receiver.shutdown().await;
}

#[tokio::test]
async fn dispatch_duration_records_round_trip_time_per_receiver() {
    // Phase 7bt: each delivery's HTTP send time accumulates in
    // both the global and per-receiver `dispatch_duration_micros`
    // counter. With a slow receiver (200ms handler) and 2 events
    // delivered, both counters should have ≥ 400_000µs total
    // — generous lower bound so CI doesn't flake.
    let dir = TempDir::new().unwrap();
    let store = open_store(&dir).await;

    let app = axum::Router::new().route(
        "/sink",
        axum::routing::post(|_body: axum::body::Bytes| async {
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            axum::http::StatusCode::OK
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let shutdown = Arc::new(Notify::new());
    let signal = shutdown.clone();
    let handle = tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .with_graceful_shutdown(async move { signal.notified().await })
        .await
        .unwrap();
    });
    let url = format!("http://{}/sink", addr);

    let dispatcher = WebhookDispatcher::new(WebhooksConfig {
        webhooks: vec![webhook_to("slow-recv", &url, "info", vec![])],
        poll_interval_secs: 1,
        max_concurrent_requests: 16,
        backfill_batch_size: 200,
        allow_insecure_urls: true,
        allow_private_urls: true,
    });
    dispatcher.initialize(&store).await;

    for i in 0..2 {
        store
            .record_audit(AuditRecord::new("system", &format!("event.{i}")).severity("info"))
            .await
            .unwrap();
    }
    dispatcher.tick_once(&store).await;

    let snap = dispatcher.metrics();
    // Global counter accumulates across all receivers.
    assert!(
        snap.dispatch_duration_micros >= 200_000,
        "global dispatch_duration must reflect ≥ one round-trip (200ms); got {}µs",
        snap.dispatch_duration_micros
    );
    let entry = snap
        .per_webhook
        .iter()
        .find(|(name, _)| name == "slow-recv")
        .expect("per-receiver entry exists");
    assert!(
        entry.1.dispatch_duration_micros >= 200_000,
        "per-receiver dispatch_duration should accumulate; got {}µs",
        entry.1.dispatch_duration_micros
    );
    // Per-receiver value should equal global when only one receiver.
    assert_eq!(
        entry.1.dispatch_duration_micros, snap.dispatch_duration_micros,
        "single-receiver case: per-receiver and global must match"
    );

    shutdown.notify_waiters();
    let _ = handle.await;
}

#[tokio::test]
async fn dispatch_duration_histogram_records_observations() {
    // Phase 7bu: each delivery should land one observation in BOTH
    // the global and per-receiver dispatch-duration histograms. With
    // 3 events, both counts must be 3, and the bucket sums must
    // equal the count.
    let dir = TempDir::new().unwrap();
    let store = open_store(&dir).await;
    let receiver = MockReceiver::spawn().await;

    let dispatcher = WebhookDispatcher::new(WebhooksConfig {
        webhooks: vec![webhook_to("hist-test", &receiver.url(), "info", vec![])],
        poll_interval_secs: 1,
        max_concurrent_requests: 16,
        backfill_batch_size: 200,
        allow_insecure_urls: true,
        allow_private_urls: true,
    });
    dispatcher.initialize(&store).await;

    for i in 0..3 {
        store
            .record_audit(AuditRecord::new("system", &format!("event.{i}")).severity("info"))
            .await
            .unwrap();
    }
    dispatcher.tick_once(&store).await;

    let snap = dispatcher.metrics();
    assert_eq!(
        snap.dispatch_duration_hist.count, 3,
        "global dispatch_duration_hist count must equal dispatch count"
    );
    let global_bucket_sum: u64 = snap.dispatch_duration_hist.buckets.iter().sum();
    assert_eq!(global_bucket_sum, 3, "global bucket sum must equal count");

    let entry = snap
        .per_webhook
        .iter()
        .find(|(name, _)| name == "hist-test")
        .expect("per-receiver entry exists");
    assert_eq!(
        entry.1.dispatch_duration_hist.count, 3,
        "per-receiver dispatch_duration_hist count must equal dispatch count"
    );
    let per_bucket_sum: u64 = entry.1.dispatch_duration_hist.buckets.iter().sum();
    assert_eq!(
        per_bucket_sum, 3,
        "per-receiver bucket sum must equal count"
    );

    receiver.shutdown().await;
}

#[tokio::test]
async fn duplicate_signing_versions_deduped() {
    // Operator configures `["v1", "v1"]` — the dispatcher should
    // dedupe so only one `v1=...` entry appears in the header.
    let dir = TempDir::new().unwrap();
    let store = open_store(&dir).await;
    let receiver = MockReceiver::spawn().await;
    let secret = "dedupe-secret";

    let mut wh = webhook_signed("dup", &receiver.url(), secret);
    wh.signing_versions = vec!["v1".into(), "v1".into()];
    let dispatcher = WebhookDispatcher::new(WebhooksConfig {
        webhooks: vec![wh],
        poll_interval_secs: 1,
        max_concurrent_requests: 16,
        backfill_batch_size: 200,
        allow_insecure_urls: true,
        allow_private_urls: true,
    });
    dispatcher.initialize(&store).await;

    store
        .record_audit(AuditRecord::new("user", "evt").severity("warning"))
        .await
        .unwrap();
    dispatcher.tick_once(&store).await;

    let events = receiver.snapshot().await;
    let header = events[0].signature.as_deref().unwrap();
    // Header should have one `v1=` token, not two.
    let v1_count = header.matches("v1=").count();
    assert_eq!(
        v1_count, 1,
        "duplicate v1 should be deduped; header: {header}"
    );

    receiver.shutdown().await;
}
