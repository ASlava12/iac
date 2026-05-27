// Phase 7da.6: real Cloudflare DNS integration test for `dns.record`.
//
// Skipped unless ALL of these env vars are set:
//   CLOUDFLARE_DNS_API_TOKEN — scoped token with `Zone.DNS:Edit` for
//                              the test zone
//   CLOUDFLARE_TEST_ZONE     — the zone to mutate, e.g. `iactest.example`
//
// The test creates a TXT record under a unique randomised name (so
// concurrent runs don't collide), reads it back, updates it, and
// deletes it. Touches only TXT records under `iac-test-<random>`,
// so it can't disturb any operator-owned records as long as that
// subdomain is unused.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use iac_providers::dns::{CloudflareCli, CloudflareCreds, DnsBackend, RecordType};

fn token() -> Option<String> {
    std::env::var("CLOUDFLARE_DNS_API_TOKEN").ok()
}

fn zone() -> Option<String> {
    std::env::var("CLOUDFLARE_TEST_ZONE").ok()
}

fn random_name() -> String {
    // Cheap, no extra dep: nanos since UNIX_EPOCH gives us per-run
    // uniqueness sufficient for parallel CI workers. A dedicated PRNG
    // would be overkill for a single-run scratch label.
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("iac-test-{nanos:x}")
}

#[test]
fn cloudflare_create_read_update_delete_txt_record() {
    let (Some(tok), Some(zone)) = (token(), zone()) else {
        eprintln!("skipping: set CLOUDFLARE_DNS_API_TOKEN and CLOUDFLARE_TEST_ZONE");
        return;
    };

    let cli = CloudflareCli::new(CloudflareCreds { api_token: tok });
    let name = random_name();
    let fqdn = format!("{name}.{zone}");

    // Pre-test: nothing should exist with this random label. If it
    // does, something else owns the namespace and we should bail.
    let pre = cli
        .find_record(&zone, &fqdn, RecordType::TXT)
        .expect("pre find_record");
    assert!(
        pre.is_none(),
        "unexpected: random-named record already exists: {pre:?}",
    );

    // 1. Create.
    let id = cli
        .create_record(&zone, &fqdn, RecordType::TXT, "iac-real-test-v1", 300)
        .expect("create_record");
    assert!(!id.is_empty());

    // 2. Read back.
    let found = cli
        .find_record(&zone, &fqdn, RecordType::TXT)
        .expect("find after create")
        .expect("record should exist");
    assert_eq!(found.id, id, "round-tripped id");
    // Cloudflare wraps TXT values in quotes; tolerate either form.
    let v = found.value.trim_matches('"');
    assert_eq!(v, "iac-real-test-v1");
    assert_eq!(found.ttl, 300);

    // 3. Update.
    cli.update_record(&zone, &id, &fqdn, RecordType::TXT, "iac-real-test-v2", 600)
        .expect("update_record");

    let updated = cli
        .find_record(&zone, &fqdn, RecordType::TXT)
        .expect("find after update")
        .expect("record should still exist");
    let v = updated.value.trim_matches('"');
    assert_eq!(v, "iac-real-test-v2");
    assert_eq!(updated.ttl, 600);

    // 4. Delete.
    cli.delete_record(&zone, &id).expect("delete_record");
    let after = cli
        .find_record(&zone, &fqdn, RecordType::TXT)
        .expect("find after delete");
    assert!(after.is_none(), "record should be gone, got {after:?}");
}
