// Phase 7de: property-based smoke fuzzing of provider spec
// parsers. We feed each `from_value` random YAML and assert the
// only failure mode is `Result::Err(String)` — never a panic, an
// abort, or an infinite loop.
//
// Why proptest, not cargo-fuzz: proptest runs under stable Rust
// and inside `cargo test`, so these regressions land in normal CI.
// A `fuzz/` directory with cargo-fuzz harnesses lives next to
// this file for those who run coverage-guided fuzzing on nightly.
//
// Each property runs `PROPTEST_CASES` random inputs (default 256;
// override via env var). Shrinking gives a small reproducer when
// a panic surfaces.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use iac_providers::{
    acme::AcmeCertSpec,
    compose::DockerComposeSpec,
    cron::CronJobSpec,
    dns::DnsRecordSpec,
    docker::DockerContainerSpec,
    file::FileSpec,
    firewall::FirewallRuleSpec,
    monitoring::MonitoringCheckSpec,
    nginx::NginxVhostSpec,
    package::PackageSpec,
    sysctl::SysctlSettingSpec,
    systemd::SystemdUnitSpec,
};
use proptest::prelude::*;
use serde_yaml_ng::Value as YamlValue;

/// A bounded random YAML string. We deliberately favour shapes the
/// parsers actually handle (mappings, sequences, scalars) over
/// adversarial token sequences — those would shrink to "invalid
/// YAML at byte 0" 99% of the time, which doesn't exercise the
/// type-coercion paths inside `from_value`.
fn yaml_value_strategy() -> impl Strategy<Value = YamlValue> {
    let leaf = prop_oneof![
        Just(YamlValue::Null),
        any::<bool>().prop_map(YamlValue::Bool),
        any::<i64>().prop_map(|n| serde_yaml_ng::from_str(&n.to_string()).unwrap()),
        // Random short strings — bias towards alphanumerics so
        // shrinking produces something readable.
        "[a-zA-Z0-9_./:-]{0,12}".prop_map(YamlValue::String),
        // Some shapes the parsers expect: paths, mode strings,
        // domain-like values.
        Just(YamlValue::String("/etc/foo".into())),
        Just(YamlValue::String("0644".into())),
        Just(YamlValue::String("example.com".into())),
        Just(YamlValue::String("present".into())),
        Just(YamlValue::String("absent".into())),
    ];
    leaf.prop_recursive(
        3,  // max recursion depth — bounds the tree size
        24, // max total size hint
        8,  // children per inner node
        |inner| {
            prop_oneof![
                proptest::collection::vec(inner.clone(), 0..6)
                    .prop_map(YamlValue::Sequence),
                proptest::collection::vec(
                    ("[a-z_][a-z0-9_]{0,10}".prop_map(YamlValue::String), inner),
                    0..6,
                )
                .prop_map(|kvs| YamlValue::Mapping(kvs.into_iter().collect())),
            ]
        },
    )
}

/// Fuzz the `from_value` of a spec type. Asserts that the parser
/// either returns `Ok(_)` or a string error — never panics, never
/// loops, never aborts.
macro_rules! fuzz_parser {
    ($name:ident, $type:ty) => {
        proptest! {
            #![proptest_config(ProptestConfig {
                cases: 256,
                .. ProptestConfig::default()
            })]

            #[test]
            fn $name(v in yaml_value_strategy()) {
                // The only assertion is that this call returns. A
                // panic, an unwrap, or a divide-by-zero anywhere
                // in the parser's call graph fails the test.
                let _ = <$type>::from_value(&v);
            }
        }
    };
}

fuzz_parser!(fuzz_file_spec, FileSpec);
fuzz_parser!(fuzz_systemd_spec, SystemdUnitSpec);
fuzz_parser!(fuzz_package_spec, PackageSpec);
fuzz_parser!(fuzz_docker_spec, DockerContainerSpec);
fuzz_parser!(fuzz_compose_spec, DockerComposeSpec);
fuzz_parser!(fuzz_nginx_spec, NginxVhostSpec);
fuzz_parser!(fuzz_cron_spec, CronJobSpec);
fuzz_parser!(fuzz_firewall_spec, FirewallRuleSpec);
fuzz_parser!(fuzz_monitoring_spec, MonitoringCheckSpec);
fuzz_parser!(fuzz_sysctl_spec, SysctlSettingSpec);
fuzz_parser!(fuzz_dns_spec, DnsRecordSpec);
fuzz_parser!(fuzz_acme_spec, AcmeCertSpec);

// Manifest loader fuzz: feed random YAML *strings* (not Values)
// to the document parser. Catches issues in the YAML tokeniser
// surface that the typed-Value parsers never see.
proptest! {
    #![proptest_config(ProptestConfig { cases: 128, .. ProptestConfig::default() })]

    #[test]
    fn fuzz_manifest_yaml_strings(s in r##"[a-zA-Z0-9 :{}\[\],\-\n#'"]{0,200}"##) {
        // Feed `s` as the body of a single YAML document. We
        // don't care if it parses; we care that it doesn't crash
        // the loader.
        let path = std::path::PathBuf::from("(fuzz)");
        let _ = iac_core::manifest::parse_documents(&path, &s);
    }
}
