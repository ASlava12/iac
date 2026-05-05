// cargo-fuzz target: feed arbitrary bytes interpreted as YAML to
// every provider spec parser. Crashes (panics, OOMs, infinite
// loops detected by the timeout) are reported by libfuzzer.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(value) = serde_yaml_ng::from_str::<serde_yaml_ng::Value>(text) else {
        return;
    };
    // Every provider's `from_value` must tolerate any YAML shape —
    // the only legal failure mode is `Result::Err(String)`.
    let _ = iac_providers::file::FileSpec::from_value(&value);
    let _ = iac_providers::systemd::SystemdUnitSpec::from_value(&value);
    let _ = iac_providers::package::PackageSpec::from_value(&value);
    let _ = iac_providers::docker::DockerContainerSpec::from_value(&value);
    let _ = iac_providers::compose::DockerComposeSpec::from_value(&value);
    let _ = iac_providers::nginx::NginxVhostSpec::from_value(&value);
    let _ = iac_providers::cron::CronJobSpec::from_value(&value);
    let _ = iac_providers::firewall::FirewallRuleSpec::from_value(&value);
    let _ = iac_providers::monitoring::MonitoringCheckSpec::from_value(&value);
    let _ = iac_providers::sysctl::SysctlSettingSpec::from_value(&value);
    let _ = iac_providers::dns::DnsRecordSpec::from_value(&value);
    let _ = iac_providers::acme::AcmeCertSpec::from_value(&value);
});
