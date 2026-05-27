// iac-providers: built-in providers for the local executor.
// Each provider is self-contained and registered via `register_builtins`.

// Phase 7cz.16: tests-only exemption for unwrap/expect/panic.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

// Crate-wide test-only mutex. Several test modules in this crate
// write a `.sh` plugin script and immediately `Command::spawn()` it.
// Under parallel cargo-test, a sibling test's fork()+exec() can
// inherit our just-opened write fd before O_CLOEXEC fires, and our
// subsequent exec() of the same script returns ETXTBSY (Linux
// "Text file busy"). Tests in `process/handle.rs`,
// `process/provider.rs`, and `shellout/provider.rs` hold this lock
// across "write script → spawn" to close the window.
#[cfg(test)]
pub(crate) static SPAWN_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[macro_use]
mod sha256_pin;
mod step_action;
mod subprocess;

// Phase 7cz.18: shared mock-backend bookkeeping. The mocks themselves
// are `pub` for cross-crate test consumption (iac-controlplane tests
// reach for `MockCompose` etc.), so the journal can't be cfg-gated.
// Negligible overhead in release — `MockJournal` is just a `Mutex`
// wrapper; release builds simply don't construct one.
pub(crate) mod mock_journal;

pub mod acme;
pub mod compose;
pub mod cron;
pub mod dns;
pub mod docker;
pub mod file;
pub mod firewall;
pub mod monitoring;
pub mod nginx;
pub mod package;
pub mod plugin;
pub mod process;
pub mod shellout;
pub mod sysctl;
pub mod systemd;
// Phase 10: WASM provider gated behind the `wasm` feature so cross-
// compiles to architectures wasmtime/cranelift doesn't support
// (notably MIPS) build cleanly. All other providers remain active.
#[cfg(feature = "wasm")]
pub mod wasm;

use iac_core::ProviderRegistry;

pub fn register_builtins(reg: &mut ProviderRegistry) {
    reg.register(Box::new(file::FileProvider::new()));
    reg.register(Box::new(systemd::SystemdProvider::new()));
    reg.register(Box::new(package::PackageProvider::new()));
    reg.register(Box::new(docker::DockerProvider::new()));
    // Phase 7cw: stack-as-resource on top of docker compose v2 plugin.
    reg.register(Box::new(compose::DockerComposeProvider::new()));
    // Phase 7cx: pluggable DNS-record backend (Cloudflare ships in
    // 7cx; Route53 / others plug in via the same trait later).
    reg.register(Box::new(dns::DnsRecordProvider::new()));
    // Phase 7cy: ACMEv2 / Let's Encrypt cert issue+renew via lego.
    reg.register(Box::new(acme::AcmeCertProvider::new()));
    reg.register(Box::new(nginx::NginxProvider::new()));
    reg.register(Box::new(cron::CronProvider::new()));
    // Phase 7bz: first dedicated network primitive.
    reg.register(Box::new(firewall::FirewallProvider::new()));
    // Phase 7ca: active health check as asserted invariant.
    reg.register(Box::new(monitoring::MonitoringCheckProvider::new()));
    // Phase 7cb: kernel parameter management.
    reg.register(Box::new(sysctl::SysctlProvider::new()));
}
