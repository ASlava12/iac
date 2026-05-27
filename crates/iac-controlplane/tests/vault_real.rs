// Phase 7cz.16: integration tests are compiled as their own crates, so the
// crate-root #[cfg_attr(test, allow(...))] does not reach here. Add it locally.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Phase 7am: real Vault integration test for `VaultResolver`.
//!
//! Spins `hashicorp/vault:1.18` in dev mode, writes a KV-v2 secret, then
//! resolves it through `VaultResolver`. Skipped unless
//! `IAC_VAULT_INTEGRATION=1` AND the local Docker daemon is reachable.
//!
//! Vault dev mode auto-mounts a KV-v2 engine at `secret/`, so the operator
//! path is `secret/data/<key>`. We pin a fixed root token so the test config
//! is self-contained.

use iac_controlplane::secrets::VaultResolver;
use std::process::Command;
use std::time::{Duration, Instant};

const ROOT_TOKEN: &str = "iac-test-root-token";

fn integration_enabled() -> bool {
    std::env::var("IAC_VAULT_INTEGRATION").as_deref() == Ok("1")
}

fn docker_reachable() -> bool {
    Command::new("docker")
        .args(["info"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

struct VaultContainer {
    name: String,
    host_port: u16,
}

impl VaultContainer {
    fn start() -> Self {
        let name = format!("iac-vault-test-{}", std::process::id());
        let _ = Command::new("docker").args(["rm", "-f", &name]).output();

        let out = Command::new("docker")
            .args([
                "run",
                "-d",
                "--rm",
                "--name",
                &name,
                "--cap-add=IPC_LOCK",
                "-e",
                &format!("VAULT_DEV_ROOT_TOKEN_ID={ROOT_TOKEN}"),
                "-e",
                "VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200",
                "-p",
                "127.0.0.1::8200",
                "hashicorp/vault:1.18",
            ])
            .output()
            .expect("docker run vault");
        if !out.status.success() {
            panic!(
                "docker run failed: {}",
                String::from_utf8_lossy(&out.stderr)
            );
        }

        let port_out = Command::new("docker")
            .args(["port", &name, "8200/tcp"])
            .output()
            .expect("docker port");
        let port_str = String::from_utf8_lossy(&port_out.stdout);
        let host_port = port_str
            .lines()
            .find_map(|line| line.rsplit(':').next().and_then(|s| s.trim().parse().ok()))
            .unwrap_or_else(|| panic!("could not parse `docker port`: {port_str:?}"));

        Self { name, host_port }
    }

    fn addr(&self) -> String {
        format!("http://127.0.0.1:{}", self.host_port)
    }

    async fn wait_ready(&self, client: &reqwest::Client) {
        let deadline = Instant::now() + Duration::from_secs(30);
        let url = format!("{}/v1/sys/health", self.addr());
        while Instant::now() < deadline {
            if let Ok(resp) = client.get(&url).send().await
                && resp.status().is_success()
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        panic!("vault {} did not become ready within 30s", self.name);
    }

    async fn write_kv2(&self, client: &reqwest::Client, path: &str, body: serde_json::Value) {
        let url = format!("{}/v1/{}", self.addr(), path);
        let resp = client
            .post(&url)
            .header("X-Vault-Token", ROOT_TOKEN)
            .json(&serde_json::json!({ "data": body }))
            .send()
            .await
            .expect("vault write request");
        assert!(
            resp.status().is_success(),
            "vault write failed: {} {}",
            resp.status(),
            resp.text().await.unwrap_or_default()
        );
    }
}

impl Drop for VaultContainer {
    fn drop(&mut self) {
        let _ = Command::new("docker")
            .args(["rm", "-f", &self.name])
            .output();
    }
}

#[tokio::test]
async fn vault_round_trip_resolves_kv_v2_secret() {
    if !integration_enabled() || !docker_reachable() {
        eprintln!("skipping: set IAC_VAULT_INTEGRATION=1 and start Docker");
        return;
    }

    let vault = VaultContainer::start();
    let cli = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    vault.wait_ready(&cli).await;

    vault
        .write_kv2(
            &cli,
            "secret/data/myapp/db",
            serde_json::json!({
                "username": "iac",
                "password": "topsecret",
            }),
        )
        .await;

    // Phase 7cs.1: VaultResolver::new refuses plain http:// (Vault
    // token leaks otherwise). The dockerized Vault we spin up here
    // listens on http; use the test-only constructor.
    let resolver =
        VaultResolver::new_allow_insecure(vault.addr(), ROOT_TOKEN).expect("build resolver");

    let pw = resolver
        .resolve("secret/data/myapp/db", Some("password"))
        .await
        .expect("resolve password");
    assert_eq!(pw, "topsecret");

    let user = resolver
        .resolve("secret/data/myapp/db", Some("username"))
        .await
        .expect("resolve username");
    assert_eq!(user, "iac");

    let err = resolver
        .resolve("secret/data/myapp/db", Some("nope"))
        .await
        .unwrap_err();
    let msg = format!("{err:?}");
    assert!(
        msg.contains("nope"),
        "missing-field error should name the field: {msg}"
    );

    let err = resolver
        .resolve("secret/data/missing", Some("password"))
        .await
        .unwrap_err();
    let msg = format!("{err:?}");
    assert!(
        msg.contains("404") || msg.contains("HTTP"),
        "missing-path error should mention HTTP status: {msg}"
    );

    drop(vault);
}
