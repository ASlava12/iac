//! Push-mode client for the control-plane.
//!
//! The agent registers once and persists its `(agent_id, token)` to a 0600
//! file. Each cycle it pushes observations + drift + a heartbeat.
//!
//! Phase 2a started on plain HTTP with bearer tokens; Phase 7ak added
//! TLS + optional mTLS via `crate::config::AgentTlsConfig`. The
//! [`build_http_client`] helper wires the rustls-backed reqwest
//! client with the configured CA bundle + client cert/key.

use anyhow::{Context, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use iac_core::protocol::v1::{
    canonical_assignment_message, AgentHealth, AssignmentEnvelope, AssignmentList,
    AssignmentResultRequest, DesiredStateBatch, DesiredStateItem, DriftBatch, DriftItem,
    HeartbeatRequest, ObservationBatch, ObservationItem, RegisterRequest, RegisterResponse,
    SigningPubkeyBundle,
};
use iac_core::ResourceId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;

/// Phase 7cf: one entry in the agent's pinned set of accepted server
/// signing pubkeys. The agent verifies each `AssignmentEnvelope` by
/// looking up its `key_id` in this set — multi-key allows the server
/// to rotate (Phase 7ce) without locking out agents pinned to the old
/// key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPubkey {
    pub key_id: String,
    /// Base64-encoded raw 32-byte Ed25519 public key.
    pub public_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Identity {
    pub agent_id: String,
    pub token: String,
    pub server_url: String,
    pub registered_at: String,
    /// Phase 7cf: pinned set of accepted server signing pubkeys.
    /// On first contact the agent fetches `/v1/signing-keys` and pins
    /// the full bundle. On reconnect it re-fetches and replaces this
    /// set, but only if the new bundle has at least one key in common
    /// with the existing pinned set — no overlap means the server
    /// identity has rolled (or the connection is being MITM'd) and
    /// the agent refuses to update silently.
    ///
    /// Empty Vec means "not yet pinned" (first connect). Single-key
    /// pre-7cf identity files are auto-migrated on load.
    #[serde(default)]
    pub server_pubkeys: Vec<ServerPubkey>,
    /// Pre-7cf legacy fields. Kept on disk so a roll-back to an
    /// older agent version still works during the upgrade window.
    /// New code should consume `server_pubkeys` instead.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_key_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_public_key: Option<String>,
    /// Phase 7cd: token expiry in ISO 8601 UTC. `None` = grandfathered
    /// token (server has no TTL configured); rotation skipped.
    /// `Some(...)` = agent must rotate before this deadline via
    /// `POST /v1/agents/{id}/rotate-token`. Cached here so the agent
    /// runtime can decide when to rotate without round-tripping.
    #[serde(default)]
    pub token_expires_at: Option<String>,
}

impl Identity {
    /// Phase 7cf: migrate pre-7cf single-key identity to the new
    /// pubkey set. Run-once: if `server_pubkeys` is empty but legacy
    /// fields are populated, copy them in. After this, the legacy
    /// fields stay on disk until the next persist (which also keeps
    /// them as a roll-back safety net for the active key).
    fn migrate_legacy_pubkey(&mut self) {
        if self.server_pubkeys.is_empty()
            && let (Some(id), Some(pk)) = (
                self.server_key_id.as_ref(),
                self.server_public_key.as_ref(),
            ) {
                self.server_pubkeys.push(ServerPubkey {
                    key_id: id.clone(),
                    public_key: pk.clone(),
                });
            }
    }
}

#[derive(Debug, Clone)]
pub struct Client {
    http: reqwest::Client,
    base_url: String,
    identity: Identity,
    /// Phase 7cf: compiled verifier set keyed by `key_id`. Built from
    /// `identity.server_pubkeys` on load and rebuilt after every
    /// `refresh_signing_keys`. Empty until the first successful
    /// bundle fetch.
    verifiers: HashMap<String, VerifyingKey>,
}

impl Client {
    /// Either load an existing identity from disk or register a fresh agent
    /// against `server_url` and persist credentials to `identity_file`.
    /// On first connect (or whenever the cached pubkey is missing) the agent
    /// fetches the server's signing public key and pins it in the identity
    /// file. Mismatch on subsequent fetches is fatal.
    pub async fn connect(
        server_url: &str,
        identity_file: &Path,
        register: RegisterRequest,
    ) -> Result<Self> {
        Self::connect_with_tls(
            server_url,
            identity_file,
            register,
            &crate::config::AgentTlsConfig::default(),
        )
        .await
    }

    /// Phase 7ak: like [`Self::connect`] but lets the caller wire
    /// a CA-bundle + client cert/key into the underlying reqwest
    /// client. Used by the agent's run loop when the operator has
    /// configured `[tls]` in the agent config; tests use this
    /// directly to point at a test-CA-issued server.
    pub async fn connect_with_tls(
        server_url: &str,
        identity_file: &Path,
        register: RegisterRequest,
        tls: &crate::config::AgentTlsConfig,
    ) -> Result<Self> {
        let http = build_http_client(tls)?;

        let mut identity = if identity_file.exists() {
            let text = std::fs::read_to_string(identity_file)
                .with_context(|| format!("reading identity file {}", identity_file.display()))?;
            let mut id: Identity = serde_json::from_str(&text)
                .with_context(|| format!("parsing identity file {}", identity_file.display()))?;
            // Phase 7cf: forward-migrate pre-7cf identity files on load.
            id.migrate_legacy_pubkey();
            id
        } else {
            let resp = http
                .post(format!("{server_url}/v1/agents/register"))
                .json(&register)
                .send()
                .await
                .context("registering with control-plane")?;
            let status = resp.status();
            if !status.is_success() {
                let body = resp.text().await.unwrap_or_default();
                anyhow::bail!("register failed: {status}: {body}");
            }
            let creds: RegisterResponse = resp.json().await.context("decoding register response")?;
            let id = Identity {
                agent_id: creds.agent_id,
                token: creds.token,
                server_url: server_url.trim_end_matches('/').to_string(),
                registered_at: jiff::Timestamp::now().to_string(),
                server_pubkeys: Vec::new(),
                server_key_id: None,
                server_public_key: None,
                token_expires_at: creds.expires_at,
            };
            persist_identity(identity_file, &id)?;
            id
        };

        let base_url = server_url.trim_end_matches('/').to_string();

        // Phase 7cf: fetch the *bundle* of accepted keys. On first
        // contact pin the whole set. On reconnect, require at least
        // one overlap with the existing pinned set — that's our TOFU
        // anchor for "this is still the same server." No overlap is
        // fatal (server identity changed or active MITM).
        let bundle = fetch_signing_bundle(&http, &base_url)
            .await
            .context("fetching server signing bundle")?;
        if identity.server_pubkeys.is_empty() {
            // First contact — pin every key in the bundle.
            identity.server_pubkeys = bundle
                .keys
                .iter()
                .map(|k| ServerPubkey {
                    key_id: k.key_id.clone(),
                    public_key: k.public_key.clone(),
                })
                .collect();
            // Keep the legacy duo populated with the *active* key so
            // any older agent code reading this file still works.
            identity.server_key_id = Some(bundle.active_key_id.clone());
            identity.server_public_key = bundle
                .keys
                .iter()
                .find(|k| k.key_id == bundle.active_key_id)
                .map(|k| k.public_key.clone());
            persist_identity(identity_file, &identity)?;
            tracing::info!(
                active_key_id = %bundle.active_key_id,
                pinned_count = identity.server_pubkeys.len(),
                "pinned server signing key set on first contact"
            );
        } else {
            let pinned_ids: std::collections::HashSet<&str> = identity
                .server_pubkeys
                .iter()
                .map(|k| k.key_id.as_str())
                .collect();
            let overlap = bundle
                .keys
                .iter()
                .any(|k| pinned_ids.contains(k.key_id.as_str()));
            if !overlap {
                anyhow::bail!(
                    "server signing bundle has no overlap with pinned keys — \
                     refusing to update silently. If the rotation was intended, \
                     clear `server_pubkeys` in {} after manual verification",
                    identity_file.display()
                );
            }
            // Verify pubkey content for any pinned key the server still
            // advertises — catches a key_id-reuse swap.
            let by_id: std::collections::HashMap<&str, &str> = bundle
                .keys
                .iter()
                .map(|k| (k.key_id.as_str(), k.public_key.as_str()))
                .collect();
            for pinned in &identity.server_pubkeys {
                if let Some(srv_pk) = by_id.get(pinned.key_id.as_str())
                    && *srv_pk != pinned.public_key.as_str() {
                        anyhow::bail!(
                            "pinned key {} pubkey diverged from server — refusing",
                            pinned.key_id
                        );
                    }
            }
            // Replace pinned set with the server's authoritative view.
            identity.server_pubkeys = bundle
                .keys
                .iter()
                .map(|k| ServerPubkey {
                    key_id: k.key_id.clone(),
                    public_key: k.public_key.clone(),
                })
                .collect();
            identity.server_key_id = Some(bundle.active_key_id.clone());
            identity.server_public_key = bundle
                .keys
                .iter()
                .find(|k| k.key_id == bundle.active_key_id)
                .map(|k| k.public_key.clone());
            persist_identity(identity_file, &identity)?;
        }

        let verifiers = build_verifier_set(&identity)?;
        Ok(Self { http, base_url, identity, verifiers })
    }

    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    /// Phase 7cd: how soon (in seconds) until this token expires.
    /// `None` = grandfathered (no expiry). `Some(secs)` = positive
    /// time-to-live; `Some(0)` or `Some(<0 seen as 0)` = already
    /// expired (caller should re-register, not rotate).
    pub fn token_seconds_until_expiry(&self) -> Option<i64> {
        let exp = self.identity.token_expires_at.as_deref()?;
        let exp_ts: jiff::Timestamp = exp.parse().ok()?;
        let now_secs = jiff::Timestamp::now().as_second();
        Some((exp_ts.as_second() - now_secs).max(0))
    }

    /// Phase 7cd: rotate the bearer token. Calls
    /// `POST /v1/agents/{id}/rotate-token` with the current token,
    /// receives a new one + new expiry, persists to the on-disk
    /// identity file, and updates this client's in-memory state.
    /// On any error the in-memory and on-disk state remain unchanged
    /// — partial rotations don't leave the agent stuck without a
    /// usable token.
    pub async fn rotate_token(&mut self, identity_file: &Path) -> Result<()> {
        let url = format!(
            "{}/v1/agents/{}/rotate-token",
            self.base_url, self.identity.agent_id
        );
        let resp = self
            .http
            .post(url)
            .bearer_auth(&self.identity.token)
            .send()
            .await
            .context("rotating token")?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("rotate-token failed: {status}: {body}");
        }
        let creds: RegisterResponse =
            resp.json().await.context("decoding rotate response")?;
        // Build a candidate identity, persist it, then swap in. Order
        // matters: if persist fails (disk full, permissions changed),
        // we keep the old token in memory and on disk.
        let mut new_identity = self.identity.clone();
        new_identity.token = creds.token;
        new_identity.token_expires_at = creds.expires_at;
        persist_identity(identity_file, &new_identity)?;
        self.identity = new_identity;
        tracing::info!(
            agent_id = %self.identity.agent_id,
            expires_at = ?self.identity.token_expires_at,
            "rotated agent token"
        );
        Ok(())
    }

    /// Phase 7cd: rotate when within `safety_margin_secs` of expiry.
    /// `None` returned when no rotation was needed; `Some(())` when
    /// rotation succeeded. Errors propagate. Designed to be called
    /// periodically from the agent runtime loop.
    ///
    /// Recommended `safety_margin_secs`: TTL/3 — rotation has a
    /// generous window to retry on transient network failures
    /// before the token actually expires.
    pub async fn rotate_if_needed(
        &mut self,
        identity_file: &Path,
        safety_margin_secs: i64,
    ) -> Result<Option<()>> {
        let Some(remaining) = self.token_seconds_until_expiry() else {
            // Grandfathered token (no expiry) — never rotate.
            return Ok(None);
        };
        if remaining > safety_margin_secs {
            return Ok(None);
        }
        self.rotate_token(identity_file).await?;
        Ok(Some(()))
    }

    pub async fn push_observations(&self, items: Vec<ObservationItem>) -> Result<u32> {
        if items.is_empty() {
            return Ok(0);
        }
        let url = format!(
            "{}/v1/agents/{}/observations",
            self.base_url, self.identity.agent_id
        );
        let resp = self
            .http
            .post(url)
            .bearer_auth(&self.identity.token)
            .json(&ObservationBatch { items })
            .send()
            .await
            .context("pushing observations")?;
        check_ok(resp).await?;
        Ok(0)
    }

    pub async fn push_drift(&self, items: Vec<DriftItem>) -> Result<u32> {
        let url = format!(
            "{}/v1/agents/{}/drift",
            self.base_url, self.identity.agent_id
        );
        let resp = self
            .http
            .post(url)
            .bearer_auth(&self.identity.token)
            .json(&DriftBatch { items })
            .send()
            .await
            .context("pushing drift")?;
        check_ok(resp).await?;
        Ok(0)
    }

    /// Pull pending assignments. Each envelope is verified against the
    /// pinned server public key — any tampered or unsigned envelope is
    /// rejected with an error so the caller sees the failure rather than
    /// silently applying compromised work.
    pub async fn fetch_assignments(&self) -> Result<Vec<AssignmentEnvelope>> {
        let url = format!(
            "{}/v1/agents/{}/assignments",
            self.base_url, self.identity.agent_id
        );
        let resp = self
            .http
            .get(url)
            .bearer_auth(&self.identity.token)
            .send()
            .await
            .context("fetching assignments")?;
        check_ok_status(&resp)?;
        let list: AssignmentList = resp.json().await.context("decoding assignment list")?;
        for env in &list.items {
            self.verify_envelope(env).with_context(|| {
                format!("verifying signature on assignment {}", env.assignment_id)
            })?;
        }
        Ok(list.items)
    }

    fn verify_envelope(&self, env: &AssignmentEnvelope) -> Result<()> {
        if self.verifiers.is_empty() {
            anyhow::bail!("agent has no pinned server pubkeys — can't verify");
        }
        let verifier = self.verifiers.get(&env.key_id).with_context(|| {
            format!(
                "envelope key_id {} not in pinned set ({} keys pinned)",
                env.key_id,
                self.verifiers.len()
            )
        })?;
        if let Some(max_age) = max_envelope_age_secs() {
            check_envelope_freshness(
                jiff::Timestamp::now(),
                &env.created_at,
                max_age,
                FUTURE_GRACE_SECS,
            )?;
        }
        let payload_json = serde_json::to_vec(&env.payload)?;
        let msg = canonical_assignment_message(
            &self.identity.agent_id,
            &env.assignment_id,
            &env.operation_id,
            &env.created_at,
            &payload_json,
        );
        let sig_bytes = B64
            .decode(&env.signature)
            .context("decoding base64 signature")?;
        let signature =
            Signature::from_slice(&sig_bytes).context("constructing Signature from bytes")?;
        verifier
            .verify(&msg, &signature)
            .context("Ed25519 signature verification failed")?;
        Ok(())
    }

    /// Phase 7cf: refresh the pinned pubkey set from the server's
    /// `/v1/signing-keys` bundle. Idempotent — safe to call on every
    /// poll. Same overlap rule as `connect`: at least one pinned key
    /// must remain in the new bundle, otherwise this errors out
    /// without updating state. Persists to disk on success.
    pub async fn refresh_signing_keys(&mut self, identity_file: &Path) -> Result<()> {
        let bundle = fetch_signing_bundle(&self.http, &self.base_url)
            .await
            .context("fetching server signing bundle for refresh")?;
        let pinned_ids: std::collections::HashSet<&str> = self
            .identity
            .server_pubkeys
            .iter()
            .map(|k| k.key_id.as_str())
            .collect();
        let overlap = bundle
            .keys
            .iter()
            .any(|k| pinned_ids.contains(k.key_id.as_str()));
        if !overlap {
            anyhow::bail!(
                "refresh: server bundle has no overlap with pinned keys; \
                 not updating"
            );
        }
        let by_id: std::collections::HashMap<&str, &str> = bundle
            .keys
            .iter()
            .map(|k| (k.key_id.as_str(), k.public_key.as_str()))
            .collect();
        for pinned in &self.identity.server_pubkeys {
            if let Some(srv_pk) = by_id.get(pinned.key_id.as_str())
                && *srv_pk != pinned.public_key.as_str() {
                    anyhow::bail!(
                        "refresh: pinned key {} pubkey diverged from server",
                        pinned.key_id
                    );
                }
        }
        let mut new_identity = self.identity.clone();
        new_identity.server_pubkeys = bundle
            .keys
            .iter()
            .map(|k| ServerPubkey {
                key_id: k.key_id.clone(),
                public_key: k.public_key.clone(),
            })
            .collect();
        new_identity.server_key_id = Some(bundle.active_key_id.clone());
        new_identity.server_public_key = bundle
            .keys
            .iter()
            .find(|k| k.key_id == bundle.active_key_id)
            .map(|k| k.public_key.clone());
        persist_identity(identity_file, &new_identity)?;
        let verifiers = build_verifier_set(&new_identity)?;
        self.identity = new_identity;
        self.verifiers = verifiers;
        Ok(())
    }

    /// Fetch the latest desired-state watch list. Returns an empty list if
    /// the server has nothing scoped to this agent.
    pub async fn fetch_desired_state(&self) -> Result<Vec<DesiredStateItem>> {
        let url = format!(
            "{}/v1/agents/{}/desired-state",
            self.base_url, self.identity.agent_id
        );
        let resp = self
            .http
            .get(url)
            .bearer_auth(&self.identity.token)
            .send()
            .await
            .context("fetching desired-state")?;
        check_ok_status(&resp)?;
        let batch: DesiredStateBatch = resp.json().await.context("decoding desired-state")?;
        Ok(batch.items)
    }

    pub async fn report_assignment(
        &self,
        assignment_id: &str,
        result: AssignmentResultRequest,
    ) -> Result<()> {
        let url = format!(
            "{}/v1/agents/{}/assignments/{}/result",
            self.base_url, self.identity.agent_id, assignment_id
        );
        let resp = self
            .http
            .post(url)
            .bearer_auth(&self.identity.token)
            .json(&result)
            .send()
            .await
            .context("reporting assignment")?;
        check_ok(resp).await?;
        Ok(())
    }

    pub async fn heartbeat(
        &self,
        status: AgentHealth,
        managed: u32,
        open_drifts: u32,
        last_observe_at: Option<String>,
    ) -> Result<()> {
        let url = format!(
            "{}/v1/agents/{}/heartbeat",
            self.base_url, self.identity.agent_id
        );
        let resp = self
            .http
            .post(url)
            .bearer_auth(&self.identity.token)
            .json(&HeartbeatRequest { status, managed, open_drifts, last_observe_at })
            .send()
            .await
            .context("sending heartbeat")?;
        check_ok(resp).await?;
        Ok(())
    }
}

async fn check_ok(resp: reqwest::Response) -> Result<()> {
    let status = resp.status();
    if status.is_success() {
        return Ok(());
    }
    let body = resp.text().await.unwrap_or_default();
    anyhow::bail!("control-plane returned {status}: {body}")
}

fn check_ok_status(resp: &reqwest::Response) -> Result<()> {
    let s = resp.status();
    if s.is_success() {
        Ok(())
    } else {
        anyhow::bail!("control-plane returned {s}")
    }
}

/// Phase 7cf: fetch the full accepted-keys bundle. Replaces the
/// single-key `/v1/signing-pubkey` for multi-key-aware agents.
/// Older endpoint is still served (backwards compat) but unused
/// by this client.
async fn fetch_signing_bundle(
    http: &reqwest::Client,
    base_url: &str,
) -> Result<SigningPubkeyBundle> {
    let resp = http
        .get(format!("{base_url}/v1/signing-keys"))
        .send()
        .await
        .context("GET /v1/signing-keys")?;
    check_ok_status(&resp)?;
    let bundle: SigningPubkeyBundle = resp.json().await.context("decoding signing bundle")?;
    if bundle.keys.is_empty() {
        anyhow::bail!("server returned empty signing bundle");
    }
    if !bundle.keys.iter().any(|k| k.key_id == bundle.active_key_id) {
        anyhow::bail!(
            "server bundle is inconsistent: active_key_id {} not in keys",
            bundle.active_key_id
        );
    }
    Ok(bundle)
}

/// Phase 7dh.12: how far into the future an envelope's `created_at`
/// is allowed to be relative to the agent's wall clock. Tolerates
/// small NTP-scale skew (<= 5 min) between server and agent without
/// dropping legitimate work. Larger skew (server clock drifting hours
/// ahead, or a forged envelope) is treated as a replay attempt.
const FUTURE_GRACE_SECS: i64 = 300;

/// Phase 7dh.12: pure-function age check, extracted from
/// `verify_envelope` so it can be tested with a deterministic `now`
/// instead of the system clock. Returns `Ok(())` when `created_at` is
/// inside the symmetric window `[now - max_age, now + future_grace]`
/// and an `Err` describing the failure otherwise.
///
/// Errors:
/// * unparseable `created_at` → "refusing to verify"
/// * `created_at` older than `max_age` seconds → too-old reject
/// * `created_at` more than `future_grace` seconds in the future →
///   future-dated reject
fn check_envelope_freshness(
    now: jiff::Timestamp,
    created_at: &str,
    max_age: u64,
    future_grace: i64,
) -> Result<()> {
    let created = match created_at.parse::<jiff::Timestamp>() {
        Ok(t) => t,
        Err(_) => {
            anyhow::bail!(
                "envelope created_at {created_at:?} unparseable — refusing to verify"
            );
        }
    };
    let age = now.as_second().saturating_sub(created.as_second());
    if age > max_age as i64 {
        anyhow::bail!(
            "envelope created_at {created_at} is {age}s old (cap {max_age}s) — replay rejected"
        );
    }
    if age < -future_grace {
        anyhow::bail!(
            "envelope created_at {created_at} is {}s in the future (grace {future_grace}s) — replay rejected",
            -age
        );
    }
    Ok(())
}

/// Phase 7cf: compile the agent's pinned set into a `key_id` →
/// `VerifyingKey` map for O(1) lookup during envelope verification.
/// Phase 7cq.2: maximum age (in seconds) the agent will accept on a
/// signed envelope. `Some(0)` = reject everything (test-only).
/// `None` = no age check (matches pre-7cq.2 behavior; the env var
/// `IAC_AGENT_DISABLE_AGE_CHECK=1` selects this for ops who actually
/// need it). Default is 24 hours — long enough for reasonable agent
/// pull cadences, short enough that a stolen envelope from yesterday
/// is rejected today.
///
/// Phase 7dh.10 (audit fix C3): when the disable flag is observed we
/// emit a WARN once per process so the operator (and anyone reading
/// the logs after the fact) knows replay protection is off. Without
/// this an `IAC_AGENT_DISABLE_AGE_CHECK=1` set during a "we'll fix it
/// later" deploy could persist silently.
fn max_envelope_age_secs() -> Option<u64> {
    if std::env::var("IAC_AGENT_DISABLE_AGE_CHECK").ok().as_deref() == Some("1") {
        static WARNED: std::sync::Once = std::sync::Once::new();
        WARNED.call_once(|| {
            tracing::warn!(
                "IAC_AGENT_DISABLE_AGE_CHECK=1 — envelope replay protection is DISABLED; \
                 a stolen signed envelope can be replayed indefinitely until the signing \
                 key is rotated. Unset this variable in production."
            );
        });
        return None;
    }
    std::env::var("IAC_AGENT_MAX_ENVELOPE_AGE_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .or(Some(24 * 60 * 60))
}

fn build_verifier_set(identity: &Identity) -> Result<HashMap<String, VerifyingKey>> {
    let mut out = HashMap::with_capacity(identity.server_pubkeys.len());
    for entry in &identity.server_pubkeys {
        let bytes = B64
            .decode(&entry.public_key)
            .with_context(|| format!("decoding pubkey for {}", entry.key_id))?;
        if bytes.len() != 32 {
            anyhow::bail!(
                "pubkey for {} is {} bytes, expected 32",
                entry.key_id,
                bytes.len()
            );
        }
        let mut buf = [0u8; 32];
        buf.copy_from_slice(&bytes);
        let vk = VerifyingKey::from_bytes(&buf)
            .with_context(|| format!("constructing VerifyingKey for {}", entry.key_id))?;
        out.insert(entry.key_id.clone(), vk);
    }
    Ok(out)
}

fn persist_identity(path: &Path, id: &Identity) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(id)?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating identity dir {}", parent.display()))?;
    }
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, &bytes)?;

    // 0600 — secrets in this file
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
    std::fs::rename(&tmp, path)
        .with_context(|| format!("renaming identity file {}", path.display()))?;
    Ok(())
}

/// Convert a row from the local agent store into a wire `DriftItem`. Returns
/// `None` if the resource id can't be parsed.
pub fn drift_row_to_item(row: &crate::store::DriftRow) -> Option<DriftItem> {
    let rid = ResourceId::parse(&row.resource_id)?;
    Some(DriftItem {
        resource_id: rid,
        severity: row.severity.clone(),
        detected_at: row.detected_at.clone(),
        diff: row.diff.clone(),
    })
}

/// Phase 7ak: build the reqwest client with the configured TLS
/// settings. When `ca_file` is set, the CA bundle is added to the
/// trust store so a self-signed test PKI works without disabling
/// verification. When `client_cert_file` + `client_key_file` are
/// both set, the cert is presented during the TLS handshake (mTLS).
///
/// Empty config falls back to the default reqwest client (system
/// trust store, no client cert) — keeps existing plain-HTTP and
/// "trust system roots" deployments working.
pub fn build_http_client(tls: &crate::config::AgentTlsConfig) -> Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .user_agent(concat!("iac-agent/", env!("CARGO_PKG_VERSION")));

    if let Some(ca_path) = &tls.ca_file {
        let bytes = std::fs::read(ca_path)
            .with_context(|| format!("reading CA file {}", ca_path.display()))?;
        // The PEM file may carry one or many certs; reqwest takes
        // them as separate `Certificate` instances.
        let mut reader = std::io::BufReader::new(&bytes[..]);
        for der in rustls_pemfile::certs(&mut reader)
            .collect::<Result<Vec<_>, _>>()
            .with_context(|| format!("parsing CA file {}", ca_path.display()))?
        {
            let cert = reqwest::Certificate::from_der(&der)
                .with_context(|| format!("loading cert from {}", ca_path.display()))?;
            builder = builder.add_root_certificate(cert);
        }
    }

    if tls.has_client_cert() {
        // SAFETY: `has_client_cert()` returns true only when both
        // fields are `Some`. Phase 7cz.16 keeps the expect for clarity
        // but tags it for clippy.
        #[allow(clippy::expect_used)]
        let cert_path = tls.client_cert_file.as_deref().expect("checked above");
        #[allow(clippy::expect_used)]
        let key_path = tls.client_key_file.as_deref().expect("checked above");
        let cert_bytes = std::fs::read(cert_path)
            .with_context(|| format!("reading client cert {}", cert_path.display()))?;
        let key_bytes = std::fs::read(key_path)
            .with_context(|| format!("reading client key {}", key_path.display()))?;
        // reqwest's Identity::from_pem expects cert + key concatenated
        // in a single PEM blob; produce that here.
        let mut combined = cert_bytes;
        combined.extend_from_slice(b"\n");
        combined.extend_from_slice(&key_bytes);
        let identity = reqwest::Identity::from_pem(&combined)
            .context("building reqwest Identity from client cert + key")?;
        builder = builder.identity(identity);
    }

    builder.build().context("build http client")
}

#[cfg(test)]
mod tests {
    //! F5 (Phase 9 deferred → done locally): time-skew handling on the
    //! envelope freshness check. The window must be symmetric and
    //! deterministic across the agent fleet — every operator running
    //! mismatched clocks (NTP not yet converged on a fresh boot, or a
    //! genuinely-skewed VM) reaches these branches in production. The
    //! tests use a fixed `now` so the assertions don't drift with the
    //! system clock.
    use super::*;

    /// Helper: build a Timestamp at a known offset from `now`.
    fn ts(now: jiff::Timestamp, offset_secs: i64) -> String {
        now.checked_add(jiff::Span::new().seconds(offset_secs))
            .unwrap()
            .to_string()
    }

    fn fixed_now() -> jiff::Timestamp {
        // 2026-05-05T12:00:00Z — pinned so test traces are easy to
        // reason about regardless of what the host clock says.
        "2026-05-05T12:00:00Z".parse().unwrap()
    }

    const MAX_AGE: u64 = 24 * 60 * 60; // 24h, matches the production default
    const GRACE: i64 = FUTURE_GRACE_SECS;

    // ---- accept paths ----

    #[test]
    fn accepts_envelope_at_exactly_now() {
        let now = fixed_now();
        check_envelope_freshness(now, &ts(now, 0), MAX_AGE, GRACE).unwrap();
    }

    #[test]
    fn accepts_envelope_one_second_old() {
        let now = fixed_now();
        check_envelope_freshness(now, &ts(now, -1), MAX_AGE, GRACE).unwrap();
    }

    #[test]
    fn accepts_envelope_within_future_grace() {
        // Server clock 4 minutes ahead of agent clock — common after a
        // VM resume before NTP catches up. Should pass.
        let now = fixed_now();
        check_envelope_freshness(now, &ts(now, 4 * 60), MAX_AGE, GRACE).unwrap();
    }

    #[test]
    fn accepts_envelope_at_max_age_boundary() {
        // Exactly at the 24h boundary — rule is `> max_age` rejects,
        // so equal must pass.
        let now = fixed_now();
        check_envelope_freshness(now, &ts(now, -(MAX_AGE as i64)), MAX_AGE, GRACE).unwrap();
    }

    #[test]
    fn accepts_envelope_at_future_grace_boundary() {
        // Exactly at the 5-min future grace — rule is `< -grace`
        // rejects, so `age == -grace` (i.e. exactly grace seconds
        // ahead) must pass.
        let now = fixed_now();
        check_envelope_freshness(now, &ts(now, GRACE), MAX_AGE, GRACE).unwrap();
    }

    // ---- reject paths ----

    #[test]
    fn rejects_envelope_older_than_max_age() {
        // 25 hours old — past the 24h replay window. The canonical
        // "stolen envelope from yesterday" scenario.
        let now = fixed_now();
        let err = check_envelope_freshness(now, &ts(now, -(25 * 60 * 60)), MAX_AGE, GRACE)
            .unwrap_err();
        assert!(err.to_string().contains("old"), "got: {err}");
        assert!(err.to_string().contains("replay rejected"));
    }

    #[test]
    fn rejects_envelope_one_second_past_max_age() {
        // Off-by-one regression test: max_age + 1 must reject.
        let now = fixed_now();
        let err =
            check_envelope_freshness(now, &ts(now, -(MAX_AGE as i64 + 1)), MAX_AGE, GRACE)
                .unwrap_err();
        assert!(err.to_string().contains("old"));
    }

    #[test]
    fn rejects_envelope_25h_in_the_future() {
        // F5 directly: agent's clock is 25 hours behind. Pre-7dh.12
        // this passed silently (negative `age`, `if age > max_age`
        // false, `if age < -GRACE` branch absent). Must reject now.
        let now = fixed_now();
        let err = check_envelope_freshness(now, &ts(now, 25 * 60 * 60), MAX_AGE, GRACE)
            .unwrap_err();
        assert!(err.to_string().contains("future"), "got: {err}");
        assert!(err.to_string().contains("replay rejected"));
    }

    #[test]
    fn rejects_envelope_one_second_past_future_grace() {
        // Off-by-one regression test for the future-side boundary.
        let now = fixed_now();
        let err = check_envelope_freshness(now, &ts(now, GRACE + 1), MAX_AGE, GRACE)
            .unwrap_err();
        assert!(err.to_string().contains("future"));
    }

    // ---- malformed input ----

    #[test]
    fn rejects_unparseable_created_at() {
        let err = check_envelope_freshness(fixed_now(), "not-a-timestamp", MAX_AGE, GRACE)
            .unwrap_err();
        assert!(err.to_string().contains("unparseable"));
    }

    #[test]
    fn rejects_empty_created_at() {
        let err = check_envelope_freshness(fixed_now(), "", MAX_AGE, GRACE).unwrap_err();
        assert!(err.to_string().contains("unparseable"));
    }

    // ---- edge cases on max_age = 0 (test-only mode) ----

    #[test]
    fn max_age_zero_rejects_anything_in_the_past() {
        // `max_age = 0` is the "reject everything" testing knob. A 1s-
        // old envelope must reject.
        let now = fixed_now();
        let err = check_envelope_freshness(now, &ts(now, -1), 0, GRACE).unwrap_err();
        assert!(err.to_string().contains("old"));
    }

    #[test]
    fn max_age_zero_still_accepts_envelopes_within_future_grace() {
        // Asymmetry by design: max_age=0 disallows past-dated, but the
        // future-grace window is independent (driven by `future_grace`).
        let now = fixed_now();
        check_envelope_freshness(now, &ts(now, 30), 0, GRACE).unwrap();
    }

    // ----- F4 (Phase 9 deferred → done locally): identity-persist
    // atomic-write semantics under a write failure. Disk-full / read-
    // only filesystem / quota-exceeded all surface the same way at
    // this layer (`std::fs::write` returns `Err`). The contract: the
    // existing identity.json must survive intact; a half-written
    // identity that would lose a token rotation is the failure mode
    // we're guarding against.
    use std::os::unix::fs::PermissionsExt;
    use tempfile::TempDir;

    fn synthetic_identity(token: &str) -> Identity {
        Identity {
            agent_id: "01TESTAGENTID".into(),
            token: token.into(),
            server_url: "https://example/".into(),
            registered_at: "2026-05-05T12:00:00Z".into(),
            server_pubkeys: vec![],
            server_key_id: None,
            server_public_key: None,
            token_expires_at: None,
        }
    }

    fn read_identity(path: &Path) -> Identity {
        let bytes = std::fs::read(path).unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[test]
    fn persist_identity_creates_file_on_first_write() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("identity.json");
        persist_identity(&path, &synthetic_identity("first")).unwrap();
        assert_eq!(read_identity(&path).token, "first");

        // The 0600-on-the-tempfile pattern means the final file is
        // 0600. Verifying so a future change that breaks the
        // permission step (which is silent if permissions match the
        // umask default) gets caught by this test.
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "identity must be 0600");
    }

    #[test]
    fn persist_identity_replaces_atomically_on_overwrite() {
        // The .tmp + rename pattern is the contract; this test asserts
        // we don't accidentally regress to "open + write" (which would
        // briefly truncate the file).
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("identity.json");
        persist_identity(&path, &synthetic_identity("v1")).unwrap();
        persist_identity(&path, &synthetic_identity("v2")).unwrap();
        assert_eq!(read_identity(&path).token, "v2");
        // No `.tmp` orphan should be left behind on the happy path.
        assert!(!path.with_extension("json.tmp").exists());
    }

    #[test]
    fn persist_identity_failure_preserves_prior_identity() {
        // F4 main case. Pre-load a valid identity; then make the
        // parent directory read-only so the next write to .tmp fails.
        // The original identity.json must remain readable and
        // unchanged — losing it would force a fresh re-registration
        // and break the tight "this agent IS this agent" guarantee.
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("identity.json");
        persist_identity(&path, &synthetic_identity("good")).unwrap();
        let canonical_bytes = std::fs::read(&path).unwrap();

        // 0o500 = read+execute, no write — `fs::write` to .tmp errors.
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o500))
            .unwrap();
        let result = persist_identity(&path, &synthetic_identity("rotated"));
        // Restore so the TempDir drop can clean up.
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
            .unwrap();

        if result.is_ok() {
            // DAC bypass (running as root) or a filesystem that
            // ignored chmod (some FUSE / overlay setups). The
            // failure-injection didn't fire; skip the assertions
            // since they wouldn't be exercising the path we mean.
            eprintln!(
                "persist_identity_failure_preserves_prior_identity: chmod 0500 didn't \
                 block the write; skipping (root or special FS?)"
            );
            return;
        }

        // The original file is untouched.
        assert_eq!(std::fs::read(&path).unwrap(), canonical_bytes);
        let still_loadable = read_identity(&path);
        assert_eq!(still_loadable.token, "good");
    }

    #[test]
    fn persist_identity_does_not_leak_tmp_when_rename_succeeds() {
        // Defensive: confirm the .tmp file does NOT remain after a
        // successful persist. Some Linux fs cleanup races could in
        // theory leave it; the rename target is the canonical path
        // so a leftover .tmp would mean rename copied instead of
        // moved (it doesn't, but the test pins the invariant).
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("identity.json");
        let tmp = path.with_extension("json.tmp");
        for token in ["a", "b", "c", "d", "e"] {
            persist_identity(&path, &synthetic_identity(token)).unwrap();
            assert!(!tmp.exists(), "leftover .tmp after persist of {token:?}");
        }
    }

}
