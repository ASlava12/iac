//! Phase 6f: per-user credential storage for the `iac` CLI.
//!
//! `iac login` writes a single JSON file at `~/.iac/credentials.json` (mode
//! `0600`) keyed by server URL. Subsequent commands that take `--server`
//! look up the saved token automatically when `IAC_ADMIN_TOKEN` is not set.
//!
//! Tokens are 24-hour bearer credentials handed out by `POST /v1/auth/login`.
//! When they expire the next call will get 401 and the operator should
//! re-run `iac login`. Phase 7+ will add silent refresh.

use anyhow::{Context, Result};
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

#[derive(Debug, Serialize, Deserialize)]
pub struct CredentialStore {
    #[serde(default = "default_version")]
    pub version: u32,
    /// Server URL (with `http(s)://`, no trailing slash) → entry.
    #[serde(default)]
    pub credentials: IndexMap<String, Entry>,
}

impl Default for CredentialStore {
    fn default() -> Self {
        Self { version: default_version(), credentials: IndexMap::new() }
    }
}

fn default_version() -> u32 {
    1
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entry {
    pub username: String,
    pub token: String,
    pub expires_at: String,
    pub saved_at: String,
    /// Roles returned by `/v1/auth/login`. Cached so `iac` can show them
    /// without a re-login round trip.
    #[serde(default)]
    pub roles: Vec<String>,
}

impl CredentialStore {
    pub fn load_default() -> Result<Self> {
        Self::load(&default_path()?)
    }

    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let bytes = fs::read(path)
            .with_context(|| format!("reading credentials {}", path.display()))?;
        let store: Self = serde_json::from_slice(&bytes)
            .with_context(|| format!("parsing credentials {}", path.display()))?;
        Ok(store)
    }

    pub fn save_default(&self) -> Result<()> {
        let path = default_path()?;
        self.save(&path)
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("creating credentials dir {}", parent.display()))?;
        }
        let bytes = serde_json::to_vec_pretty(self)?;
        let tmp = path.with_extension("json.tmp");
        fs::write(&tmp, &bytes)
            .with_context(|| format!("writing temp credentials {}", tmp.display()))?;
        fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))
            .with_context(|| format!("chmod 0600 {}", tmp.display()))?;
        fs::rename(&tmp, path)
            .with_context(|| format!("renaming credentials to {}", path.display()))?;
        Ok(())
    }

    pub fn lookup(&self, server_url: &str) -> Option<&Entry> {
        let key = normalize(server_url);
        self.credentials.get(&key)
    }

    pub fn upsert(&mut self, server_url: &str, entry: Entry) {
        self.credentials.insert(normalize(server_url), entry);
    }

    pub fn remove(&mut self, server_url: &str) -> Option<Entry> {
        self.credentials.shift_remove(&normalize(server_url))
    }
}

pub fn normalize(server_url: &str) -> String {
    server_url.trim_end_matches('/').to_string()
}

pub fn default_path() -> Result<PathBuf> {
    let home = std::env::var("HOME").context("HOME not set")?;
    Ok(PathBuf::from(home).join(".iac").join("credentials.json"))
}

/// Resolve a usable bearer token for `server_url`. Order:
///   1. `IAC_ADMIN_TOKEN` env var (legacy admin path).
///   2. Saved entry in credentials store.
///
/// If the saved entry's `expires_at` is within `REFRESH_WINDOW_SECS`,
/// transparently call `POST /v1/auth/refresh` to rotate. The refreshed
/// token + roles + expiry are written back to disk before returning.
/// On refresh failure (expired token, server down, …) the call falls
/// back to returning the stale token so callers get a clean 401 instead
/// of a confusing resolver-time error.
///
/// Skipped entirely for the env-var (legacy admin) path: that token has
/// no refresh semantics.
pub async fn resolve_admin_token_with_refresh(server_url: &str) -> Result<String> {
    resolve_admin_token_with_refresh_at(server_url, &default_path()?).await
}

/// Path-explicit variant. Production code calls
/// [`resolve_admin_token_with_refresh`]; tests pass an explicit path
/// so they don't have to mutate `HOME` (workspace lints forbid the
/// unsafe block that `std::env::set_var` requires on edition 2024).
pub async fn resolve_admin_token_with_refresh_at(
    server_url: &str,
    store_path: &Path,
) -> Result<String> {
    if let Ok(t) = std::env::var("IAC_ADMIN_TOKEN")
        && !t.is_empty() {
            return Ok(t);
        }
    let mut store = CredentialStore::load(store_path)?;
    let Some(entry) = store.lookup(server_url).cloned() else {
        anyhow::bail!(
            "no credentials for {server_url}: set IAC_ADMIN_TOKEN or run `iac login --server {server_url} --user <name>`"
        );
    };

    // Decide if we should refresh. Parse-failures fall through to the
    // "use the saved token as-is" path — better to make one network
    // round trip with a stale token than to error before any I/O.
    let now = jiff::Timestamp::now();
    let window = jiff::SignedDuration::from_secs(REFRESH_WINDOW_SECS);
    let needs_refresh = match entry.expires_at.parse::<jiff::Timestamp>() {
        Ok(exp) => exp.duration_since(now) < window,
        Err(_) => false,
    };
    if !needs_refresh {
        return Ok(entry.token);
    }

    // Refresh. Best-effort: on failure return the stale token so the
    // caller's request goes through and a clean 401 is the worst case.
    match try_refresh(server_url, &entry.token).await {
        Ok(refreshed) => {
            let new_entry = Entry {
                username: entry.username.clone(),
                token: refreshed.token.clone(),
                expires_at: refreshed.expires_at,
                saved_at: jiff::Timestamp::now().to_string(),
                roles: refreshed.roles,
            };
            store.upsert(server_url, new_entry);
            store.save(store_path)?;
            Ok(refreshed.token)
        }
        Err(_) => Ok(entry.token),
    }
}

/// Refresh window: rotate when the saved token has less than this much
/// validity remaining. 1 hour balances "don't burn refresh round trips
/// on short-lived CLI invocations" with "don't be the reason an
/// operator's automation runs into a 401 mid-pipeline."
const REFRESH_WINDOW_SECS: i64 = 60 * 60;

#[derive(serde::Deserialize)]
struct RefreshResponse {
    token: String,
    expires_at: String,
    roles: Vec<String>,
}

async fn try_refresh(server_url: &str, token: &str) -> Result<RefreshResponse> {
    let url = format!("{}/v1/auth/refresh", server_url.trim_end_matches('/'));
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()?;
    let resp = client.post(&url).bearer_auth(token).send().await?;
    if !resp.status().is_success() {
        anyhow::bail!("refresh returned status {}", resp.status());
    }
    let body: RefreshResponse = resp.json().await?;
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn entry(token: &str) -> Entry {
        Entry {
            username: "alice".into(),
            token: token.into(),
            expires_at: "2030-01-01T00:00:00Z".into(),
            saved_at: "2026-01-01T00:00:00Z".into(),
            roles: vec!["operator".into()],
        }
    }

    #[test]
    fn empty_store_round_trip() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("credentials.json");
        let store = CredentialStore::default();
        store.save(&path).unwrap();
        let loaded = CredentialStore::load(&path).unwrap();
        assert_eq!(loaded.credentials.len(), 0);

        // Mode 0600.
        use std::os::unix::fs::MetadataExt;
        let mode = fs::metadata(&path).unwrap().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn upsert_and_lookup() {
        let mut s = CredentialStore::default();
        s.upsert("http://server.example/", entry("t1"));
        assert_eq!(s.lookup("http://server.example").unwrap().token, "t1");
        // Trailing slash normalized.
        assert_eq!(s.lookup("http://server.example/").unwrap().token, "t1");
        // Different server: not present.
        assert!(s.lookup("http://other").is_none());
    }

    #[test]
    fn upsert_overwrites_existing_entry() {
        let mut s = CredentialStore::default();
        s.upsert("http://server", entry("t1"));
        s.upsert("http://server", entry("t2"));
        assert_eq!(s.lookup("http://server").unwrap().token, "t2");
    }

    #[test]
    fn remove_clears_entry() {
        let mut s = CredentialStore::default();
        s.upsert("http://server", entry("t1"));
        s.remove("http://server").unwrap();
        assert!(s.lookup("http://server").is_none());
    }

    #[test]
    fn nonexistent_path_loads_as_empty() {
        let dir = TempDir::new().unwrap();
        let store = CredentialStore::load(&dir.path().join("nope.json")).unwrap();
        assert!(store.credentials.is_empty());
    }

    #[test]
    fn save_then_load_preserves_entries() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("credentials.json");
        let mut s = CredentialStore::default();
        s.upsert("http://a", entry("ta"));
        s.upsert("http://b", entry("tb"));
        s.save(&path).unwrap();
        let loaded = CredentialStore::load(&path).unwrap();
        assert_eq!(loaded.lookup("http://a").unwrap().token, "ta");
        assert_eq!(loaded.lookup("http://b").unwrap().token, "tb");
    }

    fn save_to(path: &Path, server_url: &str, e: Entry) {
        let mut s = CredentialStore::default();
        s.upsert(server_url, e);
        s.save(path).unwrap();
    }

    /// Phase 7f: when the saved expiry is far in the future, the
    /// resolver must NOT make a network call. RFC5737 address +
    /// unreachable port 1 means a refresh attempt would hang or error;
    /// passing without timing out proves the fast path skipped it.
    #[tokio::test]
    async fn fresh_token_skips_refresh() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("credentials.json");
        save_to(
            &path,
            "http://203.0.113.1:1",
            Entry {
                username: "alice".into(),
                token: "fresh-token".into(),
                expires_at: "2099-01-01T00:00:00Z".into(),
                saved_at: "2026-01-01T00:00:00Z".into(),
                roles: vec!["operator".into()],
            },
        );

        let resolved = resolve_admin_token_with_refresh_at("http://203.0.113.1:1", &path)
            .await
            .unwrap();
        assert_eq!(resolved, "fresh-token");
    }

    /// When refresh fails (server unreachable), the resolver returns
    /// the saved (stale) token so the caller's request still happens
    /// and produces a clean 401 — better than failing at resolver time.
    #[tokio::test]
    async fn refresh_failure_falls_back_to_stale_token() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("credentials.json");
        save_to(
            &path,
            "http://203.0.113.1:1",
            Entry {
                username: "alice".into(),
                token: "stale-token".into(),
                expires_at: "2020-01-01T00:00:00Z".into(),
                saved_at: "2020-01-01T00:00:00Z".into(),
                roles: vec!["operator".into()],
            },
        );

        let resolved = resolve_admin_token_with_refresh_at("http://203.0.113.1:1", &path)
            .await
            .unwrap();
        assert_eq!(resolved, "stale-token");
    }

    /// Resolver bails when no entry is saved.
    #[tokio::test]
    async fn missing_entry_errors() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("nonexistent.json");
        let res = resolve_admin_token_with_refresh_at("http://203.0.113.1:1", &path).await;
        assert!(res.is_err());
        let msg = format!("{}", res.unwrap_err());
        assert!(msg.contains("no credentials"), "msg: {msg}");
    }

    /// Unparseable `expires_at` falls through to "use the saved token
    /// as-is" rather than blocking on a refresh attempt.
    #[tokio::test]
    async fn unparseable_expiry_skips_refresh() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("credentials.json");
        save_to(
            &path,
            "http://203.0.113.1:1",
            Entry {
                username: "alice".into(),
                token: "as-is-token".into(),
                expires_at: "not-a-real-timestamp".into(),
                saved_at: "2026-01-01T00:00:00Z".into(),
                roles: vec!["operator".into()],
            },
        );
        let resolved = resolve_admin_token_with_refresh_at("http://203.0.113.1:1", &path)
            .await
            .unwrap();
        assert_eq!(resolved, "as-is-token");
    }
}
