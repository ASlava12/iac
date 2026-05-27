//! Phase 7am: secret-reference resolution for desired-state submissions.
//!
//! Operators write `${secret://<resolver>/<path>[#field]}` inside resource
//! spec strings; the control-plane substitutes the value by dispatching to
//! a configured resolver. Phase 7co moved that substitution to
//! agent-fetch time (see `api/agents.rs::list_assignments`): the DB stores
//! the `${secret://...}` reference verbatim and the plaintext is folded
//! into the signed envelope only as it's handed to the agent, so rotated
//! secrets propagate without resubmitting the manifest and the stored
//! manifest never holds plaintext. The registry is the only piece that
//! holds credentials.
//!
//! The resolver set is closed (env, file, vault, …) so we avoid `dyn` and
//! `async_trait` and use enum dispatch instead. Adding a backend is one
//! `Resolver::Foo` variant + the matching match arm.

use crate::error::{ApiError, ApiResult};
use std::collections::HashMap;

/// Parsed `${secret://<resolver>/<path>[#field]}` reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretRef {
    pub resolver: String,
    pub path: String,
    pub field: Option<String>,
}

impl SecretRef {
    /// Parse one `${secret://...}` token. `None` for malformed input.
    pub fn parse(token: &str) -> Option<Self> {
        let inner = token.strip_prefix("${secret://")?.strip_suffix('}')?;
        if inner.is_empty() {
            return None;
        }
        let (path_part, field) = match inner.split_once('#') {
            Some((a, b)) if !b.is_empty() => (a, Some(b.to_string())),
            _ => (inner, None),
        };
        let (resolver, path) = path_part.split_once('/')?;
        if resolver.is_empty() || path.is_empty() {
            return None;
        }
        Some(Self {
            resolver: resolver.to_string(),
            path: path.to_string(),
            field,
        })
    }
}

/// Find every `${secret://...}` token in `s`. Returns (start, end, ref) in
/// left-to-right order, non-overlapping.
fn find_refs_in_string(s: &str) -> Vec<(usize, usize, SecretRef)> {
    let mut out = Vec::new();
    let bytes = s.as_bytes();
    let mut i = 0;
    while i + 11 <= bytes.len() {
        if &bytes[i..i + 11] == b"${secret://"
            && let Some(end_off) = s[i + 11..].find('}')
        {
            let end = i + 11 + end_off + 1;
            let token = &s[i..end];
            if let Some(sref) = SecretRef::parse(token) {
                out.push((i, end, sref));
                i = end;
                continue;
            }
        }
        i += 1;
    }
    out
}

// ---- backends -------------------------------------------------------------

/// `${secret://env/FOO}` → reads `$FOO`. Useful for development and unit
/// tests; production setups should prefer Vault.
#[derive(Debug, Clone, Copy)]
pub struct EnvResolver;

impl EnvResolver {
    pub fn name(&self) -> &'static str {
        "env"
    }

    pub async fn resolve(&self, path: &str, field: Option<&str>) -> ApiResult<String> {
        if field.is_some() {
            return Err(ApiError::BadRequest(
                "env resolver does not support `#field`; env vars are flat strings".into(),
            ));
        }
        std::env::var(path).map_err(|_| ApiError::BadRequest(format!("env var {path:?} not set")))
    }
}

/// `${secret://vault/<mount>/data/<path>[#field]}` → KV v2 lookup against
/// a HashiCorp Vault server over HTTP. Configured with the operator's
/// `(addr, token)` at server start; one resolver instance can answer for
/// every path on that Vault.
///
/// The `#field` fragment is mandatory: KV v2 always returns a JSON object
/// under `data.data`, and we require the operator to disambiguate which
/// key they want. Empty fragments are rejected at parse time.
///
/// Phase 7cs.1 (security fix #4.13): the Vault token is wrapped in
/// `RedactedToken` so it can never leak through `Debug` formatting.
/// Future `tracing::debug!(?resolver, ...)` calls would otherwise dump
/// the raw token into logs.
#[derive(Debug, Clone)]
pub struct VaultResolver {
    addr: String,
    token: RedactedToken,
    client: reqwest::Client,
}

/// Phase 7cs.1: a `String` wrapper whose `Debug` impl prints
/// `<redacted>` instead of the contents. Used for the Vault token
/// and any other secret-class field we need to keep around in
/// memory without risking it ending up in a log line.
#[derive(Clone)]
struct RedactedToken(String);

impl std::fmt::Debug for RedactedToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<redacted>")
    }
}

impl RedactedToken {
    fn as_str(&self) -> &str {
        &self.0
    }
}

impl VaultResolver {
    /// `addr` should be the Vault root URL (e.g. `https://vault.internal:8200`)
    /// without a trailing slash. `token` is the API token used in the
    /// `X-Vault-Token` header.
    ///
    /// Phase 7cs.1 (security fix #4.8): refuses plain HTTP. The Vault
    /// token rides in a request header; on plain HTTP any network
    /// observer between the control plane and Vault reads it.
    /// Production deployments must use HTTPS. Tests against a local
    /// docker Vault should use [`Self::new_allow_insecure`].
    pub fn new(addr: impl Into<String>, token: impl Into<String>) -> ApiResult<Self> {
        Self::new_inner(addr, token, false)
    }

    /// Phase 7cs.1: test/dev escape hatch for plain HTTP. Production
    /// callers must use [`Self::new`]. The name is deliberately
    /// noisy so a typo in production code reads as wrong at review.
    pub fn new_allow_insecure(
        addr: impl Into<String>,
        token: impl Into<String>,
    ) -> ApiResult<Self> {
        Self::new_inner(addr, token, true)
    }

    fn new_inner(
        addr: impl Into<String>,
        token: impl Into<String>,
        allow_insecure: bool,
    ) -> ApiResult<Self> {
        let addr = addr.into();
        let addr = addr.trim_end_matches('/').to_string();
        if !allow_insecure && !addr.starts_with("https://") {
            return Err(ApiError::BadRequest(format!(
                "vault addr {addr:?} must use https:// — Vault tokens travel \
                 plaintext over HTTP. Use VaultResolver::new_allow_insecure for \
                 test/dev only."
            )));
        }
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .map_err(|e| ApiError::Internal(format!("vault http client: {e}")))?;
        Ok(Self {
            addr,
            token: RedactedToken(token.into()),
            client,
        })
    }

    pub fn name(&self) -> &'static str {
        "vault"
    }

    pub async fn resolve(&self, path: &str, field: Option<&str>) -> ApiResult<String> {
        let field = field.ok_or_else(|| {
            ApiError::BadRequest(
                "vault resolver requires `#field`; KV v2 returns a JSON object".into(),
            )
        })?;
        let url = format!("{}/v1/{}", self.addr, path);
        let resp = self
            .client
            .get(&url)
            .header("X-Vault-Token", self.token.as_str())
            .send()
            .await
            .map_err(|e| ApiError::Internal(format!("vault GET {url} failed: {e}")))?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(ApiError::BadRequest(format!(
                "vault GET {path}: HTTP {status}: {body}"
            )));
        }
        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| ApiError::Internal(format!("vault parse JSON: {e}")))?;
        // KV v2: { "data": { "data": { ...kv... }, "metadata": {...} } }
        // KV v1 has a flatter shape but we don't try to support both at once
        // — operators set the path explicitly, including the `data/` segment.
        let val = body
            .get("data")
            .and_then(|d| d.get("data"))
            .and_then(|d| d.get(field))
            .ok_or_else(|| {
                ApiError::BadRequest(format!(
                    "vault {path}: field {field:?} not present at .data.data"
                ))
            })?;
        match val {
            serde_json::Value::String(s) => Ok(s.clone()),
            other => Err(ApiError::BadRequest(format!(
                "vault {path}#{field}: expected string, got {}",
                short_kind(other)
            ))),
        }
    }
}

fn short_kind(v: &serde_json::Value) -> &'static str {
    match v {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "bool",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
}

/// Phase 7ct: `${secret://sops/<file>#<field>}` → shells out to the
/// system `sops` binary to decrypt an age/PGP-encrypted YAML/JSON file
/// from a sandboxed base directory.
///
/// Same shell-out pattern we already use for `git` and `ssh`: keys live
/// in the operator's normal keyring (age private key file or gpg-agent),
/// so we never re-implement crypto. Operators run `sops --decrypt foo.enc.yaml`
/// once interactively to verify their setup, then point us at the same files.
///
/// Sandbox: every reference is resolved against `base_dir` and the
/// canonicalised result must still live inside it. Without this an
/// operator's manifest could reach `${secret://sops/../../etc/shadow}`
/// and ask `sops` to attempt to decrypt arbitrary files on the server —
/// `sops` would fail loudly, but the read is still wrong by policy.
///
/// `#field` is optional. With it, we use `sops --decrypt --extract '["field"]'`
/// — supports nested paths via the standard `'["a"]["b"]'` syntax. Without
/// a field we return the entire decrypted file as a string, which is the
/// right shape for SSH private keys, TLS certificates, .env-style blobs,
/// etc.
#[derive(Debug, Clone)]
pub struct SopsResolver {
    base_dir: std::path::PathBuf,
    binary: String,
}

impl SopsResolver {
    /// `base_dir` should be an existing directory; it is canonicalised
    /// once at construction and used as the sandbox root for every
    /// subsequent resolve call. `binary` is the path to the `sops`
    /// executable — typically just `"sops"` to use `$PATH`, or an
    /// absolute path for hardened deployments.
    pub fn new(
        base_dir: impl Into<std::path::PathBuf>,
        binary: impl Into<String>,
    ) -> ApiResult<Self> {
        let base_dir = base_dir.into();
        let canonical = std::fs::canonicalize(&base_dir).map_err(|e| {
            ApiError::BadRequest(format!(
                "sops base_dir {base_dir:?} not found / not readable: {e}"
            ))
        })?;
        Ok(Self {
            base_dir: canonical,
            binary: binary.into(),
        })
    }

    pub fn name(&self) -> &'static str {
        "sops"
    }

    /// Resolve `path` (relative to `base_dir`) into the absolute path we
    /// will hand to `sops`. Rejects:
    /// - absolute paths (operators must use a relative path inside the sandbox)
    /// - paths that escape the sandbox after canonicalisation (symlink tricks)
    /// - paths containing NUL bytes (defence-in-depth — `Command` would also reject)
    fn resolve_sandboxed_path(&self, path: &str) -> ApiResult<std::path::PathBuf> {
        if path.contains('\0') {
            return Err(ApiError::BadRequest("sops path contains NUL byte".into()));
        }
        let candidate = std::path::Path::new(path);
        if candidate.is_absolute() {
            return Err(ApiError::BadRequest(format!(
                "sops path {path:?} must be relative to base_dir, not absolute"
            )));
        }
        let joined = self.base_dir.join(candidate);
        // Canonicalise — this resolves `..` and any symlinks. If the
        // file does not exist, sops will fail anyway, so a missing-file
        // error here is also fine; we map it to BadRequest so the
        // operator sees their bad reference.
        let canonical = std::fs::canonicalize(&joined).map_err(|e| {
            ApiError::BadRequest(format!(
                "sops file {path:?}: cannot resolve {} ({e})",
                joined.display()
            ))
        })?;
        if !canonical.starts_with(&self.base_dir) {
            return Err(ApiError::BadRequest(format!(
                "sops path {path:?} escapes base_dir {} (resolved to {})",
                self.base_dir.display(),
                canonical.display()
            )));
        }
        Ok(canonical)
    }

    pub async fn resolve(&self, path: &str, field: Option<&str>) -> ApiResult<String> {
        let abs = self.resolve_sandboxed_path(path)?;

        let mut cmd = tokio::process::Command::new(&self.binary);
        cmd.arg("--decrypt");
        if let Some(field) = field {
            // sops's --extract syntax is `'["a"]["b"]'`. We support a
            // single top-level field (the common case for KV-style
            // secret files); if an operator needs nested extraction they
            // can write the path inline as `field=outer"]["inner` —
            // which is gnarly enough that we'll add structured support
            // later if it's actually wanted.
            cmd.arg("--extract")
                .arg(format!("[\"{}\"]", field.replace('"', "\\\"")));
        }
        cmd.arg(&abs);
        // Pipe stdin from /dev/null so sops never blocks on prompts —
        // age/gpg-agent setups should be non-interactive on the server.
        cmd.stdin(std::process::Stdio::null());
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());

        let output = tokio::time::timeout(std::time::Duration::from_secs(10), cmd.output())
            .await
            .map_err(|_| {
                ApiError::Internal(format!(
                    "sops {path}: timed out after 10s — keys missing / agent stuck?"
                ))
            })?
            .map_err(|e| {
                ApiError::Internal(format!(
                    "sops {path}: failed to spawn {:?}: {e}",
                    self.binary
                ))
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // Trim — sops stderr is multi-line and often noisy.
            let stderr = stderr.trim();
            return Err(ApiError::BadRequest(format!(
                "sops {path}: exit {:?}: {stderr}",
                output.status.code()
            )));
        }

        let mut s = String::from_utf8(output.stdout).map_err(|_| {
            ApiError::BadRequest(format!("sops {path}: decrypted output is not valid UTF-8"))
        })?;
        // sops appends a trailing newline (it prints a YAML/JSON
        // document). For single-field extracts the field value is
        // followed by `\n`; for whole-file extracts the document ends
        // with `\n`. Strip exactly one trailing `\n` so secrets like
        // tokens don't end up with stray whitespace — a multi-line
        // secret (TLS cert, SSH private key) keeps its internal
        // newlines intact.
        if s.ends_with('\n') {
            s.pop();
        }
        Ok(s)
    }
}

/// Closed set of secret-resolver backends. Add a variant + match arm to
/// extend; callers reach through `SecretRegistry::register`.
pub enum Resolver {
    Env(EnvResolver),
    Vault(VaultResolver),
    Sops(SopsResolver),
    /// Test-only: returns the configured static string for any path.
    /// Behind `#[cfg(test)]` to keep the prod surface small.
    #[cfg(test)]
    Static(StaticResolver),
}

impl Resolver {
    pub fn name(&self) -> &str {
        match self {
            Self::Env(r) => r.name(),
            Self::Vault(r) => r.name(),
            Self::Sops(r) => r.name(),
            #[cfg(test)]
            Self::Static(r) => r.name(),
        }
    }

    pub async fn resolve(&self, path: &str, field: Option<&str>) -> ApiResult<String> {
        match self {
            Self::Env(r) => r.resolve(path, field).await,
            Self::Vault(r) => r.resolve(path, field).await,
            Self::Sops(r) => r.resolve(path, field).await,
            #[cfg(test)]
            Self::Static(r) => r.resolve(path, field).await,
        }
    }
}

#[cfg(test)]
#[derive(Debug, Clone)]
pub struct StaticResolver {
    pub scheme: &'static str,
    pub value: String,
}

#[cfg(test)]
impl StaticResolver {
    pub fn name(&self) -> &str {
        self.scheme
    }
    pub async fn resolve(&self, _path: &str, _field: Option<&str>) -> ApiResult<String> {
        Ok(self.value.clone())
    }
}

// ---- registry --------------------------------------------------------------

/// Dispatch table mapping `SecretRef::resolver` → backend.
pub struct SecretRegistry {
    resolvers: HashMap<String, Resolver>,
}

impl std::fmt::Debug for SecretRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Don't leak the configured tokens via Debug — only the
        // registered scheme names.
        f.debug_struct("SecretRegistry")
            .field("schemes", &self.resolvers.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl SecretRegistry {
    pub fn new() -> Self {
        Self {
            resolvers: HashMap::new(),
        }
    }

    pub fn register(&mut self, resolver: Resolver) {
        self.resolvers.insert(resolver.name().to_string(), resolver);
    }

    /// Resolve a single ref. `BadRequest` for unknown schemes — operators
    /// see the bad token in the error and can fix the manifest.
    pub async fn resolve(&self, sref: &SecretRef) -> ApiResult<String> {
        let backend = self.resolvers.get(&sref.resolver).ok_or_else(|| {
            ApiError::BadRequest(format!(
                "unknown secret resolver {:?} (registered: {:?})",
                sref.resolver,
                self.resolvers.keys().collect::<Vec<_>>()
            ))
        })?;
        backend.resolve(&sref.path, sref.field.as_deref()).await
    }

    /// Walk `value` in place, resolving every `${secret://...}` token in
    /// every string field. Returns the count of resolved references. On
    /// error the value is partially mutated; callers should treat it as
    /// poisoned.
    pub async fn substitute_in_value(&self, value: &mut serde_json::Value) -> ApiResult<u32> {
        let pointers = collect_string_pointers(value);
        let mut count = 0;
        for ptr in pointers {
            let original = match value.pointer(&ptr) {
                Some(serde_json::Value::String(s)) => s.clone(),
                _ => continue,
            };
            let refs = find_refs_in_string(&original);
            if refs.is_empty() {
                continue;
            }
            let mut out = String::with_capacity(original.len());
            let mut cursor = 0;
            for (start, end, sref) in &refs {
                out.push_str(&original[cursor..*start]);
                let resolved = self.resolve(sref).await?;
                out.push_str(&resolved);
                cursor = *end;
                count += 1;
            }
            out.push_str(&original[cursor..]);
            if let Some(target) = value.pointer_mut(&ptr) {
                *target = serde_json::Value::String(out);
            }
        }
        Ok(count)
    }
}

impl Default for SecretRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Collect RFC 6901 JSON pointers for every string-valued node in `value`.
fn collect_string_pointers(value: &serde_json::Value) -> Vec<String> {
    let mut out = Vec::new();
    walk(value, String::new(), &mut out);
    out
}

fn walk(v: &serde_json::Value, prefix: String, out: &mut Vec<String>) {
    match v {
        serde_json::Value::String(_) => out.push(prefix),
        serde_json::Value::Object(map) => {
            for (k, val) in map {
                let escaped = k.replace('~', "~0").replace('/', "~1");
                let p = format!("{prefix}/{escaped}");
                walk(val, p, out);
            }
        }
        serde_json::Value::Array(arr) => {
            for (i, val) in arr.iter().enumerate() {
                let p = format!("{prefix}/{i}");
                walk(val, p, out);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parse_env_ref() {
        let r = SecretRef::parse("${secret://env/DB_PASSWORD}").unwrap();
        assert_eq!(r.resolver, "env");
        assert_eq!(r.path, "DB_PASSWORD");
        assert_eq!(r.field, None);
    }

    #[test]
    fn parse_vault_ref_with_field() {
        let r = SecretRef::parse("${secret://vault/secret/data/myapp/db#password}").unwrap();
        assert_eq!(r.resolver, "vault");
        assert_eq!(r.path, "secret/data/myapp/db");
        assert_eq!(r.field.as_deref(), Some("password"));
    }

    #[test]
    fn parse_rejects_garbage() {
        assert!(SecretRef::parse("not a ref").is_none());
        assert!(SecretRef::parse("${secret://}").is_none());
        assert!(SecretRef::parse("${secret://env/}").is_none());
        assert!(SecretRef::parse("${secret:///path}").is_none());
        let r = SecretRef::parse("${secret://env/FOO#}").unwrap();
        assert_eq!(r.field, None);
    }

    #[test]
    fn find_refs_locates_multiple_in_one_string() {
        let s = "jdbc:postgres://${secret://env/USER}:${secret://env/PASS}@db/app";
        let refs = find_refs_in_string(s);
        assert_eq!(refs.len(), 2);
        assert_eq!(refs[0].2.path, "USER");
        assert_eq!(refs[1].2.path, "PASS");
        assert!(refs[0].1 <= refs[1].0);
    }

    #[test]
    fn find_refs_skips_unrelated_dollar_brace() {
        let s = "foo ${not_secret} bar ${secret://env/REAL} baz";
        let refs = find_refs_in_string(s);
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].2.path, "REAL");
    }

    fn static_registry(value: &str) -> SecretRegistry {
        let mut r = SecretRegistry::new();
        r.register(Resolver::Static(StaticResolver {
            scheme: "static",
            value: value.to_string(),
        }));
        r
    }

    #[tokio::test]
    async fn substitute_in_simple_string() {
        let reg = static_registry("RESOLVED");
        let mut v = json!({
            "spec": { "password": "${secret://static/db}" }
        });
        let n = reg.substitute_in_value(&mut v).await.unwrap();
        assert_eq!(n, 1);
        assert_eq!(v["spec"]["password"], "RESOLVED");
    }

    #[tokio::test]
    async fn substitute_handles_arrays_and_multiple_refs() {
        let reg = static_registry("X");
        let mut v = json!({
            "spec": {
                "envs": ["${secret://static/a}", "no-secret", "${secret://static/b}"],
                "uri": "user:${secret://static/c}@host:${secret://static/d}/db",
            }
        });
        let n = reg.substitute_in_value(&mut v).await.unwrap();
        assert_eq!(n, 4);
        assert_eq!(v["spec"]["envs"][0], "X");
        assert_eq!(v["spec"]["envs"][1], "no-secret");
        assert_eq!(v["spec"]["envs"][2], "X");
        assert_eq!(v["spec"]["uri"], "user:X@host:X/db");
    }

    #[tokio::test]
    async fn substitute_unknown_resolver_returns_bad_request() {
        let reg = SecretRegistry::new();
        let mut v = json!({"k": "${secret://nope/x}"});
        let err = reg.substitute_in_value(&mut v).await.unwrap_err();
        match err {
            ApiError::BadRequest(msg) => assert!(msg.contains("nope")),
            other => panic!("expected BadRequest, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn env_resolver_reads_environment() {
        // PATH is virtually guaranteed to be set on every platform we run
        // tests on. We don't care about the exact value — only that the
        // resolver successfully read *something* and inserted it.
        let path_value = std::env::var("PATH").expect("PATH must be set");
        let mut reg = SecretRegistry::new();
        reg.register(Resolver::Env(EnvResolver));
        let mut v = json!({"k": "${secret://env/PATH}"});
        reg.substitute_in_value(&mut v).await.unwrap();
        assert_eq!(v["k"], path_value);
    }

    #[tokio::test]
    async fn env_resolver_unset_var_returns_bad_request() {
        let mut reg = SecretRegistry::new();
        reg.register(Resolver::Env(EnvResolver));
        let mut v = json!({"k": "${secret://env/IAC_DEFINITELY_NOT_SET_FOR_PHASE_7AM_TESTS}"});
        let err = reg.substitute_in_value(&mut v).await.unwrap_err();
        match err {
            ApiError::BadRequest(msg) => assert!(msg.contains("not set")),
            other => panic!("expected BadRequest, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn env_resolver_rejects_field_selector() {
        let mut reg = SecretRegistry::new();
        reg.register(Resolver::Env(EnvResolver));
        let mut v = json!({"k": "${secret://env/FOO#bar}"});
        let err = reg.substitute_in_value(&mut v).await.unwrap_err();
        assert!(matches!(err, ApiError::BadRequest(_)));
    }

    #[tokio::test]
    async fn substitute_no_refs_returns_zero() {
        let reg = SecretRegistry::new();
        let mut v = json!({"a": "plain", "b": [1, 2, 3], "c": {"d": "still plain"}});
        let n = reg.substitute_in_value(&mut v).await.unwrap();
        assert_eq!(n, 0);
        assert_eq!(v["c"]["d"], "still plain");
    }

    // ---- SopsResolver tests (Phase 7ct) -----------------------------------
    //
    // We can't depend on the real `sops` binary being installed, so we
    // build a tiny POSIX shell stub that mimics the subset of the
    // `sops --decrypt [--extract '["field"]'] <file>` interface we
    // actually use. Tests that need a successful decrypt write a YAML
    // file in plaintext and pretend the stub is decrypting it; tests
    // that need failure point at a stub that exits non-zero.

    use std::os::unix::fs::PermissionsExt;
    use tempfile::TempDir;

    /// Write a shell script and `chmod +x` it. Used to fake `sops`.
    fn write_stub(dir: &std::path::Path, name: &str, body: &str) -> std::path::PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, body).unwrap();
        let mut perms = std::fs::metadata(&path).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&path, perms).unwrap();
        path
    }

    /// A stub that mimics `sops --decrypt [--extract] <file>` by reading
    /// the file as YAML-ish key:value lines. With `--extract '["k"]'`
    /// it prints the value of key `k`; otherwise it cats the whole file.
    /// Good enough to verify the resolver wires args correctly.
    const SOPS_STUB: &str = r#"#!/bin/sh
file=""
field=""
while [ $# -gt 0 ]; do
  case "$1" in
    --decrypt) shift ;;
    --extract) field="$2"; shift 2 ;;
    *) file="$1"; shift ;;
  esac
done
if [ -n "$field" ]; then
  key=$(printf '%s' "$field" | sed 's/^\["//; s/"\]$//')
  awk -v k="$key" -F': *' '$1 == k { sub(/^[^:]*: */, ""); print; exit }' "$file"
else
  cat "$file"
fi
"#;

    /// A stub that always exits non-zero with a fixed stderr.
    const SOPS_STUB_FAIL: &str = "#!/bin/sh\necho 'fake sops: no key for file' >&2\nexit 1\n";

    #[tokio::test]
    async fn sops_resolver_extracts_field() {
        let stub_dir = TempDir::new().unwrap();
        let stub = write_stub(stub_dir.path(), "sops", SOPS_STUB);
        let base = TempDir::new().unwrap();
        std::fs::write(
            base.path().join("db.enc.yaml"),
            "user: deploy\npassword: hunter2\n",
        )
        .unwrap();

        let resolver = SopsResolver::new(base.path(), stub.to_string_lossy()).unwrap();
        let v = resolver
            .resolve("db.enc.yaml", Some("password"))
            .await
            .unwrap();
        assert_eq!(v, "hunter2");
    }

    #[tokio::test]
    async fn sops_resolver_returns_whole_file_without_field() {
        let stub_dir = TempDir::new().unwrap();
        let stub = write_stub(stub_dir.path(), "sops", SOPS_STUB);
        let base = TempDir::new().unwrap();
        std::fs::write(
            base.path().join("cert.pem.enc"),
            "-----BEGIN CERTIFICATE-----\nABCDEF\n-----END CERTIFICATE-----\n",
        )
        .unwrap();

        let resolver = SopsResolver::new(base.path(), stub.to_string_lossy()).unwrap();
        let v = resolver.resolve("cert.pem.enc", None).await.unwrap();
        assert_eq!(
            v,
            "-----BEGIN CERTIFICATE-----\nABCDEF\n-----END CERTIFICATE-----"
        );
    }

    #[tokio::test]
    async fn sops_resolver_rejects_absolute_path() {
        let stub_dir = TempDir::new().unwrap();
        let stub = write_stub(stub_dir.path(), "sops", SOPS_STUB);
        let base = TempDir::new().unwrap();
        let resolver = SopsResolver::new(base.path(), stub.to_string_lossy()).unwrap();
        let err = resolver.resolve("/etc/passwd", None).await.unwrap_err();
        match err {
            ApiError::BadRequest(msg) => assert!(msg.contains("absolute"), "{msg}"),
            other => panic!("expected BadRequest, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn sops_resolver_rejects_dotdot_escape() {
        let stub_dir = TempDir::new().unwrap();
        let stub = write_stub(stub_dir.path(), "sops", SOPS_STUB);
        let base_parent = TempDir::new().unwrap();
        std::fs::create_dir(base_parent.path().join("inside")).unwrap();
        std::fs::write(base_parent.path().join("outside.yaml"), "key: value\n").unwrap();
        let base = base_parent.path().join("inside");

        let resolver = SopsResolver::new(&base, stub.to_string_lossy()).unwrap();
        let err = resolver.resolve("../outside.yaml", None).await.unwrap_err();
        // canonicalize() on `inside/../outside.yaml` resolves to base_parent
        // which does not start with `inside/` → escape rejected.
        match err {
            ApiError::BadRequest(msg) => {
                assert!(msg.contains("escapes") || msg.contains("base_dir"), "{msg}")
            }
            other => panic!("expected BadRequest, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn sops_resolver_rejects_nul_byte() {
        let stub_dir = TempDir::new().unwrap();
        let stub = write_stub(stub_dir.path(), "sops", SOPS_STUB);
        let base = TempDir::new().unwrap();
        let resolver = SopsResolver::new(base.path(), stub.to_string_lossy()).unwrap();
        let err = resolver.resolve("foo\0bar", None).await.unwrap_err();
        match err {
            ApiError::BadRequest(msg) => assert!(msg.contains("NUL"), "{msg}"),
            other => panic!("expected BadRequest, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn sops_resolver_propagates_stub_failure() {
        let stub_dir = TempDir::new().unwrap();
        let stub = write_stub(stub_dir.path(), "sops", SOPS_STUB_FAIL);
        let base = TempDir::new().unwrap();
        std::fs::write(base.path().join("missing-key.enc.yaml"), "x: 1\n").unwrap();

        let resolver = SopsResolver::new(base.path(), stub.to_string_lossy()).unwrap();
        let err = resolver
            .resolve("missing-key.enc.yaml", None)
            .await
            .unwrap_err();
        match err {
            ApiError::BadRequest(msg) => {
                assert!(msg.contains("no key for file"), "{msg}")
            }
            other => panic!("expected BadRequest, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn sops_resolver_through_registry_substitution() {
        let stub_dir = TempDir::new().unwrap();
        let stub = write_stub(stub_dir.path(), "sops", SOPS_STUB);
        let base = TempDir::new().unwrap();
        std::fs::write(base.path().join("creds.enc.yaml"), "api_token: abc123\n").unwrap();

        let mut reg = SecretRegistry::new();
        reg.register(Resolver::Sops(
            SopsResolver::new(base.path(), stub.to_string_lossy()).unwrap(),
        ));
        let mut v = json!({
            "spec": { "auth": "Bearer ${secret://sops/creds.enc.yaml#api_token}" }
        });
        let n = reg.substitute_in_value(&mut v).await.unwrap();
        assert_eq!(n, 1);
        assert_eq!(v["spec"]["auth"], "Bearer abc123");
    }

    #[tokio::test]
    async fn sops_resolver_missing_base_dir_errors_at_construction() {
        let stub_dir = TempDir::new().unwrap();
        let stub = write_stub(stub_dir.path(), "sops", SOPS_STUB);
        let result = SopsResolver::new("/nonexistent/sops/base/dir", stub.to_string_lossy());
        match result {
            Err(ApiError::BadRequest(msg)) => {
                assert!(
                    msg.contains("not found") || msg.contains("readable"),
                    "{msg}"
                )
            }
            other => panic!("expected BadRequest, got {other:?}"),
        }
    }
}
