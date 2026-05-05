//! Phase 7ch: GitOps fetch helper.
//!
//! Fetches a manifest tree from a Git repository at a specific
//! revision and returns the local checkout path + the resolved
//! commit SHA. The CLI then loads manifests from that path the same
//! way it loads from a local directory.
//!
//! Why CLI-side (not server-side):
//! * The server stays a pure control-plane — no need to hand it
//!   credentials for every git remote.
//! * CI runners already have git + auth in their environment.
//! * Operators can run `iac plan --git-repo … --git-ref …` from a
//!   CI pipeline without giving the server outbound network access
//!   to GitHub/GitLab/etc.
//!
//! Why shell out to `git` instead of linking libgit2:
//! * libgit2 + native deps (openssl, libssh2) bloat the static
//!   binary by 5-10 MB and complicate cross-compile to musl.
//! * `git` is already installed on every CI runner and ops box;
//!   shelling out is the same model `terraform`, `helm`, `kustomize`
//!   etc. all use.
//! * No new advisories surface area — depend on the system's
//!   already-patched git.
//!
//! Repo cache layout: `<cache_dir>/<sha256-of-repo-url>/`. Keyed by
//! URL only — different refs in the same repo share the on-disk
//! clone, we just `git fetch` + `git checkout` per invocation.

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use std::process::Command;

/// What `fetch_revision` produces: the local working-tree path the
/// caller can read manifests from, plus the resolved commit SHA the
/// caller can use as `source_commit` in the operation submit.
#[derive(Debug, Clone)]
pub struct GitCheckout {
    /// Filesystem path to the working tree (after checkout). Manifest
    /// loading (`load_manifests`) walks this directly.
    pub root: PathBuf,
    /// Full 40-char SHA the ref resolved to. Round-trips to the
    /// server in `source_commit`.
    pub sha: String,
}

/// Fetch + checkout `repo_url@ref` and return the working-tree path
/// (joined with `path` if given) plus the resolved SHA. Uses a per-
/// repo cache under `cache_dir` so repeated invocations don't re-
/// download the whole history.
///
/// `ref_spec` may be a branch name, tag, or short / full SHA. We
/// resolve it via `git rev-parse` after fetching so the caller gets
/// the canonical 40-char SHA — never a movable label.
///
/// `path` is an optional sub-directory inside the repo to scope the
/// returned root to. Manifests typically live in `manifests/` or
/// `envs/prod/`; passing that here means the rest of the repo
/// doesn't need to be parsed.
pub fn fetch_revision(
    repo_url: &str,
    ref_spec: &str,
    path: Option<&str>,
    cache_dir: &Path,
) -> Result<GitCheckout> {
    std::fs::create_dir_all(cache_dir)
        .with_context(|| format!("creating git cache dir {}", cache_dir.display()))?;
    let key = repo_key(repo_url);
    let repo_dir = cache_dir.join(&key);

    if !repo_dir.join(".git").exists() {
        // First time we've seen this URL — clone bare-ish so we have
        // a `.git` directory to fetch into. Shallow clone of the
        // single ref keeps the disk + bandwidth footprint small.
        std::fs::create_dir_all(&repo_dir)
            .with_context(|| format!("creating clone dir {}", repo_dir.display()))?;
        run_git(&repo_dir, &["init", "--quiet"]).context("git init")?;
        run_git(&repo_dir, &["remote", "add", "origin", repo_url])
            .context("git remote add origin")?;
    }

    // Always fetch — operator may have pushed since the cache was
    // populated. `--depth 1` keeps it cheap; rev-parse below verifies
    // the ref actually exists locally after the fetch.
    let fetch_args = ["fetch", "--depth=1", "--quiet", "origin", ref_spec];
    run_git(&repo_dir, &fetch_args).with_context(|| {
        format!("git fetch {repo_url} ref={ref_spec} (does the ref exist?)")
    })?;

    // FETCH_HEAD always points at what we just pulled. Resolve to a
    // canonical SHA before checkout — no chance of a different
    // process moving the ref under us mid-operation.
    let sha = run_git(&repo_dir, &["rev-parse", "FETCH_HEAD"])
        .context("rev-parse FETCH_HEAD")?
        .trim()
        .to_string();
    if sha.len() != 40 || !sha.chars().all(|c| c.is_ascii_hexdigit()) {
        anyhow::bail!("rev-parse returned non-SHA: {sha:?}");
    }

    // `git checkout <sha>` puts the working tree in detached-HEAD
    // mode at the resolved commit. Idempotent on re-run with the
    // same SHA.
    run_git(&repo_dir, &["checkout", "--quiet", "--detach", &sha])
        .with_context(|| format!("checkout {sha}"))?;

    let root = match path {
        Some(p) if !p.is_empty() && p != "." => repo_dir.join(p),
        _ => repo_dir.clone(),
    };
    if !root.exists() {
        anyhow::bail!(
            "path {} does not exist in {repo_url}@{sha}",
            root.display()
        );
    }
    Ok(GitCheckout { root, sha })
}

/// Per-repo cache directory key. Just sha256 the URL; no need to
/// preserve the URL shape on disk — the cache directory is
/// machine-internal. We truncate to 16 hex chars (8 bytes of digest)
/// to keep filenames short — collision is irrelevant for a content-
/// addressed cache where the repo URL itself is the input.
fn repo_key(repo_url: &str) -> String {
    let full = iac_core::hash::sha256_hex(repo_url.as_bytes());
    full[..32].to_string() // 16 bytes worth of hex
}

fn run_git(cwd: &Path, args: &[&str]) -> Result<String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(cwd)
        .args(args)
        .output()
        .context("spawning git (is it installed?)")?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("git {} failed: {stderr}", args.join(" "));
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

/// Default cache directory. `$XDG_CACHE_HOME/iac-cli/git/` falls back
/// to `~/.cache/iac-cli/git/` and finally `/tmp/iac-cli-git/` when
/// neither is available (CI environment, sandboxed shells).
pub fn default_cache_dir() -> PathBuf {
    if let Ok(xdg) = std::env::var("XDG_CACHE_HOME") {
        return PathBuf::from(xdg).join("iac-cli/git");
    }
    if let Ok(home) = std::env::var("HOME") {
        return PathBuf::from(home).join(".cache/iac-cli/git");
    }
    PathBuf::from("/tmp/iac-cli-git")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repo_key_stable() {
        let a = repo_key("https://github.com/example/repo.git");
        let b = repo_key("https://github.com/example/repo.git");
        assert_eq!(a, b);
        let c = repo_key("https://github.com/example/other.git");
        assert_ne!(a, c);
    }

    #[test]
    fn repo_key_is_hex_chars() {
        let k = repo_key("git@github.com:example/repo.git");
        assert_eq!(k.len(), 32);
        assert!(k.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn fetch_local_repo_resolves_sha() {
        // Build a fresh local git repo with one commit, then fetch it
        // through our helper. Asserts SHA round-trip + checkout.
        let dir = tempfile::TempDir::new().unwrap();
        let upstream = dir.path().join("upstream");
        std::fs::create_dir_all(&upstream).unwrap();
        run_git(&upstream, &["init", "--quiet", "--initial-branch=main"]).unwrap();
        run_git(&upstream, &["config", "user.email", "test@example.com"]).unwrap();
        run_git(&upstream, &["config", "user.name", "test"]).unwrap();
        std::fs::write(upstream.join("hello.yaml"), "kind: file\n").unwrap();
        run_git(&upstream, &["add", "."]).unwrap();
        run_git(&upstream, &["commit", "-m", "init", "--quiet"]).unwrap();
        let upstream_sha = run_git(&upstream, &["rev-parse", "HEAD"])
            .unwrap()
            .trim()
            .to_string();

        let cache = dir.path().join("cache");
        let url = format!("file://{}", upstream.display());
        let checkout = fetch_revision(&url, "main", None, &cache).unwrap();
        assert_eq!(checkout.sha, upstream_sha);
        assert!(checkout.root.join("hello.yaml").exists());
    }

    #[test]
    fn fetch_with_subpath_scopes_root() {
        let dir = tempfile::TempDir::new().unwrap();
        let upstream = dir.path().join("upstream");
        std::fs::create_dir_all(&upstream).unwrap();
        run_git(&upstream, &["init", "--quiet", "--initial-branch=main"]).unwrap();
        run_git(&upstream, &["config", "user.email", "test@example.com"]).unwrap();
        run_git(&upstream, &["config", "user.name", "test"]).unwrap();
        let env_dir = upstream.join("envs/prod");
        std::fs::create_dir_all(&env_dir).unwrap();
        std::fs::write(env_dir.join("app.yaml"), "kind: file\n").unwrap();
        run_git(&upstream, &["add", "."]).unwrap();
        run_git(&upstream, &["commit", "-m", "init", "--quiet"]).unwrap();

        let cache = dir.path().join("cache");
        let url = format!("file://{}", upstream.display());
        let checkout = fetch_revision(&url, "main", Some("envs/prod"), &cache).unwrap();
        assert!(checkout.root.ends_with("envs/prod"));
        assert!(checkout.root.join("app.yaml").exists());
    }

    #[test]
    fn missing_subpath_errors_clearly() {
        let dir = tempfile::TempDir::new().unwrap();
        let upstream = dir.path().join("upstream");
        std::fs::create_dir_all(&upstream).unwrap();
        run_git(&upstream, &["init", "--quiet", "--initial-branch=main"]).unwrap();
        run_git(&upstream, &["config", "user.email", "t@e.com"]).unwrap();
        run_git(&upstream, &["config", "user.name", "t"]).unwrap();
        std::fs::write(upstream.join("only.yaml"), "x").unwrap();
        run_git(&upstream, &["add", "."]).unwrap();
        run_git(&upstream, &["commit", "-m", "init", "--quiet"]).unwrap();

        let cache = dir.path().join("cache");
        let url = format!("file://{}", upstream.display());
        let err =
            fetch_revision(&url, "main", Some("does/not/exist"), &cache).unwrap_err();
        assert!(err.to_string().contains("does not exist"));
    }
}
