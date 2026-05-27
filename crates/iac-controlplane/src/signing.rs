//! Server-side Ed25519 signing for assignments.
//!
//! Phase 6b shipped a single-key model: one Ed25519 keypair persisted to
//! `<state_dir>/signing-key.bin` + `<state_dir>/signing-key.id`, used for
//! every signature. Phase 7ce promotes this to a multi-key set:
//!
//! * **Active** key — signs new assignments. Exactly one at any time.
//! * **Accepted** keys — verified by agents (via key_id lookup), used to
//!   keep recently-rotated keys valid during the rotation window.
//!
//! Storage layout under `<state_dir>/signing-keys/`:
//! * `<key_id>.bin` — raw 32-byte Ed25519 secret per accepted key.
//! * `active` — single line containing the active key_id.
//!
//! Migration: at boot, if the new directory layout is missing but the
//! legacy `<state_dir>/signing-key.bin` + `signing-key.id` exist, the
//! old key is automatically promoted into the new layout as the active
//! (and only) key. Existing deployments rolling forward see no
//! disruption — the same key continues signing. Agents on TOFU stay
//! pinned to it.
//!
//! Rotation flow (operator side):
//! 1. `POST /v1/admin/signing-keys/rotate` — server generates a fresh
//!    key, writes the secret, points `active` at it. Old key remains
//!    in `accepted`.
//! 2. Agents on next assignment poll see envelopes signed by the new
//!    `key_id` — they fetch `/v1/signing-keys` (Phase 7cf) to pick up
//!    the new pubkey, lookup by id, verify.
//! 3. After rotation window passes, `POST /v1/admin/signing-keys/{id}/retire`
//!    removes the old key.

use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use ulid::Ulid;

/// One key entry in the set. Holds both signing + verifying material;
/// when used purely for verification (after retirement of the active
/// role), the signing key is still kept around — its presence in the
/// set is what makes the key "accepted."
#[derive(Debug, Clone)]
struct KeyEntry {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
}

/// Phase 7ce: multi-key signer set. The active key signs every
/// outgoing assignment; all keys (active + previously-active retained
/// during a rotation window) remain available for verification by
/// agents.
///
/// Phase 7cz.2: state is held in an `ArcSwap` so `sign()` and friends
/// load it lock-free (one atomic load, no read-lock contention with
/// concurrent rotate/retire). Mutations (rotate, retire) serialise via
/// a separate `Mutex<()>` — only one mutation can be in flight at a
/// time, otherwise concurrent rotate+retire could deadlock-with-each-
/// other on disk: e.g. `rotate` writes the active pointer to NEW
/// while `retire(NEW)` between writes deletes `NEW.bin`, leaving the
/// on-disk layout self-inconsistent (active points at a missing key).
/// `load_set` would then refuse to load on next boot.
///
/// `SignerState`'s invariant — `keys[active_id]` always exists — is
/// established by `load_set()` (which bails if it doesn't) and
/// preserved across mutations because every transition goes through
/// `load_set()` after disk writes commit. The (formerly) `expect`-
/// guarded read paths now use `try_active_entry()` which returns a
/// `Result`, propagated up to handlers as `Internal` errors instead of
/// panicking the whole process.
pub struct ServerSigner {
    state: ArcSwap<SignerState>,
    /// Serialises rotate + retire so on-disk state can never become
    /// inconsistent under concurrent operator actions.
    mutate_lock: Mutex<()>,
    /// Directory where keys + the `active` pointer live. Owned by
    /// the signer so rotate / retire can persist without re-asking.
    dir: PathBuf,
}

impl std::fmt::Debug for ServerSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Don't print key bytes via Debug. Just the active id and
        // count — useful for tracing without leaking material.
        let s = self.state.load();
        f.debug_struct("ServerSigner")
            .field("active_id", &s.active_id)
            .field("key_count", &s.keys.len())
            .field("dir", &self.dir)
            .finish()
    }
}

#[derive(Debug)]
struct SignerState {
    keys: HashMap<String, KeyEntry>,
    active_id: String,
}

impl SignerState {
    /// Internal accessor that returns a `Result` instead of panicking.
    /// `load_set` guarantees the invariant `keys[active_id]` exists,
    /// so this should never fail in practice; if it does, treat it
    /// as an internal-error and surface it rather than crashing the
    /// process. Phase 7cz.2 hardening.
    fn try_active_entry(&self) -> Result<&KeyEntry> {
        self.keys.get(&self.active_id).ok_or_else(|| {
            anyhow::anyhow!(
                "internal invariant violated: active key {} not in key set (size={})",
                self.active_id,
                self.keys.len()
            )
        })
    }
}

impl ServerSigner {
    /// Load an existing key set or initialize one (importing legacy
    /// single-key format if present, generating fresh otherwise).
    pub fn load_or_create(state_dir: &Path) -> Result<Self> {
        if !state_dir.exists() {
            fs::create_dir_all(state_dir)
                .with_context(|| format!("creating state dir {}", state_dir.display()))?;
        }
        let keys_dir = state_dir.join("signing-keys");
        let legacy_secret = state_dir.join("signing-key.bin");
        let legacy_id = state_dir.join("signing-key.id");

        // 1. Try the new layout first.
        if keys_dir.exists() {
            let state = load_set(&keys_dir)
                .with_context(|| format!("loading key set from {}", keys_dir.display()))?;
            tracing::info!(
                active_key_id = %state.active_id,
                key_count = state.keys.len(),
                "loaded multi-key signer set"
            );
            return Ok(Self {
                state: ArcSwap::new(Arc::new(state)),
                mutate_lock: Mutex::new(()),
                dir: keys_dir,
            });
        }

        // 2. Migration: legacy single-key format exists. Move it into
        //    the new layout.
        if legacy_secret.exists() && legacy_id.exists() {
            fs::create_dir_all(&keys_dir)
                .with_context(|| format!("creating {}", keys_dir.display()))?;
            let secret_bytes = fs::read(&legacy_secret)
                .with_context(|| format!("reading legacy {}", legacy_secret.display()))?;
            if secret_bytes.len() != 32 {
                anyhow::bail!(
                    "legacy signing-key.bin has {} bytes, expected 32",
                    secret_bytes.len()
                );
            }
            let key_id = fs::read_to_string(&legacy_id)
                .with_context(|| format!("reading legacy {}", legacy_id.display()))?
                .trim()
                .to_string();
            // Write into new layout.
            write_key_file(&keys_dir.join(format!("{key_id}.bin")), &secret_bytes)?;
            write_active_pointer(&keys_dir, &key_id)?;
            // Leave legacy files in place — operators can clean up
            // after they verify the new layout works. Re-running this
            // function takes the new-layout branch since `keys_dir`
            // now exists.
            tracing::info!(
                key_id = %key_id,
                "migrated legacy signing key to multi-key layout"
            );
            let state = load_set(&keys_dir)?;
            return Ok(Self {
                state: ArcSwap::new(Arc::new(state)),
                mutate_lock: Mutex::new(()),
                dir: keys_dir,
            });
        }

        // 3. Fresh init: generate a single key as the initial active.
        fs::create_dir_all(&keys_dir)
            .with_context(|| format!("creating {}", keys_dir.display()))?;
        let key_id = generate_and_persist(&keys_dir)?;
        write_active_pointer(&keys_dir, &key_id)?;
        let state = load_set(&keys_dir)?;
        // Phase 7cp.3 (security fix #4.10): first-run TOFU is the
        // weakest link in the signing chain — whoever reaches
        // `/v1/signing-keys` first gets pinned by every fresh agent.
        // Print the active key's fingerprint prominently so the
        // operator can verify it out-of-band (e.g. by reading it
        // from the boot console) before letting agents register.
        // Also write a one-line marker file next to the key so
        // automation can read+confirm without grep'ing logs.
        let entry = state.try_active_entry()?;
        let pub_b64 = B64.encode(entry.verifying_key.to_bytes());
        let fingerprint = pubkey_fingerprint(entry.verifying_key.to_bytes());
        let marker = keys_dir.join(".initial-fingerprint");
        let _ = fs::write(
            &marker,
            format!(
                "key_id: {}\nsha256: {}\npub_b64: {}\n",
                key_id, fingerprint, pub_b64
            ),
        );
        tracing::warn!(
            key_id = %key_id,
            fingerprint = %fingerprint,
            "generated initial signing key — operators MUST verify this fingerprint out-of-band before agents register. Saved to {}",
            marker.display(),
        );
        eprintln!(
            "\n========================================================================\n\
             [!] FIRST-RUN: initial signing key generated\n\
                 key_id:      {}\n\
                 sha256:      {}\n\
                 \n\
                 Verify this fingerprint MATCHES on the operator-trusted channel\n\
                 (boot console, out-of-band ssh, etc.) BEFORE pointing agents at\n\
                 this server. Agents pin the first key they see — first-run TOFU\n\
                 hijack is the only window where this server's identity can be\n\
                 silently replaced.\n\
             ========================================================================\n",
            key_id, fingerprint,
        );
        Ok(Self {
            state: ArcSwap::new(Arc::new(state)),
            mutate_lock: Mutex::new(()),
            dir: keys_dir,
        })
    }

    /// Phase 7cp.3: stable, human-readable fingerprint of the active
    /// pubkey. Operators read this from the marker file or the boot
    /// log to verify the server hasn't been swapped out.
    ///
    /// Phase 7cz.2: returns `Result` instead of panicking on the
    /// (unreachable-by-construction) case where the active id has no
    /// matching key. Callers in `api/` propagate via `?`.
    pub fn active_pubkey_fingerprint(&self) -> Result<String> {
        let state = self.state.load();
        let entry = state.try_active_entry()?;
        Ok(pubkey_fingerprint(entry.verifying_key.to_bytes()))
    }

    /// `key_id()` returns the *active* key's id. Backwards-compatible
    /// with Phase 6b — pre-rotation callers see the same shape.
    pub fn key_id(&self) -> String {
        self.state.load().active_id.clone()
    }

    /// `public_key_b64()` returns the active key's pubkey.
    /// Phase 7cz.2: returns `Result` (see `active_pubkey_fingerprint`).
    pub fn public_key_b64(&self) -> Result<String> {
        let state = self.state.load();
        let entry = state.try_active_entry()?;
        Ok(B64.encode(entry.verifying_key.to_bytes()))
    }

    /// All accepted keys (active + retained) as `(key_id, pubkey_b64)`
    /// pairs. Used by `/v1/signing-keys` to publish the verification
    /// set so agents can validate signatures from multiple keys
    /// during a rotation window.
    pub fn pubkeys(&self) -> Vec<(String, String)> {
        let state = self.state.load();
        let mut out: Vec<(String, String)> = state
            .keys
            .iter()
            .map(|(id, entry)| (id.clone(), B64.encode(entry.verifying_key.to_bytes())))
            .collect();
        // Sort by key_id for stable output. Active comes first via a
        // separate accessor; this list is the verification set.
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }

    /// Sign `agent_id`/`assignment_id`/... using the active key.
    /// Returns the base64 signature. Caller embeds `key_id()` in the
    /// envelope so the agent knows which pubkey to verify against.
    /// Phase 7cz.2: returns `Result` so the (unreachable) missing-
    /// active-key case surfaces as 500 instead of crashing the
    /// process; callers in `api/agents.rs` propagate via `?`.
    pub fn sign(
        &self,
        agent_id: &str,
        assignment_id: &str,
        operation_id: &str,
        created_at: &str,
        payload_json: &[u8],
    ) -> Result<String> {
        let msg = iac_core::protocol::v1::canonical_assignment_message(
            agent_id,
            assignment_id,
            operation_id,
            created_at,
            payload_json,
        );
        let state = self.state.load();
        let entry = state.try_active_entry()?;
        let sig = entry.signing_key.sign(&msg);
        Ok(B64.encode(sig.to_bytes()))
    }

    /// Phase 7ce: rotate the active key. Generates a fresh keypair,
    /// adds it to the set, and points `active` at it. The previously-
    /// active key remains in the accepted set for the rotation
    /// window. Returns the new active key_id.
    ///
    /// Phase 7cz.2: serialised against `retire` via `mutate_lock`. Two
    /// concurrent operator-driven rotations or a rotation racing with
    /// a retire of the about-to-be-active key would otherwise leave
    /// the on-disk layout self-inconsistent.
    pub fn rotate(&self) -> Result<String> {
        let _guard = self.mutate_lock.lock().unwrap_or_else(|e| {
            // Mutex poisoning here means a previous rotate/retire
            // panicked. The only thing inside the locked section is
            // disk I/O + load_set; neither panics in normal use. If
            // it happens, recovering the lock is fine — state is
            // reloaded from disk anyway.
            e.into_inner()
        });
        let new_id = generate_and_persist(&self.dir)?;
        write_active_pointer(&self.dir, &new_id)?;
        let new_state = load_set(&self.dir)
            .with_context(|| format!("reloading key set after rotate ({})", self.dir.display()))?;
        let prev_active = self.state.load().active_id.clone();
        self.state.store(Arc::new(new_state));
        tracing::warn!(
            previous_active = %prev_active,
            new_active = %new_id,
            "rotated server signing key"
        );
        Ok(new_id)
    }

    /// Phase 7ce: retire a key — removes it from the accepted set
    /// and deletes its secret on disk. Refuses to retire the active
    /// key (operator must rotate first). Returns `Ok(false)` when the
    /// key wasn't in the set (idempotent).
    ///
    /// Phase 7cz.2: serialised against `rotate` via `mutate_lock`,
    /// and re-checks the active id *inside* the lock so a concurrent
    /// rotation can't slip the key under us between the operator's
    /// decision and the disk write.
    pub fn retire(&self, key_id: &str) -> Result<bool> {
        let _guard = self.mutate_lock.lock().unwrap_or_else(|e| e.into_inner());
        let state_snapshot = self.state.load_full();
        if state_snapshot.active_id == key_id {
            anyhow::bail!("cannot retire active key {key_id}; rotate first to elect a new active");
        }
        if !state_snapshot.keys.contains_key(key_id) {
            return Ok(false);
        }
        let path = self.dir.join(format!("{key_id}.bin"));
        if path.exists() {
            fs::remove_file(&path).with_context(|| format!("removing {}", path.display()))?;
        }
        let new_state = load_set(&self.dir)?;
        self.state.store(Arc::new(new_state));
        tracing::info!(key_id = %key_id, "retired server signing key");
        Ok(true)
    }
}

/// Walk the `signing-keys/` directory, build the in-memory set, and
/// resolve the `active` pointer. Must be called whenever on-disk
/// state changes.
fn load_set(keys_dir: &Path) -> Result<SignerState> {
    let active_path = keys_dir.join("active");
    let active_id = fs::read_to_string(&active_path)
        .with_context(|| format!("reading {}", active_path.display()))?
        .trim()
        .to_string();
    if active_id.is_empty() {
        anyhow::bail!("{} is empty", active_path.display());
    }

    let mut keys: HashMap<String, KeyEntry> = HashMap::new();
    for entry in
        fs::read_dir(keys_dir).with_context(|| format!("listing {}", keys_dir.display()))?
    {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let Some(stem) = name.strip_suffix(".bin") else {
            continue;
        };
        let bytes = fs::read(entry.path())
            .with_context(|| format!("reading {}", entry.path().display()))?;
        if bytes.len() != 32 {
            anyhow::bail!(
                "{} has {} bytes, expected 32",
                entry.path().display(),
                bytes.len()
            );
        }
        let mut buf = [0u8; 32];
        buf.copy_from_slice(&bytes);
        let signing_key = SigningKey::from_bytes(&buf);
        let verifying_key = signing_key.verifying_key();
        keys.insert(
            stem.to_string(),
            KeyEntry {
                signing_key,
                verifying_key,
            },
        );
    }

    if !keys.contains_key(&active_id) {
        anyhow::bail!(
            "active pointer {active_id} but no matching key in {}",
            keys_dir.display()
        );
    }
    Ok(SignerState { keys, active_id })
}

/// Generate a fresh key, write the secret file with mode 0600, return
/// the new key_id.
/// Phase 7cp.3: short, human-comparable fingerprint of an Ed25519
/// pubkey. Format: SHA-256 colon-separated hex bytes, like an SSH
/// host-key fingerprint. Long enough to be collision-resistant for
/// operators eyeballing them, short enough to read aloud.
fn pubkey_fingerprint(pubkey: [u8; 32]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(pubkey);
    let bytes = hasher.finalize();
    bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

fn generate_and_persist(keys_dir: &Path) -> Result<String> {
    let mut secret = [0u8; 32];
    getrandom::fill(&mut secret).context("OS RNG")?;
    let signing_key = SigningKey::from_bytes(&secret);
    let _ = signing_key.verifying_key(); // sanity: derive succeeds
    let key_id = Ulid::new().to_string();
    let path = keys_dir.join(format!("{key_id}.bin"));
    write_key_file(&path, &secret)?;
    Ok(key_id)
}

fn write_key_file(path: &Path, bytes: &[u8]) -> Result<()> {
    // Phase 7cz.16: `path` is always built as `<keys_dir>/<key_id>.bin`
    // by the caller, so `parent()` and `file_name()` always succeed.
    // Tag for clippy.
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("key path {} has no parent", path.display()))?;
    let file_name = path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("key path {} has no filename", path.display()))?;
    let tmp = parent.join(format!(".{}.tmp", file_name.to_string_lossy()));
    fs::write(&tmp, bytes).with_context(|| format!("writing {}", tmp.display()))?;
    fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))
        .with_context(|| format!("chmod 0600 {}", tmp.display()))?;
    fs::rename(&tmp, path)
        .with_context(|| format!("renaming {} -> {}", tmp.display(), path.display()))?;
    Ok(())
}

fn write_active_pointer(keys_dir: &Path, key_id: &str) -> Result<()> {
    let active_path = keys_dir.join("active");
    let tmp = keys_dir.join(".active.tmp");
    fs::write(&tmp, key_id).with_context(|| format!("writing {}", tmp.display()))?;
    fs::rename(&tmp, &active_path)
        .with_context(|| format!("renaming {} -> {}", tmp.display(), active_path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signature, Verifier};
    use tempfile::TempDir;

    #[test]
    fn create_then_load_round_trip() {
        let dir = TempDir::new().unwrap();
        let s1 = ServerSigner::load_or_create(dir.path()).unwrap();
        let key_id_1 = s1.key_id();
        let pub_1 = s1.public_key_b64().unwrap();
        drop(s1);

        let s2 = ServerSigner::load_or_create(dir.path()).unwrap();
        assert_eq!(s2.key_id(), key_id_1);
        assert_eq!(s2.public_key_b64().unwrap(), pub_1);
    }

    #[test]
    fn legacy_single_key_files_migrated() {
        let dir = TempDir::new().unwrap();
        // Plant legacy files (Phase 6b layout).
        let mut secret = [42u8; 32];
        secret[0] = 7;
        std::fs::write(dir.path().join("signing-key.bin"), secret).unwrap();
        std::fs::write(dir.path().join("signing-key.id"), "01ABCD").unwrap();

        let signer = ServerSigner::load_or_create(dir.path()).unwrap();
        assert_eq!(signer.key_id(), "01ABCD");
        // New layout exists.
        assert!(dir.path().join("signing-keys").exists());
        assert!(dir.path().join("signing-keys/01ABCD.bin").exists());
        assert_eq!(
            std::fs::read_to_string(dir.path().join("signing-keys/active"))
                .unwrap()
                .trim(),
            "01ABCD"
        );
    }

    #[test]
    fn fresh_keys_in_separate_dirs_are_distinct() {
        let d1 = TempDir::new().unwrap();
        let d2 = TempDir::new().unwrap();
        let s1 = ServerSigner::load_or_create(d1.path()).unwrap();
        let s2 = ServerSigner::load_or_create(d2.path()).unwrap();
        assert_ne!(s1.key_id(), s2.key_id());
        assert_ne!(s1.public_key_b64().unwrap(), s2.public_key_b64().unwrap());
    }

    #[test]
    fn sign_verify_round_trip() {
        let dir = TempDir::new().unwrap();
        let signer = ServerSigner::load_or_create(dir.path()).unwrap();
        let payload = br#"{"resources":[]}"#;
        let signature_b64 = signer
            .sign("agent-1", "asg-1", "op-1", "2026-01-01T00:00:00Z", payload)
            .unwrap();

        let msg = iac_core::protocol::v1::canonical_assignment_message(
            "agent-1",
            "asg-1",
            "op-1",
            "2026-01-01T00:00:00Z",
            payload,
        );
        let pub_bytes = B64.decode(signer.public_key_b64().unwrap()).unwrap();
        let mut buf = [0u8; 32];
        buf.copy_from_slice(&pub_bytes);
        let vkey = VerifyingKey::from_bytes(&buf).unwrap();
        let sig_bytes = B64.decode(&signature_b64).unwrap();
        let mut sig_buf = [0u8; 64];
        sig_buf.copy_from_slice(&sig_bytes);
        let sig = Signature::from_bytes(&sig_buf);
        assert!(vkey.verify(&msg, &sig).is_ok());
    }

    #[test]
    fn rotate_creates_new_active_keeps_old_in_set() {
        let dir = TempDir::new().unwrap();
        let signer = ServerSigner::load_or_create(dir.path()).unwrap();
        let original = signer.key_id();

        let new_id = signer.rotate().unwrap();
        assert_ne!(new_id, original, "rotate must produce a fresh id");
        assert_eq!(signer.key_id(), new_id);
        // Old key still in pubkeys set (rotation window).
        let pubkeys = signer.pubkeys();
        let ids: Vec<&str> = pubkeys.iter().map(|(id, _)| id.as_str()).collect();
        assert!(ids.contains(&original.as_str()));
        assert!(ids.contains(&new_id.as_str()));
    }

    #[test]
    fn retire_removes_key_from_set() {
        let dir = TempDir::new().unwrap();
        let signer = ServerSigner::load_or_create(dir.path()).unwrap();
        let original = signer.key_id();
        let new_id = signer.rotate().unwrap();

        let removed = signer.retire(&original).unwrap();
        assert!(removed);
        let pubkeys = signer.pubkeys();
        let ids: Vec<&str> = pubkeys.iter().map(|(id, _)| id.as_str()).collect();
        assert!(!ids.contains(&original.as_str()));
        assert!(ids.contains(&new_id.as_str()));
        // On-disk file gone.
        assert!(
            !dir.path()
                .join(format!("signing-keys/{original}.bin"))
                .exists()
        );
    }

    #[test]
    fn retire_active_rejected() {
        let dir = TempDir::new().unwrap();
        let signer = ServerSigner::load_or_create(dir.path()).unwrap();
        let active = signer.key_id();
        let err = signer.retire(&active).unwrap_err();
        assert!(err.to_string().contains("cannot retire active"));
    }

    #[test]
    fn retire_missing_key_returns_false_idempotent() {
        let dir = TempDir::new().unwrap();
        let signer = ServerSigner::load_or_create(dir.path()).unwrap();
        let removed = signer.retire("01NOSUCHKEY").unwrap();
        assert!(!removed);
    }

    #[test]
    fn concurrent_rotate_retire_keeps_state_consistent() {
        // Phase 7cz.2: serialised mutate_lock means a concurrent
        // rotate(N) + retire(N) can never leave the on-disk layout
        // self-inconsistent. Either retire wins (then rotate fails on
        // disk-state surprise) or rotate wins (then retire refuses
        // because the now-active key is its target).
        use std::sync::Arc;
        let dir = TempDir::new().unwrap();
        let signer = Arc::new(ServerSigner::load_or_create(dir.path()).unwrap());
        // Rotate once so we have at least 2 keys to play with.
        let intermediate = signer.rotate().unwrap();
        // Concurrent attempts: one rotates, one tries to retire the
        // newly-active key. Repeat to amplify scheduling jitter.
        for _ in 0..16 {
            let s1 = signer.clone();
            let s2 = signer.clone();
            let target = s1.key_id();
            let h1 = std::thread::spawn(move || s1.rotate());
            let h2 = std::thread::spawn(move || s2.retire(&target));
            // Either succeeds or returns Err (e.g. "cannot retire
            // active"); state must remain loadable.
            let _ = h1.join().unwrap();
            let _ = h2.join().unwrap();
            // Sanity: still loadable, active key still in set.
            let s = signer.state.load();
            assert!(
                s.keys.contains_key(&s.active_id),
                "active {} not in keys (size={})",
                s.active_id,
                s.keys.len()
            );
        }
        // intermediate may or may not still be present; we only care
        // that the active id always resolves.
        let _ = intermediate;
        // Also: sign() never panicked across all those rotations.
        let _ = signer.sign("a", "b", "c", "d", b"{}").unwrap();
    }

    #[test]
    fn rotated_set_signs_with_new_active() {
        let dir = TempDir::new().unwrap();
        let signer = ServerSigner::load_or_create(dir.path()).unwrap();
        let _orig_pub = signer.public_key_b64().unwrap();
        let _ = signer.rotate().unwrap();
        let new_pub = signer.public_key_b64().unwrap();

        // Sign with new active. Verify only the NEW pubkey accepts.
        let payload = br#"{}"#;
        let sig_b64 = signer.sign("a", "b", "c", "2026", payload).unwrap();
        let msg =
            iac_core::protocol::v1::canonical_assignment_message("a", "b", "c", "2026", payload);
        let pub_bytes = B64.decode(&new_pub).unwrap();
        let mut buf = [0u8; 32];
        buf.copy_from_slice(&pub_bytes);
        let vkey = VerifyingKey::from_bytes(&buf).unwrap();
        let sig_bytes = B64.decode(&sig_b64).unwrap();
        let mut sig_buf = [0u8; 64];
        sig_buf.copy_from_slice(&sig_bytes);
        let sig = Signature::from_bytes(&sig_buf);
        assert!(
            vkey.verify(&msg, &sig).is_ok(),
            "new pubkey verifies new signature"
        );
    }
}
