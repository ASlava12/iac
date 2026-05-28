//! Filesystem operations for the `file` provider: observe, diff, apply, rollback.
//!
//! Atomicity: writes go to a tempfile in the same directory, then `rename(2)`.
//! `chown(2)` / `chmod(2)` are applied to the temp file before the rename so
//! a reader never sees the file with wrong permissions.

use super::spec::{FileSpec, FileState, parse_mode};
use iac_core::{
    Error, Result,
    diff::{Diff, DiffKind, FieldChange},
    hash::{sha256_hex, sha256_hex_reader},
    operation::StepResult,
    state::ObservedState,
};
use indexmap::IndexMap;
use serde_json::{Value as Json, json};
use serde_yaml_ng::Value as YamlValue;
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

const BACKUP_FILENAME: &str = "backup.bin";

// Windows-portability shims: the `file` provider is *nix-targeted
// (chmod/chown/mode/uid/gid are POSIX concepts), but the crate must
// compile on Windows so the CLI ships there. On Windows, ownership
// and mode info is reported as 0 and chown/chmod become no-ops; the
// agent never runs on Windows, so this only affects validate-time
// paths in the CLI.
#[cfg(unix)]
fn file_mode(meta: &fs::Metadata) -> u32 {
    meta.permissions().mode() & 0o7777
}
#[cfg(not(unix))]
fn file_mode(_meta: &fs::Metadata) -> u32 {
    0
}

#[cfg(unix)]
fn file_uid(meta: &fs::Metadata) -> u32 {
    meta.uid()
}
#[cfg(not(unix))]
fn file_uid(_meta: &fs::Metadata) -> u32 {
    0
}

#[cfg(unix)]
fn file_gid(meta: &fs::Metadata) -> u32 {
    meta.gid()
}
#[cfg(not(unix))]
fn file_gid(_meta: &fs::Metadata) -> u32 {
    0
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> std::io::Result<()> {
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
}
#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) -> std::io::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn set_owner(path: &Path, uid: Option<u32>, gid: Option<u32>) -> std::io::Result<()> {
    std::os::unix::fs::chown(path, uid, gid)
}
#[cfg(not(unix))]
fn set_owner(_path: &Path, _uid: Option<u32>, _gid: Option<u32>) -> std::io::Result<()> {
    Ok(())
}

pub fn observe(spec: &FileSpec) -> Result<ObservedState> {
    let path = &spec.path;
    let meta = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(ObservedState::absent()),
        Err(e) => {
            return Err(Error::Io {
                path: path.clone(),
                source: e,
            });
        }
    };

    let mut facts: IndexMap<String, YamlValue> = IndexMap::new();
    facts.insert(
        "kind".into(),
        YamlValue::String(file_kind_label(&meta).to_string()),
    );

    if !meta.file_type().is_file() {
        // Refuse to manage non-regular paths; report present-but-mismatched.
        facts.insert("present_but_not_regular".into(), YamlValue::Bool(true));
        return Ok(ObservedState {
            present: true,
            spec: YamlValue::Null,
            facts,
            observed_at: jiff::Timestamp::now(),
        });
    }

    // Stream the file through the hasher rather than slurping it into
    // a Vec — `observe` runs on every cycle for every managed file, and
    // the content is only needed to derive the sha (it's never
    // returned). A multi-GB managed file (log, DB dump, disk image)
    // would otherwise spike the agent's RSS by its full size each tick.
    let file = fs::File::open(path).map_err(|e| Error::Io {
        path: path.clone(),
        source: e,
    })?;
    let sha = sha256_hex_reader(std::io::BufReader::new(file)).map_err(|e| Error::Io {
        path: path.clone(),
        source: e,
    })?;
    let mode = file_mode(&meta);
    let uid = file_uid(&meta);
    let gid = file_gid(&meta);
    let size = meta.len();

    let mut spec_value = serde_yaml_ng::Mapping::new();
    spec_value.insert("path".into(), YamlValue::String(path.display().to_string()));
    spec_value.insert("state".into(), YamlValue::String("present".into()));
    spec_value.insert("mode".into(), YamlValue::String(format!("0{mode:o}")));
    spec_value.insert(
        "owner_uid".into(),
        YamlValue::Number(serde_yaml_ng::Number::from(uid)),
    );
    spec_value.insert(
        "group_gid".into(),
        YamlValue::Number(serde_yaml_ng::Number::from(gid)),
    );
    spec_value.insert("content_sha256".into(), YamlValue::String(sha.clone()));
    spec_value.insert(
        "size".into(),
        YamlValue::Number(serde_yaml_ng::Number::from(size)),
    );

    facts.insert("content_sha256".into(), YamlValue::String(sha));
    facts.insert(
        "size".into(),
        YamlValue::Number(serde_yaml_ng::Number::from(size)),
    );
    facts.insert("mode".into(), YamlValue::String(format!("0{mode:o}")));
    facts.insert(
        "uid".into(),
        YamlValue::Number(serde_yaml_ng::Number::from(uid)),
    );
    facts.insert(
        "gid".into(),
        YamlValue::Number(serde_yaml_ng::Number::from(gid)),
    );

    Ok(ObservedState {
        present: true,
        spec: YamlValue::Mapping(spec_value),
        facts,
        observed_at: jiff::Timestamp::now(),
    })
}

fn file_kind_label(meta: &fs::Metadata) -> &'static str {
    let ft = meta.file_type();
    if ft.is_file() {
        "regular"
    } else if ft.is_dir() {
        "directory"
    } else if ft.is_symlink() {
        "symlink"
    } else {
        "other"
    }
}

pub fn diff(spec: &FileSpec, observed: &ObservedState) -> Diff {
    let mut changes: Vec<FieldChange> = Vec::new();
    let mut reasons: Vec<String> = Vec::new();

    match (spec.state, observed.present) {
        (FileState::Absent, false) => return Diff::no_change(),
        (FileState::Absent, true) => {
            return Diff {
                kind: DiffKind::Update,
                changes: vec![FieldChange {
                    field: "state".into(),
                    from: Some(YamlValue::String("present".into())),
                    to: Some(YamlValue::String("absent".into())),
                    sensitive: false,
                }],
                reasons: vec!["file should be absent but exists".into()],
                reversible: true,
            };
        }
        (FileState::Present, false) => {
            return Diff {
                kind: DiffKind::Create,
                changes: vec![FieldChange {
                    field: "state".into(),
                    from: Some(YamlValue::String("absent".into())),
                    to: Some(YamlValue::String("present".into())),
                    sensitive: false,
                }],
                reasons: vec!["file should be present but is missing".into()],
                reversible: true,
            };
        }
        (FileState::Present, true) => {
            // fall through to field-by-field comparison
        }
    }

    // Both want present; compare fields.
    let observed_facts = &observed.facts;

    if let Some(want) = spec.content.as_ref() {
        let want_sha = sha256_hex(want.as_bytes());
        let have_sha = observed_facts
            .get("content_sha256")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        if want_sha != have_sha {
            changes.push(FieldChange {
                field: "content_sha256".into(),
                from: Some(YamlValue::String(have_sha)),
                to: Some(YamlValue::String(want_sha)),
                sensitive: false,
            });
            reasons.push("content sha256 differs".into());
        }
    }

    if let Some(want_mode) = spec.parsed_mode() {
        let have_mode_str = observed_facts
            .get("mode")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let have_mode = parse_mode(have_mode_str.trim_start_matches('0')).unwrap_or(0);
        if want_mode != have_mode {
            changes.push(FieldChange {
                field: "mode".into(),
                from: Some(YamlValue::String(format!("0{have_mode:o}"))),
                to: Some(YamlValue::String(format!("0{want_mode:o}"))),
                sensitive: false,
            });
            reasons.push(format!("mode 0{have_mode:o} -> 0{want_mode:o}"));
        }
    }

    if let Some(owner) = spec.owner.as_deref() {
        match resolve_uid(owner) {
            Ok(want_uid) => {
                let have_uid = observed_facts
                    .get("uid")
                    .and_then(YamlValue::as_u64)
                    .unwrap_or(0) as u32;
                if want_uid != have_uid {
                    changes.push(FieldChange {
                        field: "owner".into(),
                        from: Some(YamlValue::Number(serde_yaml_ng::Number::from(have_uid))),
                        to: Some(YamlValue::String(owner.into())),
                        sensitive: false,
                    });
                    reasons.push(format!("owner uid {have_uid} -> {want_uid}"));
                }
            }
            Err(e) => reasons.push(format!("could not resolve owner {owner:?}: {e}")),
        }
    }

    if let Some(group) = spec.group.as_deref() {
        match resolve_gid(group) {
            Ok(want_gid) => {
                let have_gid = observed_facts
                    .get("gid")
                    .and_then(YamlValue::as_u64)
                    .unwrap_or(0) as u32;
                if want_gid != have_gid {
                    changes.push(FieldChange {
                        field: "group".into(),
                        from: Some(YamlValue::Number(serde_yaml_ng::Number::from(have_gid))),
                        to: Some(YamlValue::String(group.into())),
                        sensitive: false,
                    });
                    reasons.push(format!("group gid {have_gid} -> {want_gid}"));
                }
            }
            Err(e) => reasons.push(format!("could not resolve group {group:?}: {e}")),
        }
    }

    if changes.is_empty() {
        Diff::no_change()
    } else {
        Diff {
            kind: DiffKind::Update,
            changes,
            reasons,
            reversible: true,
        }
    }
}

pub fn write(spec: &FileSpec) -> Result<StepResult> {
    let path = &spec.path;
    let parent = path.parent().ok_or_else(|| {
        Error::provider("file", format!("path has no parent: {}", path.display()))
    })?;
    if !parent.exists() {
        fs::create_dir_all(parent).map_err(|e| Error::Io {
            path: parent.into(),
            source: e,
        })?;
    }

    let content = spec.content.clone().unwrap_or_default();

    // Resolve owner/group up front so both backends see the same
    // arguments — Unix passes them to fchown, Windows path ignores them.
    let uid = spec
        .owner
        .as_deref()
        .map(resolve_uid)
        .transpose()
        .map_err(|e| Error::provider("file", format!("owner resolution failed: {e}")))?;
    let gid = spec
        .group
        .as_deref()
        .map(resolve_gid)
        .transpose()
        .map_err(|e| Error::provider("file", format!("group resolution failed: {e}")))?;
    let mode = spec.parsed_mode();

    #[cfg(unix)]
    write_atomic_unix(path, parent, content.as_bytes(), mode, uid, gid)?;

    #[cfg(not(unix))]
    write_legacy_non_unix(path, parent, content.as_bytes(), mode, uid, gid)?;

    let sha = sha256_hex(content.as_bytes());
    Ok(StepResult {
        status: iac_core::operation::StepStatus::Succeeded,
        message: format!("wrote {} ({} bytes)", path.display(), content.len()),
        data: json!({ "path": path, "content_sha256": sha, "bytes": content.len() }),
        error: None,
    })
}

/// Phase 9 follow-up #20: TOCTOU-safe apply path. The previous code
/// did `fs::symlink_metadata(path)` + `fs::write(tmp)` + `fs::rename`
/// against paths re-resolved at every syscall, leaving a window where
/// an attacker on the target host could plant a symlink between the
/// check and the rename and steer the write to a sensitive location.
///
/// We now anchor every step to a parent-directory fd opened with
/// `O_DIRECTORY | O_NOFOLLOW` and call `fstatat` / `openat` /
/// `renameat` with `AT_SYMLINK_NOFOLLOW`. Once the parent fd is in
/// hand, an attacker can't substitute a different inode without
/// also winning a race against open() — and even then the
/// `O_NOFOLLOW` flag on every reopened entry refuses to traverse
/// any newly-planted symlink. The rename is `renameat` within that
/// same fd, so the swap can't drift to a different directory.
///
/// Returns an `Err` on any of:
///   * the parent path itself being a symlink (we never traverse one)
///   * the existing target being a symlink or directory
///   * the tmpfile name colliding with an attacker-placed entry
///     (O_EXCL guarantees we own the tmp inode)
///   * an underlying syscall error (ENOENT, EPERM, ENOSPC, …)
#[cfg(unix)]
fn write_atomic_unix(
    path: &Path,
    parent: &Path,
    content: &[u8],
    mode: Option<u32>,
    uid: Option<u32>,
    gid: Option<u32>,
) -> Result<()> {
    use rustix::fs::{AtFlags, FileType, Mode, OFlags, openat, renameat, statat};
    use std::io::Write;
    use std::os::fd::AsFd;

    let basename = path
        .file_name()
        .ok_or_else(|| {
            Error::provider("file", format!("path has no file name: {}", path.display()))
        })?
        .to_owned();

    // Step 1: open the parent directory with O_DIRECTORY | O_NOFOLLOW.
    // If the parent path itself is a symlink we refuse — the operator
    // wrote a manifest pointing at a managed dir, not at "the thing a
    // symlink elsewhere on the system happens to point at right now".
    // CWD-relative parents are resolved here once and then frozen as
    // an fd; no later syscall re-walks the parent path.
    let parent_fd = rustix::fs::open(
        parent,
        OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| Error::Io {
        path: parent.into(),
        source: errno_to_io(e),
    })?;

    // Step 2: stat the existing target under the pinned parent fd
    // with AT_SYMLINK_NOFOLLOW. Refuse symlinks and directories the
    // same way the legacy code did — but with no second syscall to
    // re-resolve `path`, so an attacker can't race a symlink in
    // between this check and the rename.
    match statat(&parent_fd, &basename, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) => {
            let ft = FileType::from_raw_mode(stat.st_mode);
            if ft == FileType::Symlink {
                return Err(Error::provider(
                    "file",
                    format!(
                        "refusing to write through symlink at {}: \
                         remove the symlink first or change the manifest path. \
                         A symlink at this location often signals an attacker-planted \
                         redirect aimed at privilege escalation.",
                        path.display()
                    ),
                ));
            }
            if ft == FileType::Directory {
                return Err(Error::provider(
                    "file",
                    format!(
                        "{} is a directory, not a file — refusing to overwrite",
                        path.display()
                    ),
                ));
            }
        }
        Err(rustix::io::Errno::NOENT) => {
            // Absent target is the create case — fall through.
        }
        Err(e) => {
            return Err(Error::Io {
                path: path.into(),
                source: errno_to_io(e),
            });
        }
    }

    // Step 3: create the tempfile inside the parent fd with
    // O_CREAT | O_EXCL | O_NOFOLLOW. EXCL means we own the inode
    // outright; if a sibling races us to that exact ULID name we
    // surface the conflict instead of silently appending.
    let tmp_name = {
        let stem = basename.to_string_lossy();
        let ulid = ulid::Ulid::new();
        format!(".{stem}.iac.{ulid}.tmp")
    };
    let tmp_fd = openat(
        &parent_fd,
        tmp_name.as_str(),
        OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::WRONLY | OFlags::CLOEXEC,
        Mode::from_bits_truncate(0o600),
    )
    .map_err(|e| Error::Io {
        path: parent.join(&tmp_name),
        source: errno_to_io(e),
    })?;
    let mut tmp_file = std::fs::File::from(tmp_fd);
    tmp_file.write_all(content).map_err(|e| Error::Io {
        path: parent.join(&tmp_name),
        source: e,
    })?;
    tmp_file.sync_all().map_err(|e| Error::Io {
        path: parent.join(&tmp_name),
        source: e,
    })?;

    // Step 4: fchmod / fchown via the tempfile fd, then drop the
    // file handle (close) so readers can't observe the partial state.
    // Doing this BEFORE the rename means a reader hitting `path` only
    // sees the final perms / owner (and never the tmpfile).
    if let Some(mode) = mode {
        rustix::fs::fchmod(tmp_file.as_fd(), Mode::from_bits_truncate(mode)).map_err(|e| {
            Error::Io {
                path: parent.join(&tmp_name),
                source: errno_to_io(e),
            }
        })?;
    }
    if uid.is_some() || gid.is_some() {
        rustix::fs::fchown(
            tmp_file.as_fd(),
            uid.map(rustix::fs::Uid::from_raw),
            gid.map(rustix::fs::Gid::from_raw),
        )
        .map_err(|e| Error::Io {
            path: parent.join(&tmp_name),
            source: errno_to_io(e),
        })?;
    }
    drop(tmp_file);

    // Step 5: atomic rename within parent_fd. POSIX rename(2)
    // guarantees the swap is atomic on the same filesystem; doing it
    // through `renameat` against our pinned fd means the destination
    // can't be re-routed by a symlink planted at the parent dir
    // level either.
    renameat(&parent_fd, tmp_name.as_str(), &parent_fd, &basename).map_err(|e| Error::Io {
        path: path.into(),
        source: errno_to_io(e),
    })?;

    Ok(())
}

#[cfg(unix)]
fn errno_to_io(e: rustix::io::Errno) -> std::io::Error {
    std::io::Error::from_raw_os_error(e.raw_os_error())
}

/// Non-Unix fallback: same shape as the old apply path. We don't have
/// `openat`/`renameat` outside Unix; the file provider isn't a
/// production target on Windows in any case (agent only runs on Unix).
#[cfg(not(unix))]
fn write_legacy_non_unix(
    path: &Path,
    parent: &Path,
    content: &[u8],
    mode: Option<u32>,
    uid: Option<u32>,
    gid: Option<u32>,
) -> Result<()> {
    if let Ok(md) = fs::symlink_metadata(path) {
        if md.file_type().is_symlink() {
            return Err(Error::provider(
                "file",
                format!("refusing to write through symlink at {}", path.display()),
            ));
        }
        if md.file_type().is_dir() {
            return Err(Error::provider(
                "file",
                format!(
                    "{} is a directory, not a file — refusing to overwrite",
                    path.display()
                ),
            ));
        }
    }
    let tmp = temp_path_in(parent, path);
    fs::write(&tmp, content).map_err(|e| Error::Io {
        path: tmp.clone(),
        source: e,
    })?;
    if let Some(mode) = mode {
        set_mode(&tmp, mode).map_err(|e| Error::Io {
            path: tmp.clone(),
            source: e,
        })?;
    }
    if uid.is_some() || gid.is_some() {
        set_owner(&tmp, uid, gid).map_err(|e| Error::Io {
            path: tmp.clone(),
            source: e,
        })?;
    }
    fs::rename(&tmp, path).map_err(|e| Error::Io {
        path: path.into(),
        source: e,
    })?;
    Ok(())
}

pub fn delete(path: &Path) -> Result<StepResult> {
    match fs::remove_file(path) {
        Ok(()) => Ok(StepResult::ok(format!("deleted {}", path.display()))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(StepResult::skipped(format!(
            "{} already absent",
            path.display()
        ))),
        Err(e) => Err(Error::Io {
            path: path.into(),
            source: e,
        }),
    }
}

pub fn backup(path: &Path, workspace: &Path) -> Result<Json> {
    fs::create_dir_all(workspace).map_err(|e| Error::Io {
        path: workspace.into(),
        source: e,
    })?;

    let meta = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(json!({ "existed": false, "path": path }));
        }
        Err(e) => {
            return Err(Error::Io {
                path: path.into(),
                source: e,
            });
        }
    };

    if !meta.file_type().is_file() {
        return Err(Error::provider(
            "file",
            format!("refusing to back up non-regular file {}", path.display()),
        ));
    }

    let backup = workspace.join(BACKUP_FILENAME);
    fs::copy(path, &backup).map_err(|e| Error::Io {
        path: backup.clone(),
        source: e,
    })?;
    Ok(json!({
        "existed": true,
        "path": path,
        "backup": BACKUP_FILENAME,
        "mode": format!("0{:o}", file_mode(&meta)),
        "uid": file_uid(&meta),
        "gid": file_gid(&meta),
        "size": meta.len(),
    }))
}

/// Restore the file represented by `target_path` to whatever state was
/// snapshotted in `checkpoint_data`. **Critically, `target_path` is taken
/// from the live resource spec — never from the checkpoint JSON — so a
/// tampered checkpoint cannot redirect the restore to an arbitrary path.**
///
/// Phase 7cz.1: pre-7cz the path was read from `checkpoint_data["path"]`,
/// which an attacker with write access to the operations DB could rewrite
/// to `/etc/cron.d/evil` or `/root/.ssh/authorized_keys`. The signed-
/// envelope mechanism that protects assignments doesn't extend to
/// checkpoints, so the path field was effectively unauthenticated.
///
/// We still cross-check `checkpoint_data["path"]` against `target_path`
/// when present and refuse on mismatch — that catches operator-side bugs
/// (passing the wrong checkpoint to the wrong resource) and gives a
/// loud audit signal if someone *did* tamper with the row.
pub fn restore(target_path: &Path, checkpoint_data: &Json, workspace: &Path) -> Result<()> {
    if let Some(stored_path) = checkpoint_data.get("path").and_then(Json::as_str)
        && Path::new(stored_path) != target_path
    {
        return Err(Error::provider(
            "file",
            format!(
                "checkpoint path mismatch: stored={stored_path:?} but resource path={:?} \
                 (refusing to restore — possible tampered checkpoint)",
                target_path.display()
            ),
        ));
    }
    let existed = checkpoint_data
        .get("existed")
        .and_then(Json::as_bool)
        .unwrap_or(false);

    if !existed {
        match fs::remove_file(target_path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(Error::Io {
                path: target_path.to_path_buf(),
                source: e,
            }),
        }
    } else {
        let backup_name = checkpoint_data
            .get("backup")
            .and_then(Json::as_str)
            .unwrap_or(BACKUP_FILENAME);
        // Defence-in-depth: backup_name is meant to be a flat filename
        // produced by `backup()` (always BACKUP_FILENAME today). If it
        // contains a path separator or `..`, refuse — never let it
        // escape `workspace`.
        if backup_name.contains('/') || backup_name.contains('\\') || backup_name.contains("..") {
            return Err(Error::provider(
                "file",
                format!("checkpoint backup name {backup_name:?} contains path separators"),
            ));
        }
        let backup = workspace.join(backup_name);
        if !backup.exists() {
            return Err(Error::provider(
                "file",
                format!("backup file {} not found", backup.display()),
            ));
        }
        let parent = target_path.parent().ok_or_else(|| {
            Error::provider(
                "file",
                format!("path has no parent: {}", target_path.display()),
            )
        })?;
        if !parent.exists() {
            fs::create_dir_all(parent).map_err(|e| Error::Io {
                path: parent.into(),
                source: e,
            })?;
        }
        let tmp = temp_path_in(parent, target_path);
        fs::copy(&backup, &tmp).map_err(|e| Error::Io {
            path: tmp.clone(),
            source: e,
        })?;

        if let Some(mode_str) = checkpoint_data.get("mode").and_then(Json::as_str)
            && let Ok(mode) = parse_mode(mode_str.trim_start_matches('0'))
        {
            let _ = set_mode(&tmp, mode);
        }
        let uid = checkpoint_data
            .get("uid")
            .and_then(Json::as_u64)
            .and_then(|n| u32::try_from(n).ok());
        let gid = checkpoint_data
            .get("gid")
            .and_then(Json::as_u64)
            .and_then(|n| u32::try_from(n).ok());
        if uid.is_some() || gid.is_some() {
            let _ = set_owner(&tmp, uid, gid);
        }

        fs::rename(&tmp, target_path).map_err(|e| Error::Io {
            path: target_path.to_path_buf(),
            source: e,
        })?;
        Ok(())
    }
}

fn temp_path_in(dir: &Path, target: &Path) -> PathBuf {
    let stem = target
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "tmp".to_string());
    let ulid = ulid::Ulid::new();
    dir.join(format!(".{stem}.iac.{ulid}.tmp"))
}

// --- user / group resolution --------------------------------------------------

pub fn resolve_uid(spec: &str) -> std::result::Result<u32, String> {
    if let Ok(n) = spec.parse::<u32>() {
        return Ok(n);
    }
    let content = fs::read_to_string("/etc/passwd").map_err(|e| e.to_string())?;
    for line in content.lines() {
        // name:x:uid:gid:gecos:home:shell
        let mut parts = line.splitn(7, ':');
        let name = parts.next().unwrap_or("");
        let _ = parts.next();
        let uid = parts.next().unwrap_or("");
        if name == spec {
            return uid
                .parse::<u32>()
                .map_err(|e| format!("bad uid for {name}: {e}"));
        }
    }
    Err(format!("user {spec:?} not found in /etc/passwd"))
}

pub fn resolve_gid(spec: &str) -> std::result::Result<u32, String> {
    if let Ok(n) = spec.parse::<u32>() {
        return Ok(n);
    }
    let content = fs::read_to_string("/etc/group").map_err(|e| e.to_string())?;
    for line in content.lines() {
        // name:x:gid:members
        let mut parts = line.splitn(4, ':');
        let name = parts.next().unwrap_or("");
        let _ = parts.next();
        let gid = parts.next().unwrap_or("");
        if name == spec {
            return gid
                .parse::<u32>()
                .map_err(|e| format!("bad gid for {name}: {e}"));
        }
    }
    Err(format!("group {spec:?} not found in /etc/group"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use iac_core::provider::Provider;
    use iac_core::resource::{API_VERSION, Metadata, Resource, SourceLocation};
    use serde_yaml_ng::Mapping;
    use tempfile::TempDir;

    fn mk_resource(spec: serde_yaml_ng::Value) -> Resource {
        Resource {
            api_version: API_VERSION.into(),
            kind: "file".into(),
            metadata: Metadata {
                name: "test".into(),
                environment: "test".into(),
                owner: None,
                labels: Default::default(),
                annotations: Default::default(),
            },
            spec,
            policy: serde_yaml_ng::Value::Null,
            source: SourceLocation::default(),
        }
    }

    fn ws() -> TempDir {
        TempDir::new().unwrap()
    }

    #[test]
    fn observe_absent() {
        let dir = ws();
        let path = dir.path().join("nope");
        let mut spec = Mapping::new();
        spec.insert("path".into(), path.display().to_string().into());
        let resource = mk_resource(spec.into());
        let provider = super::super::FileProvider::new();
        let observed = provider.observe(&resource).unwrap();
        assert!(!observed.present);
    }

    #[test]
    fn create_then_idempotent_then_delete() {
        let dir = ws();
        let target = dir.path().join("greeting");

        let mut spec = Mapping::new();
        spec.insert("path".into(), target.display().to_string().into());
        spec.insert("content".into(), "hello\n".into());
        spec.insert("mode".into(), "0644".into());
        let resource = mk_resource(spec.clone().into());

        let provider = super::super::FileProvider::new();

        // Plan should produce a write step on first observe.
        let observed = provider.observe(&resource).unwrap();
        let diff = provider.diff(&resource, &observed).unwrap();
        assert_eq!(diff.kind, DiffKind::Create);

        let steps = provider.plan(&resource, &diff).unwrap();
        assert_eq!(steps.len(), 1);
        assert_eq!(steps[0].action, "file.write");

        // Apply.
        let workspace = dir.path().join("ws-create");
        fs::create_dir_all(&workspace).unwrap();
        let ctx = iac_core::ApplyContext {
            operation_id: ulid::Ulid::new(),
            workspace: workspace.clone(),
        };
        let pre = provider.pre_apply(&resource, &steps[0], &ctx).unwrap();
        assert_eq!(pre.get("existed").unwrap(), &json!(false));
        let result = provider.apply(&resource, &steps[0], &ctx).unwrap();
        assert_eq!(result.status, iac_core::operation::StepStatus::Succeeded);
        assert_eq!(fs::read_to_string(&target).unwrap(), "hello\n");

        // Verify.
        let v = provider.verify(&resource).unwrap();
        assert!(v.is_match());

        // Re-plan should be NoChange.
        let observed = provider.observe(&resource).unwrap();
        let diff2 = provider.diff(&resource, &observed).unwrap();
        assert_eq!(diff2.kind, DiffKind::NoChange);

        // Now flip to absent and expect a delete step.
        let mut spec2 = Mapping::new();
        spec2.insert("path".into(), target.display().to_string().into());
        spec2.insert("state".into(), "absent".into());
        let resource2 = mk_resource(spec2.into());
        let observed = provider.observe(&resource2).unwrap();
        let diff3 = provider.diff(&resource2, &observed).unwrap();
        assert_eq!(diff3.kind, DiffKind::Update);
        let steps2 = provider.plan(&resource2, &diff3).unwrap();
        assert_eq!(steps2[0].action, "file.delete");
        let ws2 = dir.path().join("ws-del");
        fs::create_dir_all(&ws2).unwrap();
        let ctx2 = iac_core::ApplyContext {
            operation_id: ulid::Ulid::new(),
            workspace: ws2,
        };
        let _pre = provider.pre_apply(&resource2, &steps2[0], &ctx2).unwrap();
        let r = provider.apply(&resource2, &steps2[0], &ctx2).unwrap();
        assert_eq!(r.status, iac_core::operation::StepStatus::Succeeded);
        assert!(!target.exists());
    }

    #[test]
    fn rollback_restores_previous_content() {
        use iac_core::operation::Checkpoint;
        let dir = ws();
        let target = dir.path().join("file.conf");
        fs::write(&target, b"original\n").unwrap();
        let mut perms = fs::metadata(&target).unwrap().permissions();
        perms.set_mode(0o600);
        fs::set_permissions(&target, perms).unwrap();

        let mut spec = Mapping::new();
        spec.insert("path".into(), target.display().to_string().into());
        spec.insert("content".into(), "new content\n".into());
        spec.insert("mode".into(), "0644".into());
        let resource = mk_resource(spec.into());
        let provider = super::super::FileProvider::new();

        let observed = provider.observe(&resource).unwrap();
        let diff = provider.diff(&resource, &observed).unwrap();
        assert_eq!(diff.kind, DiffKind::Update);
        let steps = provider.plan(&resource, &diff).unwrap();

        let workspace = dir.path().join("ws");
        fs::create_dir_all(&workspace).unwrap();
        let ctx = iac_core::ApplyContext {
            operation_id: ulid::Ulid::new(),
            workspace: workspace.clone(),
        };

        let cp_data = provider.pre_apply(&resource, &steps[0], &ctx).unwrap();
        provider.apply(&resource, &steps[0], &ctx).unwrap();
        assert_eq!(fs::read_to_string(&target).unwrap(), "new content\n");

        let cp = Checkpoint::new(resource.id(), ctx.operation_id, cp_data);
        provider.rollback(&resource, &cp, &workspace).unwrap();
        assert_eq!(fs::read_to_string(&target).unwrap(), "original\n");
        let mode = fs::metadata(&target).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn restore_rejects_tampered_checkpoint_path() {
        // Phase 7cz.1: a tampered checkpoint claiming to restore a
        // legitimate-looking file (`/etc/hosts.bak`) onto a sensitive
        // target path must not redirect the rename. We pass the
        // *resource's* path to `restore()`, and the checkpoint's
        // `path` field is only consulted as a sanity-check —
        // mismatched paths are rejected.
        let dir = ws();
        let workspace = dir.path().join("ws");
        fs::create_dir_all(&workspace).unwrap();
        // Plant a backup blob the attacker would want copied somewhere.
        fs::write(workspace.join(BACKUP_FILENAME), b"attacker-payload\n").unwrap();
        let target = dir.path().join("legitimate.conf");
        let attacker_target = dir.path().join("etc-cron-d-evil");
        let cp = json!({
            "existed": true,
            "path": attacker_target.display().to_string(),
            "backup": BACKUP_FILENAME,
        });
        let err = restore(&target, &cp, &workspace).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("checkpoint path mismatch") || msg.contains("tampered"),
            "expected mismatch error, got: {msg}"
        );
        // Crucial: neither file was created.
        assert!(!target.exists());
        assert!(!attacker_target.exists());
    }

    #[test]
    fn restore_rejects_path_separator_in_backup_name() {
        // Phase 7cz.1: backup filename comes from the checkpoint and is
        // joined to `workspace`. A `..` segment or absolute path would
        // let an attacker read arbitrary files via the rename copy.
        let dir = ws();
        let workspace = dir.path().join("ws");
        fs::create_dir_all(&workspace).unwrap();
        let target = dir.path().join("greeting");
        let cp = json!({
            "existed": true,
            "path": target.display().to_string(),
            "backup": "../../../etc/passwd",
        });
        let err = restore(&target, &cp, &workspace).unwrap_err();
        assert!(err.to_string().contains("path separators"), "got: {err}");
    }

    #[test]
    fn write_refuses_symlink_target() {
        // Phase 7cr (security fix #4.9): a symlink at the manifest's
        // path means an attacker (low-priv user on the target) is
        // trying to redirect a root-driven write to a sensitive
        // file. The provider must refuse, not follow the link.
        let dir = ws();
        let victim = dir.path().join("victim.txt");
        std::fs::write(&victim, b"original sensitive content\n").unwrap();
        let attacker_managed = dir.path().join("managed.conf");
        std::os::unix::fs::symlink(&victim, &attacker_managed).unwrap();

        let spec = FileSpec {
            path: attacker_managed.clone(),
            content: Some("malicious content\n".into()),
            mode: Some("0644".into()),
            owner: None,
            group: None,
            state: super::super::spec::FileState::Present,
        };
        let result = write(&spec);
        assert!(result.is_err(), "expected symlink rejection");
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("symlink") || msg.contains("refusing"),
            "unexpected error: {msg}"
        );
        // Victim must still hold its original content.
        assert_eq!(
            std::fs::read_to_string(&victim).unwrap(),
            "original sensitive content\n"
        );
    }

    #[cfg(unix)]
    #[test]
    fn write_refuses_symlinked_parent_directory() {
        // Phase 9 follow-up #20: when the parent directory of the
        // target is itself a symlink, the previous `fs::*` apply path
        // silently traversed it (rename(2) follows the parent
        // component normally) — letting an attacker who controls a
        // writable directory on the box redirect the whole write into
        // some other tree by replacing the operator's stated parent
        // with a symlink to attacker-chosen ground. The openat path
        // opens the parent with O_NOFOLLOW; a parent symlink now
        // surfaces as an explicit ELOOP-style error instead.
        let dir = ws();
        let real_parent = dir.path().join("real");
        std::fs::create_dir(&real_parent).unwrap();
        let attacker_target = dir.path().join("attacker_target");
        std::fs::create_dir(&attacker_target).unwrap();
        let symlinked_parent = dir.path().join("operator_managed_dir");
        std::os::unix::fs::symlink(&attacker_target, &symlinked_parent).unwrap();

        let spec = FileSpec {
            path: symlinked_parent.join("config.conf"),
            content: Some("important config\n".into()),
            mode: Some("0644".into()),
            owner: None,
            group: None,
            state: super::super::spec::FileState::Present,
        };
        let result = write(&spec);
        assert!(result.is_err(), "expected parent-symlink rejection");
        // Confirm the rename never reached the attacker's preferred tree.
        assert!(
            !attacker_target.join("config.conf").exists(),
            "write must not have landed in the symlink target"
        );
    }
}
