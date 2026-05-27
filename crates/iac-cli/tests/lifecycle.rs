// Phase 7cz.16: integration tests are compiled as their own crates, so the
// crate-root #[cfg_attr(test, allow(...))] does not reach here. Add it locally.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! End-to-end test: drives the `iac` binary against a real filesystem manifest.
//! Walks: plan → apply → re-plan (no change) → drift → re-plan (change) → rollback.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use tempfile::TempDir;

fn iac_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_iac"))
}

fn run(state_dir: &Path, args: &[&str]) -> Output {
    Command::new(iac_bin())
        .arg("--state-dir")
        .arg(state_dir)
        .arg("--actor")
        .arg("test")
        .args(args)
        .output()
        .expect("spawn iac")
}

fn write_manifest(target_path: &Path, content: &str, dir: &Path) -> PathBuf {
    let manifest = dir.join("manifest.yaml");
    let mut f = std::fs::File::create(&manifest).unwrap();
    writeln!(
        f,
        r#"apiVersion: iac.example/v1
kind: file
metadata:
  name: greeting
  environment: test
spec:
  path: {path}
  mode: "0644"
  content: |
{content}"#,
        path = target_path.display(),
        content = indent(content, 4)
    )
    .unwrap();
    manifest
}

fn indent(s: &str, n: usize) -> String {
    let prefix = " ".repeat(n);
    s.lines()
        .map(|l| format!("{prefix}{l}"))
        .collect::<Vec<_>>()
        .join("\n")
}

fn stdout(o: &Output) -> String {
    let mut combined = String::from_utf8_lossy(&o.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&o.stderr);
    if !stderr.is_empty() {
        combined.push_str("\n--- stderr ---\n");
        combined.push_str(&stderr);
    }
    combined
}

#[test]
fn full_lifecycle_create_apply_rollback() {
    let work = TempDir::new().unwrap();
    let state = work.path().join("state");
    let target_dir = work.path().join("target");
    std::fs::create_dir_all(&target_dir).unwrap();
    let target = target_dir.join("hello.txt");

    let manifest = write_manifest(&target, "hello\n", work.path());

    // 1. validate
    let o = run(&state, &["validate", manifest.to_str().unwrap()]);
    assert!(o.status.success(), "validate failed: {}", stdout(&o));

    // 2. plan: 1 change, exit 2.
    let o = run(&state, &["plan", manifest.to_str().unwrap()]);
    assert_eq!(
        o.status.code(),
        Some(2),
        "expected exit 2 for plan with changes"
    );
    assert!(stdout(&o).contains("file/test/greeting"));

    // 3. apply.
    let o = run(&state, &["apply", "--yes", manifest.to_str().unwrap()]);
    assert!(o.status.success(), "apply failed: {}", stdout(&o));
    assert_eq!(std::fs::read_to_string(&target).unwrap(), "hello\n");

    // 4. plan again: no changes.
    let o = run(&state, &["plan", manifest.to_str().unwrap()]);
    assert_eq!(o.status.code(), Some(0), "expected idempotent plan");

    // 5. drift the file.
    std::fs::write(&target, "drift\n").unwrap();
    let o = run(&state, &["plan", manifest.to_str().unwrap()]);
    assert_eq!(o.status.code(), Some(2), "expected drift detected");
    assert!(stdout(&o).contains("content_sha256"));

    // 6. apply restores.
    let o = run(&state, &["apply", "--yes", manifest.to_str().unwrap()]);
    assert!(o.status.success());
    assert_eq!(std::fs::read_to_string(&target).unwrap(), "hello\n");

    // 7. find the most-recent apply operation and roll it back.
    let ops_dir = state.join("operations");
    let mut ops: Vec<_> = std::fs::read_dir(&ops_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|name| {
            // Operation dirs hold `operation.json`; plan operations are not persisted to disk.
            ops_dir.join(name).join("operation.json").exists()
        })
        .collect();
    ops.sort();
    let latest_apply = ops.last().expect("expected at least one apply operation");

    // The latest apply was the drift-restore; rolling it back should re-introduce drift content.
    let o = run(&state, &["rollback", latest_apply]);
    assert!(o.status.success(), "rollback failed: {}", stdout(&o));
    assert_eq!(std::fs::read_to_string(&target).unwrap(), "drift\n");
}

#[test]
fn validate_reports_unknown_kind() {
    let work = TempDir::new().unwrap();
    let manifest = work.path().join("bad.yaml");
    std::fs::write(
        &manifest,
        r#"apiVersion: iac.example/v1
kind: nonexistent.thing
metadata:
  name: x
  environment: test
spec: {}
"#,
    )
    .unwrap();

    let state = work.path().join("state");
    let o = run(&state, &["validate", manifest.to_str().unwrap()]);
    assert!(!o.status.success());
    let combined = format!("{}{}", stdout(&o), String::from_utf8_lossy(&o.stderr));
    assert!(
        combined.contains("unknown resource kind"),
        "actual: {combined}"
    );
}

#[test]
fn observe_outputs_facts_for_existing_file() {
    let work = TempDir::new().unwrap();
    let target_dir = work.path().join("target");
    std::fs::create_dir_all(&target_dir).unwrap();
    let target = target_dir.join("present.txt");
    std::fs::write(&target, "world\n").unwrap();
    let manifest = write_manifest(&target, "world\n", work.path());

    let state = work.path().join("state");
    let o = run(&state, &["observe", manifest.to_str().unwrap()]);
    assert!(o.status.success());
    let s = stdout(&o);
    assert!(s.contains("present: true"), "stdout: {s}");
    assert!(s.contains("content_sha256"), "stdout: {s}");
}
