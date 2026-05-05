// Phase 7dd: tiny component-model plugin used by `wasm::component`
// round-trip tests. Demonstrates the full author surface: one
// `wit_bindgen::generate!` line, one `Guest` impl, one `export!`
// call. Operators writing real plugins follow this exact shape.
//
// We deliberately keep dependencies minimal (only `wit-bindgen`)
// so the fixture compiles fast on CI and stays small on disk.

#![allow(clippy::expect_used)]

wit_bindgen::generate!({
    world: "plugin",
    path: "wit/plugin.wit",
    generate_all,
});

use exports::iac::plugin::provider::{
    ApplyOutcome, DiffKind, DiffResult, FieldChange, Guest, Metadata, Observed, Phase,
    VerifyOutcome,
};

struct TestPlugin;

impl Guest for TestPlugin {
    fn kind() -> String {
        "test.plugin".into()
    }

    fn methods() -> Vec<String> {
        // Phase 7df+7dg: opt into all four optional methods so the
        // host wires every typed lifecycle export through this
        // fixture. Without listing them the host falls back to the
        // generic spec-equality / re-apply paths.
        vec![
            "diff".into(),
            "verify".into(),
            "pre-apply".into(),
            "rollback".into(),
        ]
    }

    fn observe(metadata: Metadata, _spec_json: String) -> Result<Observed, String> {
        // Trivial: report present iff the resource name starts with
        // "exists-". Lets the test drive both branches without any
        // host-side state.
        let present = metadata.name.starts_with("exists-");
        Ok(Observed {
            present,
            spec_json: if present {
                format!(r#"{{"name":"{}"}}"#, metadata.name)
            } else {
                String::new()
            },
        })
    }

    fn diff(
        metadata: Metadata,
        _desired_spec_json: String,
        observed: Observed,
    ) -> DiffResult {
        // Demonstrates the typed-diff surface. We compare against
        // observed.present and emit a structured `field-change` for
        // the `name` field whenever it's a Create. The host wraps
        // this verbatim — no JSON round-trip on the wire.
        if !observed.present {
            DiffResult {
                kind: DiffKind::Create,
                changes: vec![FieldChange {
                    field: "spec.name".into(),
                    from_json: None,
                    to_json: Some(format!(r#""{}""#, metadata.name)),
                    sensitive: false,
                }],
                reasons: vec!["typed-diff: resource absent".into()],
                reversible: true,
            }
        } else {
            DiffResult {
                kind: DiffKind::NoChange,
                changes: vec![],
                reasons: vec!["typed-diff: present and matching".into()],
                reversible: true,
            }
        }
    }

    fn pre_apply(metadata: Metadata, spec_json: String) -> Result<String, String> {
        // Phase 7dg: stash a plugin-shaped checkpoint. The host
        // doesn't peek inside; it will hand the bytes back to
        // `rollback` verbatim. We pack name + len-of-spec so we
        // can verify on the rollback side that the bytes
        // round-tripped.
        Ok(format!(
            r#"{{"plugin":"test.plugin","pre_name":"{}","pre_spec_len":{}}}"#,
            metadata.name,
            spec_json.len()
        ))
    }

    fn apply(metadata: Metadata, _spec_json: String, phase: Phase) -> ApplyOutcome {
        let phase_label = match phase {
            Phase::Create => "create",
            Phase::Update => "update",
            Phase::Delete => "delete",
        };
        ApplyOutcome {
            ok: true,
            message: format!("{phase_label} {} via test.plugin", metadata.name),
        }
    }

    fn rollback(metadata: Metadata, checkpoint_json: String) -> Result<(), String> {
        // Phase 7dg: validate that the bytes we got match what
        // pre_apply produced — the host should round-trip the
        // checkpoint string verbatim.
        if !checkpoint_json.contains(&format!(r#""pre_name":"{}""#, metadata.name)) {
            return Err(format!(
                "rollback checkpoint missing pre_name={:?}: {checkpoint_json}",
                metadata.name
            ));
        }
        Ok(())
    }

    fn verify(metadata: Metadata, _spec_json: String) -> VerifyOutcome {
        // Plugin's verify mirrors observe: name starting with
        // "exists-" → match; otherwise mismatch with one structured
        // change record.
        if metadata.name.starts_with("exists-") {
            VerifyOutcome::Ok
        } else {
            VerifyOutcome::Mismatch(vec![FieldChange {
                field: "spec.name".into(),
                from_json: None,
                to_json: Some(format!(r#""{}""#, metadata.name)),
                sensitive: false,
            }])
        }
    }

    fn capability_keys(metadata: Metadata, _spec_json: String) -> Vec<String> {
        vec![metadata.name]
    }
}

export!(TestPlugin);
