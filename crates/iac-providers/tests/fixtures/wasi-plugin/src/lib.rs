// Phase 7de: WASI fixture plugin. The plugin reads
// `/state/marker.txt` from its preopened guest filesystem and
// reflects the contents through `observe.spec_json`. Proves that
// the WASI preview2 preopen actually plumbs bytes from the host
// to the guest at runtime.

#![allow(clippy::expect_used)]

wit_bindgen::generate!({
    world: "plugin",
    path: "wit/plugin.wit",
    generate_all,
});

use exports::iac::plugin::provider::{
    ApplyOutcome, DiffKind, DiffResult, Guest, Metadata, Observed, Phase, VerifyOutcome,
};

struct WasiPlugin;

impl Guest for WasiPlugin {
    fn kind() -> String {
        "wasi.test".into()
    }

    fn methods() -> Vec<String> {
        // Stays on the host's diff/verify fallbacks — this fixture
        // is about WASI capabilities, not typed diff. The trait
        // still requires implementations below; we return safe
        // defaults that would be ignored even if the host called
        // them.
        Vec::new()
    }

    fn observe(_metadata: Metadata, _spec_json: String) -> Result<Observed, String> {
        // Reading via std::fs goes through WASI preview2 imports.
        // If the host didn't preopen `/state` (or made it not
        // contain `marker.txt`), this returns an error string
        // we hand back through the typed `result<observed, string>`.
        match std::fs::read_to_string("/state/marker.txt") {
            Ok(content) => Ok(Observed {
                present: true,
                spec_json: format!(r#"{{"marker":"{}"}}"#, content.trim()),
            }),
            Err(e) => Err(format!("read /state/marker.txt: {e}")),
        }
    }

    fn diff(
        _metadata: Metadata,
        _desired_spec_json: String,
        _observed: Observed,
    ) -> DiffResult {
        // Required by the WIT trait but never called for this
        // fixture (we don't list "diff" in `methods()`). Return a
        // safe default just in case.
        DiffResult {
            kind: DiffKind::NoChange,
            changes: vec![],
            reasons: vec![],
            reversible: true,
        }
    }

    fn pre_apply(_metadata: Metadata, _spec_json: String) -> Result<String, String> {
        // Required by the WIT trait but never invoked because we
        // don't list "pre-apply" in `methods()`.
        Ok(String::new())
    }

    fn apply(metadata: Metadata, _spec_json: String, phase: Phase) -> ApplyOutcome {
        let phase_label = match phase {
            Phase::Create => "create",
            Phase::Update => "update",
            Phase::Delete => "delete",
        };
        ApplyOutcome {
            ok: true,
            message: format!("{phase_label} {} via wasi.test", metadata.name),
        }
    }

    fn verify(_metadata: Metadata, _spec_json: String) -> VerifyOutcome {
        // Same story as `diff` above — required by the trait,
        // never invoked because we don't opt into "verify".
        VerifyOutcome::Ok
    }

    fn rollback(_metadata: Metadata, _checkpoint_json: String) -> Result<(), String> {
        // Required stub; not opted into via `methods()`.
        Ok(())
    }

    fn capability_keys(metadata: Metadata, _spec_json: String) -> Vec<String> {
        vec![metadata.name]
    }
}

export!(WasiPlugin);
