//! Phase 7di.2: shared YAML ↔ JSON conversions and the diff-shape
//! helpers built on top of them.
//!
//! Pre-7di.2 these were copy-pasted across the four dynamic-provider
//! runtimes (shellout / external-process / wasm-core / wasm-component).
//! The copies were identical byte-for-byte, which made them a
//! bug-class hazard: a fix in one runtime wouldn't propagate to the
//! other three. Now they live here and every runtime calls the same
//! function.
//!
//! Why "lossy" by design: both `serde_yaml_ng::to_value` and
//! `serde_json::to_value` can in principle fail on exotic edge cases
//! (NaN, non-string mapping keys). We collapse those to `Null` so
//! the call sites don't have to thread `Result` through what's
//! conceptually an infallible coercion. If a provider needs to
//! distinguish "value was Null" from "conversion failed", it has to
//! validate the input first.

use crate::diff::FieldChange;
use crate::resource::Resource;
use serde_json::{Value as Json, json};
use serde_yaml_ng::Value as YamlValue;

/// Best-effort YAML → JSON coercion. Returns `Json::Null` on any
/// error (see module docs for rationale).
pub fn yaml_to_json(v: &YamlValue) -> Json {
    serde_json::to_value(v).unwrap_or(Json::Null)
}

/// Phase 7dh.10 / A2: render a [`Resource`]'s metadata block into
/// the JSON shape every dynamic-runtime plugin (shellout, external-
/// process, wasm-core) sends in its envelope. Plugin authors see
/// `{ name, environment, labels, annotations }` regardless of which
/// runtime carries the bytes — this function makes that contract
/// a single source of truth so the four runtimes can't drift.
///
/// (The wasm-component runtime builds a typed WIT `Metadata` record
/// instead of JSON, so it doesn't go through this helper. Keeping
/// the shapes parallel between the JSON and WIT paths is part of
/// what `iac-core::protocol` is for; deliberate decision to keep
/// the canonical fields here next to the other coercions.)
pub fn resource_metadata_to_json(resource: &Resource) -> Json {
    json!({
        "name": resource.metadata.name,
        "environment": resource.metadata.environment,
        "labels": resource.metadata.labels,
        "annotations": resource.metadata.annotations,
    })
}

/// Best-effort JSON → YAML coercion. Returns `YamlValue::Null` on
/// any error.
pub fn json_to_yaml(v: &Json) -> YamlValue {
    serde_yaml_ng::to_value(v).unwrap_or(YamlValue::Null)
}

/// Compute a flat list of field-level changes between two top-level
/// JSON objects. Plugins use this to produce plan-output diffs
/// without having to walk nested structures themselves.
///
/// Behaviour:
/// * Both inputs must be `Json::Object`; anything else returns an
///   empty vec (no-op).
/// * Each top-level key whose value differs becomes one
///   [`FieldChange`] with `field = "spec.<key>"`.
/// * Keys present only in `want` show `from = None`; only in `have`
///   show `to = None`.
/// * `sensitive` is always `false` here — providers that need to
///   redact specific fields wrap the output and tag those fields
///   themselves.
pub fn collect_top_level_changes(want: &Json, have: &Json) -> Vec<FieldChange> {
    let (Json::Object(w), Json::Object(h)) = (want, have) else {
        return vec![];
    };
    let mut out = Vec::new();
    for (k, wv) in w {
        let hv = h.get(k);
        if hv != Some(wv) {
            out.push(FieldChange {
                field: format!("spec.{k}"),
                from: hv.map(json_to_yaml),
                to: Some(json_to_yaml(wv)),
                sensitive: false,
            });
        }
    }
    for (k, hv) in h {
        if !w.contains_key(k) {
            out.push(FieldChange {
                field: format!("spec.{k}"),
                from: Some(json_to_yaml(hv)),
                to: None,
                sensitive: false,
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn yaml_json_round_trip_object() {
        let yaml: YamlValue = serde_yaml_ng::from_str("name: foo\nport: 80\n").unwrap();
        let j = yaml_to_json(&yaml);
        assert_eq!(j, json!({ "name": "foo", "port": 80 }));
        let back = json_to_yaml(&j);
        assert_eq!(back, yaml);
    }

    #[test]
    fn yaml_to_json_null_for_truly_unsupported() {
        // Mappings with non-string keys are valid YAML but not JSON.
        // We collapse to Null per the lossy contract.
        let yaml: YamlValue = serde_yaml_ng::from_str("? [1, 2]\n: ok\n").unwrap();
        let j = yaml_to_json(&yaml);
        assert_eq!(j, Json::Null);
    }

    #[test]
    fn collect_changes_added_field() {
        let want = json!({ "name": "foo", "port": 80 });
        let have = json!({ "name": "foo" });
        let changes = collect_top_level_changes(&want, &have);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].field, "spec.port");
        assert!(changes[0].from.is_none());
        assert_eq!(changes[0].to, Some(YamlValue::Number(80.into())));
    }

    #[test]
    fn collect_changes_removed_field() {
        let want = json!({ "name": "foo" });
        let have = json!({ "name": "foo", "stale": true });
        let changes = collect_top_level_changes(&want, &have);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].field, "spec.stale");
        assert_eq!(changes[0].from, Some(YamlValue::Bool(true)));
        assert!(changes[0].to.is_none());
    }

    #[test]
    fn collect_changes_modified_field() {
        let want = json!({ "name": "new" });
        let have = json!({ "name": "old" });
        let changes = collect_top_level_changes(&want, &have);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].field, "spec.name");
        assert_eq!(changes[0].from, Some(YamlValue::String("old".into())));
        assert_eq!(changes[0].to, Some(YamlValue::String("new".into())));
    }

    #[test]
    fn collect_changes_no_diff_returns_empty() {
        let v = json!({ "name": "foo", "port": 80 });
        assert!(collect_top_level_changes(&v, &v).is_empty());
    }

    #[test]
    fn collect_changes_non_objects_returns_empty() {
        // String vs object — caller bug, but we don't panic.
        let want = json!("just a string");
        let have = json!({ "name": "foo" });
        assert!(collect_top_level_changes(&want, &have).is_empty());
    }
}
