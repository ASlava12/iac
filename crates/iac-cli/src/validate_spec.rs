//! Phase 7r: CLI-side pre-submit validation against expander spec
//! fields.
//!
//! When `iac apply --server` submits a manifest containing a composite
//! kind, we fetch `GET /v1/expanders` first (with a short timeout +
//! best-effort: catalog unreachable → skip validation) and check each
//! resource's spec against the descriptor's `spec_fields`. Catches the
//! common operator mistake of "missing required field" before the
//! server's 400 round trip.
//!
//! Validation is intentionally shallow: required fields present, no
//! unknown top-level fields, and a coarse type sniff. Deep validation
//! (port range, hostname syntax) stays server-side where the
//! authoritative serde rules live.

use anyhow::{Result, anyhow};
use iac_core::Resource;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ExpanderDescriptor {
    pub kind: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub emits: Vec<String>,
    #[serde(default)]
    pub spec_fields: Vec<SpecField>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SpecField {
    pub name: String,
    pub r#type: String,
    pub required: bool,
    #[serde(default)]
    pub description: String,
}

/// Validate every resource whose `kind` matches a known expander. Each
/// resource's spec must include all required fields and no unknown
/// fields. Returns a list of human-readable errors (empty on success).
/// Resources whose `kind` is not in the catalog pass through unchanged
/// — primitives are validated by the providers, not by us.
///
/// Phase 7bi: also checks each present field's JSON value type against
/// the catalog descriptor's declared `r#type`. Catches `port: "8080"`
/// (string vs. number) and `env: "KEY=VAL"` (string vs. object) before
/// the round-trip. Type matching is shallow — `map<string,string>` only
/// requires "is a JSON object," not "every value is a string." Deep
/// validation stays server-side.
pub fn validate_resources(
    resources: &[Resource],
    descriptors: &[ExpanderDescriptor],
) -> Vec<String> {
    let mut errors = Vec::new();
    for r in resources {
        let Some(desc) = descriptors.iter().find(|d| d.kind == r.kind) else {
            continue;
        };
        let spec_obj = match resource_spec_object(r) {
            Ok(obj) => obj,
            Err(e) => {
                errors.push(format!("{}: {e}", r.id()));
                continue;
            }
        };
        let known: BTreeSet<&str> = desc.spec_fields.iter().map(|f| f.name.as_str()).collect();

        // Required fields present?
        for field in &desc.spec_fields {
            if field.required && !spec_obj.contains_key(field.name.as_str()) {
                errors.push(format!(
                    "{}: spec.{} is required ({})",
                    r.id(),
                    field.name,
                    field.description
                ));
            }
        }
        // Any unknown top-level fields?
        for got in spec_obj.keys() {
            if !known.contains(got.as_str()) {
                errors.push(format!(
                    "{}: spec.{got} is not a known field for kind={}",
                    r.id(),
                    r.kind
                ));
            }
        }
        // Phase 7bi: type-check each present field. Skip absent fields —
        // the required-field pass above handles those.
        for field in &desc.spec_fields {
            let Some(value) = spec_obj.get(field.name.as_str()) else {
                continue;
            };
            if let Some(observed) = type_mismatch(&field.r#type, value) {
                errors.push(format!(
                    "{}: spec.{} expected {}, got {observed}",
                    r.id(),
                    field.name,
                    field.r#type
                ));
            }
        }
    }
    errors
}

/// Treat the resource's `spec` as a JSON object and return it. Non-object
/// specs are a 400 server-side too, so we surface the same shape here.
fn resource_spec_object(r: &Resource) -> Result<serde_json::Map<String, serde_json::Value>> {
    let json: serde_json::Value = serde_json::to_value(&r.spec)
        .map_err(|e| anyhow!("spec must be a JSON-compatible object ({e})"))?;
    match json {
        serde_json::Value::Object(m) => Ok(m),
        _ => Err(anyhow!("spec must be an object")),
    }
}

/// Phase 7bi: return `Some("<observed-kind>")` when `value` doesn't match
/// the declared catalog type, `None` on a match. Type strings in the
/// catalog today: `"string"`, `"number"`, `"object"`, `"map<...>"`, plus
/// future-proofing for `"bool"` / `"boolean"` / `"array"`. Unknown
/// declared types pass through (returns `None`) so a future catalog
/// type addition doesn't immediately break older CLI builds.
///
/// Phase 7bl: when the declared type is `array<T>` or `map<K,V>`, recurse
/// into elements / values and report element-level mismatches with a
/// path suffix (e.g. `"number at index 0"`, `"string at key 'env'"`).
/// `map<K,V>`'s key type is unenforced — JSON keys are always strings,
/// and a non-string key declaration in the catalog is ignored
/// (forward-compat with future declarative shapes).
fn type_mismatch(declared: &str, value: &serde_json::Value) -> Option<String> {
    // Phase 7bl: array<T> — element-type recursion. `array` (no parameter)
    // still matches the shallow "is array" check below.
    if let Some(inner) = declared
        .strip_prefix("array<")
        .and_then(|s| s.strip_suffix('>'))
    {
        return match value {
            serde_json::Value::Array(arr) => {
                for (i, elem) in arr.iter().enumerate() {
                    if let Some(inner_msg) = type_mismatch(inner.trim(), elem) {
                        return Some(format!("{inner_msg} at index {i}"));
                    }
                }
                None
            }
            _ => Some(json_kind(value).to_string()),
        };
    }

    // Phase 7bl: map<K,V> — value-type recursion. We split top-level commas
    // (depth-aware) so `map<string, array<number>>` works.
    if let Some(inside) = declared
        .strip_prefix("map<")
        .and_then(|s| s.strip_suffix('>'))
    {
        return match value {
            serde_json::Value::Object(obj) => {
                let parts = split_top_level_comma(inside);
                if parts.len() != 2 {
                    // Malformed catalog declaration (e.g. `map<>` or
                    // `map<a,b,c>`) — fall back to shallow object check.
                    return None;
                }
                let value_type = parts[1].trim();
                for (key, val) in obj {
                    if let Some(inner_msg) = type_mismatch(value_type, val) {
                        return Some(format!("{inner_msg} at key '{key}'"));
                    }
                }
                None
            }
            _ => Some(json_kind(value).to_string()),
        };
    }

    let observed = json_kind(value);
    let ok = match declared {
        "string" => matches!(value, serde_json::Value::String(_)),
        "number" => value.is_number(),
        "bool" | "boolean" => value.is_boolean(),
        "array" => value.is_array(),
        // Unparameterized `object`: shallow check.
        "object" => value.is_object(),
        // Unknown / future type: don't reject. CLI runs against a server
        // that may emit a richer catalog than this CLI build understands.
        _ => return None,
    };
    if ok { None } else { Some(observed.to_string()) }
}

/// Split on top-level commas only — i.e. commas inside `<...>` are part of
/// a nested type and don't separate parameters. Used to parse
/// `map<K,V>` parameters where K or V can themselves be parameterized.
fn split_top_level_comma(s: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut depth: i32 = 0;
    let mut start = 0;
    for (i, c) in s.char_indices() {
        match c {
            '<' => depth += 1,
            '>' => depth -= 1,
            ',' if depth == 0 => {
                parts.push(&s[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    parts.push(&s[start..]);
    parts
}

fn json_kind(v: &serde_json::Value) -> &'static str {
    match v {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "bool",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
}

/// Fetch the catalog from a running control-plane. Best-effort: any
/// failure (network, auth, timeout) returns `None` so the caller can
/// decide whether to skip validation rather than block the submission.
pub async fn fetch_catalog(server_url: &str, bearer: &str) -> Result<Vec<ExpanderDescriptor>> {
    let url = format!("{}/v1/expanders", server_url.trim_end_matches('/'));
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()?;
    let resp = client.get(&url).bearer_auth(bearer).send().await?;
    if !resp.status().is_success() {
        anyhow::bail!("catalog fetch returned {}", resp.status());
    }
    let list: Vec<ExpanderDescriptor> = resp.json().await?;
    Ok(list)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_yaml_ng::Value;

    fn descriptor() -> ExpanderDescriptor {
        ExpanderDescriptor {
            kind: "service".into(),
            description: "test".into(),
            emits: vec![],
            spec_fields: vec![
                SpecField {
                    name: "image".into(),
                    r#type: "string".into(),
                    required: true,
                    description: "img".into(),
                },
                SpecField {
                    name: "port".into(),
                    r#type: "number".into(),
                    required: true,
                    description: "port".into(),
                },
                SpecField {
                    name: "domain".into(),
                    r#type: "string".into(),
                    required: true,
                    description: "domain".into(),
                },
                SpecField {
                    name: "internal_port".into(),
                    r#type: "number".into(),
                    required: false,
                    description: "internal port".into(),
                },
            ],
        }
    }

    fn service_resource(spec_yaml: &str) -> Resource {
        let spec: Value = serde_yaml_ng::from_str(spec_yaml).unwrap();
        Resource {
            api_version: "iac.example/v1".into(),
            kind: "service".into(),
            metadata: iac_core::Metadata {
                name: "x".into(),
                environment: "test".into(),
                owner: None,
                labels: indexmap::IndexMap::new(),
                annotations: indexmap::IndexMap::new(),
            },
            spec,
            policy: Value::Null,
            source: iac_core::resource::SourceLocation::default(),
        }
    }

    #[test]
    fn complete_spec_passes() {
        let res = service_resource("image: nginx\nport: 8080\ndomain: x.example");
        let errs = validate_resources(&[res], &[descriptor()]);
        assert!(errs.is_empty(), "errors: {errs:?}");
    }

    #[test]
    fn missing_required_field_reports_error() {
        let res = service_resource("image: nginx\nport: 8080");
        let errs = validate_resources(&[res], &[descriptor()]);
        assert_eq!(errs.len(), 1);
        assert!(
            errs[0].contains("spec.domain is required"),
            "errs: {errs:?}"
        );
    }

    #[test]
    fn missing_multiple_required_fields_reports_each() {
        let res = service_resource("image: nginx");
        let errs = validate_resources(&[res], &[descriptor()]);
        assert_eq!(errs.len(), 2);
        assert!(errs.iter().any(|e| e.contains("spec.port")));
        assert!(errs.iter().any(|e| e.contains("spec.domain")));
    }

    #[test]
    fn unknown_field_reports_error() {
        let res =
            service_resource("image: nginx\nport: 8080\ndomain: x.example\ntotally_made_up: 1");
        let errs = validate_resources(&[res], &[descriptor()]);
        assert_eq!(errs.len(), 1);
        assert!(errs[0].contains("totally_made_up"), "errs: {errs:?}");
    }

    #[test]
    fn optional_field_not_required() {
        // `internal_port` is optional → omitting it is fine.
        let res = service_resource("image: nginx\nport: 8080\ndomain: x.example");
        let errs = validate_resources(&[res], &[descriptor()]);
        assert!(errs.is_empty(), "errs: {errs:?}");
    }

    #[test]
    fn unknown_kind_skipped() {
        // `file` isn't in the catalog → primitives are providers' job.
        let mut res = service_resource("path: /etc/foo");
        res.kind = "file".into();
        let errs = validate_resources(&[res], &[descriptor()]);
        assert!(errs.is_empty());
    }

    #[test]
    fn empty_descriptor_list_short_circuits() {
        let res = service_resource("image: nginx\nport: 8080\ndomain: x.example");
        let errs = validate_resources(&[res], &[]);
        assert!(errs.is_empty(), "no descriptors → no errors");
    }

    #[test]
    fn non_object_spec_reports_error() {
        // Spec must be an object.
        let mut res = service_resource("image: nginx\nport: 8080\ndomain: x.example");
        res.spec = serde_yaml_ng::Value::String("not-an-object".into());
        let errs = validate_resources(&[res], &[descriptor()]);
        assert_eq!(errs.len(), 1);
        assert!(errs[0].contains("must be an object"), "errs: {errs:?}");
    }

    #[test]
    fn validates_each_resource_independently() {
        // First valid, second missing port.
        let r1 = service_resource("image: nginx\nport: 8080\ndomain: a.example");
        let r2 = service_resource("image: nginx\ndomain: b.example");
        let errs = validate_resources(&[r1, r2], &[descriptor()]);
        assert_eq!(errs.len(), 1);
        assert!(errs[0].contains("spec.port"));
    }

    // Phase 7bi: type-mismatch tests.

    #[test]
    fn quoted_number_in_string_field_is_caught() {
        // `port` is declared as "number"; a YAML-quoted "8080" reaches
        // serde as a string.
        let res = service_resource("image: nginx\nport: \"8080\"\ndomain: x.example");
        let errs = validate_resources(&[res], &[descriptor()]);
        assert_eq!(errs.len(), 1, "errs: {errs:?}");
        assert!(errs[0].contains("spec.port expected number"));
        assert!(errs[0].contains("got string"));
    }

    #[test]
    fn number_in_string_field_is_caught() {
        // `image` is declared as "string"; a bare number is a number.
        let res = service_resource("image: 42\nport: 8080\ndomain: x.example");
        let errs = validate_resources(&[res], &[descriptor()]);
        assert_eq!(errs.len(), 1, "errs: {errs:?}");
        assert!(errs[0].contains("spec.image expected string"));
        assert!(errs[0].contains("got number"));
    }

    #[test]
    fn map_type_accepts_object() {
        // Add a `map<string,string>` field to the descriptor and pass an
        // object — should accept.
        let mut desc = descriptor();
        desc.spec_fields.push(SpecField {
            name: "env".into(),
            r#type: "map<string,string>".into(),
            required: false,
            description: "env vars".into(),
        });
        let res = service_resource("image: nginx\nport: 8080\ndomain: x.example\nenv:\n  KEY: VAL");
        let errs = validate_resources(&[res], &[desc]);
        assert!(errs.is_empty(), "errs: {errs:?}");
    }

    #[test]
    fn map_type_rejects_string() {
        let mut desc = descriptor();
        desc.spec_fields.push(SpecField {
            name: "env".into(),
            r#type: "map<string,string>".into(),
            required: false,
            description: "env vars".into(),
        });
        let res = service_resource("image: nginx\nport: 8080\ndomain: x.example\nenv: \"KEY=VAL\"");
        let errs = validate_resources(&[res], &[desc]);
        assert_eq!(errs.len(), 1, "errs: {errs:?}");
        assert!(errs[0].contains("spec.env expected map<string,string>"));
        assert!(errs[0].contains("got string"));
    }

    #[test]
    fn unknown_declared_type_passes_through() {
        // Phase 7bi forward-compat: a future catalog might add types
        // this CLI build doesn't recognize. Don't reject — fall through
        // to the server's authoritative serde rules.
        let mut desc = descriptor();
        desc.spec_fields.push(SpecField {
            name: "future_field".into(),
            r#type: "duration".into(), // unknown to current CLI
            required: false,
            description: "".into(),
        });
        let res =
            service_resource("image: nginx\nport: 8080\ndomain: x.example\nfuture_field: 30s");
        let errs = validate_resources(&[res], &[desc]);
        assert!(
            errs.is_empty(),
            "unknown declared type must NOT reject: {errs:?}"
        );
    }

    #[test]
    fn missing_field_short_circuits_type_check() {
        // Required-field error fires; a separate type-mismatch error
        // does NOT fire for the absent field (we have nothing to type
        // against). Verify by checking the optional `internal_port`
        // doesn't produce a type error when omitted.
        let res = service_resource("image: nginx\nport: 8080\ndomain: x.example");
        let errs = validate_resources(&[res], &[descriptor()]);
        assert!(
            errs.is_empty(),
            "absent optional field must not trigger type check: {errs:?}"
        );
    }

    #[test]
    fn type_mismatch_doesnt_mask_unknown_field_error() {
        // A wrong-type known field + an unknown field should produce
        // BOTH errors so the operator fixes both at once.
        let res = service_resource("image: 42\nport: 8080\ndomain: x.example\nweird_field: foo");
        let errs = validate_resources(&[res], &[descriptor()]);
        assert_eq!(errs.len(), 2, "errs: {errs:?}");
        assert!(
            errs.iter()
                .any(|e| e.contains("spec.image expected string"))
        );
        assert!(
            errs.iter()
                .any(|e| e.contains("weird_field is not a known field"))
        );
    }

    // Phase 7bl: deep map<K,V> + array<T> element-type validation.

    fn descriptor_with(extra: SpecField) -> ExpanderDescriptor {
        let mut d = descriptor();
        d.spec_fields.push(extra);
        d
    }

    #[test]
    fn array_of_string_accepts_homogeneous_strings() {
        let desc = descriptor_with(SpecField {
            name: "tags".into(),
            r#type: "array<string>".into(),
            required: false,
            description: "tags".into(),
        });
        let res = service_resource(
            "image: nginx\nport: 8080\ndomain: x.example\ntags:\n  - a\n  - b\n  - c",
        );
        let errs = validate_resources(&[res], &[desc]);
        assert!(errs.is_empty(), "errs: {errs:?}");
    }

    #[test]
    fn array_of_string_rejects_number_element() {
        // Catches `tags: [a, 42, c]` — middle element is a number.
        let desc = descriptor_with(SpecField {
            name: "tags".into(),
            r#type: "array<string>".into(),
            required: false,
            description: "tags".into(),
        });
        let res = service_resource(
            "image: nginx\nport: 8080\ndomain: x.example\ntags:\n  - a\n  - 42\n  - c",
        );
        let errs = validate_resources(&[res], &[desc]);
        assert_eq!(errs.len(), 1, "errs: {errs:?}");
        assert!(errs[0].contains("spec.tags expected array<string>"));
        assert!(errs[0].contains("got number at index 1"), "errs: {errs:?}");
    }

    #[test]
    fn array_of_string_rejects_non_array_value() {
        // Top-level "got string": shallow shape check still works.
        let desc = descriptor_with(SpecField {
            name: "tags".into(),
            r#type: "array<string>".into(),
            required: false,
            description: "tags".into(),
        });
        let res =
            service_resource("image: nginx\nport: 8080\ndomain: x.example\ntags: not-an-array");
        let errs = validate_resources(&[res], &[desc]);
        assert_eq!(errs.len(), 1, "errs: {errs:?}");
        assert!(errs[0].contains("spec.tags expected array<string>"));
        assert!(errs[0].contains("got string"));
    }

    #[test]
    fn map_string_number_accepts_homogeneous_numbers() {
        let desc = descriptor_with(SpecField {
            name: "counts".into(),
            r#type: "map<string,number>".into(),
            required: false,
            description: "counts".into(),
        });
        let res = service_resource(
            "image: nginx\nport: 8080\ndomain: x.example\ncounts:\n  a: 1\n  b: 2",
        );
        let errs = validate_resources(&[res], &[desc]);
        assert!(errs.is_empty(), "errs: {errs:?}");
    }

    #[test]
    fn map_string_number_rejects_string_value() {
        // Catches `counts: {a: "one"}` — value side is a string.
        let desc = descriptor_with(SpecField {
            name: "counts".into(),
            r#type: "map<string,number>".into(),
            required: false,
            description: "counts".into(),
        });
        let res = service_resource(
            "image: nginx\nport: 8080\ndomain: x.example\ncounts:\n  a: 1\n  b: \"two\"",
        );
        let errs = validate_resources(&[res], &[desc]);
        assert_eq!(errs.len(), 1, "errs: {errs:?}");
        assert!(errs[0].contains("spec.counts expected map<string,number>"));
        assert!(errs[0].contains("got string at key 'b'"), "errs: {errs:?}");
    }

    #[test]
    fn map_string_string_existing_test_still_passes() {
        // Phase 7bi shipped `map<string,string>` with shallow object check.
        // Phase 7bl deepens it: with all-string values, still OK.
        let desc = descriptor_with(SpecField {
            name: "env".into(),
            r#type: "map<string,string>".into(),
            required: false,
            description: "env vars".into(),
        });
        let res = service_resource(
            "image: nginx\nport: 8080\ndomain: x.example\nenv:\n  KEY: VAL\n  K2: V2",
        );
        let errs = validate_resources(&[res], &[desc]);
        assert!(errs.is_empty(), "errs: {errs:?}");
    }

    #[test]
    fn map_string_string_rejects_number_value() {
        // Phase 7bl tightens the shallow check: a number value in a
        // `map<string,string>` field is now caught CLI-side.
        let desc = descriptor_with(SpecField {
            name: "env".into(),
            r#type: "map<string,string>".into(),
            required: false,
            description: "env vars".into(),
        });
        let res = service_resource(
            "image: nginx\nport: 8080\ndomain: x.example\nenv:\n  KEY: VAL\n  PORT: 8080",
        );
        let errs = validate_resources(&[res], &[desc]);
        assert_eq!(errs.len(), 1, "errs: {errs:?}");
        assert!(errs[0].contains("spec.env expected map<string,string>"));
        assert!(
            errs[0].contains("got number at key 'PORT'"),
            "errs: {errs:?}"
        );
    }

    #[test]
    fn nested_array_of_map_string_string_validates_deeply() {
        // Pathological nested type — verify the recursion + comma split
        // handle `array<map<string,string>>` correctly.
        let desc = descriptor_with(SpecField {
            name: "matrix".into(),
            r#type: "array<map<string,string>>".into(),
            required: false,
            description: "matrix".into(),
        });
        // Valid case: array of two maps, all string values.
        let ok_res = service_resource(
            "image: nginx\nport: 8080\ndomain: x.example\nmatrix:\n  - {a: b}\n  - {c: d}",
        );
        let errs = validate_resources(&[ok_res], std::slice::from_ref(&desc));
        assert!(errs.is_empty(), "valid nested case: {errs:?}");

        // Invalid: second element's `bad` key has a number value.
        let bad_res = service_resource(
            "image: nginx\nport: 8080\ndomain: x.example\nmatrix:\n  - {a: b}\n  - {bad: 42}",
        );
        let errs = validate_resources(&[bad_res], &[desc]);
        assert_eq!(errs.len(), 1, "errs: {errs:?}");
        assert!(errs[0].contains("spec.matrix expected"));
        // Inner-most observation propagates outward with both path layers.
        assert!(errs[0].contains("at key 'bad'"));
        assert!(errs[0].contains("at index 1"));
    }

    #[test]
    fn split_top_level_comma_handles_nested_brackets() {
        // Unit test for the helper — `<` / `>` depth tracking.
        assert_eq!(split_top_level_comma("a,b"), vec!["a", "b"]);
        assert_eq!(
            split_top_level_comma("string,array<number>"),
            vec!["string", "array<number>"]
        );
        assert_eq!(split_top_level_comma("map<a,b>,c"), vec!["map<a,b>", "c"]);
        assert_eq!(split_top_level_comma(""), vec![""]);
    }

    #[test]
    fn malformed_map_declaration_falls_through() {
        // `map<>` or `map<a,b,c>` is malformed; we don't crash, we let it
        // through with the shallow object check.
        let desc = descriptor_with(SpecField {
            name: "weird".into(),
            r#type: "map<a,b,c>".into(),
            required: false,
            description: "weird".into(),
        });
        let res = service_resource("image: nginx\nport: 8080\ndomain: x.example\nweird:\n  k: v");
        let errs = validate_resources(&[res], &[desc]);
        // Object passes shallow check (the `match value { Object(_) => ... None ... }`
        // path returns None for malformed parts).
        assert!(
            errs.is_empty(),
            "malformed map declaration must not crash: {errs:?}"
        );
    }
}
