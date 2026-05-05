//! Phase 7di.3: shared `{{ field }}` template renderer.
//!
//! Three call sites used to carry near-identical copies (shellout +
//! external-process providers, controlplane modules expander) — the
//! same scan-and-substitute loop differing only in the type of the
//! variable scope (YAML vs JSON map). This module collapses them onto
//! one core function plus two thin format-specific wrappers.
//!
//! # Syntax
//!
//! `{{ name }}` — substituted with the scalar form of `name`. White-
//! space inside the braces is trimmed. Braces don't nest. Anything
//! more elaborate (paths, arithmetic, conditionals) is intentionally
//! out of scope; operators who need it should use a real provider.
//!
//! # Errors
//!
//! Every error variant is recoverable — the caller decides whether to
//! surface it as a parse failure or a hint. We never panic on user
//! input. See [`TemplateError`].

use serde_json::{Map as JsonMap, Value as JsonValue};
use serde_yaml_ng::Value as YamlValue;
use std::fmt;

/// What can go wrong rendering a template. Returned as `Err` from
/// [`render`] and the format-specific helpers; never panics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TemplateError {
    /// `{{` opened but `}}` never closed before end-of-input.
    Unterminated,
    /// `{{ name }}` referenced a key the lookup didn't have. Carries
    /// the key for human-readable diagnostics.
    MissingKey(String),
    /// `{{ name }}` resolved to a non-scalar value (array, object,
    /// or — for some inputs — null). Carries the key.
    NotScalar(String),
}

impl fmt::Display for TemplateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unterminated => f.write_str("unterminated `{{` in template"),
            Self::MissingKey(k) => write!(f, "template variable {{{{ {k} }}}} not found"),
            Self::NotScalar(k) => write!(
                f,
                "template variable {{{{ {k} }}}} is array/object; only scalar substitution is supported"
            ),
        }
    }
}

impl std::error::Error for TemplateError {}

/// Walk `template`, substituting every `{{ key }}` with the result of
/// `lookup(key)`. The closure returns:
///
/// * `Ok(Some(s))` — a scalar string to splice in
/// * `Ok(None)`   — key exists but isn't scalar; surfaces as
///   [`TemplateError::NotScalar`]
/// * `Err(MissingKey)` — key not in scope
///
/// `{` and `}` are ASCII so we scan byte-wise without UTF-8 worries.
pub fn render<F>(template: &str, mut lookup: F) -> Result<String, TemplateError>
where
    F: FnMut(&str) -> Result<Option<String>, TemplateError>,
{
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(start) = rest.find("{{") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let end = after.find("}}").ok_or(TemplateError::Unterminated)?;
        let key = after[..end].trim();
        match lookup(key)? {
            Some(s) => out.push_str(&s),
            None => return Err(TemplateError::NotScalar(key.into())),
        }
        rest = &after[end + 2..];
    }
    out.push_str(rest);
    Ok(out)
}

/// Render with substitutions taken from the top-level scalar fields
/// of a YAML mapping. Used by shellout / external-process providers.
///
/// Scalars: `String`, `Number`, `Bool`. Anything else (mappings,
/// sequences, null, tagged) → [`TemplateError::NotScalar`].
pub fn render_yaml_top_scalars(
    template: &str,
    spec: &YamlValue,
) -> Result<String, TemplateError> {
    let map = spec.as_mapping();
    render(template, |key| match map.and_then(|m| m.get(YamlValue::String(key.into()))) {
        None => Err(TemplateError::MissingKey(key.into())),
        Some(YamlValue::String(s)) => Ok(Some(s.clone())),
        Some(YamlValue::Number(n)) => Ok(Some(n.to_string())),
        Some(YamlValue::Bool(b)) => Ok(Some(b.to_string())),
        Some(_) => Ok(None),
    })
}

/// Render with substitutions taken from a flat JSON object. Used by
/// the controlplane module expander, where module parameters are
/// pre-validated against a JSON Schema before render time.
///
/// Scalars: `String`, `Number`, `Bool`. `Null` is treated as the
/// empty string (legacy behaviour from `iac-controlplane::modules` —
/// downstream YAML parser surfaces missing-required-field as a real
/// error). Arrays and objects → [`TemplateError::NotScalar`].
pub fn render_json_top_scalars(
    template: &str,
    vars: &JsonMap<String, JsonValue>,
) -> Result<String, TemplateError> {
    render(template, |key| match vars.get(key) {
        None => Err(TemplateError::MissingKey(key.into())),
        Some(JsonValue::String(s)) => Ok(Some(s.clone())),
        Some(JsonValue::Number(n)) => Ok(Some(n.to_string())),
        Some(JsonValue::Bool(b)) => Ok(Some(if *b { "true".into() } else { "false".into() })),
        Some(JsonValue::Null) => Ok(Some(String::new())),
        Some(JsonValue::Array(_) | JsonValue::Object(_)) => Ok(None),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn yaml(s: &str) -> YamlValue {
        serde_yaml_ng::from_str(s).unwrap()
    }

    // ---- core renderer ----

    #[test]
    fn passthrough_when_no_braces() {
        let out = render("hello world", |_| unreachable!()).unwrap();
        assert_eq!(out, "hello world");
    }

    #[test]
    fn substitutes_single_var() {
        let out = render("name={{ x }}", |k| {
            assert_eq!(k, "x");
            Ok(Some("alice".into()))
        })
        .unwrap();
        assert_eq!(out, "name=alice");
    }

    #[test]
    fn substitutes_multiple_vars_back_to_back() {
        let out = render("{{ a }}-{{ b }}", |k| {
            Ok(Some(match k {
                "a" => "1",
                "b" => "2",
                _ => panic!(),
            }
            .into()))
        })
        .unwrap();
        assert_eq!(out, "1-2");
    }

    #[test]
    fn trims_whitespace_inside_braces() {
        let out = render("{{   spaced   }}", |k| {
            assert_eq!(k, "spaced");
            Ok(Some("yes".into()))
        })
        .unwrap();
        assert_eq!(out, "yes");
    }

    #[test]
    fn unterminated_open_brace_is_error() {
        let err = render("{{ x", |_| Ok(Some("v".into()))).unwrap_err();
        assert_eq!(err, TemplateError::Unterminated);
    }

    #[test]
    fn missing_key_propagates() {
        let err = render("{{ nope }}", |k| {
            Err(TemplateError::MissingKey(k.into()))
        })
        .unwrap_err();
        assert!(matches!(err, TemplateError::MissingKey(k) if k == "nope"));
    }

    #[test]
    fn non_scalar_lookup_becomes_typed_error() {
        let err = render("{{ x }}", |_| Ok(None)).unwrap_err();
        assert!(matches!(err, TemplateError::NotScalar(k) if k == "x"));
    }

    // ---- yaml helper ----

    #[test]
    fn yaml_top_scalars_renders_string_number_bool() {
        let spec = yaml("name: bob\ncount: 42\nactive: true\n");
        let out = render_yaml_top_scalars("{{ name }} {{ count }} {{ active }}", &spec).unwrap();
        assert_eq!(out, "bob 42 true");
    }

    #[test]
    fn yaml_top_scalars_rejects_nested_mapping() {
        let spec = yaml("nested:\n  a: 1\n");
        let err = render_yaml_top_scalars("{{ nested }}", &spec).unwrap_err();
        assert!(matches!(err, TemplateError::NotScalar(k) if k == "nested"));
    }

    #[test]
    fn yaml_top_scalars_rejects_missing_key() {
        let spec = yaml("a: 1\n");
        let err = render_yaml_top_scalars("{{ b }}", &spec).unwrap_err();
        assert!(matches!(err, TemplateError::MissingKey(k) if k == "b"));
    }

    #[test]
    fn yaml_top_scalars_handles_non_mapping_root() {
        // A bare scalar/sequence at the root has no top-level keys.
        let spec = yaml("hello\n");
        let err = render_yaml_top_scalars("{{ x }}", &spec).unwrap_err();
        assert!(matches!(err, TemplateError::MissingKey(_)));
    }

    // ---- json helper ----

    #[test]
    fn json_top_scalars_renders_string_number_bool() {
        let m: JsonMap<String, JsonValue> =
            json!({"n": "abc", "i": 7, "b": false}).as_object().unwrap().clone();
        let out = render_json_top_scalars("{{ n }}/{{ i }}/{{ b }}", &m).unwrap();
        assert_eq!(out, "abc/7/false");
    }

    #[test]
    fn json_top_scalars_treats_null_as_empty_string() {
        // Legacy behaviour from controlplane::modules. The downstream
        // YAML parser surfaces missing-required-field as a real error.
        let m: JsonMap<String, JsonValue> =
            json!({"x": null}).as_object().unwrap().clone();
        let out = render_json_top_scalars("[{{ x }}]", &m).unwrap();
        assert_eq!(out, "[]");
    }

    #[test]
    fn json_top_scalars_rejects_array_object() {
        let m: JsonMap<String, JsonValue> =
            json!({"arr": [1, 2], "obj": {"k": "v"}}).as_object().unwrap().clone();
        let err = render_json_top_scalars("{{ arr }}", &m).unwrap_err();
        assert!(matches!(err, TemplateError::NotScalar(k) if k == "arr"));
        let err = render_json_top_scalars("{{ obj }}", &m).unwrap_err();
        assert!(matches!(err, TemplateError::NotScalar(k) if k == "obj"));
    }

    #[test]
    fn json_top_scalars_rejects_missing_key() {
        let m: JsonMap<String, JsonValue> = json!({}).as_object().unwrap().clone();
        let err = render_json_top_scalars("{{ none }}", &m).unwrap_err();
        assert!(matches!(err, TemplateError::MissingKey(k) if k == "none"));
    }
}
