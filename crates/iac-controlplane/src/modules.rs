//! Phase 7bv: operator-defined composite expanders ("modules").
//!
//! Built-in expanders (Phase 7a/7c/7k) — `service`, `cron-job-bundle`,
//! `web-with-monitoring` — are hardcoded for the few patterns the
//! project's first users wanted. Real IaC needs operators to write
//! their own. This module adds a config-driven expander system:
//! operators declare `[[modules]]` entries with parameters + a YAML
//! template, the server expands them on submit just like the built-ins.
//!
//! Template syntax is intentionally minimal — string substitution
//! `{{ name }}` only, no expressions / conditionals / loops. The
//! design philosophy: modules compose primitives, complex logic stays
//! out of templates and into operator-side tooling that generates the
//! manifests. Operators wanting Turing-complete composition can use
//! their preferred tool (Jsonnet, Cue, etc.) to produce manifests
//! that submit primitive resources directly — modules are for the
//! common "wrap N primitives behind one logical kind" case.
//!
//! Special variables available in templates: `name` and `environment`
//! pull from the resource's metadata; the rest are operator-declared
//! parameters. Required parameters fail validation if missing;
//! optional parameters fall back to their declared `default`.

use crate::error::{ApiError, ApiResult};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::collections::BTreeSet;

/// One operator-defined composite expander loaded from `[[modules]]`
/// in the TOML config.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Module {
    /// Composite kind operators write in manifests, e.g. `"db-with-backup"`.
    /// Must be unique across modules AND not collide with built-in
    /// composites (`service`, `cron-job-bundle`, `web-with-monitoring`)
    /// or any primitive kind. Validated at config load.
    pub name: String,
    /// One-line summary surfaced in `/v1/expanders`.
    #[serde(default)]
    pub description: String,
    /// Resource kinds the template emits. Hand-curated (no automatic
    /// inference) since the catalog API needs them before any
    /// expansion runs. Sorted+deduped at validation.
    #[serde(default)]
    pub emits: Vec<String>,
    /// Declared parameters. Each parameter's `name` becomes a
    /// substitution variable inside `template`. Built-in `name` and
    /// `environment` (metadata fields) are always available and
    /// MUST NOT be redeclared here.
    #[serde(default)]
    pub parameters: Vec<ModuleParameter>,
    /// YAML body emitted by the module. Should parse to a YAML
    /// sequence (array). Each entry becomes one primitive resource.
    /// Substitutions: `{{ var }}` where var is a parameter name or
    /// `name` / `environment`.
    pub template: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleParameter {
    /// Parameter name. Must be a valid Rust identifier-ish: alpha,
    /// digits, underscore, no hyphens. Substituted into the template
    /// as `{{ name }}`.
    pub name: String,
    /// Type hint for the catalog descriptor + CLI-side validation
    /// (Phase 7bi). Stringly-typed: `"string"` / `"number"` /
    /// `"bool"` / `"array"` / `"object"` / `"map<...>"`.
    pub r#type: String,
    /// `true` if the parameter must be set in the manifest. `false`
    /// means the manifest may omit it; `default` (if any) is used.
    #[serde(default)]
    pub required: bool,
    /// Fallback value for optional parameters. Substituted into the
    /// template if the manifest doesn't specify the parameter. JSON
    /// scalars only; nested defaults aren't supported (operators
    /// who need that should make the parameter required).
    #[serde(default)]
    pub default: Option<Value>,
    /// Operator-readable description shown in `/v1/expanders`.
    #[serde(default)]
    pub description: String,
}

/// Reserved variable names that the template engine populates from
/// the resource's metadata. Operators declaring a parameter with one
/// of these names get a config error.
const RESERVED_VARS: &[&str] = &["name", "environment"];

impl Module {
    /// Validate a module definition at config load. Catches duplicates
    /// in parameter names, reserved-var collisions, malformed names,
    /// and templates that mention undeclared variables.
    pub fn validate(&self) -> Result<(), String> {
        if self.name.trim().is_empty() {
            return Err("module name must not be empty".into());
        }
        if !self.name.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_') {
            return Err(format!(
                "module name {:?} must be alphanumeric with optional '-' or '_'",
                self.name
            ));
        }
        if matches!(
            self.name.as_str(),
            "service" | "cron-job-bundle" | "web-with-monitoring"
        ) {
            return Err(format!(
                "module name {:?} collides with a built-in composite",
                self.name
            ));
        }
        let mut seen = BTreeSet::new();
        for p in &self.parameters {
            if !p.name.chars().all(|c| c.is_alphanumeric() || c == '_') {
                return Err(format!(
                    "parameter {:?} name must be alphanumeric/underscore",
                    p.name
                ));
            }
            if RESERVED_VARS.contains(&p.name.as_str()) {
                return Err(format!(
                    "parameter {:?} collides with reserved metadata var",
                    p.name
                ));
            }
            if !seen.insert(p.name.as_str()) {
                return Err(format!("parameter {:?} declared twice", p.name));
            }
        }
        // Template reachability: every {{ var }} must reference a
        // declared parameter or reserved var. Catches typos at config
        // load instead of at first apply.
        for var in template_variables(&self.template) {
            if RESERVED_VARS.contains(&var.as_str()) {
                continue;
            }
            if !self.parameters.iter().any(|p| p.name == var) {
                return Err(format!(
                    "template references undeclared variable {{{{ {var} }}}} \
                     — declare it as a parameter or remove it"
                ));
            }
        }
        Ok(())
    }
}

/// Extract the set of substitution variable names from a template.
/// Matches `{{ var }}` and `{{var}}` (whitespace-tolerant inside the
/// braces). Used for static reachability checks at config load and
/// for substitution at expansion time.
fn template_variables(template: &str) -> Vec<String> {
    let mut out = Vec::new();
    let bytes = template.as_bytes();
    let mut i = 0;
    while i + 1 < bytes.len() {
        if bytes[i] == b'{' && bytes[i + 1] == b'{' {
            // Find closing `}}`.
            let start = i + 2;
            let mut j = start;
            while j + 1 < bytes.len() {
                if bytes[j] == b'}' && bytes[j + 1] == b'}' {
                    break;
                }
                j += 1;
            }
            if j + 1 >= bytes.len() {
                break; // unterminated — let runtime substitution surface it
            }
            let var = template[start..j].trim().to_string();
            if !var.is_empty() {
                out.push(var);
            }
            i = j + 2;
        } else {
            i += 1;
        }
    }
    out
}

// Phase 7di.3: template rendering moved to `iac_core::template`.
// Kept this thin wrapper so call sites stay terse and the test cases
// below continue to assert the JSON-flavoured semantics this expander
// promises (Null → empty, Array/Object → reject).
fn render_template(template: &str, vars: &Map<String, Value>) -> Result<String, String> {
    iac_core::template::render_json_top_scalars(template, vars).map_err(|e| e.to_string())
}

/// Expand a single composite resource through an operator-defined
/// module. Same shape as the built-in `expand_service` etc.: pulls
/// `metadata.name` / `metadata.environment` for the substitution
/// context, validates required parameters, applies defaults for
/// optional ones, renders the template, parses as a YAML sequence,
/// and annotates each emitted resource with `iac.example/composite-of`.
pub fn expand_module(module: &Module, raw: &Value) -> ApiResult<Vec<Value>> {
    let metadata = raw
        .get("metadata")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            ApiError::BadRequest(format!("{}: metadata required", module.name))
        })?;
    let name = metadata
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            ApiError::BadRequest(format!("{}: metadata.name required", module.name))
        })?
        .to_string();
    let environment = metadata
        .get("environment")
        .and_then(Value::as_str)
        .unwrap_or("default")
        .to_string();

    let spec = raw
        .get("spec")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();

    // Build the substitution context: metadata vars + each declared
    // parameter (manifest value if present, else default). Required
    // parameters with no manifest value AND no default error out.
    let mut vars: Map<String, Value> = Map::new();
    vars.insert("name".into(), json!(name));
    vars.insert("environment".into(), json!(environment));
    for p in &module.parameters {
        let v = if let Some(v) = spec.get(&p.name) {
            v.clone()
        } else if let Some(d) = &p.default {
            d.clone()
        } else if p.required {
            return Err(ApiError::BadRequest(format!(
                "{}: spec.{} is required ({})",
                module.name, p.name, p.description
            )));
        } else {
            Value::Null
        };
        vars.insert(p.name.clone(), v);
    }

    // Reject unknown spec fields — operators get a clear error
    // instead of a silently ignored typo.
    let known: BTreeSet<&str> = module
        .parameters
        .iter()
        .map(|p| p.name.as_str())
        .collect();
    for got in spec.keys() {
        if !known.contains(got.as_str()) {
            return Err(ApiError::BadRequest(format!(
                "{}: spec.{} is not a known parameter for module {}",
                module.name, got, module.name
            )));
        }
    }

    let rendered = render_template(&module.template, &vars).map_err(|e| {
        ApiError::BadRequest(format!("{}: template render: {e}", module.name))
    })?;
    let parsed: serde_yaml_ng::Value = serde_yaml_ng::from_str(&rendered)
        .map_err(|e| ApiError::BadRequest(format!("{}: template YAML: {e}", module.name)))?;
    let seq = parsed.as_sequence().ok_or_else(|| {
        ApiError::BadRequest(format!(
            "{}: template must produce a YAML sequence (array of resources), got {:?}",
            module.name,
            yaml_kind(&parsed)
        ))
    })?;

    let mut out: Vec<Value> = Vec::with_capacity(seq.len());
    for (i, item) in seq.iter().enumerate() {
        let mut json_item: Value = serde_json::to_value(item).map_err(|e| {
            ApiError::BadRequest(format!(
                "{}: template item {i} not JSON-compatible: {e}",
                module.name
            ))
        })?;
        // Annotate with composite-of so the audit log shows where the
        // primitive came from. Phase 7a's built-ins do the same.
        let meta = json_item
            .as_object_mut()
            .and_then(|m| m.entry("metadata").or_insert_with(|| json!({})).as_object_mut());
        if let Some(m) = meta {
            let annotations = m
                .entry("annotations")
                .or_insert_with(|| json!({}))
                .as_object_mut();
            if let Some(a) = annotations {
                a.insert(
                    "iac.example/composite-of".into(),
                    json!(module.name),
                );
            }
        }
        out.push(json_item);
    }
    Ok(out)
}

fn yaml_kind(v: &serde_yaml_ng::Value) -> &'static str {
    match v {
        serde_yaml_ng::Value::Null => "null",
        serde_yaml_ng::Value::Bool(_) => "bool",
        serde_yaml_ng::Value::Number(_) => "number",
        serde_yaml_ng::Value::String(_) => "string",
        serde_yaml_ng::Value::Sequence(_) => "sequence",
        serde_yaml_ng::Value::Mapping(_) => "mapping",
        serde_yaml_ng::Value::Tagged(_) => "tagged",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn module() -> Module {
        Module {
            name: "test-module".into(),
            description: "test".into(),
            emits: vec!["file".into()],
            parameters: vec![
                ModuleParameter {
                    name: "path".into(),
                    r#type: "string".into(),
                    required: true,
                    default: None,
                    description: "file path".into(),
                },
                ModuleParameter {
                    name: "mode".into(),
                    r#type: "string".into(),
                    required: false,
                    default: Some(json!("0644")),
                    description: "file mode".into(),
                },
            ],
            template: r#"
- apiVersion: iac.example/v1
  kind: file
  metadata:
    name: {{ name }}
    environment: {{ environment }}
  spec:
    path: {{ path }}
    state: present
    mode: "{{ mode }}"
"#
            .to_string(),
        }
    }

    #[test]
    fn validates_well_formed_module() {
        module().validate().unwrap();
    }

    #[test]
    fn rejects_empty_name() {
        let mut m = module();
        m.name = "  ".into();
        assert!(m.validate().is_err());
    }

    #[test]
    fn rejects_collision_with_builtin() {
        let mut m = module();
        m.name = "service".into();
        let err = m.validate().unwrap_err();
        assert!(err.contains("built-in"));
    }

    #[test]
    fn rejects_reserved_param_name() {
        let mut m = module();
        m.parameters[0].name = "name".into();
        let err = m.validate().unwrap_err();
        assert!(err.contains("reserved"));
    }

    #[test]
    fn rejects_duplicate_param() {
        let mut m = module();
        m.parameters.push(m.parameters[0].clone());
        let err = m.validate().unwrap_err();
        assert!(err.contains("declared twice"));
    }

    #[test]
    fn rejects_undeclared_template_var() {
        let mut m = module();
        m.template.push_str("\n# {{ undeclared_var }}\n");
        let err = m.validate().unwrap_err();
        assert!(err.contains("undeclared"));
    }

    #[test]
    fn template_variables_extracts_all_uses() {
        let v = template_variables("{{ a }} text {{b}} {{ c }}");
        assert_eq!(v, vec!["a", "b", "c"]);
    }

    #[test]
    fn template_variables_handles_no_vars() {
        let v = template_variables("plain text no variables");
        assert!(v.is_empty());
    }

    #[test]
    fn template_variables_handles_unterminated() {
        // No panic; just stops at unterminated.
        let v = template_variables("{{ a }} {{ unterminated ");
        assert_eq!(v, vec!["a"]);
    }

    #[test]
    fn render_substitutes_string_value() {
        let mut vars = Map::new();
        vars.insert("name".into(), json!("alice"));
        let out = render_template("hello {{ name }}!", &vars).unwrap();
        assert_eq!(out, "hello alice!");
    }

    #[test]
    fn render_substitutes_number_unquoted() {
        let mut vars = Map::new();
        vars.insert("port".into(), json!(8080));
        let out = render_template("port: {{ port }}", &vars).unwrap();
        assert_eq!(out, "port: 8080");
    }

    #[test]
    fn render_substitutes_bool() {
        let mut vars = Map::new();
        vars.insert("enabled".into(), json!(true));
        let out = render_template("on: {{ enabled }}", &vars).unwrap();
        assert_eq!(out, "on: true");
    }

    #[test]
    fn render_rejects_array_substitution() {
        let mut vars = Map::new();
        vars.insert("xs".into(), json!([1, 2, 3]));
        let err = render_template("{{ xs }}", &vars).unwrap_err();
        assert!(err.contains("only scalar"));
    }

    #[test]
    fn render_rejects_unknown_var() {
        let vars = Map::new();
        let err = render_template("{{ ghost }}", &vars).unwrap_err();
        assert!(err.contains("not found"));
    }

    #[test]
    fn expand_module_renders_template_into_resources() {
        let m = module();
        let raw = json!({
            "apiVersion": "iac.example/v1",
            "kind": "test-module",
            "metadata": { "name": "marker", "environment": "prod" },
            "spec": { "path": "/etc/marker", "mode": "0755" }
        });
        let out = expand_module(&m, &raw).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0]["kind"], "file");
        assert_eq!(out[0]["metadata"]["name"], "marker");
        assert_eq!(out[0]["metadata"]["environment"], "prod");
        assert_eq!(out[0]["spec"]["path"], "/etc/marker");
        assert_eq!(out[0]["spec"]["mode"], "0755");
        assert_eq!(
            out[0]["metadata"]["annotations"]["iac.example/composite-of"],
            "test-module"
        );
    }

    #[test]
    fn expand_module_uses_default_for_optional_param() {
        let m = module();
        // Omit `mode` — should pick up the default "0644".
        let raw = json!({
            "apiVersion": "iac.example/v1",
            "kind": "test-module",
            "metadata": { "name": "x", "environment": "test" },
            "spec": { "path": "/etc/x" }
        });
        let out = expand_module(&m, &raw).unwrap();
        assert_eq!(out[0]["spec"]["mode"], "0644");
    }

    #[test]
    fn expand_module_rejects_missing_required() {
        let m = module();
        // Omit `path` (required, no default).
        let raw = json!({
            "apiVersion": "iac.example/v1",
            "kind": "test-module",
            "metadata": { "name": "x", "environment": "test" },
            "spec": {}
        });
        let err = expand_module(&m, &raw).unwrap_err();
        match err {
            ApiError::BadRequest(msg) => assert!(msg.contains("spec.path"), "msg: {msg}"),
            other => panic!("expected BadRequest, got {other:?}"),
        }
    }

    #[test]
    fn expand_module_rejects_unknown_field() {
        let m = module();
        let raw = json!({
            "apiVersion": "iac.example/v1",
            "kind": "test-module",
            "metadata": { "name": "x", "environment": "test" },
            "spec": { "path": "/etc/x", "ghost_field": "boom" }
        });
        let err = expand_module(&m, &raw).unwrap_err();
        match err {
            ApiError::BadRequest(msg) => assert!(msg.contains("ghost_field"), "msg: {msg}"),
            other => panic!("expected BadRequest, got {other:?}"),
        }
    }

    #[test]
    fn expand_module_rejects_non_sequence_template() {
        let mut m = module();
        m.template = "this is just a string".into();
        let raw = json!({
            "apiVersion": "iac.example/v1",
            "kind": "test-module",
            "metadata": { "name": "x", "environment": "test" },
            "spec": { "path": "/etc/x" }
        });
        let err = expand_module(&m, &raw).unwrap_err();
        match err {
            ApiError::BadRequest(msg) => {
                assert!(msg.contains("YAML sequence") || msg.contains("template YAML"), "msg: {msg}")
            }
            other => panic!("expected BadRequest, got {other:?}"),
        }
    }

    #[test]
    fn expand_module_emits_multiple_resources() {
        let mut m = module();
        m.emits = vec!["file".into(), "file".into()];
        m.template = r#"
- apiVersion: iac.example/v1
  kind: file
  metadata: { name: {{ name }}-a, environment: {{ environment }} }
  spec: { path: /a, state: present }
- apiVersion: iac.example/v1
  kind: file
  metadata: { name: {{ name }}-b, environment: {{ environment }} }
  spec: { path: /b, state: present }
"#
        .into();
        let raw = json!({
            "apiVersion": "iac.example/v1",
            "kind": "test-module",
            "metadata": { "name": "x", "environment": "test" },
            "spec": { "path": "/unused" }
        });
        let out = expand_module(&m, &raw).unwrap();
        assert_eq!(out.len(), 2);
        assert_eq!(out[0]["metadata"]["name"], "x-a");
        assert_eq!(out[1]["metadata"]["name"], "x-b");
    }
}
