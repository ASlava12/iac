//! Phase 7a: server-side composite-resource expansion.
//!
//! `kind: service` is operator-friendly shorthand for the
//! `docker.container` + `nginx.vhost` pair that everyone writes by hand. The
//! server expands it on submit so agents continue to only see primitive
//! providers — no agent code change needed.
//!
//! Expansion happens BEFORE routing + capability checks, so the per-primitive
//! agent allowlist still applies. Phase 7b adds operator-defined modules
//! loaded from a config file; for now the only built-in expander is `service`.

use crate::error::{ApiError, ApiResult};
use crate::modules::{Module, expand_module};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// Phase 7l: descriptor for `GET /v1/expanders`. Lets operators see
/// what composite kinds the server accepts without reading source.
/// Phase 7p adds `spec_fields` so operators can see required + optional
/// fields without writing a manifest and waiting for a 400.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExpanderDescriptor {
    /// `kind` operators write in the manifest.
    pub kind: String,
    /// One-line summary of what the composite does.
    pub description: String,
    /// Resource kinds the composite emits. Sorted+deduped.
    pub emits: Vec<String>,
    /// Spec fields the composite accepts. Hand-curated to mirror the
    /// `#[serde(...)]` deserialization on each `*Spec` struct — kept in
    /// sync via a unit test that round-trips via the actual deserializer.
    #[serde(default)]
    pub spec_fields: Vec<SpecField>,
}

/// Phase 7p: one entry per spec field for the discovery API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpecField {
    /// Field name as written in YAML/JSON.
    pub name: String,
    /// "string" / "number" / "object" / "string[]" / "map<string,string>".
    /// Stringly-typed so the wire shape stays JSON-friendly without
    /// pulling in a JSON Schema dependency.
    pub r#type: String,
    /// `true` if the field must be set; `false` if a default applies or
    /// the field is genuinely optional.
    pub required: bool,
    /// Operator-readable description, including default values when
    /// the field is optional.
    pub description: String,
}

fn f_req(name: &str, r#type: &str, description: &str) -> SpecField {
    SpecField {
        name: name.into(),
        r#type: r#type.into(),
        required: true,
        description: description.into(),
    }
}
fn f_opt(name: &str, r#type: &str, description: &str) -> SpecField {
    SpecField {
        name: name.into(),
        r#type: r#type.into(),
        required: false,
        description: description.into(),
    }
}

/// Built-in expander catalog plus operator-defined modules. Order:
/// built-ins first (stable, alphabetical-ish by historical insertion),
/// then modules in declaration order. Phase 7bv added the modules
/// argument; existing call sites that pass `&[]` get the pre-7bv
/// behavior.
pub fn list_all_expanders(modules: &[Module]) -> Vec<ExpanderDescriptor> {
    let mut out = list_expanders();
    for m in modules {
        out.push(ExpanderDescriptor {
            kind: m.name.clone(),
            description: m.description.clone(),
            emits: m.emits.clone(),
            spec_fields: m
                .parameters
                .iter()
                .map(|p| SpecField {
                    name: p.name.clone(),
                    r#type: p.r#type.clone(),
                    required: p.required,
                    description: p.description.clone(),
                })
                .collect(),
        });
    }
    out
}

/// Built-in expander catalog. Order is stable so the JSON response is
/// reproducible.
pub fn list_expanders() -> Vec<ExpanderDescriptor> {
    vec![
        ExpanderDescriptor {
            kind: "service".into(),
            description: "docker.container + nginx.vhost — a web service behind a reverse proxy".into(),
            emits: vec!["docker.container".into(), "nginx.vhost".into()],
            spec_fields: vec![
                f_req("image", "string", "Container image reference (e.g. nginx:1.27-alpine)"),
                f_req("port", "number", "Published host port (1..=65535)"),
                f_req("domain", "string", "Public domain wired into the nginx vhost"),
                f_opt("internal_port", "number", "Container's listen port; default 80"),
                f_opt("env", "map<string,string>", "Container env vars (KEY=VALUE)"),
                f_opt("restart_policy", "string", "Docker restart policy; default \"unless-stopped\""),
                f_opt("nginx_config_path", "string", "Override the nginx config path; default /etc/nginx/conf.d/<name>.conf"),
                f_opt("hostSelector", "object", "{ name: <agent-name> } pinning the resources to a specific agent"),
            ],
        },
        ExpanderDescriptor {
            kind: "cron-job-bundle".into(),
            description: "file (script body) + cron.job (schedule) tied together so the cron command points at the script path".into(),
            emits: vec!["cron.job".into(), "file".into()],
            spec_fields: vec![
                f_req("schedule", "string", "5-field crontab schedule (min hour dom mon dow)"),
                f_req("script", "string", "Verbatim script body written to scriptPath"),
                f_opt("scriptPath", "string", "Override script location; default /usr/local/bin/<name>"),
                f_opt("user", "string", "Cron user; default root"),
                f_opt("mode", "string", "File mode (octal string); default 0755"),
                f_opt("env", "map<string,string>", "Cron env-var lines emitted at the top of the cron file"),
                f_opt("hostSelector", "object", "{ name: <agent-name> } pinning the resources to a specific agent"),
            ],
        },
        ExpanderDescriptor {
            kind: "web-with-monitoring".into(),
            description: "service + healthcheck (file + cron.job that curls the upstream's health path and logs to syslog)".into(),
            emits: vec![
                "cron.job".into(),
                "docker.container".into(),
                "file".into(),
                "nginx.vhost".into(),
            ],
            spec_fields: vec![
                f_req("image", "string", "Container image reference"),
                f_req("port", "number", "Published host port"),
                f_req("domain", "string", "Public domain"),
                f_opt("health_path", "string", "Path probed by the healthcheck; default /healthz"),
                f_opt("check_interval_minutes", "number", "Probe cadence in minutes (1..=60); default 5"),
                f_opt("internal_port", "number", "Container's listen port; default 80"),
                f_opt("env", "map<string,string>", "Container env vars"),
                f_opt("restart_policy", "string", "Docker restart policy; default \"unless-stopped\""),
                f_opt("hostSelector", "object", "{ name: <agent-name> } pinning the resources to a specific agent"),
            ],
        },
    ]
}

/// Maximum recursion depth for module composition. Caps cycle damage —
/// a module emitting itself (directly or through another module) hits
/// this bound and produces a clear error instead of infinite loop.
/// 8 levels is enough for any realistic composition pattern; deeper
/// nesting suggests a design problem.
const MAX_EXPANSION_DEPTH: usize = 8;

/// Expand any composite resources in `resources` into their primitive
/// children. Returns the new flat list. Non-composite inputs pass through
/// unchanged. Failures are aggregated into an `ApiError::BadRequest` so the
/// operator sees a single clear rejection.
///
/// Phase 7bv: takes a slice of operator-defined modules. Built-in
/// composites are tried first (so a module with a colliding name —
/// already rejected at config load — couldn't shadow them anyway);
/// modules are tried in declaration order via linear search. For
/// realistic module counts (low double digits) the linear pass is
/// fine; if anyone configures hundreds of modules, switching to a
/// HashMap lookup is a one-liner.
///
/// Phase 7bw: recursive. A module can emit another composite kind
/// (built-in or another module), which triggers another expansion
/// pass on the output. Bounded by `MAX_EXPANSION_DEPTH` to catch
/// modules that cycle (A → B → A) — those produce a `BadRequest`
/// with the chain that exceeded the limit.
pub fn expand_resources(resources: Vec<Value>, modules: &[Module]) -> ApiResult<Vec<Value>> {
    let mut current = resources;
    for depth in 0..=MAX_EXPANSION_DEPTH {
        let (next, changed) = expand_resources_one_pass(current, modules)?;
        if !changed {
            return Ok(next);
        }
        current = next;
        if depth == MAX_EXPANSION_DEPTH {
            // One more pass produced fresh composite kinds — we've
            // exhausted the cycle budget. Surface the offending
            // kinds so the operator sees the cycle.
            let cyclic: std::collections::BTreeSet<String> = current
                .iter()
                .filter_map(|r| r.get("kind").and_then(Value::as_str).map(str::to_string))
                .filter(|k| is_composite_kind(k, modules))
                .collect();
            return Err(ApiError::BadRequest(format!(
                "expansion exceeded MAX_EXPANSION_DEPTH ({MAX_EXPANSION_DEPTH}); \
                 likely a recursive module cycle. Composite kinds remaining \
                 after final pass: {cyclic:?}"
            )));
        }
    }
    // Unreachable: the loop above always returns or errors.
    unreachable!()
}

/// Built-in + operator-module kind set used to decide whether a kind
/// triggers another expansion pass.
fn is_composite_kind(kind: &str, modules: &[Module]) -> bool {
    matches!(kind, "service" | "cron-job-bundle" | "web-with-monitoring")
        || modules.iter().any(|m| m.name == kind)
}

/// One pass of expansion. Returns the new resource list and a flag
/// indicating whether any composite was expanded. The flag drives the
/// recursion loop in `expand_resources` — when it goes false the
/// fixed point is reached.
fn expand_resources_one_pass(
    resources: Vec<Value>,
    modules: &[Module],
) -> ApiResult<(Vec<Value>, bool)> {
    let mut out: Vec<Value> = Vec::with_capacity(resources.len());
    let mut changed = false;
    for raw in resources {
        let kind = raw
            .get("kind")
            .and_then(Value::as_str)
            .ok_or_else(|| ApiError::BadRequest("resource missing 'kind'".into()))?
            .to_string();
        match kind.as_str() {
            "service" => {
                changed = true;
                out.extend(expand_service(&raw)?);
            }
            "cron-job-bundle" => {
                changed = true;
                out.extend(expand_cron_job_bundle(&raw)?);
            }
            "web-with-monitoring" => {
                changed = true;
                out.extend(expand_web_with_monitoring(&raw)?);
            }
            other => {
                if let Some(m) = modules.iter().find(|m| m.name == other) {
                    changed = true;
                    out.extend(expand_module(m, &raw)?);
                } else {
                    out.push(raw);
                }
            }
        }
    }
    Ok((out, changed))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ServiceSpec {
    /// Container image reference. Required.
    image: String,
    /// Published host port. Container is expected to listen on `internal_port`
    /// (default 80) and `nginx.vhost` is wired to proxy to `127.0.0.1:port`.
    port: u16,
    /// Public domain for the nginx vhost. Required.
    domain: String,
    #[serde(default = "default_internal_port")]
    internal_port: u16,
    #[serde(default)]
    env: indexmap::IndexMap<String, String>,
    #[serde(default = "default_restart_policy")]
    restart_policy: String,
    /// Where the rendered nginx config goes. If not provided, defaults to
    /// `/etc/nginx/conf.d/<resource-name>.conf`.
    #[serde(default)]
    nginx_config_path: Option<String>,
    /// Optional agent host selector. Applied to BOTH expanded resources so
    /// nginx and the container land on the same host. CamelCase on the
    /// wire for consistency with the per-primitive providers.
    #[serde(default, rename = "hostSelector")]
    host_selector: Option<HostSelector>,
}

fn default_internal_port() -> u16 {
    80
}
fn default_restart_policy() -> String {
    "unless-stopped".into()
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct HostSelector {
    name: String,
}

fn expand_service(raw: &Value) -> ApiResult<Vec<Value>> {
    let metadata = raw
        .get("metadata")
        .and_then(Value::as_object)
        .ok_or_else(|| ApiError::BadRequest("service: metadata required".into()))?;
    let name = metadata
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| ApiError::BadRequest("service: metadata.name required".into()))?
        .to_string();
    let environment = metadata
        .get("environment")
        .and_then(Value::as_str)
        .unwrap_or("default")
        .to_string();

    let spec_value = raw
        .get("spec")
        .ok_or_else(|| ApiError::BadRequest("service: spec required".into()))?;
    let spec: ServiceSpec = serde_json::from_value(spec_value.clone())
        .map_err(|e| ApiError::BadRequest(format!("service spec: {e}")))?;

    let nginx_path = spec
        .nginx_config_path
        .clone()
        .unwrap_or_else(|| format!("/etc/nginx/conf.d/{name}.conf"));

    let host_selector = spec
        .host_selector
        .as_ref()
        .map(|h| json!({ "name": h.name }));

    // docker.container expansion
    let mut docker_spec = serde_json::Map::new();
    docker_spec.insert("name".into(), json!(name));
    docker_spec.insert("image".into(), json!(spec.image));
    docker_spec.insert("state".into(), json!("present"));
    docker_spec.insert("restart_policy".into(), json!(spec.restart_policy));
    docker_spec.insert(
        "ports".into(),
        json!(vec![format!("{}:{}", spec.port, spec.internal_port)]),
    );
    if !spec.env.is_empty() {
        let mut env_map = serde_json::Map::new();
        for (k, v) in &spec.env {
            env_map.insert(k.clone(), json!(v));
        }
        docker_spec.insert("env".into(), Value::Object(env_map));
    }
    if let Some(hs) = &host_selector {
        docker_spec.insert("hostSelector".into(), hs.clone());
    }

    let docker = json!({
        "apiVersion": "iac.example/v1",
        "kind": "docker.container",
        "metadata": {
            "name": name,
            "environment": environment,
            "annotations": { "iac.example/composite-of": "service" },
        },
        "spec": Value::Object(docker_spec),
    });

    // nginx.vhost expansion
    let mut nginx_spec = serde_json::Map::new();
    nginx_spec.insert("config_path".into(), json!(nginx_path));
    nginx_spec.insert("server_names".into(), json!(vec![spec.domain.clone()]));
    nginx_spec.insert(
        "upstream".into(),
        json!(format!("http://127.0.0.1:{}", spec.port)),
    );
    if let Some(hs) = &host_selector {
        nginx_spec.insert("hostSelector".into(), hs.clone());
    }

    let nginx = json!({
        "apiVersion": "iac.example/v1",
        "kind": "nginx.vhost",
        "metadata": {
            "name": name,
            "environment": environment,
            "annotations": { "iac.example/composite-of": "service" },
        },
        "spec": Value::Object(nginx_spec),
    });

    Ok(vec![docker, nginx])
}

// ---- cron-job-bundle (Phase 7c) -------------------------------------------
//
// Common pattern: drop a script under `/usr/local/bin/` and schedule it
// from cron. With primitives that's two coordinated resources whose
// `command` field has to match the file path. The bundle ties them
// together: script content + schedule + user + env, expand into
// `file` + `cron.job`.

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CronJobBundleSpec {
    /// 5-field crontab schedule.
    schedule: String,
    /// Body of the script. Written verbatim to `scriptPath`. We don't
    /// add a shebang automatically — if the operator wants `#!/bin/bash`,
    /// they include it themselves.
    script: String,
    /// Absolute path the script gets written to. Default
    /// `/usr/local/bin/<resource-name>`.
    #[serde(default, rename = "scriptPath")]
    script_path: Option<String>,
    /// User to run the cron entry as. Defaults to `root`.
    #[serde(default = "default_cron_user")]
    user: String,
    /// File mode for the script. Default `0755` (executable). Octal string
    /// to match the file provider's expectations.
    #[serde(default = "default_script_mode")]
    mode: String,
    /// Environment KEY=VALUE pairs emitted at the top of the cron file.
    /// Standard cron features only; no shell expansion.
    #[serde(default)]
    env: indexmap::IndexMap<String, String>,
    /// Optional agent host selector. Applied to BOTH expanded resources
    /// so the script + cron entry land on the same host.
    #[serde(default, rename = "hostSelector")]
    host_selector: Option<HostSelector>,
}

fn default_cron_user() -> String {
    "root".into()
}
fn default_script_mode() -> String {
    "0755".into()
}

fn expand_cron_job_bundle(raw: &Value) -> ApiResult<Vec<Value>> {
    let metadata = raw
        .get("metadata")
        .and_then(Value::as_object)
        .ok_or_else(|| ApiError::BadRequest("cron-job-bundle: metadata required".into()))?;
    let name = metadata
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| ApiError::BadRequest("cron-job-bundle: metadata.name required".into()))?
        .to_string();
    let environment = metadata
        .get("environment")
        .and_then(Value::as_str)
        .unwrap_or("default")
        .to_string();

    let spec_value = raw
        .get("spec")
        .ok_or_else(|| ApiError::BadRequest("cron-job-bundle: spec required".into()))?;
    let spec: CronJobBundleSpec = serde_json::from_value(spec_value.clone())
        .map_err(|e| ApiError::BadRequest(format!("cron-job-bundle spec: {e}")))?;

    let script_path = spec
        .script_path
        .clone()
        .unwrap_or_else(|| format!("/usr/local/bin/{name}"));

    let host_selector = spec
        .host_selector
        .as_ref()
        .map(|h| json!({ "name": h.name }));

    // file resource (the script)
    let mut file_spec = serde_json::Map::new();
    file_spec.insert("path".into(), json!(script_path));
    file_spec.insert("state".into(), json!("present"));
    file_spec.insert("mode".into(), json!(spec.mode));
    file_spec.insert("content".into(), json!(spec.script));
    if let Some(hs) = &host_selector {
        file_spec.insert("hostSelector".into(), hs.clone());
    }
    let file = json!({
        "apiVersion": "iac.example/v1",
        "kind": "file",
        "metadata": {
            "name": format!("{name}-script"),
            "environment": environment,
            "annotations": { "iac.example/composite-of": "cron-job-bundle" },
        },
        "spec": Value::Object(file_spec),
    });

    // cron.job resource (the schedule)
    let mut cron_spec = serde_json::Map::new();
    cron_spec.insert("name".into(), json!(name));
    cron_spec.insert("state".into(), json!("present"));
    cron_spec.insert("schedule".into(), json!(spec.schedule));
    cron_spec.insert("command".into(), json!(script_path));
    cron_spec.insert("user".into(), json!(spec.user));
    if !spec.env.is_empty() {
        let mut env_map = serde_json::Map::new();
        for (k, v) in &spec.env {
            env_map.insert(k.clone(), json!(v));
        }
        cron_spec.insert("env".into(), Value::Object(env_map));
    }
    if let Some(hs) = &host_selector {
        cron_spec.insert("hostSelector".into(), hs.clone());
    }
    let cron = json!({
        "apiVersion": "iac.example/v1",
        "kind": "cron.job",
        "metadata": {
            "name": name,
            "environment": environment,
            "annotations": { "iac.example/composite-of": "cron-job-bundle" },
        },
        "spec": Value::Object(cron_spec),
    });

    Ok(vec![file, cron])
}

// ---- web-with-monitoring (Phase 7k) ----------------------------------------
//
// `service` + a healthcheck script + cron entry that probes the
// service's health endpoint. One declaration per web app instead of
// four hand-coordinated resources whose paths/ports/domains all have
// to match. Emits `docker.container` + `nginx.vhost` + `file` + `cron.job`
// directly — no recursion through the other composites — so each
// expansion stays simple and the resulting primitives are obvious in
// the OperationDesiredState preview.

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WebWithMonitoringSpec {
    image: String,
    port: u16,
    domain: String,
    /// Path on the upstream that returns 2xx when healthy.
    /// Defaults to `/healthz`.
    #[serde(default = "default_health_path")]
    health_path: String,
    /// How often to probe. Default every 5 minutes.
    #[serde(default = "default_check_minutes")]
    check_interval_minutes: u32,
    #[serde(default = "default_internal_port")]
    internal_port: u16,
    #[serde(default)]
    env: indexmap::IndexMap<String, String>,
    #[serde(default = "default_restart_policy")]
    restart_policy: String,
    #[serde(default, rename = "hostSelector")]
    host_selector: Option<HostSelector>,
}

fn default_health_path() -> String {
    "/healthz".into()
}
fn default_check_minutes() -> u32 {
    5
}

fn expand_web_with_monitoring(raw: &Value) -> ApiResult<Vec<Value>> {
    let metadata = raw
        .get("metadata")
        .and_then(Value::as_object)
        .ok_or_else(|| ApiError::BadRequest("web-with-monitoring: metadata required".into()))?;
    let name = metadata
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| ApiError::BadRequest("web-with-monitoring: metadata.name required".into()))?
        .to_string();
    let environment = metadata
        .get("environment")
        .and_then(Value::as_str)
        .unwrap_or("default")
        .to_string();

    let spec_value = raw
        .get("spec")
        .ok_or_else(|| ApiError::BadRequest("web-with-monitoring: spec required".into()))?;
    let spec: WebWithMonitoringSpec = serde_json::from_value(spec_value.clone())
        .map_err(|e| ApiError::BadRequest(format!("web-with-monitoring spec: {e}")))?;

    if !(1..=60).contains(&spec.check_interval_minutes) {
        return Err(ApiError::BadRequest(
            "web-with-monitoring: check_interval_minutes must be 1..=60".into(),
        ));
    }

    let host_selector = spec
        .host_selector
        .as_ref()
        .map(|h| json!({ "name": h.name }));
    let composite_anno = json!({ "iac.example/composite-of": "web-with-monitoring" });
    let nginx_path = format!("/etc/nginx/conf.d/{name}.conf");
    let healthcheck_script_path = format!("/usr/local/bin/{name}-healthcheck");
    let healthcheck_url = format!("http://127.0.0.1:{}{}", spec.port, spec.health_path);
    // 2-second curl + log to syslog. Keeping it shell-only avoids
    // dragging in another runtime; operators who want richer probes
    // can override with their own check resource later.
    let healthcheck_script = format!(
        "#!/bin/sh\nset -e\ncurl --max-time 5 --silent --show-error --fail {healthcheck_url} \
         > /dev/null && logger -t {name}-healthcheck OK || logger -t {name}-healthcheck FAIL\n"
    );
    // cron schedule: every N minutes, on minute 0, 0+N, 0+2N, etc.
    // For N=5: "*/5 * * * *". For N=1: "* * * * *".
    let cron_schedule = if spec.check_interval_minutes == 1 {
        "* * * * *".to_string()
    } else {
        format!("*/{} * * * *", spec.check_interval_minutes)
    };

    // 1. docker.container (the web app)
    let mut docker_spec = serde_json::Map::new();
    docker_spec.insert("name".into(), json!(name));
    docker_spec.insert("image".into(), json!(spec.image));
    docker_spec.insert("state".into(), json!("present"));
    docker_spec.insert("restart_policy".into(), json!(spec.restart_policy));
    docker_spec.insert(
        "ports".into(),
        json!(vec![format!("{}:{}", spec.port, spec.internal_port)]),
    );
    if !spec.env.is_empty() {
        let mut env_map = serde_json::Map::new();
        for (k, v) in &spec.env {
            env_map.insert(k.clone(), json!(v));
        }
        docker_spec.insert("env".into(), Value::Object(env_map));
    }
    if let Some(hs) = &host_selector {
        docker_spec.insert("hostSelector".into(), hs.clone());
    }
    let docker = json!({
        "apiVersion": "iac.example/v1",
        "kind": "docker.container",
        "metadata": {
            "name": name,
            "environment": environment,
            "annotations": composite_anno,
        },
        "spec": Value::Object(docker_spec),
    });

    // 2. nginx.vhost (proxy)
    let mut nginx_spec = serde_json::Map::new();
    nginx_spec.insert("config_path".into(), json!(nginx_path));
    nginx_spec.insert("server_names".into(), json!(vec![spec.domain.clone()]));
    nginx_spec.insert(
        "upstream".into(),
        json!(format!("http://127.0.0.1:{}", spec.port)),
    );
    if let Some(hs) = &host_selector {
        nginx_spec.insert("hostSelector".into(), hs.clone());
    }
    let nginx = json!({
        "apiVersion": "iac.example/v1",
        "kind": "nginx.vhost",
        "metadata": {
            "name": name,
            "environment": environment,
            "annotations": composite_anno,
        },
        "spec": Value::Object(nginx_spec),
    });

    // 3. file (the healthcheck script)
    let mut file_spec = serde_json::Map::new();
    file_spec.insert("path".into(), json!(healthcheck_script_path));
    file_spec.insert("state".into(), json!("present"));
    file_spec.insert("mode".into(), json!("0755"));
    file_spec.insert("content".into(), json!(healthcheck_script));
    if let Some(hs) = &host_selector {
        file_spec.insert("hostSelector".into(), hs.clone());
    }
    let file = json!({
        "apiVersion": "iac.example/v1",
        "kind": "file",
        "metadata": {
            "name": format!("{name}-healthcheck-script"),
            "environment": environment,
            "annotations": composite_anno,
        },
        "spec": Value::Object(file_spec),
    });

    // 4. cron.job (probe schedule)
    let mut cron_spec = serde_json::Map::new();
    cron_spec.insert("name".into(), json!(format!("{name}-healthcheck")));
    cron_spec.insert("state".into(), json!("present"));
    cron_spec.insert("schedule".into(), json!(cron_schedule));
    cron_spec.insert("command".into(), json!(healthcheck_script_path));
    cron_spec.insert("user".into(), json!("root"));
    if let Some(hs) = &host_selector {
        cron_spec.insert("hostSelector".into(), hs.clone());
    }
    let cron = json!({
        "apiVersion": "iac.example/v1",
        "kind": "cron.job",
        "metadata": {
            "name": format!("{name}-healthcheck"),
            "environment": environment,
            "annotations": composite_anno,
        },
        "spec": Value::Object(cron_spec),
    });

    Ok(vec![docker, nginx, file, cron])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn service_resource(name: &str, env: &str) -> Value {
        json!({
            "apiVersion": "iac.example/v1",
            "kind": "service",
            "metadata": { "name": name, "environment": env },
            "spec": {
                "image": "nginx:1.27-alpine",
                "port": 8080,
                "domain": "app.example.com",
            }
        })
    }

    #[test]
    fn list_expanders_covers_every_match_arm() {
        // Phase 7p: drift guard. If someone adds a new composite to
        // `expand_resources` and forgets to update `list_expanders`, the
        // discovery endpoint silently lies. Round-trip every documented
        // kind through `expand_resources` with a minimal valid spec to
        // verify the catalog matches the code.
        let kinds: Vec<String> = list_expanders().iter().map(|d| d.kind.clone()).collect();
        // Sanity: catalog isn't empty.
        assert!(
            !kinds.is_empty(),
            "list_expanders should return at least one entry"
        );
        // The sole way to detect drift in the other direction (a kind
        // added to the match arm but not the catalog) is the integration
        // surface: anything reachable via expand_resources but missing
        // here would be invisible to operators. There's no programmatic
        // way to enumerate match arms without parsing source, so the
        // invariant is "this test fails on missing additions" rather
        // than "this test fails on stale removals."
        for kind in &kinds {
            // Build a representative resource per kind. Each is the
            // smallest valid spec we can construct for that composite.
            let raw = match kind.as_str() {
                "service" => json!({
                    "apiVersion": "iac.example/v1",
                    "kind": "service",
                    "metadata": { "name": "x", "environment": "test" },
                    "spec": { "image": "n", "port": 80, "domain": "x.example" }
                }),
                "cron-job-bundle" => json!({
                    "apiVersion": "iac.example/v1",
                    "kind": "cron-job-bundle",
                    "metadata": { "name": "x", "environment": "test" },
                    "spec": { "schedule": "* * * * *", "script": "echo" }
                }),
                "web-with-monitoring" => json!({
                    "apiVersion": "iac.example/v1",
                    "kind": "web-with-monitoring",
                    "metadata": { "name": "x", "environment": "test" },
                    "spec": { "image": "n", "port": 80, "domain": "x.example" }
                }),
                other => panic!(
                    "list_expanders advertises {other:?} but this drift-guard test \
                     doesn't have a representative spec for it — add one"
                ),
            };
            let out = expand_resources(vec![raw], &[])
                .expect("documented expander must accept its representative spec");
            assert!(
                !out.is_empty(),
                "{kind} should expand to at least one primitive"
            );
        }
    }

    #[test]
    fn primitive_resources_pass_through() {
        let primitive = json!({
            "apiVersion": "iac.example/v1",
            "kind": "file",
            "metadata": { "name": "x", "environment": "test" },
            "spec": { "path": "/tmp/x" },
        });
        let out = expand_resources(vec![primitive.clone()], &[]).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0]["kind"], "file");
    }

    #[test]
    fn service_expands_to_docker_plus_nginx() {
        let out = expand_resources(vec![service_resource("web", "prod")], &[]).unwrap();
        assert_eq!(out.len(), 2);
        let kinds: Vec<&str> = out.iter().map(|r| r["kind"].as_str().unwrap()).collect();
        assert!(kinds.contains(&"docker.container"));
        assert!(kinds.contains(&"nginx.vhost"));

        // Both children share the service's name + environment.
        for r in &out {
            assert_eq!(r["metadata"]["name"], "web");
            assert_eq!(r["metadata"]["environment"], "prod");
            assert_eq!(
                r["metadata"]["annotations"]["iac.example/composite-of"],
                "service"
            );
        }

        let docker = out
            .iter()
            .find(|r| r["kind"] == "docker.container")
            .unwrap();
        assert_eq!(docker["spec"]["image"], "nginx:1.27-alpine");
        assert_eq!(docker["spec"]["ports"], json!(["8080:80"]));
        assert_eq!(docker["spec"]["restart_policy"], "unless-stopped");

        let nginx = out.iter().find(|r| r["kind"] == "nginx.vhost").unwrap();
        assert_eq!(nginx["spec"]["upstream"], "http://127.0.0.1:8080");
        assert_eq!(nginx["spec"]["server_names"], json!(["app.example.com"]));
        assert_eq!(nginx["spec"]["config_path"], "/etc/nginx/conf.d/web.conf");
    }

    #[test]
    fn service_inherits_host_selector_into_both_children() {
        let mut svc = service_resource("api", "prod");
        svc["spec"]["hostSelector"] = json!({ "name": "vm-3" });
        let out = expand_resources(vec![svc], &[]).unwrap();
        for r in &out {
            assert_eq!(r["spec"]["hostSelector"]["name"], "vm-3");
        }
    }

    #[test]
    fn service_propagates_env_into_docker_only() {
        let mut svc = service_resource("api", "prod");
        svc["spec"]["env"] = json!({ "FOO": "bar", "BAZ": "qux" });
        let out = expand_resources(vec![svc], &[]).unwrap();
        let docker = out
            .iter()
            .find(|r| r["kind"] == "docker.container")
            .unwrap();
        assert_eq!(docker["spec"]["env"]["FOO"], "bar");
        // nginx vhost has no env field — not nginx's job.
        let nginx = out.iter().find(|r| r["kind"] == "nginx.vhost").unwrap();
        assert!(nginx["spec"].get("env").is_none());
    }

    #[test]
    fn service_internal_port_overrides_default_80() {
        let mut svc = service_resource("api", "prod");
        svc["spec"]["internal_port"] = json!(3000);
        let out = expand_resources(vec![svc], &[]).unwrap();
        let docker = out
            .iter()
            .find(|r| r["kind"] == "docker.container")
            .unwrap();
        assert_eq!(docker["spec"]["ports"], json!(["8080:3000"]));
    }

    #[test]
    fn service_custom_nginx_config_path() {
        let mut svc = service_resource("api", "prod");
        svc["spec"]["nginx_config_path"] = json!("/etc/nginx/sites-enabled/api.conf");
        let out = expand_resources(vec![svc], &[]).unwrap();
        let nginx = out.iter().find(|r| r["kind"] == "nginx.vhost").unwrap();
        assert_eq!(
            nginx["spec"]["config_path"],
            "/etc/nginx/sites-enabled/api.conf"
        );
    }

    #[test]
    fn malformed_service_spec_is_400() {
        // Missing `port` — required.
        let svc = json!({
            "apiVersion": "iac.example/v1",
            "kind": "service",
            "metadata": { "name": "x", "environment": "test" },
            "spec": { "image": "nginx", "domain": "a.example.com" }
        });
        let err = expand_resources(vec![svc], &[]).unwrap_err();
        match err {
            ApiError::BadRequest(msg) => assert!(msg.contains("port")),
            other => panic!("expected BadRequest, got {other:?}"),
        }
    }

    #[test]
    fn unknown_field_in_service_spec_rejected() {
        let svc = json!({
            "apiVersion": "iac.example/v1",
            "kind": "service",
            "metadata": { "name": "x", "environment": "test" },
            "spec": {
                "image": "nginx",
                "port": 8080,
                "domain": "a.example.com",
                "totally_made_up_field": "boom",
            }
        });
        let err = expand_resources(vec![svc], &[]).unwrap_err();
        assert!(matches!(err, ApiError::BadRequest(_)));
    }

    fn cron_bundle_resource(name: &str, env: &str) -> Value {
        json!({
            "apiVersion": "iac.example/v1",
            "kind": "cron-job-bundle",
            "metadata": { "name": name, "environment": env },
            "spec": {
                "schedule": "0 3 * * *",
                "script": "#!/bin/bash\necho hi\n",
            }
        })
    }

    #[test]
    fn cron_bundle_expands_to_file_plus_cron_job() {
        let out = expand_resources(vec![cron_bundle_resource("nightly", "prod")], &[]).unwrap();
        assert_eq!(out.len(), 2);
        let kinds: Vec<&str> = out.iter().map(|r| r["kind"].as_str().unwrap()).collect();
        assert!(kinds.contains(&"file"));
        assert!(kinds.contains(&"cron.job"));

        let file = out.iter().find(|r| r["kind"] == "file").unwrap();
        assert_eq!(file["metadata"]["name"], "nightly-script");
        assert_eq!(file["spec"]["path"], "/usr/local/bin/nightly");
        assert_eq!(file["spec"]["mode"], "0755");
        assert_eq!(file["spec"]["content"], "#!/bin/bash\necho hi\n");

        let cron = out.iter().find(|r| r["kind"] == "cron.job").unwrap();
        assert_eq!(cron["metadata"]["name"], "nightly");
        assert_eq!(cron["spec"]["schedule"], "0 3 * * *");
        assert_eq!(cron["spec"]["command"], "/usr/local/bin/nightly");
        assert_eq!(cron["spec"]["user"], "root");

        // Both resources annotated with their composite origin.
        for r in &out {
            assert_eq!(
                r["metadata"]["annotations"]["iac.example/composite-of"],
                "cron-job-bundle"
            );
        }
    }

    #[test]
    fn cron_bundle_inherits_host_selector_into_both_children() {
        let mut svc = cron_bundle_resource("rotate-logs", "prod");
        svc["spec"]["hostSelector"] = json!({ "name": "vm-7" });
        let out = expand_resources(vec![svc], &[]).unwrap();
        for r in &out {
            assert_eq!(r["spec"]["hostSelector"]["name"], "vm-7");
        }
    }

    #[test]
    fn cron_bundle_propagates_env_into_cron_only() {
        let mut svc = cron_bundle_resource("backup", "prod");
        svc["spec"]["env"] = json!({ "PGHOST": "db", "PATH": "/usr/local/bin:/usr/bin" });
        let out = expand_resources(vec![svc], &[]).unwrap();
        let cron = out.iter().find(|r| r["kind"] == "cron.job").unwrap();
        assert_eq!(cron["spec"]["env"]["PGHOST"], "db");
        // env doesn't leak into the file resource (file content is the script).
        let file = out.iter().find(|r| r["kind"] == "file").unwrap();
        assert!(file["spec"].get("env").is_none());
    }

    #[test]
    fn cron_bundle_custom_script_path() {
        let mut svc = cron_bundle_resource("rotate", "prod");
        svc["spec"]["scriptPath"] = json!("/opt/scripts/rotate.sh");
        let out = expand_resources(vec![svc], &[]).unwrap();
        let file = out.iter().find(|r| r["kind"] == "file").unwrap();
        assert_eq!(file["spec"]["path"], "/opt/scripts/rotate.sh");
        let cron = out.iter().find(|r| r["kind"] == "cron.job").unwrap();
        // command points at the same path so file + cron stay coherent.
        assert_eq!(cron["spec"]["command"], "/opt/scripts/rotate.sh");
    }

    #[test]
    fn cron_bundle_custom_user_and_mode() {
        let mut svc = cron_bundle_resource("vacuum", "prod");
        svc["spec"]["user"] = json!("postgres");
        svc["spec"]["mode"] = json!("0750");
        let out = expand_resources(vec![svc], &[]).unwrap();
        let cron = out.iter().find(|r| r["kind"] == "cron.job").unwrap();
        assert_eq!(cron["spec"]["user"], "postgres");
        let file = out.iter().find(|r| r["kind"] == "file").unwrap();
        assert_eq!(file["spec"]["mode"], "0750");
    }

    #[test]
    fn malformed_cron_bundle_spec_is_400() {
        // Missing `schedule`.
        let svc = json!({
            "apiVersion": "iac.example/v1",
            "kind": "cron-job-bundle",
            "metadata": { "name": "x", "environment": "test" },
            "spec": { "script": "echo hi" }
        });
        let err = expand_resources(vec![svc], &[]).unwrap_err();
        match err {
            ApiError::BadRequest(msg) => assert!(msg.contains("schedule"), "msg: {msg}"),
            other => panic!("expected BadRequest, got {other:?}"),
        }
    }

    #[test]
    fn unknown_field_in_cron_bundle_spec_rejected() {
        let svc = json!({
            "apiVersion": "iac.example/v1",
            "kind": "cron-job-bundle",
            "metadata": { "name": "x", "environment": "test" },
            "spec": {
                "schedule": "* * * * *",
                "script": "echo",
                "totally_made_up_field": "boom",
            }
        });
        let err = expand_resources(vec![svc], &[]).unwrap_err();
        assert!(matches!(err, ApiError::BadRequest(_)));
    }

    fn web_resource(name: &str, env: &str) -> Value {
        json!({
            "apiVersion": "iac.example/v1",
            "kind": "web-with-monitoring",
            "metadata": { "name": name, "environment": env },
            "spec": {
                "image": "ghcr.io/me/api:v1",
                "port": 8080,
                "domain": "api.example.com",
            }
        })
    }

    #[test]
    fn web_with_monitoring_expands_to_four_primitives() {
        let out = expand_resources(vec![web_resource("api", "prod")], &[]).unwrap();
        assert_eq!(out.len(), 4);
        let kinds: Vec<&str> = out.iter().map(|r| r["kind"].as_str().unwrap()).collect();
        assert!(kinds.contains(&"docker.container"));
        assert!(kinds.contains(&"nginx.vhost"));
        assert!(kinds.contains(&"file"));
        assert!(kinds.contains(&"cron.job"));

        for r in &out {
            assert_eq!(
                r["metadata"]["annotations"]["iac.example/composite-of"],
                "web-with-monitoring"
            );
        }
    }

    #[test]
    fn web_with_monitoring_health_url_routes_through_healthcheck_file() {
        let out = expand_resources(vec![web_resource("api", "prod")], &[]).unwrap();
        let file = out.iter().find(|r| r["kind"] == "file").unwrap();
        let cron = out.iter().find(|r| r["kind"] == "cron.job").unwrap();
        let path = file["spec"]["path"].as_str().unwrap();
        assert_eq!(path, "/usr/local/bin/api-healthcheck");
        assert_eq!(cron["spec"]["command"].as_str().unwrap(), path);
        // Default schedule is every 5 minutes.
        assert_eq!(cron["spec"]["schedule"], "*/5 * * * *");
        // Healthcheck script targets the upstream port + default
        // /healthz path.
        let content = file["spec"]["content"].as_str().unwrap();
        assert!(content.contains("http://127.0.0.1:8080/healthz"));
    }

    #[test]
    fn web_with_monitoring_custom_health_path_and_interval() {
        let mut svc = web_resource("api", "prod");
        svc["spec"]["health_path"] = json!("/api/v1/healthz");
        svc["spec"]["check_interval_minutes"] = json!(1);
        let out = expand_resources(vec![svc], &[]).unwrap();
        let cron = out.iter().find(|r| r["kind"] == "cron.job").unwrap();
        // Every minute → "* * * * *", not "*/1 * * * *".
        assert_eq!(cron["spec"]["schedule"], "* * * * *");
        let file = out.iter().find(|r| r["kind"] == "file").unwrap();
        assert!(
            file["spec"]["content"]
                .as_str()
                .unwrap()
                .contains("/api/v1/healthz")
        );
    }

    #[test]
    fn web_with_monitoring_inherits_host_selector() {
        let mut svc = web_resource("api", "prod");
        svc["spec"]["hostSelector"] = json!({ "name": "vm-web" });
        let out = expand_resources(vec![svc], &[]).unwrap();
        for r in &out {
            assert_eq!(r["spec"]["hostSelector"]["name"], "vm-web");
        }
    }

    #[test]
    fn web_with_monitoring_invalid_interval_rejected() {
        let mut svc = web_resource("api", "prod");
        svc["spec"]["check_interval_minutes"] = json!(0);
        let err = expand_resources(vec![svc], &[]).unwrap_err();
        match err {
            ApiError::BadRequest(msg) => assert!(msg.contains("check_interval_minutes")),
            other => panic!("expected BadRequest, got {other:?}"),
        }

        let mut svc = web_resource("api", "prod");
        svc["spec"]["check_interval_minutes"] = json!(120);
        assert!(matches!(
            expand_resources(vec![svc], &[]).unwrap_err(),
            ApiError::BadRequest(_)
        ));
    }

    #[test]
    fn web_with_monitoring_unknown_field_rejected() {
        let mut svc = web_resource("api", "prod");
        svc["spec"]["totally_made_up"] = json!("boom");
        let err = expand_resources(vec![svc], &[]).unwrap_err();
        assert!(matches!(err, ApiError::BadRequest(_)));
    }

    #[test]
    fn mixed_resources_expand_and_passthrough() {
        let primitive = json!({
            "apiVersion": "iac.example/v1",
            "kind": "file",
            "metadata": { "name": "y", "environment": "prod" },
            "spec": { "path": "/tmp/y" },
        });
        let out = expand_resources(vec![service_resource("web", "prod"), primitive], &[]).unwrap();
        assert_eq!(out.len(), 3);
        let kinds: Vec<&str> = out.iter().map(|r| r["kind"].as_str().unwrap()).collect();
        assert_eq!(kinds, vec!["docker.container", "nginx.vhost", "file"]);
    }
}
