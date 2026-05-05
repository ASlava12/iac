use super::backend::{normalize_port_spec, ContainerHealthcheck, DockerBackend};
use super::spec::{
    env_kv, normalize_volume_spec, parse_health_duration_secs, parse_volume_spec,
    DockerContainerSpec, DockerHealthcheck, DockerState, RestartPolicy,
};
use iac_core::{
    diff::{Diff, DiffKind, FieldChange},
    operation::{Step, StepResult},
    state::ObservedState,
    Error, Result,
};
use indexmap::IndexMap;
use serde_json::{json, Value as Json};
use serde_yaml_ng::{Mapping, Value as YamlValue};

pub fn observe(backend: &dyn DockerBackend, spec: &DockerContainerSpec) -> Result<ObservedState> {
    let info = backend.inspect_container(&spec.name)?;
    let mut facts: IndexMap<String, YamlValue> = IndexMap::new();
    let Some(info) = info else {
        facts.insert("exists".into(), YamlValue::Bool(false));
        return Ok(ObservedState {
            present: false,
            spec: YamlValue::Null,
            facts,
            observed_at: jiff::Timestamp::now(),
        });
    };

    facts.insert("exists".into(), YamlValue::Bool(true));
    facts.insert("running".into(), YamlValue::Bool(info.running));
    facts.insert("status".into(), YamlValue::String(info.status.clone()));
    facts.insert("image_ref".into(), YamlValue::String(info.image_ref.clone()));
    facts.insert("image_id".into(), YamlValue::String(info.image_id.clone()));
    facts.insert(
        "restart_policy".into(),
        YamlValue::String(info.restart_policy.clone()),
    );

    let mut spec_value = Mapping::new();
    spec_value.insert("name".into(), YamlValue::String(spec.name.clone()));
    spec_value.insert("image".into(), YamlValue::String(info.image_ref.clone()));
    spec_value.insert("running".into(), YamlValue::Bool(info.running));
    spec_value.insert(
        "restart_policy".into(),
        YamlValue::String(info.restart_policy.clone()),
    );
    spec_value.insert(
        "ports".into(),
        YamlValue::Sequence(info.ports.iter().cloned().map(YamlValue::String).collect()),
    );
    spec_value.insert(
        "env".into(),
        YamlValue::Sequence(info.env.iter().cloned().map(YamlValue::String).collect()),
    );
    // Phase 7ax: surface labels so the diff path can see them.
    spec_value.insert(
        "labels".into(),
        YamlValue::Sequence(
            info.labels.iter().cloned().map(YamlValue::String).collect(),
        ),
    );
    // Phase 7ay: surface the command override (or `Null` for "image
    // default") so the diff path can compare exact-match.
    spec_value.insert(
        "command".into(),
        match &info.command {
            Some(cmd) => YamlValue::Sequence(
                cmd.iter().cloned().map(YamlValue::String).collect(),
            ),
            None => YamlValue::Null,
        },
    );
    // Phase 7az: surface the healthcheck snapshot — same `Null` vs
    // mapping pattern. Durations carried as integer seconds so the
    // diff comparison stays direct.
    spec_value.insert(
        "healthcheck".into(),
        healthcheck_to_yaml(info.healthcheck.as_ref()),
    );
    // Phase 7ba: surface mounts in normalized `source:destination[:ro]`
    // form so the diff path can compare with the spec's input format.
    spec_value.insert(
        "volumes".into(),
        YamlValue::Sequence(
            info.volumes.iter().cloned().map(YamlValue::String).collect(),
        ),
    );
    // Phase 7bb: surface attached networks (sorted) so the diff path
    // can check set-equality against the spec's singleton.
    spec_value.insert(
        "networks".into(),
        YamlValue::Sequence(
            info.networks.iter().cloned().map(YamlValue::String).collect(),
        ),
    );
    // Phase 7bo: surface tmpfs target paths so the diff path can compare
    // against `spec.mounts` filter type=tmpfs.
    spec_value.insert(
        "tmpfs_mounts".into(),
        YamlValue::Sequence(
            info.tmpfs_mounts
                .iter()
                .cloned()
                .map(YamlValue::String)
                .collect(),
        ),
    );

    Ok(ObservedState {
        present: true,
        spec: YamlValue::Mapping(spec_value),
        facts,
        observed_at: jiff::Timestamp::now(),
    })
}

pub fn diff(
    backend: &dyn DockerBackend,
    spec: &DockerContainerSpec,
    observed: &ObservedState,
) -> Result<Diff> {
    let exists = observed.facts.get("exists").and_then(YamlValue::as_bool).unwrap_or(false);

    match (spec.state, exists) {
        (DockerState::Absent, false) => Ok(Diff::no_change()),
        (DockerState::Absent, true) => Ok(Diff {
            kind: DiffKind::Update,
            changes: vec![FieldChange {
                field: "exists".into(),
                from: Some(YamlValue::Bool(true)),
                to: Some(YamlValue::Bool(false)),
                sensitive: false,
            }],
            reasons: vec![format!("remove container {}", spec.name)],
            reversible: true,
        }),
        (DockerState::Present, false) => Ok(Diff {
            kind: DiffKind::Create,
            changes: vec![FieldChange {
                field: "exists".into(),
                from: Some(YamlValue::Bool(false)),
                to: Some(YamlValue::Bool(true)),
                sensitive: false,
            }],
            reasons: vec![format!("create container {}", spec.name)],
            reversible: true,
        }),
        (DockerState::Present, true) => {
            let mut changes: Vec<FieldChange> = Vec::new();
            let mut reasons: Vec<String> = Vec::new();

            // Compare image identity. Prefer digest comparison: pull the
            // desired image, look up its local digest, compare against the
            // running container's `.Image`.
            if let Some(desired_image) = spec.image.as_deref() {
                let observed_id = observed
                    .facts
                    .get("image_id")
                    .and_then(YamlValue::as_str)
                    .unwrap_or_default()
                    .to_string();
                let observed_ref = observed
                    .facts
                    .get("image_ref")
                    .and_then(YamlValue::as_str)
                    .unwrap_or_default()
                    .to_string();
                if let Some(desired_id) = backend.image_id(desired_image)? {
                    if desired_id != observed_id {
                        changes.push(FieldChange {
                            field: "image_id".into(),
                            from: Some(YamlValue::String(observed_id.clone())),
                            to: Some(YamlValue::String(desired_id.clone())),
                            sensitive: false,
                        });
                        reasons.push(format!("image digest {observed_id} -> {desired_id}"));
                    }
                } else if desired_image != observed_ref {
                    // Fallback: image not pulled locally yet; compare ref strings.
                    changes.push(FieldChange {
                        field: "image".into(),
                        from: Some(YamlValue::String(observed_ref.clone())),
                        to: Some(YamlValue::String(desired_image.into())),
                        sensitive: false,
                    });
                    reasons.push(format!("image {observed_ref:?} -> {desired_image:?}"));
                }
            }

            // Restart policy.
            let observed_restart = observed
                .facts
                .get("restart_policy")
                .and_then(YamlValue::as_str)
                .unwrap_or("");
            if observed_restart != spec.restart_policy.as_docker() {
                changes.push(FieldChange {
                    field: "restart_policy".into(),
                    from: Some(YamlValue::String(observed_restart.into())),
                    to: Some(YamlValue::String(spec.restart_policy.as_docker().into())),
                    sensitive: false,
                });
                reasons.push(format!(
                    "restart_policy {observed_restart:?} -> {:?}",
                    spec.restart_policy.as_docker()
                ));
            }

            // Ports — compare normalized sorted sets so "8080:80" matches "8080:80/tcp".
            let observed_ports: Vec<String> = observed
                .spec
                .as_mapping()
                .and_then(|m| m.get(YamlValue::String("ports".into())))
                .and_then(YamlValue::as_sequence)
                .map(|s| {
                    s.iter()
                        .filter_map(YamlValue::as_str)
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_default();
            let mut desired_ports: Vec<String> =
                spec.ports.iter().map(|p| normalize_port_spec(p)).collect();
            desired_ports.sort();
            let mut have_ports = observed_ports.clone();
            have_ports.sort();
            if have_ports != desired_ports {
                changes.push(FieldChange {
                    field: "ports".into(),
                    from: Some(yaml_string_list(&have_ports)),
                    to: Some(yaml_string_list(&desired_ports)),
                    sensitive: false,
                });
                reasons.push("port bindings differ".into());
            }

            // Env — compare as sets so order doesn't matter.
            let observed_env: Vec<String> = observed
                .spec
                .as_mapping()
                .and_then(|m| m.get(YamlValue::String("env".into())))
                .and_then(YamlValue::as_sequence)
                .map(|s| {
                    s.iter()
                        .filter_map(YamlValue::as_str)
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_default();
            let desired_env = env_kv(&spec.env);
            if !env_subset(&desired_env, &observed_env) {
                changes.push(FieldChange {
                    field: "env".into(),
                    from: Some(yaml_string_list(&observed_env)),
                    to: Some(yaml_string_list(&desired_env)),
                    sensitive: false,
                });
                reasons.push("env vars differ".into());
            }

            // Phase 7ax: labels — same subset semantics as env. Docker
            // auto-injects `org.opencontainers.image.*` labels from the
            // image and we don't want them to count as drift.
            let observed_labels: Vec<String> = observed
                .spec
                .as_mapping()
                .and_then(|m| m.get(YamlValue::String("labels".into())))
                .and_then(YamlValue::as_sequence)
                .map(|s| {
                    s.iter()
                        .filter_map(YamlValue::as_str)
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_default();
            let desired_labels: Vec<String> =
                spec.labels.iter().map(|(k, v)| format!("{k}={v}")).collect();
            if !env_subset(&desired_labels, &observed_labels) {
                changes.push(FieldChange {
                    field: "labels".into(),
                    from: Some(yaml_string_list(&observed_labels)),
                    to: Some(yaml_string_list(&desired_labels)),
                    sensitive: false,
                });
                reasons.push("labels differ".into());
            }

            // Phase 7ba: volumes — sorted-set comparison. Operators
            // re-arranging the list in the manifest must NOT trigger
            // drift; container-side ordering also doesn't matter.
            // Normalize both sides through `parse_volume_spec` first so
            // `host:/c` and `host:/c:rw` compare equal (both default
            // read-write).
            let observed_volumes: Vec<String> = observed
                .spec
                .as_mapping()
                .and_then(|m| m.get(YamlValue::String("volumes".into())))
                .and_then(YamlValue::as_sequence)
                .map(|s| {
                    s.iter()
                        .filter_map(YamlValue::as_str)
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_default();
            // Phase 7bn: merge `volumes` (short-form) + `mounts`
            // (long-form, bind/volume). Both feed the same observed set
            // post-`docker run`. Tmpfs entries — only expressible via
            // long-form — are skipped here because we don't observe
            // tmpfs-only mounts yet (see "Open after Phase 7bn").
            let mut desired_volumes: Vec<String> = spec
                .volumes
                .iter()
                .filter_map(|s| {
                    let (src, dst, ro) = parse_volume_spec(s).ok()?;
                    Some(normalize_volume_spec(src, dst, ro))
                })
                .chain(spec.mounts.iter().filter_map(super::spec::mount_to_short_form))
                .collect();
            desired_volumes.sort();
            let mut have_volumes = observed_volumes.clone();
            have_volumes.sort();
            if have_volumes != desired_volumes {
                changes.push(FieldChange {
                    field: "volumes".into(),
                    from: Some(yaml_string_list(&have_volumes)),
                    to: Some(yaml_string_list(&desired_volumes)),
                    sensitive: false,
                });
                reasons.push("volumes differ".into());
            }

            // Phase 7bo: tmpfs target paths. Spec entries are
            // `mounts` filter type=tmpfs; observed comes from
            // `.HostConfig.Tmpfs` keys. Both sorted; set-based
            // comparison. Skipped when both desired and observed are
            // empty so a plain container (no tmpfs) doesn't carry a
            // no-op diff field.
            let mut desired_tmpfs: Vec<String> = spec
                .mounts
                .iter()
                .filter(|m| m.r#type == "tmpfs")
                .map(|m| m.target.clone())
                .collect();
            desired_tmpfs.sort();
            let mut observed_tmpfs: Vec<String> = observed
                .spec
                .as_mapping()
                .and_then(|m| m.get(YamlValue::String("tmpfs_mounts".into())))
                .and_then(YamlValue::as_sequence)
                .map(|s| {
                    s.iter()
                        .filter_map(YamlValue::as_str)
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_default();
            observed_tmpfs.sort();
            if desired_tmpfs != observed_tmpfs
                && !(desired_tmpfs.is_empty() && observed_tmpfs.is_empty())
            {
                changes.push(FieldChange {
                    field: "tmpfs_mounts".into(),
                    from: Some(yaml_string_list(&observed_tmpfs)),
                    to: Some(yaml_string_list(&desired_tmpfs)),
                    sensitive: false,
                });
                reasons.push(format!(
                    "tmpfs targets {observed_tmpfs:?} -> {desired_tmpfs:?}"
                ));
            }

            // Phase 7bb / 7bm: network attachment — check the observed
            // network set against the spec's primary + extras. Comparison
            // is set-based (sorted) so reordering `extra_networks` in a
            // manifest doesn't trigger drift; `docker inspect`'s output
            // ordering is also non-deterministic. No comparison when
            // `spec.network` is `None` AND `extra_networks` is empty —
            // operator hasn't expressed a preference, default-bridge
            // container shouldn't drift.
            if spec.network.is_some() || !spec.extra_networks.is_empty() {
                let observed_nets: Vec<String> = observed
                    .spec
                    .as_mapping()
                    .and_then(|m| m.get(YamlValue::String("networks".into())))
                    .and_then(YamlValue::as_sequence)
                    .map(|s| {
                        s.iter()
                            .filter_map(YamlValue::as_str)
                            .map(str::to_string)
                            .collect()
                    })
                    .unwrap_or_default();
                let mut have = observed_nets.clone();
                have.sort();
                let mut want: Vec<String> = spec
                    .network
                    .iter()
                    .cloned()
                    .chain(spec.extra_networks.iter().cloned())
                    .collect();
                want.sort();
                if have != want {
                    changes.push(FieldChange {
                        field: "network".into(),
                        from: Some(yaml_string_list(&have)),
                        to: Some(yaml_string_list(&want)),
                        sensitive: false,
                    });
                    reasons.push(format!(
                        "network attachment {have:?} -> {want:?}"
                    ));
                }
            }

            // Phase 7az: healthcheck — exact-match per field. Only fires
            // when the operator declared `healthcheck:` in the spec.
            // `None` desired never claims drift against whatever the
            // image's default looks like.
            if let Some(desired_hc) = &spec.healthcheck {
                // Re-extract the observed healthcheck as a structured
                // form. It's faster than walking the YAML mapping and
                // also clearer for the FieldChange `from`/`to` payload.
                let observed_hc: Option<&YamlValue> = observed
                    .spec
                    .as_mapping()
                    .and_then(|m| m.get(YamlValue::String("healthcheck".into())));
                let mut hc_diffs: Vec<String> = Vec::new();
                let observed_cmd = observed_hc
                    .and_then(YamlValue::as_mapping)
                    .and_then(|m| m.get(YamlValue::String("command".into())))
                    .and_then(YamlValue::as_str);
                if observed_cmd != Some(desired_hc.command.as_str()) {
                    hc_diffs.push(format!(
                        "command {:?} -> {:?}",
                        observed_cmd.unwrap_or(""),
                        desired_hc.command
                    ));
                }
                let want_interval = desired_hc
                    .interval
                    .as_deref()
                    .and_then(|s| parse_health_duration_secs(s).ok());
                let have_interval = observed_hc
                    .and_then(YamlValue::as_mapping)
                    .and_then(|m| m.get(YamlValue::String("interval_secs".into())))
                    .and_then(YamlValue::as_u64);
                if want_interval != have_interval {
                    hc_diffs.push(format!(
                        "interval {have_interval:?}s -> {want_interval:?}s"
                    ));
                }
                let want_timeout = desired_hc
                    .timeout
                    .as_deref()
                    .and_then(|s| parse_health_duration_secs(s).ok());
                let have_timeout = observed_hc
                    .and_then(YamlValue::as_mapping)
                    .and_then(|m| m.get(YamlValue::String("timeout_secs".into())))
                    .and_then(YamlValue::as_u64);
                if want_timeout != have_timeout {
                    hc_diffs.push(format!(
                        "timeout {have_timeout:?}s -> {want_timeout:?}s"
                    ));
                }
                let want_retries = desired_hc.retries.map(u64::from);
                let have_retries = observed_hc
                    .and_then(YamlValue::as_mapping)
                    .and_then(|m| m.get(YamlValue::String("retries".into())))
                    .and_then(YamlValue::as_u64);
                if want_retries != have_retries {
                    hc_diffs.push(format!(
                        "retries {have_retries:?} -> {want_retries:?}"
                    ));
                }
                if !hc_diffs.is_empty() {
                    changes.push(FieldChange {
                        field: "healthcheck".into(),
                        from: Some(
                            observed_hc.cloned().unwrap_or(YamlValue::Null),
                        ),
                        to: Some(serde_yaml_ng::to_value(desired_hc).unwrap_or(YamlValue::Null)),
                        sensitive: false,
                    });
                    reasons.push(format!("healthcheck differs: {}", hc_diffs.join(", ")));
                }
            }

            // Phase 7ay: command override — exact-match comparison. Only
            // fires when the operator declared a `command:` in the spec;
            // `None` means "use image default" and we never claim drift
            // against whatever the running container's CMD actually is.
            if let Some(desired_cmd) = &spec.command {
                let observed_cmd: Vec<String> = observed
                    .spec
                    .as_mapping()
                    .and_then(|m| m.get(YamlValue::String("command".into())))
                    .and_then(YamlValue::as_sequence)
                    .map(|s| {
                        s.iter()
                            .filter_map(YamlValue::as_str)
                            .map(str::to_string)
                            .collect()
                    })
                    .unwrap_or_default();
                if &observed_cmd != desired_cmd {
                    changes.push(FieldChange {
                        field: "command".into(),
                        from: Some(yaml_string_list(&observed_cmd)),
                        to: Some(yaml_string_list(desired_cmd)),
                        sensitive: false,
                    });
                    reasons.push("command differs".into());
                }
            }

            // Container should be running for state=present.
            let running = observed.facts.get("running").and_then(YamlValue::as_bool).unwrap_or(false);
            if !running {
                changes.push(FieldChange {
                    field: "running".into(),
                    from: Some(YamlValue::Bool(false)),
                    to: Some(YamlValue::Bool(true)),
                    sensitive: false,
                });
                reasons.push("container is not running".into());
            }

            if changes.is_empty() {
                Ok(Diff::no_change())
            } else {
                Ok(Diff { kind: DiffKind::Update, changes, reasons, reversible: true })
            }
        }
    }
}

fn yaml_string_list(items: &[String]) -> YamlValue {
    YamlValue::Sequence(items.iter().cloned().map(YamlValue::String).collect())
}

/// Phase 7az: render the healthcheck snapshot as a YAML mapping (or
/// `Null` when none configured). Keys match the spec field names so
/// diff output reads naturally.
fn healthcheck_to_yaml(hc: Option<&ContainerHealthcheck>) -> YamlValue {
    let Some(hc) = hc else {
        return YamlValue::Null;
    };
    let mut m = Mapping::new();
    if let Some(c) = &hc.command {
        m.insert("command".into(), YamlValue::String(c.clone()));
    }
    if let Some(s) = hc.interval_secs {
        m.insert("interval_secs".into(), YamlValue::Number(s.into()));
    }
    if let Some(s) = hc.timeout_secs {
        m.insert("timeout_secs".into(), YamlValue::Number(s.into()));
    }
    if let Some(r) = hc.retries {
        m.insert("retries".into(), YamlValue::Number(r.into()));
    }
    YamlValue::Mapping(m)
}

/// `desired ⊆ observed`. Docker auto-injects PATH and similar entries we don't
/// want to fight, so we only require that all desired k/v pairs are present.
fn env_subset(desired: &[String], observed: &[String]) -> bool {
    desired.iter().all(|d| observed.iter().any(|o| o == d))
}

pub fn plan(spec: &DockerContainerSpec, diff: &Diff) -> Vec<Step> {
    if !diff.is_change() {
        return vec![];
    }
    match spec.state {
        DockerState::Present => {
            // Whether create-or-recreate, the apply path is the same: ensure
            // the image is pulled, stop+remove if exists, then run.
            vec![
                Step::new(
                    super::DockerAction::Pull.as_str(),
                    format!("pull {}", spec.image.as_deref().unwrap_or("")),
                    json!({ "image": spec.image }),
                ),
                Step::new(
                    super::DockerAction::Recreate.as_str(),
                    format!("recreate container {}", spec.name),
                    json!({ "name": spec.name }),
                ),
            ]
        }
        DockerState::Absent => vec![Step::new(
            super::DockerAction::Remove.as_str(),
            format!("remove container {}", spec.name),
            json!({ "name": spec.name }),
        )],
    }
}

pub fn pre_apply(backend: &dyn DockerBackend, spec: &DockerContainerSpec) -> Result<Json> {
    let info = backend.inspect_container(&spec.name)?;
    Ok(match info {
        Some(c) => json!({
            "name": spec.name,
            "previous_existed": true,
            "previous_image_ref": c.image_ref,
            "previous_image_id": c.image_id,
            "previous_env": c.env,
            "previous_ports": c.ports,
            "previous_restart_policy": c.restart_policy,
            // Phase 7ax: keep labels in the checkpoint so rollback restores
            // the same set, not just env/ports.
            "previous_labels": c.labels,
            // Phase 7ay: same for the command override. `null` means
            // "image default CMD", preserved across rollback.
            "previous_command": c.command,
            // Phase 7az: healthcheck snapshot for rollback. Encoded as
            // a JSON object with the seconds-form durations the spec
            // layer emits. `null` means "no healthcheck observed."
            "previous_healthcheck": c.healthcheck.as_ref().map(|hc| {
                json!({
                    "command": hc.command,
                    "interval_secs": hc.interval_secs,
                    "timeout_secs": hc.timeout_secs,
                    "retries": hc.retries,
                })
            }),
            // Phase 7ba: mount snapshot. Already in canonical
            // `source:destination[:ro]` strings, so rollback can
            // re-feed them straight back into spec.volumes.
            "previous_volumes": c.volumes,
            // Phase 7bb: primary network. We snapshot the FIRST attached
            // network as the rollback target. If the previous container
            // was on the default bridge (no operator-declared network),
            // the observed list is `["bridge"]` — restore that explicitly
            // so the rollback recreates with the same attachment.
            "previous_networks": c.networks,
        }),
        None => json!({
            "name": spec.name,
            "previous_existed": false,
        }),
    })
}

pub fn apply(backend: &dyn DockerBackend, spec: &DockerContainerSpec, step: &Step) -> Result<StepResult> {
    let name = step
        .payload
        .get("name")
        .and_then(Json::as_str)
        .unwrap_or(&spec.name);
    match super::DockerAction::parse(&step.action)? {
        super::DockerAction::Pull => {
            let image = step
                .payload
                .get("image")
                .and_then(Json::as_str)
                .or(spec.image.as_deref())
                .ok_or_else(|| Error::provider("docker", "pull requires image"))?;
            backend.pull(image)?;
            Ok(StepResult::ok(format!("pulled {image}")))
        }
        super::DockerAction::Recreate => {
            // Idempotent: stop+remove if it exists, then run.
            backend.stop(name)?;
            backend.remove(name, true)?;
            backend.run(spec)?;
            // Phase 7bm: attach to additional networks post-create.
            // `--network` at create time only covers the primary; extras
            // are connected via `docker network connect` here. Order
            // matches the spec field order, so operators see consistent
            // attachment ordering between manifests and `docker
            // inspect` output.
            for net in &spec.extra_networks {
                backend.connect_network(name, net)?;
            }
            Ok(StepResult::ok(format!("recreated {name}")))
        }
        super::DockerAction::Remove => {
            backend.stop(name)?;
            backend.remove(name, true)?;
            Ok(StepResult::ok(format!("removed {name}")))
        }
    }
}

pub fn rollback(
    backend: &dyn DockerBackend,
    spec: &DockerContainerSpec,
    checkpoint: &Json,
) -> Result<()> {
    let existed = checkpoint.get("previous_existed").and_then(Json::as_bool).unwrap_or(false);
    let name = checkpoint
        .get("name")
        .and_then(Json::as_str)
        .unwrap_or(&spec.name);
    if !existed {
        // Container didn't exist before — remove anything we created.
        backend.stop(name)?;
        backend.remove(name, true)?;
        return Ok(());
    }
    let prev_image = checkpoint
        .get("previous_image_ref")
        .and_then(Json::as_str)
        .ok_or_else(|| Error::provider("docker", "rollback missing previous_image_ref"))?;
    let prev_env: Vec<String> = checkpoint
        .get("previous_env")
        .and_then(Json::as_array)
        .map(|a| a.iter().filter_map(Json::as_str).map(str::to_string).collect())
        .unwrap_or_default();
    let prev_ports: Vec<String> = checkpoint
        .get("previous_ports")
        .and_then(Json::as_array)
        .map(|a| a.iter().filter_map(Json::as_str).map(str::to_string).collect())
        .unwrap_or_default();
    let prev_restart = checkpoint
        .get("previous_restart_policy")
        .and_then(Json::as_str)
        .unwrap_or("unless-stopped");
    let restart_policy = RestartPolicy::parse(prev_restart).unwrap_or_default();
    // Phase 7ax: restore labels from the checkpoint. Pre-7ax checkpoints
    // won't have this field; fall back to empty so rollbacks of older
    // operations still work.
    let prev_labels: Vec<String> = checkpoint
        .get("previous_labels")
        .and_then(Json::as_array)
        .map(|a| a.iter().filter_map(Json::as_str).map(str::to_string).collect())
        .unwrap_or_default();
    // Phase 7ay: restore the command override. Distinguish three cases:
    //   * `null` (or pre-7ay missing) → None: image default CMD.
    //   * non-empty array → Some(args).
    //   * empty array → treat as None (impossible to write today, but
    //     defensive in case an older checkpoint snuck through).
    let prev_command: Option<Vec<String>> = checkpoint
        .get("previous_command")
        .and_then(Json::as_array)
        .map(|a| a.iter().filter_map(Json::as_str).map(str::to_string).collect())
        .filter(|v: &Vec<String>| !v.is_empty());
    // Phase 7ba: restore mount strings. Pre-7ba checkpoints don't carry
    // this field; fall back to empty so older rollbacks still work.
    let prev_volumes: Vec<String> = checkpoint
        .get("previous_volumes")
        .and_then(Json::as_array)
        .map(|a| a.iter().filter_map(Json::as_str).map(str::to_string).collect())
        .unwrap_or_default();
    // Phase 7bb / 7bm: restore network attachments. The first observed
    // non-bridge network becomes the primary `--network`; remaining
    // entries become `extra_networks`. Bridge alone collapses to `None`
    // (no explicit `--network`) — same effective state, cleaner spec.
    let prev_networks_all: Vec<String> = checkpoint
        .get("previous_networks")
        .and_then(Json::as_array)
        .map(|a| a.iter().filter_map(Json::as_str).map(str::to_string).collect())
        .unwrap_or_default();
    let mut prev_networks_filtered: Vec<String> = prev_networks_all
        .into_iter()
        .filter(|n| n != "bridge")
        .collect();
    let prev_network: Option<String> = if prev_networks_filtered.is_empty() {
        None
    } else {
        Some(prev_networks_filtered.remove(0))
    };
    let prev_extra_networks: Vec<String> = prev_networks_filtered;
    // Phase 7az: restore the healthcheck. Pre-7az checkpoints don't have
    // this field; fall back to None. The reverse mapping converts the
    // stored seconds-form durations back into the `"<n>s"` strings the
    // spec layer emits.
    let prev_healthcheck: Option<DockerHealthcheck> = checkpoint
        .get("previous_healthcheck")
        .and_then(|v| v.as_object())
        .and_then(|m| {
            let command = m
                .get("command")
                .and_then(Json::as_str)
                .map(str::to_string)?;
            let interval = m
                .get("interval_secs")
                .and_then(Json::as_u64)
                .map(|s| format!("{s}s"));
            let timeout = m
                .get("timeout_secs")
                .and_then(Json::as_u64)
                .map(|s| format!("{s}s"));
            let retries = m
                .get("retries")
                .and_then(Json::as_u64)
                .and_then(|n| u32::try_from(n).ok());
            Some(DockerHealthcheck { command, interval, timeout, retries })
        });

    let mut env = IndexMap::new();
    for entry in &prev_env {
        if let Some((k, v)) = entry.split_once('=') {
            env.insert(k.to_string(), v.to_string());
        }
    }
    let mut labels = IndexMap::new();
    for entry in &prev_labels {
        if let Some((k, v)) = entry.split_once('=') {
            labels.insert(k.to_string(), v.to_string());
        }
    }

    let prev_spec = DockerContainerSpec {
        name: name.to_string(),
        image: Some(prev_image.to_string()),
        state: DockerState::Present,
        env,
        ports: prev_ports,
        restart_policy,
        labels,
        command: prev_command,
        healthcheck: prev_healthcheck,
        volumes: prev_volumes,
        network: prev_network,
        extra_networks: prev_extra_networks.clone(),

        mounts: vec![],
    };
    backend.stop(name)?;
    backend.remove(name, true)?;
    backend.pull(prev_image)?;
    backend.run(&prev_spec)?;
    // Phase 7bm: re-attach extra networks post-`run`. The primary
    // `--network` was set at create time; extras need the same
    // `network connect` post-step the apply path uses.
    for net in &prev_extra_networks {
        backend.connect_network(name, net)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::backend::MockDocker;
    use super::*;

    fn make_spec(name: &str, image: &str) -> DockerContainerSpec {
        DockerContainerSpec {
            name: name.into(),
            image: Some(image.into()),
            state: DockerState::Present,
            env: IndexMap::new(),
            ports: vec![],
            restart_policy: RestartPolicy::UnlessStopped,
            labels: indexmap::IndexMap::new(),
            command: None,
            healthcheck: None,
            volumes: vec![],
            network: None,
            extra_networks: vec![],

            mounts: vec![],
        }
    }

    #[test]
    fn create_when_absent() {
        let backend = MockDocker::new();
        let spec = make_spec("web", "nginx:1.27");
        let observed = observe(&backend, &spec).unwrap();
        let d = diff(&backend, &spec, &observed).unwrap();
        assert_eq!(d.kind, DiffKind::Create);
        let steps = plan(&spec, &d);
        assert_eq!(steps.len(), 2);
        assert_eq!(steps[0].action, "docker.pull");
        assert_eq!(steps[1].action, "docker.recreate");

        // Run them.
        for s in &steps {
            apply(&backend, &spec, s).unwrap();
        }
        let info = backend.inspect_container("web").unwrap().unwrap();
        assert!(info.running);
        assert_eq!(info.image_ref, "nginx:1.27");
    }

    #[test]
    fn idempotent_when_already_correct() {
        let backend = MockDocker::new();
        backend.set_image_digest("nginx:1.27", "sha256:abc");
        backend.containers.lock().unwrap().insert(
            "web".into(),
            super::super::backend::MockContainer {
                running: true,
                image_ref: "nginx:1.27".into(),
                image_id: "sha256:abc".into(),
                env: vec![],
                ports: vec![],
                restart_policy: "unless-stopped".into(),
                            labels: vec![],
                            command: None,
                            healthcheck: None,
                            volumes: vec![],
                            networks: vec![],

                            tmpfs_mounts: vec![],
            },
        );
        let spec = make_spec("web", "nginx:1.27");
        let observed = observe(&backend, &spec).unwrap();
        let d = diff(&backend, &spec, &observed).unwrap();
        assert_eq!(d.kind, DiffKind::NoChange);
    }

    #[test]
    fn image_digest_change_recreates() {
        let backend = MockDocker::new();
        // Existing container with old digest.
        backend.containers.lock().unwrap().insert(
            "web".into(),
            super::super::backend::MockContainer {
                running: true,
                image_ref: "nginx:1.27".into(),
                image_id: "sha256:old".into(),
                env: vec![],
                ports: vec![],
                restart_policy: "unless-stopped".into(),
                            labels: vec![],
                            command: None,
                            healthcheck: None,
                            volumes: vec![],
                            networks: vec![],

                            tmpfs_mounts: vec![],
            },
        );
        // Local image now has a different digest (e.g. tag was repointed upstream).
        backend.set_image_digest("nginx:1.27", "sha256:new");
        let spec = make_spec("web", "nginx:1.27");
        let observed = observe(&backend, &spec).unwrap();
        let d = diff(&backend, &spec, &observed).unwrap();
        assert_eq!(d.kind, DiffKind::Update);
        assert!(d.changes.iter().any(|c| c.field == "image_id"));
    }

    #[test]
    fn port_change_recreates() {
        let backend = MockDocker::new();
        backend.set_image_digest("nginx:1.27", "sha256:x");
        backend.containers.lock().unwrap().insert(
            "web".into(),
            super::super::backend::MockContainer {
                running: true,
                image_ref: "nginx:1.27".into(),
                image_id: "sha256:x".into(),
                env: vec![],
                ports: vec!["8080:80/tcp".into()],
                restart_policy: "unless-stopped".into(),
                            labels: vec![],
                            command: None,
                            healthcheck: None,
                            volumes: vec![],
                            networks: vec![],

                            tmpfs_mounts: vec![],
            },
        );
        let mut spec = make_spec("web", "nginx:1.27");
        spec.ports = vec!["9090:80".into()]; // unnormalized form
        let observed = observe(&backend, &spec).unwrap();
        let d = diff(&backend, &spec, &observed).unwrap();
        assert_eq!(d.kind, DiffKind::Update);
        assert!(d.changes.iter().any(|c| c.field == "ports"));
    }

    #[test]
    fn env_subset_treats_extra_observed_as_ok() {
        let desired = vec!["FOO=bar".into()];
        let observed = vec!["PATH=/usr/bin".into(), "FOO=bar".into()];
        assert!(env_subset(&desired, &observed));

        // Missing desired → not subset.
        assert!(!env_subset(&["FOO=bar".into()], &["PATH=/usr/bin".into()]));
    }

    #[test]
    fn absent_when_present_removes() {
        let backend = MockDocker::new();
        backend.containers.lock().unwrap().insert(
            "web".into(),
            super::super::backend::MockContainer {
                running: true,
                image_ref: "nginx:1.27".into(),
                image_id: "sha256:x".into(),
                ..Default::default()
            },
        );
        let spec = DockerContainerSpec {
            name: "web".into(),
            image: None,
            state: DockerState::Absent,
            env: IndexMap::new(),
            ports: vec![],
            restart_policy: RestartPolicy::UnlessStopped,
                    labels: indexmap::IndexMap::new(),
                    command: None,
                    healthcheck: None,
                    volumes: vec![],
                    network: None,

                    extra_networks: vec![],


                    mounts: vec![],
        };
        let observed = observe(&backend, &spec).unwrap();
        let d = diff(&backend, &spec, &observed).unwrap();
        assert_eq!(d.kind, DiffKind::Update);
        let steps = plan(&spec, &d);
        assert_eq!(steps[0].action, "docker.remove");
        apply(&backend, &spec, &steps[0]).unwrap();
        assert!(backend.inspect_container("web").unwrap().is_none());
    }

    #[test]
    fn rollback_recreates_with_previous_image() {
        let backend = MockDocker::new();
        // Set up: there was a container with image v1.
        backend.set_image_digest("nginx:1.0", "sha256:v1");
        backend.containers.lock().unwrap().insert(
            "web".into(),
            super::super::backend::MockContainer {
                running: true,
                image_ref: "nginx:1.0".into(),
                image_id: "sha256:v1".into(),
                env: vec!["FOO=bar".into()],
                ports: vec!["8080:80/tcp".into()],
                restart_policy: "unless-stopped".into(),
                            labels: vec![],
                            command: None,
                            healthcheck: None,
                            volumes: vec![],
                            networks: vec![],

                            tmpfs_mounts: vec![],
            },
        );

        let cp = pre_apply(&backend, &DockerContainerSpec {
            name: "web".into(),
            image: Some("nginx:2.0".into()),
            state: DockerState::Present,
            env: IndexMap::new(),
            ports: vec![],
            restart_policy: RestartPolicy::UnlessStopped,
                    labels: indexmap::IndexMap::new(),
                    command: None,
                    healthcheck: None,
                    volumes: vec![],
                    network: None,

                    extra_networks: vec![],


                    mounts: vec![],
        }).unwrap();

        // Now upgrade to v2.
        backend.set_image_digest("nginx:2.0", "sha256:v2");
        let new_spec = DockerContainerSpec {
            name: "web".into(),
            image: Some("nginx:2.0".into()),
            state: DockerState::Present,
            env: IndexMap::new(),
            ports: vec![],
            restart_policy: RestartPolicy::UnlessStopped,
                    labels: indexmap::IndexMap::new(),
                    command: None,
                    healthcheck: None,
                    volumes: vec![],
                    network: None,

                    extra_networks: vec![],


                    mounts: vec![],
        };
        backend.stop("web").unwrap();
        backend.remove("web", true).unwrap();
        backend.run(&new_spec).unwrap();
        assert_eq!(backend.inspect_container("web").unwrap().unwrap().image_ref, "nginx:2.0");

        // Rollback to checkpoint.
        rollback(&backend, &new_spec, &cp).unwrap();
        let restored = backend.inspect_container("web").unwrap().unwrap();
        assert_eq!(restored.image_ref, "nginx:1.0");
        assert!(restored.env.contains(&"FOO=bar".to_string()));
        assert_eq!(restored.ports, vec!["8080:80/tcp"]);
    }

    #[test]
    fn rollback_removes_when_no_previous() {
        let backend = MockDocker::new();
        let spec = make_spec("web", "nginx:1.27");
        let cp = pre_apply(&backend, &spec).unwrap();
        backend.set_image_digest("nginx:1.27", "sha256:x");
        backend.run(&spec).unwrap();
        assert!(backend.inspect_container("web").unwrap().is_some());
        rollback(&backend, &spec, &cp).unwrap();
        assert!(backend.inspect_container("web").unwrap().is_none());
    }

    #[test]
    fn missing_labels_show_as_drift_then_apply_recreates() {
        // Phase 7ax: a desired label not present on the running container
        // should surface in the diff and trigger a recreate.
        let backend = MockDocker::new();
        let mut spec = make_spec("web", "nginx:1.27");
        // First create without labels.
        backend.set_image_digest("nginx:1.27", "sha256:x");
        backend.run(&spec).unwrap();
        // Now declare labels — diff should fire on `labels`.
        spec.labels.insert("app".into(), "web".into());
        spec.labels.insert("managed-by".into(), "iac".into());
        let observed = observe(&backend, &spec).unwrap();
        let d = diff(&backend, &spec, &observed).unwrap();
        assert!(d.is_change(), "labels mismatch should produce diff");
        let label_change = d.changes.iter().find(|c| c.field == "labels");
        assert!(label_change.is_some(), "labels field change expected");
    }

    #[test]
    fn extra_observed_labels_are_subset_tolerated() {
        // Phase 7ax: extra labels on the running container (e.g. those
        // baked into the image) MUST NOT count as drift, mirroring the
        // env-subset semantics.
        let backend = MockDocker::new();
        let mut spec = make_spec("web", "nginx:1.27");
        spec.labels.insert("app".into(), "web".into());
        backend.set_image_digest("nginx:1.27", "sha256:x");
        backend.run(&spec).unwrap();

        // Sneak an extra label onto the mock container directly. Real
        // Docker's behavior we're imitating: image-baked labels appear
        // in inspect output without us setting them.
        backend
            .containers
            .lock()
            .unwrap()
            .get_mut("web")
            .unwrap()
            .labels
            .push("org.opencontainers.image.source=ghcr.io/x".to_string());

        let observed = observe(&backend, &spec).unwrap();
        let d = diff(&backend, &spec, &observed).unwrap();
        // Subset check passes — desired labels still all present.
        let label_change = d.changes.iter().find(|c| c.field == "labels");
        assert!(
            label_change.is_none(),
            "extra observed labels should not produce drift"
        );
    }

    #[test]
    fn missing_command_field_means_no_drift_against_image_default() {
        // Phase 7ay: spec.command = None means "image default CMD";
        // observed CMD (whatever it is) must NOT show as drift.
        let backend = MockDocker::new();
        let spec = make_spec("web", "nginx:1.27");
        backend.set_image_digest("nginx:1.27", "sha256:x");
        backend.run(&spec).unwrap();

        // Sneak a CMD onto the mock container as if the image declared one.
        backend
            .containers
            .lock()
            .unwrap()
            .get_mut("web")
            .unwrap()
            .command = Some(vec!["nginx".into(), "-g".into(), "daemon off;".into()]);

        let observed = observe(&backend, &spec).unwrap();
        let d = diff(&backend, &spec, &observed).unwrap();
        let cmd_change = d.changes.iter().find(|c| c.field == "command");
        assert!(
            cmd_change.is_none(),
            "spec.command=None should NOT diff against image default"
        );
    }

    #[test]
    fn explicit_command_drifts_when_observed_differs() {
        // Phase 7ay: declaring `command:` MUST exact-match observed argv.
        let backend = MockDocker::new();
        let mut spec = make_spec("worker", "alpine:3.20");
        spec.command = Some(vec!["worker".into(), "--queue=high".into()]);
        backend.set_image_digest("alpine:3.20", "sha256:x");
        backend.run(&spec).unwrap();

        // Mutate observed to a different argv (simulating an out-of-band
        // recreation by a human).
        backend
            .containers
            .lock()
            .unwrap()
            .get_mut("worker")
            .unwrap()
            .command = Some(vec!["worker".into(), "--queue=low".into()]);

        let observed = observe(&backend, &spec).unwrap();
        let d = diff(&backend, &spec, &observed).unwrap();
        let cmd_change = d.changes.iter().find(|c| c.field == "command");
        assert!(cmd_change.is_some(), "explicit command mismatch must drift");
    }

    #[test]
    fn command_argument_order_matters() {
        // Phase 7ay: argv is order-sensitive — `["a", "b"]` vs `["b", "a"]`
        // is real drift, not a false-positive from sort-order asymmetry.
        let backend = MockDocker::new();
        let mut spec = make_spec("worker", "alpine:3.20");
        spec.command = Some(vec!["a".into(), "b".into()]);
        backend.set_image_digest("alpine:3.20", "sha256:x");
        backend.run(&spec).unwrap();

        backend
            .containers
            .lock()
            .unwrap()
            .get_mut("worker")
            .unwrap()
            .command = Some(vec!["b".into(), "a".into()]);

        let observed = observe(&backend, &spec).unwrap();
        let d = diff(&backend, &spec, &observed).unwrap();
        assert!(d.changes.iter().any(|c| c.field == "command"));
    }

    #[test]
    fn rollback_restores_command_from_checkpoint() {
        // Phase 7ay: the checkpoint must carry the previous command argv
        // so rollback recreates with the same override (or absence).
        let backend = MockDocker::new();
        let mut prev_spec = make_spec("worker", "alpine:3.20");
        prev_spec.command = Some(vec!["worker".into(), "--queue=high".into()]);
        backend.set_image_digest("alpine:3.20", "sha256:old");
        backend.run(&prev_spec).unwrap();

        let new_spec = make_spec("worker", "alpine:3.21");
        let cp = pre_apply(&backend, &new_spec).unwrap();

        // Apply the upgrade with a different command.
        let mut new_spec_with_cmd = new_spec.clone();
        new_spec_with_cmd.command = Some(vec!["worker".into(), "--queue=low".into()]);
        backend.set_image_digest("alpine:3.21", "sha256:new");
        backend.stop("worker").unwrap();
        backend.remove("worker", true).unwrap();
        backend.run(&new_spec_with_cmd).unwrap();
        assert_eq!(
            backend.inspect_container("worker").unwrap().unwrap().command,
            Some(vec!["worker".into(), "--queue=low".into()])
        );

        // Rollback should restore the OLD argv.
        rollback(&backend, &new_spec, &cp).unwrap();
        let restored = backend.inspect_container("worker").unwrap().unwrap();
        assert_eq!(
            restored.command,
            Some(vec!["worker".into(), "--queue=high".into()]),
            "rollback should restore prev argv"
        );
    }

    #[test]
    fn network_drifts_when_observed_attaches_to_default_bridge() {
        // Phase 7bb: spec declares `my-net`, but the observed container
        // landed on `bridge` (e.g. an old container created before the
        // network field was added). Diff must fire.
        let backend = MockDocker::new();
        let mut spec = make_spec("web", "nginx:1.27");
        backend.set_image_digest("nginx:1.27", "sha256:x");
        backend.run(&spec).unwrap();
        // Mock currently has the container on `bridge`. Now declare a
        // different network.
        spec.network = Some("my-net".into());
        let observed = observe(&backend, &spec).unwrap();
        let d = diff(&backend, &spec, &observed).unwrap();
        assert!(
            d.changes.iter().any(|c| c.field == "network"),
            "network mismatch must drift"
        );
    }

    #[test]
    fn network_no_drift_when_spec_unset_and_observed_default() {
        // Phase 7bb: spec.network = None means "operator hasn't expressed
        // a preference"; observed = ["bridge"] should NOT drift.
        let backend = MockDocker::new();
        let spec = make_spec("web", "nginx:1.27");
        backend.set_image_digest("nginx:1.27", "sha256:x");
        backend.run(&spec).unwrap();
        let observed = observe(&backend, &spec).unwrap();
        let d = diff(&backend, &spec, &observed).unwrap();
        assert!(
            d.changes.iter().all(|c| c.field != "network"),
            "default-bridge with no spec.network must NOT drift"
        );
    }

    #[test]
    fn network_no_drift_when_spec_matches_observed() {
        let backend = MockDocker::new();
        let mut spec = make_spec("web", "nginx:1.27");
        spec.network = Some("custom-net".into());
        backend.set_image_digest("nginx:1.27", "sha256:x");
        backend.run(&spec).unwrap();
        let observed = observe(&backend, &spec).unwrap();
        let d = diff(&backend, &spec, &observed).unwrap();
        assert!(
            d.changes.iter().all(|c| c.field != "network"),
            "matching network must NOT drift"
        );
    }

    #[test]
    fn rollback_restores_network_from_checkpoint() {
        let backend = MockDocker::new();
        let mut prev_spec = make_spec("web", "nginx:1.0");
        prev_spec.network = Some("old-net".into());
        backend.set_image_digest("nginx:1.0", "sha256:old");
        backend.run(&prev_spec).unwrap();

        let new_spec = make_spec("web", "nginx:2.0");
        let cp = pre_apply(&backend, &new_spec).unwrap();

        // Apply with a new network.
        let mut new_with_net = new_spec.clone();
        new_with_net.network = Some("new-net".into());
        backend.set_image_digest("nginx:2.0", "sha256:new");
        backend.stop("web").unwrap();
        backend.remove("web", true).unwrap();
        backend.run(&new_with_net).unwrap();

        // Rollback to OLD network.
        rollback(&backend, &new_spec, &cp).unwrap();
        let restored = backend.inspect_container("web").unwrap().unwrap();
        assert_eq!(restored.networks, vec!["old-net".to_string()]);
    }

    #[test]
    fn rollback_to_default_bridge_leaves_no_explicit_network() {
        // Phase 7bb: if the previous container was on default `bridge`
        // (no operator-set network), rollback should NOT re-set an
        // explicit network — leaving spec.network = None.
        let backend = MockDocker::new();
        let prev_spec = make_spec("web", "nginx:1.0"); // no .network
        backend.set_image_digest("nginx:1.0", "sha256:old");
        backend.run(&prev_spec).unwrap();

        let new_spec = make_spec("web", "nginx:2.0");
        let cp = pre_apply(&backend, &new_spec).unwrap();

        // Apply with an explicit network.
        let mut new_with_net = new_spec.clone();
        new_with_net.network = Some("explicit-net".into());
        backend.set_image_digest("nginx:2.0", "sha256:new");
        backend.stop("web").unwrap();
        backend.remove("web", true).unwrap();
        backend.run(&new_with_net).unwrap();

        rollback(&backend, &new_spec, &cp).unwrap();
        // After rollback, container is on default bridge (no explicit
        // network arg means MockDocker stores ["bridge"]).
        let restored = backend.inspect_container("web").unwrap().unwrap();
        assert_eq!(restored.networks, vec!["bridge".to_string()]);
    }

    // Phase 7bm: extra_networks (multi-network attach).

    #[test]
    fn apply_attaches_extra_networks_after_run() {
        // Apply path: docker.recreate runs the container then issues
        // `docker network connect` per extra_networks entry. MockDocker
        // tracks each connect call and updates the container's networks
        // list, so the post-apply observed state should include all
        // declared networks.
        let backend = MockDocker::new();
        let mut spec = make_spec("web", "nginx:1.27");
        spec.network = Some("primary".into());
        spec.extra_networks = vec!["mon".into(), "audit".into()];
        backend.set_image_digest("nginx:1.27", "sha256:x");

        let observed = observe(&backend, &spec).unwrap();
        let d = diff(&backend, &spec, &observed).unwrap();
        let steps = plan(&spec, &d);
        for s in &steps {
            apply(&backend, &spec, s).unwrap();
        }
        let info = backend.inspect_container("web").unwrap().unwrap();
        let mut got = info.networks;
        got.sort();
        assert_eq!(
            got,
            vec!["audit".to_string(), "mon".to_string(), "primary".to_string()]
        );
        // Verify the connect_network call sequence — both extras hit it.
        let calls = backend.calls();
        assert!(calls.iter().any(|c| c == "connect_network web mon"));
        assert!(calls.iter().any(|c| c == "connect_network web audit"));
    }

    #[test]
    fn diff_fires_when_extra_network_missing_from_observed() {
        // Spec declares primary + 1 extra, but the container is only on
        // the primary. Diff must catch the missing attachment.
        let backend = MockDocker::new();
        let mut spec = make_spec("web", "nginx:1.27");
        spec.network = Some("primary".into());
        backend.set_image_digest("nginx:1.27", "sha256:x");
        backend.run(&spec).unwrap(); // creates container on `primary` only

        spec.extra_networks = vec!["mon".into()];
        let observed = observe(&backend, &spec).unwrap();
        let d = diff(&backend, &spec, &observed).unwrap();
        assert!(
            d.changes.iter().any(|c| c.field == "network"),
            "missing extra network must trigger drift"
        );
    }

    #[test]
    fn diff_no_drift_when_extra_networks_match_observed_set() {
        // After full attach (primary + extras), observed networks match
        // the spec's declared set; no drift should fire.
        let backend = MockDocker::new();
        let mut spec = make_spec("web", "nginx:1.27");
        spec.network = Some("primary".into());
        spec.extra_networks = vec!["mon".into(), "audit".into()];
        backend.set_image_digest("nginx:1.27", "sha256:x");
        backend.run(&spec).unwrap();
        // Manually attach extras to mirror what the real apply path does.
        backend.connect_network("web", "mon").unwrap();
        backend.connect_network("web", "audit").unwrap();

        let observed = observe(&backend, &spec).unwrap();
        let d = diff(&backend, &spec, &observed).unwrap();
        assert!(
            d.changes.iter().all(|c| c.field != "network"),
            "matching network set must NOT drift"
        );
    }

    #[test]
    fn diff_no_drift_when_extra_networks_reordered() {
        // Set-based comparison: re-ordering the spec's extra_networks
        // declaration must not trigger drift since the observed set is
        // identical.
        let backend = MockDocker::new();
        let mut spec = make_spec("web", "nginx:1.27");
        spec.network = Some("primary".into());
        spec.extra_networks = vec!["mon".into(), "audit".into()];
        backend.set_image_digest("nginx:1.27", "sha256:x");
        backend.run(&spec).unwrap();
        backend.connect_network("web", "mon").unwrap();
        backend.connect_network("web", "audit").unwrap();

        let mut reordered = spec.clone();
        reordered.extra_networks = vec!["audit".into(), "mon".into()]; // swapped
        let observed = observe(&backend, &reordered).unwrap();
        let d = diff(&backend, &reordered, &observed).unwrap();
        assert!(
            d.changes.iter().all(|c| c.field != "network"),
            "reordered extras must NOT drift; got changes: {:?}",
            d.changes
        );
    }

    // Phase 7bn: long-form mounts equivalence with short-form volumes.

    #[test]
    fn long_form_mount_produces_same_observed_state_as_short_form() {
        let backend = MockDocker::new();
        backend.set_image_digest("nginx:1.27", "sha256:x");

        // Spec A: short-form `volumes`.
        let mut spec_short = make_spec("a", "nginx:1.27");
        spec_short.volumes = vec!["/host:/cont".into()];
        backend.run(&spec_short).unwrap();

        // Spec B: long-form `mounts`, same logical mount.
        let mut spec_long = make_spec("b", "nginx:1.27");
        spec_long.mounts = vec![super::super::spec::DockerMount {
            r#type: "bind".into(),
            source: Some("/host".into()),
            target: "/cont".into(),
            readonly: false,
        }];
        backend.run(&spec_long).unwrap();

        let info_a = backend.inspect_container("a").unwrap().unwrap();
        let info_b = backend.inspect_container("b").unwrap().unwrap();
        assert_eq!(info_a.volumes, info_b.volumes);
    }

    #[test]
    fn diff_no_drift_when_long_form_matches_short_form_observed() {
        // Container was created with short-form `-v /host:/cont`. Operator
        // re-declares the same mount as long-form. Diff must NOT fire —
        // the canonical short-form is identical.
        let backend = MockDocker::new();
        backend.set_image_digest("nginx:1.27", "sha256:x");
        let mut spec = make_spec("web", "nginx:1.27");
        spec.volumes = vec!["/host:/cont".into()];
        backend.run(&spec).unwrap();

        // Now re-declare with long-form.
        let mut new_spec = make_spec("web", "nginx:1.27");
        new_spec.mounts = vec![super::super::spec::DockerMount {
            r#type: "bind".into(),
            source: Some("/host".into()),
            target: "/cont".into(),
            readonly: false,
        }];
        let observed = observe(&backend, &new_spec).unwrap();
        let d = diff(&backend, &new_spec, &observed).unwrap();
        assert!(
            d.changes.iter().all(|c| c.field != "volumes"),
            "long-form should canonicalize to short-form; got: {:?}",
            d.changes
        );
    }

    // Phase 7bo: tmpfs round-trip through diff.

    #[test]
    fn tmpfs_round_trips_no_drift_on_reapply() {
        // Container created with tmpfs mount; re-running observe + diff
        // against the same spec should NOT report drift. This was the
        // open-after-7bn issue: tmpfs targets weren't observed.
        let backend = MockDocker::new();
        backend.set_image_digest("nginx:1.27", "sha256:x");
        let mut spec = make_spec("web", "nginx:1.27");
        spec.mounts = vec![super::super::spec::DockerMount {
            r#type: "tmpfs".into(),
            source: None,
            target: "/cache".into(),
            readonly: false,
        }];
        backend.run(&spec).unwrap();

        let observed = observe(&backend, &spec).unwrap();
        let d = diff(&backend, &spec, &observed).unwrap();
        assert!(
            d.changes.iter().all(|c| c.field != "tmpfs_mounts"),
            "tmpfs round-trip must NOT drift; got: {:?}",
            d.changes
        );
    }

    #[test]
    fn tmpfs_drift_when_declared_but_missing_from_observed() {
        // Container created without tmpfs; spec adds one. Diff must
        // catch it.
        let backend = MockDocker::new();
        backend.set_image_digest("nginx:1.27", "sha256:x");
        let plain_spec = make_spec("web", "nginx:1.27");
        backend.run(&plain_spec).unwrap();

        let mut new_spec = make_spec("web", "nginx:1.27");
        new_spec.mounts = vec![super::super::spec::DockerMount {
            r#type: "tmpfs".into(),
            source: None,
            target: "/cache".into(),
            readonly: false,
        }];
        let observed = observe(&backend, &new_spec).unwrap();
        let d = diff(&backend, &new_spec, &observed).unwrap();
        let tmpfs_change = d.changes.iter().find(|c| c.field == "tmpfs_mounts");
        assert!(
            tmpfs_change.is_some(),
            "missing tmpfs target must drift; got: {:?}",
            d.changes
        );
    }

    #[test]
    fn tmpfs_drift_when_extra_target_observed() {
        // Container has a tmpfs mount the spec didn't declare. Diff
        // surfaces the difference (operator can choose to revert).
        let backend = MockDocker::new();
        backend.set_image_digest("nginx:1.27", "sha256:x");
        let mut spec_with_tmpfs = make_spec("web", "nginx:1.27");
        spec_with_tmpfs.mounts = vec![super::super::spec::DockerMount {
            r#type: "tmpfs".into(),
            source: None,
            target: "/cache".into(),
            readonly: false,
        }];
        backend.run(&spec_with_tmpfs).unwrap();

        // Operator removes the tmpfs from the manifest.
        let plain_spec = make_spec("web", "nginx:1.27");
        let observed = observe(&backend, &plain_spec).unwrap();
        let d = diff(&backend, &plain_spec, &observed).unwrap();
        assert!(
            d.changes.iter().any(|c| c.field == "tmpfs_mounts"),
            "extra tmpfs target must drift; got: {:?}",
            d.changes
        );
    }

    #[test]
    fn tmpfs_set_based_no_drift_on_reorder() {
        let backend = MockDocker::new();
        backend.set_image_digest("nginx:1.27", "sha256:x");
        let mut spec = make_spec("web", "nginx:1.27");
        spec.mounts = vec![
            super::super::spec::DockerMount {
                r#type: "tmpfs".into(),
                source: None,
                target: "/cache".into(),
                readonly: false,
            },
            super::super::spec::DockerMount {
                r#type: "tmpfs".into(),
                source: None,
                target: "/run".into(),
                readonly: false,
            },
        ];
        backend.run(&spec).unwrap();

        // Reorder in the spec.
        let mut reordered = spec.clone();
        reordered.mounts.reverse();
        let observed = observe(&backend, &reordered).unwrap();
        let d = diff(&backend, &reordered, &observed).unwrap();
        assert!(
            d.changes.iter().all(|c| c.field != "tmpfs_mounts"),
            "tmpfs set comparison must be order-independent; got: {:?}",
            d.changes
        );
    }

    #[test]
    fn diff_fires_when_long_form_mount_missing() {
        // Container has no mounts; spec declares one via long-form.
        // Diff must surface the missing mount.
        let backend = MockDocker::new();
        backend.set_image_digest("nginx:1.27", "sha256:x");
        let spec = make_spec("web", "nginx:1.27");
        backend.run(&spec).unwrap(); // no volumes/mounts

        let mut new_spec = make_spec("web", "nginx:1.27");
        new_spec.mounts = vec![super::super::spec::DockerMount {
            r#type: "bind".into(),
            source: Some("/host".into()),
            target: "/cont".into(),
            readonly: true,
        }];
        let observed = observe(&backend, &new_spec).unwrap();
        let d = diff(&backend, &new_spec, &observed).unwrap();
        assert!(
            d.changes.iter().any(|c| c.field == "volumes"),
            "missing long-form mount must drift; got: {:?}",
            d.changes
        );
    }

    #[test]
    fn rollback_restores_full_network_set_including_extras() {
        // Previous container has primary + 1 extra. New apply changes
        // both. Rollback must restore the original primary AND extra.
        let backend = MockDocker::new();
        let mut prev_spec = make_spec("web", "nginx:1.0");
        prev_spec.network = Some("old-primary".into());
        prev_spec.extra_networks = vec!["old-extra".into()];
        backend.set_image_digest("nginx:1.0", "sha256:old");
        backend.run(&prev_spec).unwrap();
        backend.connect_network("web", "old-extra").unwrap();

        let new_spec = make_spec("web", "nginx:2.0");
        let cp = pre_apply(&backend, &new_spec).unwrap();

        // Apply with totally different networks.
        let mut new_with_nets = new_spec.clone();
        new_with_nets.network = Some("new-primary".into());
        new_with_nets.extra_networks = vec!["new-extra".into()];
        backend.set_image_digest("nginx:2.0", "sha256:new");
        backend.stop("web").unwrap();
        backend.remove("web", true).unwrap();
        backend.run(&new_with_nets).unwrap();
        backend.connect_network("web", "new-extra").unwrap();

        rollback(&backend, &new_spec, &cp).unwrap();
        let mut restored = backend.inspect_container("web").unwrap().unwrap().networks;
        restored.sort();
        assert_eq!(
            restored,
            vec!["old-extra".to_string(), "old-primary".to_string()],
            "rollback must restore both primary and extra"
        );
    }

    #[test]
    fn volumes_diff_is_set_based_not_order_sensitive() {
        // Phase 7ba: re-arranging the volumes list in the manifest must
        // NOT trigger drift. Same set, different order → no diff.
        let backend = MockDocker::new();
        let mut spec = make_spec("web", "nginx:1.27");
        spec.volumes = vec![
            "/var/data:/app/data".into(),
            "/etc/conf:/conf:ro".into(),
        ];
        backend.set_image_digest("nginx:1.27", "sha256:x");
        backend.run(&spec).unwrap();

        // Same volumes, different declaration order.
        let mut spec_reordered = spec.clone();
        spec_reordered.volumes = vec![
            "/etc/conf:/conf:ro".into(),
            "/var/data:/app/data".into(),
        ];
        let observed = observe(&backend, &spec_reordered).unwrap();
        let d = diff(&backend, &spec_reordered, &observed).unwrap();
        assert!(
            d.changes.iter().all(|c| c.field != "volumes"),
            "reordering volumes must NOT count as drift"
        );
    }

    #[test]
    fn volumes_diff_fires_on_added_or_removed_mount() {
        let backend = MockDocker::new();
        let mut spec = make_spec("web", "nginx:1.27");
        spec.volumes = vec!["/var/data:/app/data".into()];
        backend.set_image_digest("nginx:1.27", "sha256:x");
        backend.run(&spec).unwrap();

        // Operator adds a second volume.
        spec.volumes.push("/etc/conf:/conf:ro".into());
        let observed = observe(&backend, &spec).unwrap();
        let d = diff(&backend, &spec, &observed).unwrap();
        assert!(
            d.changes.iter().any(|c| c.field == "volumes"),
            "added volume should drift"
        );

        // And removing a volume.
        let mut spec_minus = spec.clone();
        spec_minus.volumes.clear();
        let observed = observe(&backend, &spec_minus).unwrap();
        let d = diff(&backend, &spec_minus, &observed).unwrap();
        assert!(
            d.changes.iter().any(|c| c.field == "volumes"),
            "removed volume should drift"
        );
    }

    #[test]
    fn volume_mode_change_is_drift() {
        // Phase 7ba: rw → ro is a real change (read-only is a meaningful
        // security control).
        let backend = MockDocker::new();
        let mut spec = make_spec("web", "nginx:1.27");
        spec.volumes = vec!["/var/data:/app/data".into()];
        backend.set_image_digest("nginx:1.27", "sha256:x");
        backend.run(&spec).unwrap();

        spec.volumes = vec!["/var/data:/app/data:ro".into()];
        let observed = observe(&backend, &spec).unwrap();
        let d = diff(&backend, &spec, &observed).unwrap();
        assert!(
            d.changes.iter().any(|c| c.field == "volumes"),
            "rw → ro must drift"
        );
    }

    #[test]
    fn volume_default_mode_normalizes_against_explicit_rw() {
        // `host:/c` and `host:/c:rw` are equivalent — both default to rw.
        // Diff should not fire when the operator writes one and the
        // observed reports the other.
        let backend = MockDocker::new();
        let mut spec = make_spec("web", "nginx:1.27");
        spec.volumes = vec!["/var/data:/app/data:rw".into()];
        backend.set_image_digest("nginx:1.27", "sha256:x");
        backend.run(&spec).unwrap();

        // Now query with the no-suffix form.
        let mut probe = spec.clone();
        probe.volumes = vec!["/var/data:/app/data".into()];
        let observed = observe(&backend, &probe).unwrap();
        let d = diff(&backend, &probe, &observed).unwrap();
        assert!(
            d.changes.iter().all(|c| c.field != "volumes"),
            "rw default and explicit rw must compare equal"
        );
    }

    #[test]
    fn rollback_restores_volumes_from_checkpoint() {
        let backend = MockDocker::new();
        let mut prev_spec = make_spec("web", "nginx:1.0");
        prev_spec.volumes = vec![
            "/old/data:/app/data".into(),
            "myvol:/cache".into(),
        ];
        backend.set_image_digest("nginx:1.0", "sha256:old");
        backend.run(&prev_spec).unwrap();

        let new_spec = make_spec("web", "nginx:2.0");
        let cp = pre_apply(&backend, &new_spec).unwrap();

        // Apply with completely different mounts.
        let mut new_with_vols = new_spec.clone();
        new_with_vols.volumes = vec!["/new/data:/app/data:ro".into()];
        backend.set_image_digest("nginx:2.0", "sha256:new");
        backend.stop("web").unwrap();
        backend.remove("web", true).unwrap();
        backend.run(&new_with_vols).unwrap();

        // Rollback to OLD volumes.
        rollback(&backend, &new_spec, &cp).unwrap();
        let restored = backend.inspect_container("web").unwrap().unwrap();
        let mut got = restored.volumes.clone();
        got.sort();
        assert_eq!(
            got,
            vec![
                "/old/data:/app/data".to_string(),
                "myvol:/cache".to_string(),
            ]
        );
    }

    #[test]
    fn missing_healthcheck_field_means_no_drift_against_image_default() {
        // Phase 7az: spec.healthcheck = None must NOT claim drift against
        // whatever the image's default healthcheck happens to be.
        let backend = MockDocker::new();
        let spec = make_spec("web", "nginx:1.27");
        backend.set_image_digest("nginx:1.27", "sha256:x");
        backend.run(&spec).unwrap();

        // Sneak an image-default-style healthcheck onto the mock.
        backend
            .containers
            .lock()
            .unwrap()
            .get_mut("web")
            .unwrap()
            .healthcheck = Some(super::super::backend::ContainerHealthcheck {
            command: Some("curl -f http://localhost/ || exit 1".into()),
            interval_secs: Some(30),
            timeout_secs: Some(10),
            retries: Some(3),
        });

        let observed = observe(&backend, &spec).unwrap();
        let d = diff(&backend, &spec, &observed).unwrap();
        let hc_change = d.changes.iter().find(|c| c.field == "healthcheck");
        assert!(
            hc_change.is_none(),
            "spec.healthcheck=None should NOT claim drift"
        );
    }

    #[test]
    fn explicit_healthcheck_drifts_when_observed_differs() {
        // Phase 7az: declared healthcheck must exact-match observed.
        let backend = MockDocker::new();
        let mut spec = make_spec("web", "nginx:1.27");
        spec.healthcheck = Some(DockerHealthcheck {
            command: "curl -f http://localhost/".into(),
            interval: Some("30s".into()),
            timeout: Some("5s".into()),
            retries: Some(3),
        });
        backend.set_image_digest("nginx:1.27", "sha256:x");
        backend.run(&spec).unwrap();

        // Observe initially: should match (no drift).
        let observed = observe(&backend, &spec).unwrap();
        let d = diff(&backend, &spec, &observed).unwrap();
        assert!(
            d.changes.iter().all(|c| c.field != "healthcheck"),
            "freshly-applied spec should match observed"
        );

        // Mutate observed: bump retries to 5.
        backend
            .containers
            .lock()
            .unwrap()
            .get_mut("web")
            .unwrap()
            .healthcheck
            .as_mut()
            .unwrap()
            .retries = Some(5);

        let observed = observe(&backend, &spec).unwrap();
        let d = diff(&backend, &spec, &observed).unwrap();
        let hc_change = d
            .changes
            .iter()
            .find(|c| c.field == "healthcheck")
            .expect("retries change must drift");
        assert_eq!(hc_change.field, "healthcheck");
    }

    #[test]
    fn healthcheck_duration_units_compare_correctly() {
        // Phase 7az: spec writes "30s"/"2m"/"1h"; observed stores
        // integer seconds. Diff must canonicalize.
        let backend = MockDocker::new();
        let mut spec = make_spec("web", "nginx:1.27");
        spec.healthcheck = Some(DockerHealthcheck {
            command: "true".into(),
            interval: Some("2m".into()), // 120s
            timeout: None,
            retries: None,
        });
        backend.set_image_digest("nginx:1.27", "sha256:x");
        backend.run(&spec).unwrap();

        // After run, observed.interval_secs should be 120 — same canonical
        // value as the spec's "2m".
        let observed = observe(&backend, &spec).unwrap();
        let d = diff(&backend, &spec, &observed).unwrap();
        assert!(
            d.changes.iter().all(|c| c.field != "healthcheck"),
            "2m and 120s should compare equal"
        );
    }

    #[test]
    fn rollback_restores_healthcheck_from_checkpoint() {
        // Phase 7az: rollback must restore the previous healthcheck.
        let backend = MockDocker::new();
        let mut prev_spec = make_spec("web", "nginx:1.0");
        prev_spec.healthcheck = Some(DockerHealthcheck {
            command: "curl -f http://localhost/".into(),
            interval: Some("30s".into()),
            timeout: None,
            retries: Some(3),
        });
        backend.set_image_digest("nginx:1.0", "sha256:old");
        backend.run(&prev_spec).unwrap();

        let new_spec = make_spec("web", "nginx:2.0");
        let cp = pre_apply(&backend, &new_spec).unwrap();

        // Apply with a NEW healthcheck.
        let mut new_with_hc = new_spec.clone();
        new_with_hc.healthcheck = Some(DockerHealthcheck {
            command: "wget -q --spider http://localhost/".into(),
            interval: Some("10s".into()),
            timeout: None,
            retries: Some(5),
        });
        backend.set_image_digest("nginx:2.0", "sha256:new");
        backend.stop("web").unwrap();
        backend.remove("web", true).unwrap();
        backend.run(&new_with_hc).unwrap();

        // Rollback to the OLD healthcheck.
        rollback(&backend, &new_spec, &cp).unwrap();
        let restored = backend.inspect_container("web").unwrap().unwrap();
        let hc = restored.healthcheck.expect("healthcheck restored");
        assert_eq!(hc.command.as_deref(), Some("curl -f http://localhost/"));
        assert_eq!(hc.interval_secs, Some(30));
        assert_eq!(hc.retries, Some(3));
    }

    #[test]
    fn rollback_restores_lack_of_command() {
        // Phase 7ay: if the previous container ran with the image's
        // default CMD (no override), the checkpoint stores `None` and
        // rollback must NOT re-set a command.
        let backend = MockDocker::new();
        let prev_spec = make_spec("web", "nginx:1.0"); // command = None
        backend.set_image_digest("nginx:1.0", "sha256:old");
        backend.run(&prev_spec).unwrap();

        let new_spec = make_spec("web", "nginx:2.0");
        let cp = pre_apply(&backend, &new_spec).unwrap();

        // Operator added an explicit command in the new spec.
        let mut new_with_cmd = new_spec.clone();
        new_with_cmd.command = Some(vec!["nginx".into(), "-g".into(), "daemon off;".into()]);
        backend.set_image_digest("nginx:2.0", "sha256:new");
        backend.stop("web").unwrap();
        backend.remove("web", true).unwrap();
        backend.run(&new_with_cmd).unwrap();

        rollback(&backend, &new_spec, &cp).unwrap();
        let restored = backend.inspect_container("web").unwrap().unwrap();
        assert!(
            restored.command.is_none(),
            "rollback to a no-command-override state should leave .command = None, got {:?}",
            restored.command
        );
    }

    #[test]
    fn rollback_restores_labels_from_checkpoint() {
        // Phase 7ax: the checkpoint must carry the previous label set so
        // rollback recreates the container with the same labels.
        let backend = MockDocker::new();
        let mut prev_spec = make_spec("web", "nginx:1.0");
        prev_spec.labels.insert("app".into(), "web".into());
        prev_spec.labels.insert("version".into(), "1.0".into());
        backend.set_image_digest("nginx:1.0", "sha256:old");
        backend.run(&prev_spec).unwrap();

        // Snapshot before the upgrade.
        let new_spec = make_spec("web", "nginx:2.0");
        let cp = pre_apply(&backend, &new_spec).unwrap();

        // Apply the upgrade with NEW labels.
        let mut new_spec_with_labels = new_spec.clone();
        new_spec_with_labels
            .labels
            .insert("app".into(), "web".into());
        new_spec_with_labels
            .labels
            .insert("version".into(), "2.0".into());
        backend.set_image_digest("nginx:2.0", "sha256:new");
        backend.stop("web").unwrap();
        backend.remove("web", true).unwrap();
        backend.run(&new_spec_with_labels).unwrap();

        // Rollback should restore the previous (1.0) labels.
        rollback(&backend, &new_spec, &cp).unwrap();
        let restored = backend.inspect_container("web").unwrap().unwrap();
        assert!(restored.labels.contains(&"app=web".to_string()));
        assert!(
            restored.labels.contains(&"version=1.0".to_string()),
            "expected version=1.0, got {:?}",
            restored.labels
        );
        assert!(
            !restored.labels.contains(&"version=2.0".to_string()),
            "rollback should not have the new version label"
        );
    }
}
