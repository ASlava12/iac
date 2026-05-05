//! Phase 7g: dependency-graph ordering for resources within an
//! operation.
//!
//! Operators can declare `metadata.dependsOn: [<resource_id>...]` on
//! any resource. At submit time we read those edges, validate them
//! (cycle-free, every reference points at another resource in the same
//! operation), and topologically sort the post-expansion routing list.
//! Per-agent buckets inherit that order, so each agent receives its
//! resources already sequenced — no apply-time graph machinery needed.
//!
//! Cross-agent edges become "no constraint": agents apply in parallel,
//! so the topo sort is informational rather than blocking. We don't
//! reject those today; the audit stays clean and operators get the
//! intra-agent ordering they declared. A future refinement could split
//! cross-agent dependents into a follow-up operation.
//!
//! References to ids outside the operation, or cycles, are 400.

use crate::error::{ApiError, ApiResult};
use crate::store::ResourceForRouting;
use std::collections::{BTreeMap, BTreeSet, VecDeque};

/// Phase 7by: BFS-depth ("layer") of every resource in the post-topo
/// routing list. A resource with no `dependsOn` edges incoming gets
/// layer 0; each step further down the chain adds 1.
///
/// Used by phased apply: layer-N assignments hold in
/// `status='pending_layer'` until ALL layer-(N-1) assignments succeed
/// across every agent. Cross-agent edges become real synchronization
/// barriers — agent A can't start work that depends on a resource
/// being applied on agent B until B reports success.
///
/// `routing` must already be topo-sorted (call `topo_sort_by_depends_on`
/// first) so the layer of any node's dependencies is fully known by the
/// time we visit the node.
///
/// Returns layers in the same order as `routing`. Errors only on
/// unknown / self-dependency, which the topo sort already would have
/// caught — kept defensive in case callers ever skip the sort.
pub fn compute_resource_layers(routing: &[ResourceForRouting]) -> ApiResult<Vec<i32>> {
    if routing.is_empty() {
        return Ok(Vec::new());
    }
    let mut id_to_idx: BTreeMap<String, usize> = BTreeMap::new();
    for (i, r) in routing.iter().enumerate() {
        id_to_idx.insert(r.resource_id.clone(), i);
    }
    let mut layers: Vec<i32> = vec![0; routing.len()];
    for (i, r) in routing.iter().enumerate() {
        let deps = read_depends_on(&r.resource_json)?;
        let mut max_dep_layer: i32 = -1;
        for dep_id in deps {
            let dep_idx = id_to_idx.get(&dep_id).copied().ok_or_else(|| {
                ApiError::BadRequest(format!(
                    "{}: dependsOn references unknown resource {dep_id:?}",
                    r.resource_id
                ))
            })?;
            if dep_idx >= i {
                // Topo sort guarantees deps come before; if not, caller
                // didn't sort. Rather than silently producing a wrong
                // layer, surface the inconsistency.
                return Err(ApiError::Internal(format!(
                    "compute_resource_layers: dep {dep_idx} of resource {i} \
                     not yet visited — caller must topo-sort first"
                )));
            }
            max_dep_layer = max_dep_layer.max(layers[dep_idx]);
        }
        layers[i] = max_dep_layer + 1;
    }
    Ok(layers)
}

/// Sort `routing` so any resource declared via `metadata.dependsOn`
/// comes after the resources it depends on. Resources without
/// dependencies preserve their original relative order (Kahn's
/// algorithm with an indexed `Vec` queue keeps stability). Returns
/// `BadRequest` on cycle or unknown reference.
pub fn topo_sort_by_depends_on(routing: &mut Vec<ResourceForRouting>) -> ApiResult<()> {
    if routing.is_empty() {
        return Ok(());
    }

    // Build resource_id → index in original routing list. We mutate
    // by index swap rather than re-cloning so ResourceForRouting can
    // stay non-Clone-cheap.
    let mut id_to_idx: BTreeMap<String, usize> = BTreeMap::new();
    for (i, r) in routing.iter().enumerate() {
        id_to_idx.insert(r.resource_id.clone(), i);
    }

    let n = routing.len();
    let mut in_degree: Vec<usize> = vec![0; n];
    let mut adjacency: Vec<Vec<usize>> = vec![Vec::new(); n];

    for (i, r) in routing.iter().enumerate() {
        let deps = read_depends_on(&r.resource_json)?;
        for dep_id in deps {
            let Some(&dep_idx) = id_to_idx.get(&dep_id) else {
                return Err(ApiError::BadRequest(format!(
                    "{}: dependsOn references unknown resource {dep_id:?}",
                    r.resource_id
                )));
            };
            if dep_idx == i {
                return Err(ApiError::BadRequest(format!(
                    "{}: dependsOn must not point at itself",
                    r.resource_id
                )));
            }
            adjacency[dep_idx].push(i);
            in_degree[i] += 1;
        }
    }

    // Kahn's. Seed with all zero-in-degree nodes in their original
    // index order — gives stable output.
    let mut queue: VecDeque<usize> = (0..n).filter(|&i| in_degree[i] == 0).collect();
    let mut order: Vec<usize> = Vec::with_capacity(n);
    while let Some(idx) = queue.pop_front() {
        order.push(idx);
        for &next in &adjacency[idx] {
            in_degree[next] -= 1;
            if in_degree[next] == 0 {
                queue.push_back(next);
            }
        }
    }

    if order.len() != n {
        // Some node still has in-degree > 0 → cycle. Surface a couple
        // of the involved resource ids so the operator can find the loop.
        let stuck: Vec<&str> = in_degree
            .iter()
            .enumerate()
            .filter(|(_, d)| **d > 0)
            .map(|(i, _)| routing[i].resource_id.as_str())
            .take(5)
            .collect();
        return Err(ApiError::BadRequest(format!(
            "dependsOn cycle detected (involves: {})",
            stuck.join(", ")
        )));
    }

    // Apply the new order. We need to rearrange `routing` to match
    // `order`. Build a fresh Vec by moving items out one at a time:
    // we use Option<T> as a take-out-cell since ResourceForRouting
    // isn't Default-or-Clone-friendly to fake.
    let mut taker: Vec<Option<ResourceForRouting>> =
        routing.drain(..).map(Some).collect();
    let mut sorted: Vec<ResourceForRouting> = Vec::with_capacity(n);
    for idx in order {
        // Phase 7cz.16: `order` is the topological-sort output and
        // contains each idx in `0..n` exactly once, so each `take()`
        // sees a Some. Tag for clippy.
        #[allow(clippy::expect_used)]
        let entry = taker[idx].take().expect("each idx is visited once");
        sorted.push(entry);
    }
    *routing = sorted;
    Ok(())
}

/// Read `metadata.dependsOn: [<resource_id>...]` from the resource JSON
/// blob. Missing field → empty Vec. Wrong type → 400 so operators get
/// a clear error instead of silent acceptance.
fn read_depends_on(resource_json: &str) -> ApiResult<Vec<String>> {
    let value: serde_json::Value = serde_json::from_str(resource_json)
        .map_err(|e| ApiError::BadRequest(format!("malformed resource json: {e}")))?;
    let Some(deps_value) = value
        .get("metadata")
        .and_then(|m| m.get("dependsOn"))
    else {
        return Ok(Vec::new());
    };
    let Some(arr) = deps_value.as_array() else {
        return Err(ApiError::BadRequest(
            "metadata.dependsOn must be an array of resource id strings".into(),
        ));
    };
    let mut out = Vec::with_capacity(arr.len());
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for item in arr {
        let Some(s) = item.as_str() else {
            return Err(ApiError::BadRequest(
                "metadata.dependsOn entries must be strings".into(),
            ));
        };
        if !seen.insert(s.to_string()) {
            // Duplicate is harmless but a sign of confused config —
            // keeping it strict means operators notice typos.
            return Err(ApiError::BadRequest(format!(
                "metadata.dependsOn has duplicate entry {s:?}"
            )));
        }
        out.push(s.to_string());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rfr(id: &str, depends_on: &[&str]) -> ResourceForRouting {
        let deps_json: Vec<serde_json::Value> = depends_on
            .iter()
            .map(|d| serde_json::json!(d))
            .collect();
        let json = serde_json::json!({
            "apiVersion": "iac.example/v1",
            "kind": "file",
            "metadata": {
                "name": id,
                "environment": "test",
                "dependsOn": deps_json,
            },
            "spec": {}
        });
        ResourceForRouting {
            resource_id: id.to_string(),
            kind: "file".to_string(),
            environment: "test".to_string(),
            resource_json: serde_json::to_string(&json).unwrap(),
            name: id.to_string(),
            host_selector: None,
        }
    }

    fn rfr_no_deps(id: &str) -> ResourceForRouting {
        let json = serde_json::json!({
            "apiVersion": "iac.example/v1",
            "kind": "file",
            "metadata": { "name": id, "environment": "test" },
            "spec": {}
        });
        ResourceForRouting {
            resource_id: id.to_string(),
            kind: "file".to_string(),
            environment: "test".to_string(),
            resource_json: serde_json::to_string(&json).unwrap(),
            name: id.to_string(),
            host_selector: None,
        }
    }

    fn ids(routing: &[ResourceForRouting]) -> Vec<String> {
        routing.iter().map(|r| r.resource_id.clone()).collect()
    }

    #[test]
    fn no_dependencies_preserves_order() {
        let mut r = vec![rfr_no_deps("a"), rfr_no_deps("b"), rfr_no_deps("c")];
        topo_sort_by_depends_on(&mut r).unwrap();
        assert_eq!(ids(&r), vec!["a", "b", "c"]);
    }

    #[test]
    fn dependency_moves_dependent_after_target() {
        // b depends on a → a must come before b. Provided in reverse
        // order to verify the sort actually reorders.
        let mut r = vec![rfr("b", &["a"]), rfr_no_deps("a")];
        topo_sort_by_depends_on(&mut r).unwrap();
        assert_eq!(ids(&r), vec!["a", "b"]);
    }

    #[test]
    fn chain_dependency_orders_a_b_c() {
        let mut r = vec![
            rfr("c", &["b"]),
            rfr("b", &["a"]),
            rfr_no_deps("a"),
        ];
        topo_sort_by_depends_on(&mut r).unwrap();
        assert_eq!(ids(&r), vec!["a", "b", "c"]);
    }

    #[test]
    fn diamond_dependency_works() {
        // a → b, a → c, b → d, c → d
        let mut r = vec![
            rfr("d", &["b", "c"]),
            rfr_no_deps("a"),
            rfr("c", &["a"]),
            rfr("b", &["a"]),
        ];
        topo_sort_by_depends_on(&mut r).unwrap();
        let result = ids(&r);
        let pos = |s: &str| result.iter().position(|x| x == s).unwrap();
        assert!(pos("a") < pos("b"));
        assert!(pos("a") < pos("c"));
        assert!(pos("b") < pos("d"));
        assert!(pos("c") < pos("d"));
    }

    #[test]
    fn cycle_returns_bad_request() {
        let mut r = vec![rfr("a", &["b"]), rfr("b", &["a"])];
        let err = topo_sort_by_depends_on(&mut r).unwrap_err();
        match err {
            ApiError::BadRequest(msg) => assert!(msg.contains("cycle"), "msg: {msg}"),
            other => panic!("expected BadRequest, got {other:?}"),
        }
    }

    #[test]
    fn self_loop_rejected() {
        let mut r = vec![rfr("a", &["a"])];
        let err = topo_sort_by_depends_on(&mut r).unwrap_err();
        assert!(matches!(err, ApiError::BadRequest(_)));
    }

    #[test]
    fn unknown_dependency_rejected() {
        let mut r = vec![rfr("a", &["does-not-exist"]), rfr_no_deps("b")];
        let err = topo_sort_by_depends_on(&mut r).unwrap_err();
        match err {
            ApiError::BadRequest(msg) => {
                assert!(msg.contains("does-not-exist"), "msg: {msg}");
                assert!(msg.contains("unknown"), "msg: {msg}");
            }
            other => panic!("expected BadRequest, got {other:?}"),
        }
    }

    #[test]
    fn duplicate_dependency_entry_rejected() {
        let mut r = vec![rfr("a", &["b", "b"]), rfr_no_deps("b")];
        let err = topo_sort_by_depends_on(&mut r).unwrap_err();
        assert!(matches!(err, ApiError::BadRequest(_)));
    }

    #[test]
    fn missing_depends_on_field_is_fine() {
        let mut r = vec![rfr_no_deps("a"), rfr_no_deps("b")];
        topo_sort_by_depends_on(&mut r).unwrap();
        assert_eq!(ids(&r), vec!["a", "b"]);
    }

    #[test]
    fn stable_when_multiple_zero_in_degree() {
        // a, b, c all independent → original order preserved.
        let mut r = vec![rfr_no_deps("c"), rfr_no_deps("a"), rfr_no_deps("b")];
        topo_sort_by_depends_on(&mut r).unwrap();
        assert_eq!(ids(&r), vec!["c", "a", "b"]);
    }

    #[test]
    fn empty_input_ok() {
        let mut r: Vec<ResourceForRouting> = vec![];
        topo_sort_by_depends_on(&mut r).unwrap();
        assert!(r.is_empty());
    }

    // Phase 7by: layer computation tests. Each test topo-sorts then
    // computes layers — that's the order the production submit path
    // uses, since `compute_resource_layers` requires sorted input.

    #[test]
    fn layers_no_deps_all_zero() {
        let r = vec![rfr_no_deps("a"), rfr_no_deps("b"), rfr_no_deps("c")];
        let layers = compute_resource_layers(&r).unwrap();
        assert_eq!(layers, vec![0, 0, 0]);
    }

    #[test]
    fn layers_chain_increments() {
        // a → b → c (b depends on a; c depends on b)
        let mut r = vec![
            rfr_no_deps("a"),
            rfr("b", &["a"]),
            rfr("c", &["b"]),
        ];
        topo_sort_by_depends_on(&mut r).unwrap();
        let layers = compute_resource_layers(&r).unwrap();
        // After topo sort the order is [a, b, c].
        assert_eq!(ids(&r), vec!["a", "b", "c"]);
        assert_eq!(layers, vec![0, 1, 2]);
    }

    #[test]
    fn layers_diamond_takes_max_dep_layer() {
        // a → b, a → c, both b and c → d.
        // Expected: a=0, b=1, c=1, d=2 (max(b.layer, c.layer)+1).
        let mut r = vec![
            rfr_no_deps("a"),
            rfr("b", &["a"]),
            rfr("c", &["a"]),
            rfr("d", &["b", "c"]),
        ];
        topo_sort_by_depends_on(&mut r).unwrap();
        let layers = compute_resource_layers(&r).unwrap();
        // topo sort gives [a, b, c, d]; check layer values match position.
        let id_layer: BTreeMap<String, i32> = r
            .iter()
            .zip(layers.iter())
            .map(|(res, &l)| (res.resource_id.clone(), l))
            .collect();
        assert_eq!(id_layer["a"], 0);
        assert_eq!(id_layer["b"], 1);
        assert_eq!(id_layer["c"], 1);
        assert_eq!(id_layer["d"], 2);
    }

    #[test]
    fn layers_parallel_chains_isolated() {
        // Two independent chains: a → b, c → d. Both b and d are at
        // layer 1 because each has its own root.
        let mut r = vec![
            rfr_no_deps("a"),
            rfr("b", &["a"]),
            rfr_no_deps("c"),
            rfr("d", &["c"]),
        ];
        topo_sort_by_depends_on(&mut r).unwrap();
        let layers = compute_resource_layers(&r).unwrap();
        let id_layer: BTreeMap<String, i32> = r
            .iter()
            .zip(layers.iter())
            .map(|(res, &l)| (res.resource_id.clone(), l))
            .collect();
        assert_eq!(id_layer["a"], 0);
        assert_eq!(id_layer["b"], 1);
        assert_eq!(id_layer["c"], 0);
        assert_eq!(id_layer["d"], 1);
    }

    #[test]
    fn layers_unsorted_input_errors() {
        // Caller must topo-sort first. Submitting unsorted input
        // (b depends on a but appears before a) must surface as
        // an internal error rather than silently producing wrong
        // layer values.
        let r = vec![rfr("b", &["a"]), rfr_no_deps("a")];
        let err = compute_resource_layers(&r).unwrap_err();
        match err {
            ApiError::Internal(msg) => assert!(msg.contains("topo-sort"), "msg: {msg}"),
            other => panic!("expected Internal, got {other:?}"),
        }
    }

    #[test]
    fn layers_empty_input_ok() {
        let r: Vec<ResourceForRouting> = vec![];
        let layers = compute_resource_layers(&r).unwrap();
        assert!(layers.is_empty());
    }
}
