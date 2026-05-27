//! Phase 6d: policy engine for the approval gate.
//!
//! Operators configure `[[policies]]` blocks in the server config; on every
//! `POST /v1/operations` the server evaluates them and, if any matches with
//! `requires_approval=true`, the operation lands in `pending_approval` until
//! an approver calls `POST /v1/operations/{id}/approve`.
//!
//! Phase 6d is intentionally small: matchers are exact-string for
//! `environment` and `kind`, plus a numeric `resource_count_min`. Phase 6e
//! will introduce richer matchers (label selectors, blast radius) and
//! plug RBAC roles into the `approvers` field below.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Policy {
    /// Stable, operator-readable name. Surfaces in audit + operation view.
    pub name: String,
    #[serde(default)]
    pub r#match: PolicyMatch,
    #[serde(default)]
    pub requires_approval: bool,
    /// Phase 6d placeholder — Phase 6e RBAC reads this and gates `.../approve`
    /// on the caller's role membership. Today any admin token holder can
    /// approve regardless of this field.
    #[serde(default)]
    pub approvers: Vec<String>,
    /// Phase 7n: per-policy rate limit. When this policy matches, the
    /// limiter enforces this cap (per minute) IN ADDITION to the global
    /// `rate_limit.operations_per_minute`. Stricter wins when both apply.
    /// `None` (or zero) → no per-policy cap; the global one alone applies.
    #[serde(default)]
    pub rate_limit_per_minute: Option<u32>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyMatch {
    /// Exact-match against the operation's `environment`. Wildcard `"*"`
    /// matches any environment.
    #[serde(default)]
    pub environment: Option<String>,
    /// If set, matches when ANY resource in the operation has this `kind`.
    #[serde(default)]
    pub kind: Option<String>,
    /// If set, matches when the operation submits at least this many resources.
    #[serde(default)]
    pub resource_count_min: Option<usize>,
}

#[derive(Debug, Clone)]
pub struct OperationFacts<'a> {
    pub environment: &'a str,
    pub resources: &'a [&'a str], // resource kinds
}

impl Policy {
    pub fn matches(&self, facts: &OperationFacts<'_>) -> bool {
        let m = &self.r#match;
        if let Some(env) = &m.environment
            && env != "*"
            && env != facts.environment
        {
            return false;
        }
        if let Some(min) = m.resource_count_min
            && facts.resources.len() < min
        {
            return false;
        }
        if let Some(kind) = &m.kind
            && !facts.resources.iter().any(|k| *k == kind)
        {
            return false;
        }
        // An empty policy match block matches nothing — otherwise every
        // operation would trip every empty policy. Catch it here.
        if m.environment.is_none() && m.resource_count_min.is_none() && m.kind.is_none() {
            return false;
        }
        true
    }
}

/// Evaluate every policy against the operation facts and return only the
/// matching policy names.
pub fn evaluate<'a>(policies: &'a [Policy], facts: &OperationFacts<'_>) -> Vec<&'a Policy> {
    policies.iter().filter(|p| p.matches(facts)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(
        name: &str,
        env: Option<&str>,
        kind: Option<&str>,
        min: Option<usize>,
        ra: bool,
    ) -> Policy {
        Policy {
            name: name.into(),
            r#match: PolicyMatch {
                environment: env.map(str::to_string),
                kind: kind.map(str::to_string),
                resource_count_min: min,
            },
            requires_approval: ra,
            approvers: vec![],
            rate_limit_per_minute: None,
        }
    }

    #[test]
    fn empty_match_block_matches_nothing() {
        let pol = p("empty", None, None, None, true);
        let facts = OperationFacts {
            environment: "prod",
            resources: &["file"],
        };
        assert!(!pol.matches(&facts));
    }

    #[test]
    fn environment_exact_match() {
        let pol = p("prod-only", Some("prod"), None, None, true);
        assert!(pol.matches(&OperationFacts {
            environment: "prod",
            resources: &["file"]
        }));
        assert!(!pol.matches(&OperationFacts {
            environment: "stage",
            resources: &["file"]
        }));
    }

    #[test]
    fn environment_wildcard() {
        let pol = p("any-env", Some("*"), None, None, true);
        assert!(pol.matches(&OperationFacts {
            environment: "prod",
            resources: &["file"]
        }));
        assert!(pol.matches(&OperationFacts {
            environment: "test",
            resources: &["file"]
        }));
    }

    #[test]
    fn kind_match_requires_one_resource_of_that_kind() {
        let pol = p("docker", None, Some("docker.container"), None, true);
        assert!(pol.matches(&OperationFacts {
            environment: "prod",
            resources: &["file", "docker.container"]
        }));
        assert!(!pol.matches(&OperationFacts {
            environment: "prod",
            resources: &["file", "systemd.unit"]
        }));
    }

    #[test]
    fn resource_count_min() {
        let pol = p("big-changes", None, None, Some(5), true);
        assert!(!pol.matches(&OperationFacts {
            environment: "prod",
            resources: &["a", "b", "c", "d"]
        }));
        assert!(pol.matches(&OperationFacts {
            environment: "prod",
            resources: &["a", "b", "c", "d", "e"]
        }));
    }

    #[test]
    fn all_clauses_must_match() {
        let pol = p(
            "prod-docker",
            Some("prod"),
            Some("docker.container"),
            Some(2),
            true,
        );
        let mut facts = OperationFacts {
            environment: "prod",
            resources: &["docker.container", "file"],
        };
        assert!(pol.matches(&facts));

        // Wrong env.
        facts.environment = "stage";
        assert!(!pol.matches(&facts));

        // Right env but no docker resource.
        let facts2 = OperationFacts {
            environment: "prod",
            resources: &["file", "file"],
        };
        assert!(!pol.matches(&facts2));

        // Right env + docker, but only 1 resource.
        let facts3 = OperationFacts {
            environment: "prod",
            resources: &["docker.container"],
        };
        assert!(!pol.matches(&facts3));
    }

    #[test]
    fn evaluate_returns_all_matching_in_order() {
        let policies = vec![
            p("a-env", Some("prod"), None, None, true),
            p("b-kind", None, Some("docker.container"), None, true),
            p("c-size", None, None, Some(100), true),
        ];
        let facts = OperationFacts {
            environment: "prod",
            resources: &["docker.container"],
        };
        let matched = evaluate(&policies, &facts);
        assert_eq!(matched.len(), 2);
        assert_eq!(matched[0].name, "a-env");
        assert_eq!(matched[1].name, "b-kind");
    }
}
