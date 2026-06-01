use serde::{Deserialize, Serialize};
use std::fmt;

/// Logical, human-facing identity of a managed resource.
///
/// Format: `kind/environment/name`. Stable across runs as long as the manifest
/// keeps the same metadata. The control-plane (Phase 2+) maps this to a ULID
/// for DB joins; in Phase 0 the logical form is enough.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ResourceId {
    pub kind: String,
    pub environment: String,
    pub name: String,
}

impl ResourceId {
    pub fn new(
        kind: impl Into<String>,
        environment: impl Into<String>,
        name: impl Into<String>,
    ) -> Self {
        Self {
            kind: kind.into(),
            environment: environment.into(),
            name: name.into(),
        }
    }

    /// Filesystem-safe form for state/checkpoint paths.
    ///
    /// A sanitized, human-readable prefix (for at-a-glance debugging) plus
    /// a short hash of the *canonical* `(kind, environment, name)` so two
    /// distinct resources can never collide onto the same on-disk path.
    /// Sanitization alone is non-injective — `name = "a/b"` and
    /// `name = "a b"` both sanitize to `a_b`, and the `__` separator is
    /// ambiguous against components that themselves contain `__` — which
    /// previously let one resource's applied-state / checkpoint silently
    /// overwrite another's.
    pub fn fs_key(&self) -> String {
        let digest = crate::hash::sha256_hex(
            format!("{}\u{0}{}\u{0}{}", self.kind, self.environment, self.name).as_bytes(),
        );
        format!(
            "{}__{}__{}__{}",
            sanitize(&self.kind),
            sanitize(&self.environment),
            sanitize(&self.name),
            &digest[..12]
        )
    }

    /// Parse a `kind/environment/name` string back into a `ResourceId`.
    /// Returns `None` if there are fewer than three `/`-separated segments.
    pub fn parse(s: &str) -> Option<Self> {
        let mut parts = s.splitn(3, '/');
        let kind = parts.next()?;
        let environment = parts.next()?;
        let name = parts.next()?;
        if kind.is_empty() || environment.is_empty() || name.is_empty() {
            return None;
        }
        Some(Self::new(kind, environment, name))
    }
}

fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '.' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

impl fmt::Display for ResourceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}/{}", self.kind, self.environment, self.name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_format() {
        let id = ResourceId::new("file", "prod", "nginx-main");
        assert_eq!(id.to_string(), "file/prod/nginx-main");
    }

    #[test]
    fn fs_key_is_safe() {
        let id = ResourceId::new("systemd.unit", "prod", "nginx/foo");
        // Sanitized prefix is preserved for readability; a hash suffix is
        // appended for collision-resistance.
        assert!(
            id.fs_key().starts_with("systemd.unit__prod__nginx_foo__"),
            "got {}",
            id.fs_key()
        );
        // No path-separators / nul leaked into the key.
        assert!(!id.fs_key().contains('/'));
    }

    #[test]
    fn fs_key_is_injective_across_sanitization_collisions() {
        // Distinct resources that sanitize to the same prefix must still
        // get distinct keys (regression for the silent overwrite bug).
        let a = ResourceId::new("file", "prod", "a/b").fs_key();
        let b = ResourceId::new("file", "prod", "a b").fs_key();
        assert_ne!(a, b, "sanitization-colliding names must not share a key");

        let c = ResourceId::new("file", "prod__x", "y").fs_key();
        let d = ResourceId::new("file", "prod", "x__y").fs_key();
        assert_ne!(c, d, "separator-ambiguous components must not share a key");
    }

    #[test]
    fn parse_round_trip() {
        let id = ResourceId::new("file", "prod", "nginx-conf");
        assert_eq!(ResourceId::parse(&id.to_string()), Some(id));
        assert!(ResourceId::parse("file/prod").is_none());
        assert!(ResourceId::parse("file//x").is_none());
    }
}
