//! Phase 7db.2: NDJSON-RPC wire format for external-process plugins.
//!
//! Each line over stdin/stdout is one JSON object. The plugin emits
//! a single hello message at startup; the agent then drives a
//! request/response loop keyed by integer `id`.
//!
//! Why NDJSON and not full JSON-RPC: the lifecycle here is strictly
//! request → response, no notifications, no batching. NDJSON keeps
//! the plugin author's bar low — `read line, parse json, write json
//! + newline` works in any language.
//!
//! Stability: the protocol is versioned via the `protocol_version`
//! field of [`Hello`]. The agent rejects unknown versions at handshake
//! time so an old plugin paired with a new agent fails loud, not
//! silently with garbled state.

use serde::{Deserialize, Serialize};
use serde_json::Value as Json;

pub const PROTOCOL_VERSION: u32 = 1;

/// First message a plugin sends after spawning. Identifies the kind
/// it handles + any optional capabilities.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hello {
    pub protocol_version: u32,
    pub kind: String,
    /// Templates the agent renders against `spec` to produce
    /// capability keys. Same `{{ field }}` shape as shellout.
    #[serde(default)]
    pub capability_keys: Vec<String>,
    /// Methods this plugin opts in to handling beyond the required
    /// pair (`observe` and `apply` are always required). The agent
    /// supplies fallbacks for `diff`, `verify`, `rollback`,
    /// `pre_apply`. An empty list means "fall back for all of those";
    /// plugins that implement them must enumerate the names.
    #[serde(default)]
    pub methods: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request {
    pub id: u64,
    pub method: String,
    pub params: Json,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response {
    pub id: u64,
    #[serde(default)]
    pub result: Option<Json>,
    #[serde(default)]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Frame {
    Hello { hello: Hello },
    Response(Response),
}

/// Methods the agent dispatches. Strings are the wire names.
pub mod methods {
    pub const OBSERVE: &str = "observe";
    pub const DIFF: &str = "diff";
    pub const APPLY: &str = "apply";
    pub const VERIFY: &str = "verify";
    pub const ROLLBACK: &str = "rollback";
    pub const PRE_APPLY: &str = "pre_apply";
    pub const SHUTDOWN: &str = "shutdown";
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn hello_round_trips() {
        let h = Hello {
            protocol_version: 1,
            kind: "x".into(),
            capability_keys: vec!["{{ name }}".into()],
            methods: vec!["observe".into(), "apply".into()],
        };
        let s = serde_json::to_string(&h).unwrap();
        let h2: Hello = serde_json::from_str(&s).unwrap();
        assert_eq!(h.kind, h2.kind);
    }

    #[test]
    fn response_with_error_round_trips() {
        let r = Response {
            id: 7,
            result: None,
            error: Some("boom".into()),
        };
        let s = serde_json::to_string(&r).unwrap();
        let r2: Response = serde_json::from_str(&s).unwrap();
        assert_eq!(r2.error.as_deref(), Some("boom"));
    }

    #[test]
    fn request_with_params_round_trips() {
        let q = Request {
            id: 1,
            method: methods::OBSERVE.into(),
            params: json!({"spec": {"name": "x"}}),
        };
        let s = serde_json::to_string(&q).unwrap();
        let q2: Request = serde_json::from_str(&s).unwrap();
        assert_eq!(q.method, q2.method);
        assert_eq!(q.params, q2.params);
    }
}
