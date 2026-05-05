//! Wire protocol types shared between agent and control-plane.
//!
//! Versioned via the module path so additive v2 fields can ship without
//! breaking older agents. Phase 2a defines the push direction only;
//! assignments / pull are added in Phase 2b.

pub mod v1 {
    use crate::diff::Diff;
    use crate::id::ResourceId;
    use serde::{Deserialize, Serialize};

    // ---- agent registration ---------------------------------------------

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct RegisterRequest {
        pub name: String,
        pub environment: String,
        #[serde(default)]
        pub metadata: serde_json::Value,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct RegisterResponse {
        pub agent_id: String,
        pub token: String,
        /// Phase 7cd: ISO 8601 UTC absolute time at which this token
        /// expires and the agent must have rotated by. `None` means
        /// the token was issued without a TTL (server config has
        /// `agent_token_ttl_secs: None` — grandfather mode). Agents
        /// that see `None` skip rotation entirely; agents that see
        /// `Some(...)` rotate before the deadline via
        /// `POST /v1/agents/{id}/rotate-token`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub expires_at: Option<String>,
    }

    // ---- heartbeat -------------------------------------------------------

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct HeartbeatRequest {
        pub status: AgentHealth,
        pub managed: u32,
        pub open_drifts: u32,
        pub last_observe_at: Option<String>,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    pub enum AgentHealth {
        Healthy,
        Degraded,
        Unhealthy,
    }

    // ---- observations ----------------------------------------------------

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ObservationBatch {
        pub items: Vec<ObservationItem>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ObservationItem {
        pub resource_id: ResourceId,
        pub observed_at: String,
        pub present: bool,
        pub spec: serde_json::Value,
        pub facts: serde_json::Value,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ObservationAck {
        pub accepted: u32,
    }

    // ---- drift -----------------------------------------------------------

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct DriftBatch {
        pub items: Vec<DriftItem>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct DriftItem {
        pub resource_id: ResourceId,
        pub severity: String,
        pub detected_at: String,
        pub diff: Diff,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct DriftAck {
        pub accepted: u32,
    }

    // ---- read-side -------------------------------------------------------

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct AgentSummary {
        pub agent_id: String,
        pub name: String,
        pub environment: String,
        pub registered_at: String,
        pub last_heartbeat_at: Option<String>,
        pub last_observation_at: Option<String>,
        pub open_drifts: i64,
        pub managed: i64,
        pub status: AgentHealth,
        /// Phase 7ck: how the control plane talks to this target.
        /// `"pull"` = traditional `iac-agent` daemon polling for
        /// assignments. `"ssh"` = server-side push worker SSHes to
        /// the host on each assignment. Pre-7ck deployments default
        /// to `"pull"` (backward compatible).
        #[serde(default = "default_kind_pull")]
        pub kind: String,
    }

    fn default_kind_pull() -> String {
        "pull".into()
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct DriftSummary {
        pub id: i64,
        pub agent_id: String,
        pub resource_id: String,
        pub kind: String,
        pub severity: String,
        pub detected_at: String,
        pub diff: Diff,
        #[serde(default)]
        pub ignored_until: Option<String>,
        #[serde(default)]
        pub resolved_at: Option<String>,
        #[serde(default)]
        pub resolution: Option<String>,
    }

    /// Operator → server: silence a drift event until `until` (RFC3339).
    /// While ignored, the event is excluded from `GET /v1/drift`.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct DriftIgnoreRequest {
        pub until: String,
        #[serde(default)]
        pub reason: Option<String>,
    }

    /// Operator → server: mark a drift event accepted (resolved without
    /// reverting the underlying state).
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct DriftAcceptRequest {
        pub reason: String,
    }

    /// Phase 7be: operator → server: re-apply the resource's last desired
    /// state to revert the drift. Server creates a fresh apply operation
    /// (single resource) and returns the new operation id; the drift
    /// stays open until the operator marks it accepted (or the agent
    /// stops reporting it).
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct DriftRevertRequest {
        /// Optional hint for audit + the new operation's `requested_by`
        /// field. When absent, server falls back to `<actor>` (the
        /// caller's RBAC identity) for both.
        #[serde(default)]
        pub source_commit: Option<String>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct DriftRevertResponse {
        /// Newly-created operation that re-applies the resource.
        pub operation_id: String,
        /// Resource that's being reverted (echoed for the operator's
        /// confirmation message).
        pub resource_id: String,
    }

    /// Phase 7bf: operator → server: bulk-accept every open drift event
    /// matching `filter`. Empty filter (no fields set) is rejected at
    /// the API boundary so an operator doesn't wipe the entire drift
    /// history with a typo. `reason` mirrors the single-id `accept`
    /// path and is required.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct DriftBulkAcceptRequest {
        pub reason: String,
        #[serde(default)]
        pub filter: DriftBulkFilter,
    }

    /// Phase 7bf: same shape as accept-bulk but with a TTL for the
    /// silence. Empty filter is also rejected.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct DriftBulkIgnoreRequest {
        /// `<n>{s,m,h,d}` shorthand or an absolute RFC3339 timestamp.
        /// Same parsing as the single-id `ignore` path.
        pub ttl: String,
        #[serde(default)]
        pub filter: DriftBulkFilter,
    }

    #[derive(Debug, Clone, Default, Serialize, Deserialize)]
    pub struct DriftBulkFilter {
        #[serde(default)]
        pub agent_id: Option<String>,
        #[serde(default)]
        pub kind: Option<String>,
        #[serde(default)]
        pub severity: Option<String>,
    }

    impl DriftBulkFilter {
        pub fn is_empty(&self) -> bool {
            self.agent_id.is_none() && self.kind.is_none() && self.severity.is_none()
        }
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct DriftBulkResponse {
        /// Number of drift events the operation affected.
        pub matched: u64,
    }

    // ---- audit log (Phase 6c) -------------------------------------------

    /// One row from the server's append-only audit log.
    ///
    /// `actor` is a coarse string identity until Phase 6d adds RBAC:
    ///   * `admin` — operator-initiated via the admin token,
    ///   * `agent:<agent_id>` — initiated by an agent's bearer-authenticated call,
    ///   * `system` — server-internal action (e.g. fan-out of an operation).
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct AuditEvent {
        pub id: i64,
        pub timestamp: String,
        pub actor: String,
        /// Dotted event kind, e.g. `operation.submitted`, `drift.accepted`.
        pub kind: String,
        pub severity: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub operation_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub agent_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub resource_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub drift_id: Option<i64>,
        /// Free-form structured detail. Schema varies by `kind`.
        #[serde(default)]
        pub payload: serde_json::Value,
    }

    // ---- operations / assignments (Phase 2b) -----------------------------

    /// Operator (CLI) → server: submit a desired-state apply for an
    /// environment. The server fans this out into per-agent assignments.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct SubmitOperationRequest {
        pub environment: String,
        pub requested_by: String,
        pub source_commit: Option<String>,
        pub summary: Option<String>,
        /// Resources serialized in the same shape `iac-core::Resource` uses on
        /// the wire (apiVersion, kind, metadata, spec, policy).
        pub resources: Vec<serde_json::Value>,
        /// Phase 7cg: optional canary rollout. When set, the server
        /// dispatches assignments to a percentage of agents per layer
        /// first, waits for them to complete successfully, then
        /// proceeds to the rest. Any failure in the canary batch
        /// cancels the rest of the rollout — same blast-radius
        /// containment as a layer failure in Phase 7by.
        ///
        /// `None` (the default) preserves the pre-7cg behavior:
        /// every agent in a layer receives its assignment at once.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub canary: Option<CanarySpec>,
    }

    /// Phase 7cg: canary configuration. `pct` is the percentage of
    /// agents per layer to dispatch first (1..=99). The actual count
    /// is `max(min_count.unwrap_or(1), ceil(N * pct / 100))` and is
    /// always clamped to leave at least one agent in the baseline
    /// batch (otherwise canary becomes a full rollout).
    #[derive(Debug, Clone, Copy, Serialize, Deserialize)]
    pub struct CanarySpec {
        pub pct: u8,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub min_count: Option<u32>,
    }

    /// Phase 7ci: server-side rollback request. Tells the server to
    /// build a new operation that re-applies the *prior* desired
    /// state for every resource the target operation touched —
    /// effectively undoing it. The new operation goes through the
    /// normal pipeline (policies, approval, canary if specified) so
    /// every guard rail still applies.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct RollbackOperationRequest {
        pub requested_by: String,
        /// Free-form reason recorded in the audit log. Helps the
        /// "why did we roll this back?" review later.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub reason: Option<String>,
        /// Optional canary on the rollback operation itself.
        /// Recommended for production rollbacks — even a roll-
        /// *backward* deserves blast-radius containment.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub canary: Option<CanarySpec>,
    }

    /// Phase 7ci: rollback result. The new operation id is the entry
    /// point for tracking the rollback's progress (use the existing
    /// `GET /v1/operations/{id}` endpoint). `resources_orphaned` is
    /// the list of resource ids that were first-applied in the
    /// rolled-back op and have no prior state to revert to —
    /// operators currently have to delete these manually (or apply a
    /// new manifest with `state: absent` for providers that support
    /// it).
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct RollbackOperationResponse {
        pub new_operation_id: String,
        pub assignment_count: u32,
        pub resources_reverted: u32,
        pub resources_orphaned: Vec<String>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct SubmitOperationResponse {
        pub operation_id: String,
        pub assignment_count: u32,
        pub unrouted: Vec<UnroutedResource>,
        /// Phase 7a: summary of what this operation will touch. Useful for
        /// the operator's "do you really want to do this?" moment plus the
        /// approval gate's diff preview.
        #[serde(default)]
        pub blast_radius: BlastRadius,
    }

    #[derive(Debug, Clone, Default, Serialize, Deserialize)]
    pub struct BlastRadius {
        /// Total expanded primitive resources (post-composite-expansion).
        pub resource_count: u32,
        /// Distinct agents that will receive at least one assignment.
        pub agent_count: u32,
        /// Sorted, deduped list of resource kinds touched.
        pub kinds: Vec<String>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct UnroutedResource {
        pub resource_id: String,
        pub reason: String,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    pub enum OperationStatus {
        Pending,
        /// Phase 6d: operation matched a `requires_approval` policy and is
        /// waiting for an approver to call `POST .../approve`.
        PendingApproval,
        Running,
        PartiallyApplied,
        Failed,
        Succeeded,
        /// Phase 6d: an approver called `.../reject`. Terminal.
        Rejected,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct OperationView {
        pub id: String,
        pub kind: String,
        pub environment: String,
        pub requested_by: String,
        pub status: OperationStatus,
        pub created_at: String,
        pub started_at: Option<String>,
        pub finished_at: Option<String>,
        pub assignments: Vec<AssignmentView>,
        /// Phase 6d: names of the policies that flagged this operation as
        /// requiring approval (empty for clean submits).
        #[serde(default)]
        pub matched_policies: Vec<String>,
        #[serde(default)]
        pub approved_by: Option<String>,
        #[serde(default)]
        pub approved_at: Option<String>,
        #[serde(default)]
        pub rejected_by: Option<String>,
        #[serde(default)]
        pub rejected_at: Option<String>,
        #[serde(default)]
        pub rejection_reason: Option<String>,
    }

    /// Phase 6d: approve a pending operation and let its assignments dispatch.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct OperationApproveRequest {
        #[serde(default)]
        pub reason: Option<String>,
    }

    /// Phase 6d: reject a pending operation. Terminal.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct OperationRejectRequest {
        pub reason: String,
    }

    // ---- approval preview (Phase 7b) ------------------------------------

    /// Server → operator (Viewer+): the desired-state primitives an
    /// operation will write. Available *before* approval, so approvers can
    /// see exactly what they're greenlighting. Reads from `desired_states`
    /// (populated at submit, even for `pending_approval`).
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct OperationDesiredState {
        pub operation_id: String,
        pub items: Vec<OperationDesiredStateItem>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct OperationDesiredStateItem {
        pub resource_id: String,
        pub kind: String,
        /// Which agent the resource is routed to (the `agent_id` the
        /// server bound it to via routing).
        pub agent_id: String,
        /// Full `Resource` (apiVersion / kind / metadata / spec / policy).
        pub resource: serde_json::Value,
    }

    // ---- RBAC (Phase 6e) -------------------------------------------------

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct LoginRequest {
        pub username: String,
        pub password: String,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct LoginResponse {
        pub token: String,
        pub expires_at: String,
        pub roles: Vec<String>,
    }

    // ---- user CRUD (Phase 6h) -------------------------------------------

    /// Admin → server: provision a new user. Roles use the same string
    /// names as `LoginResponse` (`viewer`, `operator`, `approver`, `admin`).
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct CreateUserRequest {
        pub username: String,
        pub password: String,
        pub roles: Vec<String>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct CreateUserResponse {
        pub user_id: String,
    }

    /// Read-side projection of a user. Never includes the password hash.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct UserView {
        pub id: String,
        pub username: String,
        pub roles: Vec<String>,
        pub created_at: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub disabled_at: Option<String>,
    }

    /// Admin → server: change roles, disable/enable, or reset password.
    /// Each field is independently optional so admins can tweak just one.
    #[derive(Debug, Clone, Default, Serialize, Deserialize)]
    pub struct UpdateUserRequest {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub roles: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub disabled: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub password: Option<String>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct AssignmentView {
        pub id: String,
        pub agent_id: String,
        pub status: String,
        pub created_at: String,
        pub fetched_at: Option<String>,
        pub completed_at: Option<String>,
        /// `result_json` parsed back into a generic value when available.
        #[serde(default)]
        pub result: Option<serde_json::Value>,
    }

    /// Server → agent: "apply these resources." Returned by the agent's
    /// `assignments` poll endpoint.
    ///
    /// `signature` is the base64-encoded Ed25519 signature over the canonical
    /// message defined in [`canonical_assignment_message`]. `key_id` names
    /// which server key produced the signature so future rotation can carry
    /// multiple valid keys.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct AssignmentEnvelope {
        pub assignment_id: String,
        pub operation_id: String,
        pub kind: String,
        pub created_at: String,
        pub expires_at: Option<String>,
        pub payload: AssignmentPayload,
        pub key_id: String,
        pub signature: String,
    }

    /// Server → agent: "here's the public key used to sign assignments."
    /// Returned by `GET /v1/signing-pubkey`. The agent caches this on first
    /// contact (TOFU) and rejects assignments whose `key_id` doesn't match.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct SigningPubkey {
        pub key_id: String,
        /// Base64-encoded raw 32-byte Ed25519 public key.
        pub public_key: String,
    }

    /// Phase 7ce: full bundle of accepted signing keys. Returned by
    /// `GET /v1/signing-keys`. Agents that support multi-key
    /// verification fetch this on every refresh so they accept
    /// signatures from both old and new keys during a rotation
    /// window. `active_key_id` is what the server is currently using
    /// to sign new assignments; `keys` is the verification set
    /// (active included).
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct SigningPubkeyBundle {
        pub active_key_id: String,
        pub keys: Vec<SigningPubkey>,
    }

    /// Build the byte string that gets signed for an assignment. Both server
    /// (signing) and agent (verifying) MUST use this exact format. The string
    /// is line-oriented for hand-debug-ability and includes:
    ///
    ///   * a versioned label,
    ///   * the agent_id (so a signature can't be reused across agents),
    ///   * the assignment_id (replay protection within an agent),
    ///   * the operation_id (audit linkage),
    ///   * the created_at timestamp,
    ///   * `sha256` of the canonically-serialized payload JSON.
    ///
    /// `payload_json` must be the same byte sequence both sides see; in
    /// practice that's the JSON the server stored in the assignments row,
    /// served verbatim to the agent.
    pub fn canonical_assignment_message(
        agent_id: &str,
        assignment_id: &str,
        operation_id: &str,
        created_at: &str,
        payload_json: &[u8],
    ) -> Vec<u8> {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(payload_json);
        let payload_sha = hex::encode(hasher.finalize());
        format!(
            "iac-assignment-v1\n{agent_id}\n{assignment_id}\n{operation_id}\n{created_at}\n{payload_sha}\n"
        )
        .into_bytes()
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct AssignmentPayload {
        pub resources: Vec<serde_json::Value>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct AssignmentList {
        pub items: Vec<AssignmentEnvelope>,
    }

    /// Agent → server: result of executing an assignment.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct AssignmentResultRequest {
        pub status: AssignmentResultStatus,
        pub summary: Option<String>,
        pub items: Vec<AssignmentItemResult>,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    pub enum AssignmentResultStatus {
        Succeeded,
        PartiallyApplied,
        Failed,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct AssignmentItemResult {
        pub resource_id: String,
        pub status: String,
        pub error: Option<String>,
    }

    // ---- desired state watch list (Phase 2c) ------------------------------

    /// Returned by the server when the agent asks "what should I be watching?"
    /// The server collapses every operation it has dispatched to this agent
    /// into the latest desired spec per `resource_id`, so the agent can
    /// observe and report drift even after the assignment that delivered the
    /// resource is closed.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct DesiredStateBatch {
        pub items: Vec<DesiredStateItem>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct DesiredStateItem {
        pub resource_id: String,
        pub operation_id: String,
        pub created_at: String,
        /// Full `Resource` (apiVersion / kind / metadata / spec / policy).
        /// Same shape the agent applies via assignments.
        pub resource: serde_json::Value,
    }
}
