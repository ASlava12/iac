// iac-core: data model, manifest loading, provider trait.
// Re-exports the public surface so downstream crates depend on a stable path.

// Phase 7cz.16: workspace lints `unwrap_used`/`expect_used`/`panic`
// are warn-level for prod code. Tests use them constantly for fixture
// setup; quieting the noise for `#[cfg(test)]` only.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod convert;
pub mod diff;
pub mod error;
pub mod executor;
pub mod hash;
pub mod id;
pub mod manifest;
pub mod operation;
pub mod protocol;
pub mod provider;
pub mod registry;
pub mod resource;
pub mod state;
pub mod subprocess;
pub mod template;

pub use diff::{Diff, DiffKind, FieldChange};
pub use error::{Error, Result};
pub use executor::{
    ApplyItem, ApplyResult, Executor, ItemStatus, PlanItem, PlanResult, StepRecord, VerifySummary,
};
pub use id::ResourceId;
pub use operation::{Checkpoint, Operation, OperationStatus, Step, StepResult, StepStatus};
pub use provider::{ApplyContext, Provider, VerifyOutcome};
pub use registry::ProviderRegistry;
pub use resource::{Metadata, Resource};
pub use state::{AppliedState, DesiredState, ObservedState};
