// iac-core: data model, manifest loading, provider trait.
// Re-exports the public surface so downstream crates depend on a stable path.

// Phase 7cz.16: workspace lints `unwrap_used`/`expect_used`/`panic`
// are warn-level for prod code. Tests use them constantly for fixture
// setup; quieting the noise for `#[cfg(test)]` only.
#![cfg_attr(
    test,
    allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

pub mod error;
pub mod id;
pub mod manifest;
pub mod resource;
pub mod state;
pub mod diff;
pub mod operation;
pub mod provider;
pub mod registry;
pub mod convert;
pub mod hash;
pub mod subprocess;
pub mod executor;
pub mod protocol;
pub mod template;

pub use error::{Error, Result};
pub use id::ResourceId;
pub use resource::{Metadata, Resource};
pub use state::{AppliedState, DesiredState, ObservedState};
pub use diff::{Diff, DiffKind, FieldChange};
pub use operation::{Checkpoint, Operation, OperationStatus, Step, StepResult, StepStatus};
pub use provider::{ApplyContext, Provider, VerifyOutcome};
pub use registry::ProviderRegistry;
pub use executor::{ApplyItem, ApplyResult, Executor, ItemStatus, PlanItem, PlanResult, StepRecord, VerifySummary};
