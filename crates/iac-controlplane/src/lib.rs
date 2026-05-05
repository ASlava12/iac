// Phase 7cz.16: tests-only exemption for unwrap/expect/panic.
#![cfg_attr(
    test,
    allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

pub mod api;
pub mod auth;
pub mod config;
pub mod depsort;
pub mod error;
pub mod expansion;
pub mod identity;
pub mod maintenance;
pub mod modules;
pub mod policy;
pub mod rate_limit;
pub mod retention;
pub mod secrets;
pub mod signing;
pub mod ssh_push;
pub mod store;
pub mod server;
pub mod tls;
pub mod webhook;

pub use config::Config;
pub use error::{ApiError, ApiResult};
pub use server::AppState;
pub use store::{Dialect, Store};
