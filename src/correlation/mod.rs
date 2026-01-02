pub(crate) mod serde;

pub(crate) mod rule;
pub(crate) use serde::{CorrelationRule, CorrelationType};
pub(crate) mod backend;

#[cfg(not(feature = "compat"))]
pub mod engine;

#[cfg(feature = "compat")]
pub mod state;
