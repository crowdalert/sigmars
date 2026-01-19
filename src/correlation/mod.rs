pub(crate) mod serde;

pub(crate) mod rule;
pub(crate) use serde::{CorrelationRule, CorrelationType};
pub(crate) mod backend;

pub mod engine;
pub use backend::CorrelationStoreNOP;
