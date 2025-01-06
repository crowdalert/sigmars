//! [`Sigma`] rule parsing and evaluation
//!
//! Provides parsing and evaluation of a collection of Sigma rules
//! against a `serde_json::Map<T, V>` (typically a log event).
//!
//! [`Sigma`]: https://sigmahq.io/
//!
mod collection;
mod detection;

pub mod event;
pub mod rule;

#[cfg(feature = "correlation")]
pub mod correlation;

pub use collection::SigmaCollection;
pub use rule::SigmaRule;

#[cfg(test)]
mod tests;
