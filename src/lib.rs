//! [`Sigma`] rule parsing and evaluation
//!
//! Provides parsing and evaluation of a collection of Sigma rules
//! against a `serde_json::Map<T, V>` (typically a log event).
//!
//! [`Sigma`]: https://sigmahq.io/
//!
mod collection;
#[cfg(feature = "correlation")]
mod correlation;
mod detection;
mod event;
mod rule;

pub(crate) use rule::Eval;

pub use collection::SigmaCollection;

#[cfg(feature = "correlation")]
pub use correlation::CorrelationRule;
pub use detection::DetectionRule;
pub use event::Event;
pub use rule::{RuleType, SigmaRule};

#[cfg(test)]
mod tests;
