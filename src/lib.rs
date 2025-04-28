//! [`Sigma`] rule parsing and evaluation
//!
//! Provides parsing and evaluation of a collection of Sigma rules
//! against log events
//!
//! [`Sigma`]: https://sigmahq.io/
//!
mod collection;
mod detection;

pub mod event;
pub mod rule;

#[doc(hidden)]
#[cfg(feature = "correlation")]
pub mod correlation;

pub use collection::SigmaCollection;
pub use event::Event;
pub use rule::SigmaRule;

#[cfg(feature = "mem_backend")]
pub use correlation::state::mem::MemBackend;
#[cfg(feature = "correlation")]
pub use correlation::Backend;
#[cfg(feature = "correlation")]
pub use correlation::RuleState;

#[cfg(test)]
mod tests;
