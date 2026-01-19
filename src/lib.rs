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

#[cfg(test)]
mod tests;
