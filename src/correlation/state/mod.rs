use std::collections::BinaryHeap;

use async_trait::async_trait;
use serde_json::Value;
use thiserror::Error;

use super::CorrelationRule;

#[cfg(feature = "mem_backend")]
pub mod mem;

pub type GroupBy = Vec<(String, Value)>;

#[derive(Debug, Clone)]
pub enum Key {
    EventCount(GroupBy),
    ValueCount(GroupBy, String),
}

impl Into<(String, Option<String>)> for &Key {
    fn into(self) -> (String, Option<String>) {
        let key = match self {
            Key::EventCount(k) => k,
            Key::ValueCount(k, _) => k,
        }
        .iter()
        .map(|(k, v)| format!("{}:{}", *k, *v))
        .collect::<BinaryHeap<String>>()
        .into_sorted_vec()
        .join(",");
        (
            key,
            match self {
                Key::EventCount(_) => None,
                Key::ValueCount(_, v) => Some((*v).clone()),
            },
        )
    }
}

/// manages the state of a correlation rule
///
/// The state is used to track the number of matches of the dependencies
/// in the time period defined by the rule and should decrement the count
/// when the time period has elapsed.
///
/// `RuleState` is a property of the individual rule and the `RuleState` trait
/// implementation becomes an attribute of the `CorrelationRule`
#[async_trait]
pub trait RuleState: Send + Sync {
    async fn incr(&self, _: &Key) -> u64;
    async fn count(&self, _: &Key) -> u64;
}

/// A backend for [`RuleState`]
///
/// The backend is the shared database for all instances of [`RuleState`]
/// in a [`SigmaCollection`]
///
/// [`RuleState`]: trait.RuleState.html
/// [`SigmaCollection`]: struct.SigmaCollection.html
#[async_trait]
pub trait Backend: Send {
    /// Register a correlation rule with the backend
    async fn register(&mut self, _: &mut CorrelationRule)
        -> Result<(), Box<dyn std::error::Error>>;
}

#[derive(Error, Debug)]
pub enum BackendError {
    #[error("state error: {0}")]
    StateError(String),
}
