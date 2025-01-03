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

#[async_trait]
pub trait RuleState: Send {
    async fn incr(&self, _: &Key) -> u64;
    async fn count(&self, _: &Key) -> u64;
}

#[async_trait]
pub trait Backend: Send {
    async fn register(&mut self, _: &mut CorrelationRule)
        -> Result<(), Box<dyn std::error::Error>>;
}

#[derive(Error, Debug)]
pub enum BackendError {
    #[error("state error: {0}")]
    StateError(String),
}
