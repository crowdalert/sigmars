use std::{collections::BinaryHeap, sync::Arc};

use super::serde::{Condition, ConditionOrList, Correlation, CorrelationRule, CorrelationType};
use super::state::{CorrelationState, EventCount, ValueCount};
use crate::SigmaRule;

impl Correlation {
    pub async fn init(&self) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(_) = self.state.get() {
            return Err("state already initialized".into());
        }

        match &self.correlation_type {
            CorrelationType::EventCount(_) => self
                .state
                .set(CorrelationState::EventCount(
                    EventCount::new(self.timespan).await,
                ))
                .map_err(|_| "Could not set correlation state".into()),
            CorrelationType::ValueCount(_) => self
                .state
                .set(CorrelationState::ValueCount(
                    ValueCount::new(self.timespan).await,
                ))
                .map_err(|_| "Could not set correlation state".into()),
            _ => Err("unsupported correlation type".into()),
        }
    }

    async fn eval(&self, event: &serde_json::Value, prev: &Vec<Arc<SigmaRule>>) -> bool {
        if !self.dependencies.iter().all(|d| {
            prev.iter().any(|r| {
                if r.id == *d {
                    true
                } else if let Some(ref name) = r.name {
                    *name == *d
                } else {
                    false
                }
            })
        }) {
            return false;
        }

        let counter = match self.state.get() {
            Some(counter) => counter,
            None => {
                eprintln!("Correlation state not initialized");
                return false;
            }
        };

        match &self.correlation_type {
            CorrelationType::EventCount(c) => {
                let counter = match counter {
                    CorrelationState::EventCount(ref c) => c,
                    _ => return false,
                };
                let key = match event.as_object() {
                    Some(e) => e,
                    None => return false,
                }
                .iter()
                .filter_map(|(k, v)| {
                    if self.group_by.contains(k) {
                        Some(format!("{}:{}", k, v.to_string()))
                    } else {
                        None
                    }
                })
                .collect::<BinaryHeap<_>>()
                .into_sorted_vec()
                .join(",");

                counter.incr(&key).await.unwrap_or_else(|e| {
                    eprintln!("Error incrementing counter: {}", e);
                });

                let count = counter.count(&key).await;

                match c.condition {
                    ConditionOrList::Condition(ref c) => {
                        vec![c]
                    }
                    ConditionOrList::List(ref l) => l.iter().collect(),
                }
                .into_iter()
                .all(|c| match c {
                    Condition::Gt(ref v) => count > *v,
                    Condition::Gte(ref v) => count >= *v,
                    Condition::Lt(ref v) => count < *v,
                    Condition::Lte(ref v) => count <= *v,
                    Condition::Eq(ref v) => count == *v,
                })
            }
            CorrelationType::ValueCount(c) => {
                let counter = match counter {
                    CorrelationState::ValueCount(ref c) => c,
                    _ => return false,
                };

                let event = match event.as_object() {
                    Some(e) => e,
                    None => return false,
                };

                let key = match self
                    .group_by
                    .iter()
                    .map(|k| match event.get(k) {
                        Some(serde_json::Value::String(v)) => Some(format!("{}:{}", k, v)),
                        Some(serde_json::Value::Number(v)) => Some(format!("{}:{}", k, v)),
                        _ => None,
                    })
                    .collect::<Option<Vec<_>>>()
                    .map(|k| {
                        k.into_iter()
                            .collect::<BinaryHeap<_>>()
                            .into_sorted_vec()
                            .join(",")
                    }) {
                    Some(k) => k,
                    None => return false,
                };

                let value: String = match event.get(&c.condition.field) {
                    Some(serde_json::Value::String(v)) => v.into(),
                    Some(serde_json::Value::Number(v)) => v.to_string(),
                    _ => return false,
                };

                counter
                    .incr(&(key.clone(), value))
                    .await
                    .unwrap_or_else(|e| {
                        eprintln!("Error incrementing counter: {}", e);
                    });

                let count = counter.count(&key).await;

                match c.condition.condition {
                    Condition::Gt(ref v) => count > *v,
                    Condition::Gte(ref v) => count >= *v,
                    Condition::Lt(ref v) => count < *v,
                    Condition::Lte(ref v) => count <= *v,
                    Condition::Eq(ref v) => count == *v,
                }
            }
            CorrelationType::Temporal => false,
            CorrelationType::TemporalOrdered => false,
        }
    }
}

impl CorrelationRule {
    pub fn dependencies(&self) -> &Vec<String> {
        &self.inner.dependencies
    }
    pub async fn eval(&self, log: &serde_json::Value, prior: &Vec<Arc<SigmaRule>>) -> bool {
        self.inner.eval(log, prior).await
    }
}
