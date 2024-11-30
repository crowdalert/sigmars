use std::{collections::BinaryHeap, sync::Arc};

use super::serde::{Condition, ConditionOrList, Correlation, CorrelationRule, CorrelationType};
use crate::SigmaRule;
use super::state;

impl Correlation {
    pub async fn init(&self) -> Result<(), Box<dyn std::error::Error>> {
        let mut state = self.state.lock().await;
        match *state {
            Some(_) => Err("state already initialized".into()),
            None => {
                state.replace(state::EventCount::new(self.timespan).await);
                Ok(())
            }
        }
    }

    async fn eval(&self, event: &serde_json::Value, prev: &Vec<Arc<SigmaRule>>) -> bool {
        let state = self.state.lock().await;
        let counter = match *state {
            None => return false,
            Some(ref s) => s
        };
        match &self.correlation_type {
            CorrelationType::EventCount(c) => {
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

                let count = counter.count(&key).await + 1;

                counter.incr(&key).await.unwrap_or_else(|e| {
                    eprintln!("Error incrementing counter: {}", e);
                });

                match c.condition {
                    ConditionOrList::Condition(ref c) => {
                        vec![c]
                    }
                    ConditionOrList::List(ref l) => l.iter().collect(),
                }
                .into_iter()
                .all(|c| {
                    match c {
                        Condition::Gt(ref v) => count > *v,
                        Condition::Gte(ref v) => count >= *v,
                        Condition::Lt(ref v) => count < *v,
                        Condition::Lte(ref v) => count <= *v,
                        Condition::Eq(ref v) => count == *v,
                    }
                })
            }
            CorrelationType::ValueCount(_) => {
                false
            }
            CorrelationType::Temporal => {
                false
            }
            CorrelationType::TemporalOrdered => {
                false
            }
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
