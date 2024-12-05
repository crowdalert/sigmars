use std::any::Any;
use std::{collections::BinaryHeap, sync::Arc, any::TypeId};

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
                )),
            CorrelationType::ValueCount(_) => self
                .state
                .set(CorrelationState::ValueCount(
                    ValueCount::new(self.timespan).await,
                )),
            CorrelationType::Temporal => self
                .state
                .set(CorrelationState::ValueCount(
                    ValueCount::new(self.timespan).await,
                )),
            CorrelationType::TemporalOrdered => self
                .state
                .set(CorrelationState::ValueCount(
                    ValueCount::new(self.timespan).await,
                )),
        }.map_err(|_| "Could not set correlation state".into())
    }

    async fn eval(&self, event: &serde_json::Value, prev: &Vec<Arc<SigmaRule>>) -> bool {
        if (self.correlation_type.type_id() == TypeId::of::<EventCount>() || 
            self.correlation_type.type_id() == TypeId::of::<ValueCount>()) &&
            !self.dependencies.iter().all(|d| {
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

        let groupkey = match event.as_object() {
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

        if groupkey.len() == 0 {
            return false;
        }

        match &self.correlation_type {
            CorrelationType::EventCount(c) => {
                let CorrelationState::EventCount(counter) = counter else { return false; };
                
                if counter.incr(&groupkey).await.is_err() {
                    eprintln!("{}: Error incrementing counter", self.id);
                    return false;
                }

                let count = counter.count(&groupkey).await;

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
                let CorrelationState::ValueCount(counter) = counter else { return false; };

                let value: String = match event.get(&c.condition.field) {
                    Some(serde_json::Value::String(v)) => v.into(),
                    Some(serde_json::Value::Number(v)) => v.to_string(),
                    _ => return false
                };

                if counter
                    .incr(&(groupkey.clone(), value))
                    .await
                    .is_err() {
                        eprintln!("{}: Error incrementing counter", self.id);
                        return false;
                    };

                let count = counter.count(&groupkey).await;
                match c.condition.condition {
                    Condition::Gt(ref v) => count > *v,
                    Condition::Gte(ref v) => count >= *v,
                    Condition::Lt(ref v) => count < *v,
                    Condition::Lte(ref v) => count <= *v,
                    Condition::Eq(ref v) => count == *v,
                }
            }
            CorrelationType::Temporal => {
                let CorrelationState::ValueCount(counter) = counter else { return false; };
                let candidates = prev.iter().filter_map(|r| {
                    match r.name {
                        Some(ref name) => {
                            if self.dependencies.contains(name) {
                                Some(&r.id)
                            } else if self.dependencies.contains(&r.id) {
                                Some(&r.id)
                            } else {
                                None
                            }
                        }
                        None => if self.dependencies.contains(&r.id) {
                            Some(&r.id)
                        } else {
                            None
                        }
                    }
                }).collect::<Vec<_>>();
                for c in candidates {
                    let _ = counter.incr(&(groupkey.clone(), c.clone())).await;
                }
                for d in &self.dependencies {
                    if !counter.has_entry(&groupkey, &d).await {
                        return false;
                    }
                }
                true
            },
            CorrelationType::TemporalOrdered => {
                let CorrelationState::ValueCount(counter) = counter else { return false; };
                let (prev_ids, prev_names) = prev.iter()
                .filter_map(|r| {
                    match r.name {
                        Some(ref name) => {
                            if self.dependencies.contains(name) {
                                Some((&r.id, Some(name)))
                            } else if self.dependencies.contains(&r.id) {
                                Some((&r.id, Some(name)))
                            } else {
                                None
                            }
                        },
                        None => if self.dependencies.contains(&r.id) {
                            Some((&r.id, None))
                        } else {
                            None
                        }
                    }
                })
                .collect::<(Vec<_>,Vec<_>)>();

                for d in &self.dependencies {
                    if counter.has_entry(&groupkey, &d).await || prev_ids.contains(&d) {
                        let _ = counter.incr(&(groupkey.clone(), d.clone())).await;
                    } else if prev_names.contains(&Some(d)) {
                        if let Some(id) = prev_names.iter().position(|n| n == &Some(d))
                        .map(|i| prev_ids[i]) {
                            let _ = counter.incr(&(groupkey.clone(), id.clone())).await;
                        } else {
                            return false;
                        }
                    } else {
                        return false;
                    }
                }
                true
            },
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
