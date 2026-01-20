use anyhow::Result;
use serde_json::{Map, Value};
use std::collections::HashSet;
use std::hash::{Hash, Hasher};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::correlation::serde::ConditionOrList;
use crate::event::RefEvent;

use super::backend::CorrelationStore;
use super::{CorrelationRule, CorrelationType};

#[cfg(feature = "tsink")]
use super::backend::tsink::TSinkStore;

/// Engine for evaluating Sigma correlation rules against events.
///
/// The `CorrelationEngine` maintains state for a single correlation rule and
/// determines when the correlation conditions are satisfied based on incoming events.
///
/// # Correlation Types
///
/// The engine supports the following correlation types:
///
/// - **Event Count**: Counts events matching the dependent rules within a timespan
/// - **Value Count**: Counts distinct values of a field across matching events
/// - **Temporal**: Detects when all specified rules have events within a timespan (order-independent)
/// - **Temporal Ordered**: Detects when all specified rules have events in a specific order within a timespan
///
/// # Example
///
/// ```rust,ignore
/// use sigmars::correlation::engine::CorrelationEngine;
/// use sigmars::correlation::backend::tsink::TSinkStore;
/// use std::time::Duration;
///
/// let store = Box::new(TSinkStore::new_with_expiry(Duration::from_secs(300)).unwrap());
/// let engine = CorrelationEngine::new_with_storage(store, corr_rule);
///
/// let result = engine.matches(&event, &vec!["rule-a".to_string()]).unwrap();
/// ```
pub struct CorrelationEngine {
    store: Box<dyn CorrelationStore>,
    rule: CorrelationRule,
}

impl CorrelationEngine {
    #[cfg(feature = "tsink")]
    pub fn new(rule: &CorrelationRule) -> Result<Self> {
        let store = Box::new(TSinkStore::new_with_expiry(rule.inner.timespan)
            .map_err(|e| anyhow::anyhow!("failed to create TSinkStore: {}", e))?);
        Ok(Self {
            store,
            rule: rule.clone(),
        })
    }

    pub fn new_with_storage(store: Box<dyn CorrelationStore>, rule: CorrelationRule) -> Self {
        Self { store, rule }
    }

    /// Inserts an event into the correlation store.
    ///
    /// Records that a rule matched for a specific group, enabling subsequent
    /// correlation checks to detect patterns across multiple rule matches.
    ///
    /// # Arguments
    ///
    /// * `origin` - The ID of the rule that matched
    /// * `group` - The group key (derived from `group-by` fields)
    /// * `data` - The event data (used for extracting values in value_count correlations)
    fn insert(&self, origin: &str, group: &str, data: &Map<String, Value>) {
        let metric = metric_name(origin, group);
        let labels = match self.rule.inner.correlation_type {
            CorrelationType::ValueCount(ref vc) => {
                if let Some(v) = data.get(&vc.condition.field) {
                    vec![super::backend::Label::new("v", json_value_to_key(v))]
                } else {
                    Vec::new()
                }
            }
            _ => Vec::new(),
        };
        let row = super::backend::Row {
            metric,
            labels,
            point: super::backend::Point {
                timestamp: unix_millis(),
                value: 1.0,
            },
        };
        let _ = self.store.insert_rows(&[row]);
    }

    /// Evaluates whether the correlation rule matches given an event and prior rule matches.
    ///
    /// This is the main entry point for correlation evaluation. It:
    /// 1. Extracts the group key from the event based on `group-by` configuration
    /// 2. Records any prior rule matches in the correlation store
    /// 3. Evaluates the correlation condition based on the correlation type
    ///
    /// # Arguments
    ///
    /// * `event` - The current event being processed
    /// * `prev` - List of rule IDs that matched for this event (from detection rules)
    ///
    /// # Returns
    ///
    /// Returns `Ok(true)` if the correlation condition is satisfied, `Ok(false)` otherwise.
    /// Returns an error if the event data is invalid or storage operations fail.
    pub fn matches(&self, event: &RefEvent, prev: &Vec<String>) -> Result<bool> {
        let Some(data) = event.data.as_object() else {
            return Ok(false);
        };
        let corr = &self.rule.inner;

        let group = match group_key(&corr.group_by, data) {
            Some(gk) => gk,
            None => return Ok(false),
        };

        prev.iter()
            .filter(|p| corr.rules.contains(*p))
            .map(|r| {
                self.insert(r, &group, &data);
            })
            .for_each(drop);

        // Capture 'now' AFTER inserting so we don't miss events we just inserted
        // Add 1ms buffer because select may use exclusive upper bound
        let now = unix_millis() + 1;
        let start = now - (corr.timespan.as_millis() as i64);

        match &corr.correlation_type {
            CorrelationType::EventCount(ec) => {
                // Event count correlation: count total events across all rules
                let mut total = 0u64;
                for src in &corr.rules {
                    let metric = metric_name(&src, &group);
                    let pts = self
                        .store
                        .select(&metric, &[], start, now)
                        .map_err(|_| anyhow::anyhow!("whatever"))?;
                    total += pts.len() as u64;
                }
                match &ec.condition {
                    ConditionOrList::Condition(c) => Ok(c.matches(total)),
                    ConditionOrList::List(conditions) => {
                        Ok(conditions.iter().all(|c| c.matches(total)))
                    }
                }
            }

            CorrelationType::ValueCount(vc) => {
                // Value count correlation: count distinct values of a field across all rules
                let mut distinct: HashSet<String> = HashSet::new();
                for src in &corr.rules {
                    let metric = metric_name(src, &group);
                    let series = self
                        .store
                        .select_all(&metric, start, now)
                        .map_err(|_| anyhow::anyhow!("idk"))?;
                    for (labels, pts) in series {
                        if pts.is_empty() {
                            continue;
                        }
                        if let Some(v) = labels
                            .into_iter()
                            .find(|l| l.name == "v")
                            .map(|l| l.value.clone())
                        {
                            distinct.insert(v);
                        }
                    }
                }
                Ok(vc.condition.condition.matches(distinct.len() as u64))
            }

            CorrelationType::Temporal => {
                // Temporal correlation: all rules must have at least one event within the timespan
                // Order does not matter
                let mut rules_with_events = HashSet::new();
                
                for src in &corr.rules {
                    let metric = metric_name(src, &group);
                    let pts = self
                        .store
                        .select(&metric, &[], start, now)
                        .map_err(|e| anyhow::anyhow!("temporal select error: {}", e))?;
                    
                    if !pts.is_empty() {
                        rules_with_events.insert(src.clone());
                    }
                }
                
                // All rules must have at least one event
                Ok(rules_with_events.len() == corr.rules.len())
            }

            CorrelationType::TemporalOrdered => {
                // Temporal ordered correlation: all rules must have events within the timespan
                // AND they must appear in the order specified in the rules array
                
                // Collect all events with their timestamps and rule index
                let mut events: Vec<(i64, usize)> = Vec::new();
                
                for (idx, src) in corr.rules.iter().enumerate() {
                    let metric = metric_name(src, &group);
                    let pts = self
                        .store
                        .select(&metric, &[], start, now)
                        .map_err(|e| anyhow::anyhow!("temporal ordered select error: {}", e))?;
                    
                    for p in pts {
                        events.push((p.timestamp, idx));
                    }
                }

                events.sort_by_key(|(ts, _)| *ts);
                
                // Check if we can find all rules in order
                let mut expected_idx = 0usize;
                
                for (_, idx) in events {
                    if idx == expected_idx {
                        expected_idx += 1;
                        if expected_idx >= corr.rules.len() {
                            return Ok(true);
                        }
                    }
                }

                Ok(false)
            }
        }
    }
}

fn unix_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_millis() as i64
}

fn group_key(group_by: &[String], group_values: &Map<String, Value>) -> Option<String> {
    let mut out = String::new();
    for (i, f) in group_by.iter().enumerate() {
        let v = group_values.get(f)?;
        if i != 0 {
            out.push('\x1f');
        }
        out.push_str(&format!("{}={}", f, json_value_to_key(v)));
    }
    Some(out)
}

fn json_value_to_key(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Null => "null".to_string(),
        _ => v.to_string(),
    }
}

fn metric_name(src_id: &str, group_key: &str) -> String {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    group_key.hash(&mut hasher);
    let h = hasher.finish();
    format!("{}::{:016x}", src_id, h)
}
