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
                timestamp: unix_seconds(),
                value: 1.0,
            },
        };
        let _ = self.store.insert_rows(&[row]);
    }

    pub fn matches(&self, event: &RefEvent, prev: &Vec<String>) -> Result<bool> {
        let now = unix_seconds();

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

        let start = now - corr.timespan.as_secs() as i64;

        match &corr.correlation_type {
            CorrelationType::EventCount(ec) => {
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
            _ => unimplemented!(),
            /*
            CorrelationType::Temporal => {
                let mut present = 0u64;
                for src in &corr.rules {
                    let metric = metric_name(src, &group_key);
                    let pts = self.store.select(&metric, &[], start, now).map_err(anyhow::Error::from)?;
                    if !pts.is_empty() { present += 1; }
                }
                Ok(c.matches(present))
            }

            CorrelationType::TemporalOrdered => {
                let mut events: Vec<(i64, usize)> = Vec::new();
                for (idx, &src) in corr.related.iter().enumerate() {
                    let metric = metric_name(src, &group_key);
                    let pts = self.store.select(&metric, &[], start, now).map_err(BackendError::from)?;
                    for p in pts {
                        events.push((p.timestamp, idx));
                    }
                }
                events.sort_by_key(|(ts, _)| *ts);

                let mut expected = 0usize;
                for (_, idx) in events {
                    if idx == expected {
                        expected += 1;
                        if expected >= corr.related.len() { break; }
                    }
                }

                Ok(vc.condition.matches(expected as u64))
            }*/
            _ => Ok(false),
        }
    }
}

fn unix_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_secs() as i64
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
