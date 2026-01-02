use anyhow::Result;
use std::hash::{Hash, Hasher};
use serde_json::{Value, Map};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::collections::{HashSet, VecDeque};

use crate::correlation::serde::{ConditionOrList, ValueCondition};
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
    pub fn new(rule: &CorrelationRule) -> Self {
        let store = Box::new(TSinkStore::default());
        Self {
            store,
            rule: rule.clone(),
        }
    }


    pub fn new_with_storage(
        store: Box<dyn CorrelationStore>,
        rule: CorrelationRule,
    ) -> Self {
        Self {
            store,
            rule,
        }
    }
/*
    pub fn on_match(
        &self,
        matched: &String,
        group_values: &Map<String, Value>,
    ) -> Result<Vec<String>> {

    self.insert(corr, corr_id, src_id, &group_key, group_values, now)?;

                if self.eval(corr, corr_id, &group_key, now)? {
                    if emitted.insert(corr_id) {
                        out.push(corr_id);
                        queue.push_back(corr_id); // chaining
                    }
                }
            }

    fn insert(
        &self,
        origin: &str,
        event: &Map<String, Value>,
        now: i64,
    ) -> Result<()> {
        let metric = metric_name(corr_id, src_id, group_key);
        println!("Inserting occurrence for metric: {}", metric);
        let p = Point::new(now, 1.0);

        let row = match corr.corr_type {
            CorrelationType::ValueCount => {
                let field = corr.field.as_deref().unwrap();
                let Some(v) = group_values.get(field) else {
                    return Ok(());
                };
                let v_str = json_value_to_key(v);
                Row::with_labels(metric, vec![Label::new("v", v_str)], p)
            }
            _ => Row::new(metric, p),
        };

        self.store.insert_rows(&[row]).map_err(BackendError::from)?;
        Ok(())
    }
    */
    fn insert(&self, origin: &str, group: &str) {}

    pub fn matches(&self,
        event: &RefEvent,
        prev: &Vec<String>) -> Result<bool> {

        let now = unix_seconds();

        let Some(data) = event.data.as_object() else { return Ok(false); };
        let corr = &self.rule.inner;

        let group = match group_key(&corr.group_by, data) {
            Some(gk) => gk,
            None => return Ok(false),
        };
        
        prev
        .iter()
        .filter(|p| {
            corr.rules.contains(*p)
        })
        .map(|r| {
            self.insert(r, &group)
        })
        .for_each(drop);

        let start = now - corr.timespan.as_secs() as i64;

        let Some(event) = event.data.as_object() else { return Ok(false); };

        let group_key = match group_key(&corr.group_by, event) {
            Some(gk) => gk,
            None => return Ok(false),
        };

        match &corr.correlation_type {
            CorrelationType::EventCount(ec) => {
                let mut total = 0u64;
                for src in &corr.rules {
                    let metric = metric_name(&src, &group_key);
                    let pts = self.store.select(&metric, &[], start, now)
                    .map_err(|_| anyhow::anyhow!("whatever"))?;
                    total += pts.len() as u64;
                }
                match &ec.condition {
                    ConditionOrList::Condition(c) => Ok(c.matches(total)),
                    ConditionOrList::List(conditions) => Ok(conditions.iter().all(|c| c.matches(total))),
                }
            }

            CorrelationType::ValueCount(vc) => {
                let mut distinct: HashSet<String> = HashSet::new();
                for src in &corr.rules {
                    let metric = metric_name(src, &group_key);
                    let series = self.store.select_all(&metric, start, now).map_err(|_| anyhow::anyhow!("idk"))?;
                    for (labels, pts) in series {
                        if pts.is_empty() { continue; }
                        if let Some(v) = labels.iter().find(|l| l.name == "v").map(|l| l.value.clone()) {
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

fn parse_timespan(s: &str) -> Result<Duration, ()> {
    if s.len() < 2 { return Err(()); }
    let (num, unit) = s.split_at(s.len() - 1);
    let n: u64 = num.parse().map_err(|_| ())?;
    let secs = match unit {
        "s" => n,
        "m" => n * 60,
        "h" => n * 3600,
        "d" => n * 86400,
        _ => return Err(()),
    };
    Ok(Duration::from_secs(secs))
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
        if i != 0 { out.push('\x1f'); }
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
