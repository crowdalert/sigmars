use crate::{Eval, SigmaRule};
use serde::{de, Deserializer, Serializer};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::sync::Arc;

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Condition {
    Gt(i64),
    Gte(i64),
    Lt(i64),
    Lte(i64),
    Eq(i64),
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ConditionOrList {
    Condition(Condition),
    List(Vec<Condition>),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EventCount {
    #[serde(with = "serde_yml::with::singleton_map_recursive")]
    pub condition: ConditionOrList,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ValueCount {
    #[serde(with = "serde_yml::with::singleton_map_recursive")]
    pub condition: Condition,
    pub field: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum CorrelationType {
    EventCount(EventCount),
    ValueCount(ValueCount),
    Temporal,
    TemporalOrdered,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct Correlation {
    #[serde(flatten)]
    correlation_type: CorrelationType,
    #[serde(rename = "rules")]
    dependencies: Vec<String>,
    #[serde(
        serialize_with = "serialize_timespan",
        deserialize_with = "deserialize_timespan"
    )]
    timespan: u64,
    group_by: Vec<String>,
    #[serde(skip)]
    pub(crate) id: String,
}

impl Eval for Correlation {
    fn eval(&self, _: &serde_json::Value, _: Option<&Vec<Arc<SigmaRule>>>) -> bool {
        match self.correlation_type {
            CorrelationType::EventCount(_) => {
                println!("EventCount: {:?}", self.group_by);
            }
            CorrelationType::ValueCount(_) => {
                println!("ValueCount: {:?}", self.group_by);
            }
            CorrelationType::Temporal => {
                println!("Temporal: {:?}", self.group_by);
            }
            CorrelationType::TemporalOrdered => {
                println!("TemporalOrdered: {:?}", self.group_by);
            }
        }
        false
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CorrelationRule {
    #[serde(rename = "correlation")]
    pub(crate) inner: Correlation,
}

impl CorrelationRule {
    pub fn dependencies(&self) -> &Vec<String> {
        &self.inner.dependencies
    }
}

impl Eval for CorrelationRule {
    fn eval(&self, log: &serde_json::Value, prior: Option<&Vec<Arc<SigmaRule>>>) -> bool {
        self.inner.eval(log, prior)
    }
}

fn serialize_timespan<S>(timespan: &u64, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&format!("{}s", timespan))
}

struct TimespanVisitor;

impl<'de> de::Visitor<'de> for TimespanVisitor {
    type Value = u64;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str(
            "a string representing a timespan as a number followed by a unit (s, m, h, d)",
        )
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        let n = value[..value.len() - 1]
            .parse::<u64>()
            .map_err(de::Error::custom)?;
        match &value[value.len() - 1..] {
            "s" => Ok(n),
            "m" => Ok(n * 60),
            "h" => Ok(n * 3600),
            "d" => Ok(n * 86400),
            other => Err(de::Error::custom(format!("invalid format: {:?}", other))),
        }
    }
}

fn deserialize_timespan<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_str(TimespanVisitor)
}
