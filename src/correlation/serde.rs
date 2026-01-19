use serde::{Deserialize, Serialize};
use serde::{Deserializer, Serializer, de};
use std::collections::HashMap;
use std::{fmt, sync::OnceLock, time::Duration};

use super::engine::CorrelationEngine;
use anyhow::Result;

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "lowercase")]
pub enum Condition {
    Gt(u64),
    Gte(u64),
    Lt(u64),
    Lte(u64),
    Eq(u64),
}

impl Condition {
    pub fn matches(&self, value: u64) -> bool {
        match self {
            Condition::Gt(n) => value > *n,
            Condition::Gte(n) => value >= *n,
            Condition::Lt(n) => value < *n,
            Condition::Lte(n) => value <= *n,
            Condition::Eq(n) => value == *n,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(untagged)]
pub enum ConditionOrList {
    Condition(Condition),
    List(Vec<Condition>),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EventCount {
    #[serde(with = "serde_yaml::with::singleton_map_recursive")]
    pub condition: ConditionOrList,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ValueCondition {
    #[serde(with = "serde_yaml::with::singleton_map_recursive", flatten)]
    pub condition: Condition,
    pub field: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ValueCount {
    pub condition: ValueCondition,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CorrelationType {
    EventCount(EventCount),
    ValueCount(ValueCount),
    Temporal,
    TemporalOrdered,
}

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct Correlation {
    #[serde(flatten)]
    pub(super) correlation_type: CorrelationType,
    pub(super) rules: Vec<String>,
    #[serde(serialize_with = "serialize_timespan")]
    pub(super) timespan: Duration,
    pub(super) group_by: Vec<String>,
    #[serde(skip)]
    pub(crate) id: String,

    #[serde(skip)]
    pub(super) state: OnceLock<Box<CorrelationEngine>>,
}

impl Correlation {
    pub fn set_engine(&self, engine: Box<CorrelationEngine>) -> Result<()> {
        let engine = Box::new(*engine);
        self.state
            .set(engine)
            .map_err(|_| anyhow::anyhow!("state already initialized"))
    }
}
impl Clone for Correlation {
    fn clone(&self) -> Self {
        Self {
            correlation_type: self.correlation_type.clone(),
            rules: self.rules.clone(),
            timespan: self.timespan,
            group_by: self.group_by.clone(),
            id: self.id.clone(),
            state: OnceLock::new(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CorrelationRule {
    #[serde(rename = "correlation")]
    pub(crate) inner: Correlation,
    #[serde(flatten)]
    pub(crate) extra: HashMap<String, String>,
}

impl<'de> Deserialize<'de> for Correlation {
    fn deserialize<D>(deserializer: D) -> Result<Correlation, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize, Debug)]
        #[serde(rename_all = "kebab-case")]
        pub struct CorrelationHelper {
            #[serde(flatten)]
            pub(super) correlation_type: CorrelationType,
            pub(super) rules: Vec<String>,
            #[serde(deserialize_with = "deserialize_timespan")]
            pub(super) timespan: Duration,
            pub(super) group_by: Vec<String>,
            #[serde(skip)]
            pub(crate) id: String,
        }

        let rule = CorrelationHelper::deserialize(deserializer)?;

        Ok(Correlation {
            correlation_type: rule.correlation_type,
            rules: rule.rules,
            timespan: rule.timespan,
            group_by: rule.group_by,
            id: rule.id,
            state: OnceLock::new(),
        })
    }
}

fn serialize_timespan<S>(timespan: &Duration, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&format!("{}s", timespan.as_secs()))
}
struct TimespanVisitor;

impl<'de> de::Visitor<'de> for TimespanVisitor {
    type Value = Duration;

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
            "s" => Ok(Duration::from_secs(n)),
            "m" => Ok(Duration::from_secs(n * 60)),
            "h" => Ok(Duration::from_secs(n * 3600)),
            "d" => Ok(Duration::from_secs(n * 86400)),
            other => Err(de::Error::custom(format!("invalid format: {:?}", other))),
        }
    }
}

fn deserialize_timespan<'de, D>(deserializer: D) -> Result<Duration, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_str(TimespanVisitor)
}

impl fmt::Debug for Correlation {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Correlation")
            .field("correlation_type", &self.correlation_type)
            .field("rules", &self.rules)
            .field("timespan", &self.timespan)
            .field("group_by", &self.group_by)
            .field("id", &self.id)
            .finish()
    }
}
