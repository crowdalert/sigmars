use serde::{de, Deserializer, Serializer};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use tokio::time::Duration;
use std::collections::HashMap;
use std::fmt;
use super::state;

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
pub enum CorrelationType {
    EventCount(EventCount),
    ValueCount(ValueCount),
    Temporal,
    TemporalOrdered,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct Correlation {
    #[serde(flatten)]
    pub(super) correlation_type: CorrelationType,
    #[serde(rename = "rules")]
    pub(super) dependencies: Vec<String>,
    #[serde(serialize_with = "serialize_timespan")]
    pub(super) timespan: Duration,
    pub(super) group_by: Vec<String>,
    #[serde(skip)]
    pub(crate) id: String,
    #[serde(skip)]
    pub(super) state: Mutex<Option<state::EventCount>>,
}

#[derive(Debug, Serialize, Deserialize)]
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
        #[derive(Deserialize)]
        #[serde(rename_all = "kebab-case")]
        pub struct CorrelationHelper {
            #[serde(flatten)]
            pub(super) correlation_type: CorrelationType,
            #[serde(rename = "rules")]
            pub(super) dependencies: Vec<String>,
            #[serde(deserialize_with = "deserialize_timespan")]
            pub(super) timespan: Duration,
            pub(super) group_by: Vec<String>,
            #[serde(skip)]
            pub(crate) id: String,
        }

        let rule = CorrelationHelper::deserialize(deserializer)?;
        let timespan = rule.timespan;

        Ok(Correlation {
            correlation_type: rule.correlation_type,
            dependencies: rule.dependencies,
            timespan,
            group_by: rule.group_by,
            id: rule.id,
            state: Mutex::new(None),
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
