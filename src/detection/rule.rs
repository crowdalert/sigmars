use serde::{self, Deserialize, Serialize};
use serde_json::Value;
use serde_yaml;

use super::detection::Detection;
use crate::event::LogSource;

#[derive(Debug, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Taxonomy {
    #[default]
    Sigma,
    Other(String),
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub struct DetectionRule {
    /// The log source information for the detection rule.
    pub logsource: LogSource,
    pub taxonomy: Taxonomy,
    pub detection: serde_yaml::Value,
    #[serde(skip)]
    compiled: Detection,
}

impl DetectionRule {
    pub fn is_match(&self, data: &Value) -> bool {
        self.compiled.is_match(data)
    }
}

impl<'de> Deserialize<'de> for DetectionRule {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct RuleHelper {
            logsource: LogSource,
            taxonomy: Option<String>,
            detection: serde_yaml::Value,
        }
        // Deserialize the detection rule from the deserializer
        let rule = RuleHelper::deserialize(deserializer)?;

        // Compile the detection criteria
        let compiled = Detection::new(&rule.detection).map_err(serde::de::Error::custom)?;

        let taxonomy = match rule.taxonomy {
            Some(t) => match t.to_lowercase().as_str() {
                "sigma" => Taxonomy::Sigma,
                _ => Taxonomy::Other(t),
            },
            None => Taxonomy::default(),
        };

        Ok(DetectionRule {
            logsource: rule.logsource,
            detection: rule.detection,
            taxonomy,
            compiled,
        })
    }
}
