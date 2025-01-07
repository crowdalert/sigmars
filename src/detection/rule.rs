use serde::{self, Deserialize, Serialize};
use serde_json::Value;
use serde_yml;

use super::detection::Detection;
use crate::event::LogSource;

#[derive(Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub struct DetectionRule {
    /// The log source information for the detection rule.
    pub logsource: LogSource,
    pub detection: serde_yml::Value,
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
            detection: serde_yml::Value,
        }
        // Deserialize the detection rule from the deserializer
        let rule = RuleHelper::deserialize(deserializer)?;

        // Compile the detection criteria
        let compiled = Detection::new(&rule.detection).map_err(serde::de::Error::custom)?;

        Ok(DetectionRule {
            logsource: rule.logsource,
            detection: rule.detection,
            compiled,
        })
    }
}
