use std::{collections::HashMap, sync::Arc};

use crate::{Eval, SigmaRule};

use super::detection::Detection;
use serde::{self, Deserialize, Serialize};
use serde_json::Value;
use serde_yml;

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct LogSource {
    pub category: Option<String>,
    pub product: Option<String>,
    pub service: Option<String>,
    /// Additional log source information
    #[serde(flatten)]
    pub(crate) extra: HashMap<String, String>,
}

/// Represents the detection criteria in a Sigma rule.
///
/// A map containing a set of search-identifiers
/// and a 'condition' field specifying the SAT criteria for
/// search-identifiers
#[derive(Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub struct DetectionRule {
    /// The log source information for the detection rule.
    pub logsource: LogSource,
    pub detection: serde_yml::Value,
    /// The compiled detection criteria.
    #[serde(skip)]
    compiled: Detection,
}

impl DetectionRule {
    pub fn logsource(&self) -> &LogSource {
        &self.logsource
    }
}

impl Eval for DetectionRule {
    fn eval(&self, log: &Value, _: Option<&Vec<Arc<SigmaRule>>>) -> bool {
        self.compiled.eval(log)
    }
}

impl<'de> Deserialize<'de> for DetectionRule {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct RuleWrapper {
            logsource: LogSource,
            detection: serde_yml::Value,
        }
        // Deserialize the detection rule from the deserializer
        let rule = RuleWrapper::deserialize(deserializer)?;

        // Compile the detection criteria
        let compiled = Detection::new(&rule.detection).map_err(serde::de::Error::custom)?;

        Ok(DetectionRule {
            logsource: rule.logsource,
            detection: rule.detection,
            compiled,
        })
    }
}
