/// The `Eval` trait defines a method for evaluating a log entry against a rule.
use std::{collections::HashMap, hash::Hash, sync::Arc};

use super::{CorrelationRule, DetectionRule};

use chrono::prelude::*;
use serde::{self, Deserialize, Serialize};
use serde_json::Value;

/// Evaluates the given log entry against the rule.
pub trait Eval {
    fn eval(&self, log: &Value, previous: Option<&Vec<Arc<SigmaRule>>>) -> bool;
}

/// Represents the status of a Sigma rule.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Stable,
    Test,
    Experimental,
    Deprecated,
    Unsupported,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RuleType {
    Detection(DetectionRule),
    Correlation(CorrelationRule),
}

impl Eval for RuleType {
    fn eval(&self, log: &Value, previous: Option<&Vec<Arc<SigmaRule>>>) -> bool {
        match self {
            RuleType::Detection(r) => r.eval(log, previous),
            RuleType::Correlation(r) => r.eval(log, previous),
        }
    }
}

/// Represents a Sigma rule
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub struct SigmaRule {
    pub title: String,
    pub id: String,
    pub name: Option<String>,
    pub description: Option<String>,
    pub references: Option<Vec<String>>,
    pub author: Option<String>,
    pub date: Option<String>,
    pub modified: Option<String>,
    pub status: Option<Status>,
    pub license: Option<String>,
    pub tags: Option<Vec<String>>,
    pub scope: Option<String>,
    pub fields: Option<Vec<String>>,
    pub falsepositives: Option<Vec<String>>,
    pub level: Option<String>,
    #[serde(flatten)]
    pub rule: RuleType,
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

/// Convert a Sigma rule to JSON as OCSF Detection Finding
impl From<&SigmaRule> for Value {
    fn from(rule: &SigmaRule) -> Value {
        let time = Utc::now().timestamp_millis();

        let severity_id = match rule.level {
            Some(ref level) => match level.as_str() {
                "informational" => 1,
                "low" => 2,
                "medium" => 3,
                "high" => 4,
                "critical" => 5,
                _ => 99,
            },
            None => 0,
        };

        let mut value = serde_json::json!({
          "category_uid": 2,
          "category_name": "Findings",
          "class_uid": 2004,
          "class_name": "Detection Finding",
          "activity_id": 1,
          "activity_name":  "Create",
          "type_uid": 200401,
          "type_name": "Detection Finding: Create",
          "status_id": 1,
          "status": "New",
          "time": time,
          "metadata": {
            "version": "1.3.0",
            "product": {
              "vendor_name": "sigmars",
              "name": "sigmars"
            }
          },
          "finding_info": {
            "title": rule.title,
            "uid": rule.id,
            "analytic": {
              "type_id": 1,
              "type": "Rule"
            }
          },
          "severity_id": severity_id,
        });

        match rule.level {
            Some(ref level) => value["severity"] = level.clone().into(),
            None => {}
        };

        value
    }
}

impl Eval for SigmaRule {
    /// Evaluates the given log entry against the Sigma rule.

    fn eval(&self, log: &Value, previous: Option<&Vec<Arc<SigmaRule>>>) -> bool {
        self.rule.eval(log, previous)
    }
}

impl PartialEq for SigmaRule {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for SigmaRule {}

impl Hash for SigmaRule {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.id.hash(state);
    }
}
