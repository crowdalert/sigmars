use std::collections::HashMap;

use super::Detection;
use chrono::prelude::*;
use serde::{self, Deserialize, Serialize};
use serde_json::Value;
use serde_yml;

#[derive(Debug, Serialize, Deserialize)]
pub struct LogSource {
    pub category: Option<String>,
    pub product: Option<String>,
    pub service: Option<String>,
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Stable,
    Test,
    Experimental,
    Deprecated,
    Unsupported,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub struct Rule {
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
    pub logsource: LogSource,
    pub detection: serde_yml::Value,
    pub scope: Option<String>,
    pub fields: Option<Vec<String>>,
    pub falsepositives: Option<Vec<String>>,
    pub level: Option<String>,
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
    #[serde(skip)]
    compiled: Detection,
}

impl Rule {
    pub fn eval(&self, log: &Value) -> bool {
        self.compiled.eval(log)
    }

    pub fn as_ocsf(&self, metadata: &HashMap<String, Value>) -> Value {
        let time = match metadata
            .get("timestamp")
            .and_then(|v| v.as_str())
            .and_then(|v| DateTime::parse_from_rfc3339(v).ok())
        {
            Some(timestamp) => timestamp.timestamp_millis(),
            None => Utc::now().timestamp_millis(),
        };

        let severity_id = match self.level {
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
              "vendor_name": "Crowdalert",
              "name": "StrIEM"
            }
          },
          "finding_info": {
            "title": self.title,
            "uid": self.id,
            "analytic": {
              "type_id": 1,
              "type": "Rule"
            }
          },
          "severity_id": severity_id,
        });

        match self.level {
            Some(ref level) => value["severity"] = level.clone().into(),
            None => {}
        };

        match metadata.get("correlation_uid") {
            Some(correlation_uid) => {
                value["metadata"]["correlation_uid"] = correlation_uid.clone();
            }
            None => {}
        };
        value
    }
}

impl<'de> Deserialize<'de> for Rule {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct RuleWrapper {
            title: String,
            id: String,
            name: Option<String>,
            description: Option<String>,
            references: Option<Vec<String>>,
            author: Option<String>,
            date: Option<String>,
            modified: Option<String>,
            status: Option<Status>,
            license: Option<String>,
            tags: Option<Vec<String>>,
            logsource: LogSource,
            detection: serde_yml::Value,
            scope: Option<String>,
            fields: Option<Vec<String>>,
            falsepositives: Option<Vec<String>>,
            level: Option<String>,
            #[serde(flatten)]
            extra: HashMap<String, serde_json::Value>,
        }

        let rule = RuleWrapper::deserialize(deserializer)?;

        let compiled = Detection::new(&rule.detection).map_err(serde::de::Error::custom)?;

        Ok(Rule {
            title: rule.title,
            id: rule.id,
            name: rule.name,
            description: rule.description,
            references: rule.references,
            author: rule.author,
            date: rule.date,
            modified: rule.modified,
            status: rule.status,
            license: rule.license,
            tags: rule.tags,
            logsource: rule.logsource,
            detection: rule.detection,
            scope: rule.scope,
            fields: rule.fields,
            falsepositives: rule.falsepositives,
            level: rule.level,
            extra: rule.extra,
            compiled,
        })
    }
}
