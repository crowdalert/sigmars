use std::{collections::HashMap, hash::Hash};

use chrono::prelude::*;
use serde::de::{self, DeserializeSeed, Deserializer, Visitor};
use serde::{self, Deserialize, Serialize};
use serde_json::Value;
use std::fmt;

use crate::detection::DetectionRule;

#[cfg(feature = "correlation")]
use crate::correlation::CorrelationRule;

#[doc(hidden)]
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Stable,
    Test,
    Experimental,
    Deprecated,
    Unsupported,
}

impl From<&str> for Status {
    fn from(s: &str) -> Self {
        match s {
            "stable" => Status::Stable,
            "test" => Status::Test,
            "experimental" => Status::Experimental,
            "deprecated" => Status::Deprecated,
            "unsupported" => Status::Unsupported,
            _ => Status::Unsupported,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub(crate) enum RuleType {
    Detection(DetectionRule),
    Correlation(CorrelationRule),
}

/// a single Sigma rule (detection or correlation)
/// fields are described by the [Sigma specification](https://github.com/SigmaHQ/sigma-specification)
#[derive(Debug, Serialize)]
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
    pub(crate) rule: RuleType,
    #[doc(hidden)]
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

/// A convenience function to convert a Sigma rule an [OCSF](https://ocsf.io) Detection Finding
/// (as JSON)
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

struct SigmaRuleSeed;

impl<'de> DeserializeSeed<'de> for SigmaRuleSeed {
    type Value = SigmaRule;

    fn deserialize<D>(self, deserializer: D) -> Result<SigmaRule, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(SigmaRuleVisitor)
    }
}

struct SigmaRuleVisitor;

impl<'de> Visitor<'de> for SigmaRuleVisitor {
    type Value = SigmaRule;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a Sigma rule")
    }

    fn visit_map<V>(self, mut map: V) -> Result<SigmaRule, V::Error>
    where
        V: serde::de::MapAccess<'de>,
    {
        #[derive(Deserialize)]
        struct SigmaRuleHelper {
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

        let mut helper =
            SigmaRuleHelper::deserialize(de::value::MapAccessDeserializer::new(&mut map))?;

        if let RuleType::Correlation(ref mut rule) = helper.rule {
            rule.inner.id = helper.id.clone();
        }

        Ok(SigmaRule {
            title: helper.title,
            id: helper.id,
            name: helper.name,
            description: helper.description,
            references: helper.references,
            author: helper.author,
            date: helper.date,
            modified: helper.modified,
            status: helper.status,
            license: helper.license,
            tags: helper.tags,
            scope: helper.scope,
            fields: helper.fields,
            falsepositives: helper.falsepositives,
            level: helper.level,
            rule: helper.rule,
            extra: helper.extra,
        })
    }
}

impl<'de> Deserialize<'de> for SigmaRule {
    fn deserialize<D>(deserializer: D) -> Result<SigmaRule, D::Error>
    where
        D: Deserializer<'de>,
    {
        SigmaRuleSeed.deserialize(deserializer)
    }
}

#[cfg(not(feature = "correlation"))]
#[derive(Debug, Serialize, Deserialize)]
pub struct Correlation {
    #[serde(skip)]
    pub id: String,
    #[serde(flatten)]
    extra: HashMap<String, serde_yml::Value>,
}
#[cfg(not(feature = "correlation"))]
#[derive(Debug, Serialize, Deserialize)]
pub struct CorrelationRule {
    #[serde(rename = "correlation")]
    pub inner: Correlation,
}
