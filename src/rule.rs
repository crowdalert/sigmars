use std::sync::atomic::AtomicBool;
use std::{collections::HashMap, hash::Hash};

use serde::de::{self, DeserializeSeed, Deserializer, Visitor};
use serde::{self, Deserialize, Serialize};
use std::fmt;

use crate::detection::DetectionRule;

fn is_disabled_false(disabled: &AtomicBool) -> bool {
    !disabled.load(std::sync::atomic::Ordering::Relaxed)
}

#[cfg(feature = "correlation")]
use crate::correlation::CorrelationRule;

#[doc(hidden)]
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
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

    /// Fields for compatibility with the general fields in
    /// [RunReveal's Sigma extension](https://docs.runreveal.com/detections/sigma-streaming)
    /// that aren't specific to their system
    ///
    /// Excluded are the mitreAttacks & mitreTechniques fields: the information they carry
    /// is in the core Sigma specification under the tags.attack taxonomy
    #[serde(skip_serializing_if = "is_disabled_false")]
    pub disabled: AtomicBool,
    #[serde(rename = "riskScore", skip_serializing_if = "Option::is_none")]
    pub risk_score: Option<u32>,
    #[serde(rename = "notificationNames", skip_serializing_if = "Option::is_none")]
    pub notification_names: Option<Vec<String>>,
    #[serde(rename = "notificationTemplate", skip_serializing_if = "Option::is_none")]
    pub notification_template: Option<String>,

    // anything left over
    #[doc(hidden)]
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

impl SigmaRule {
    pub fn is_enabled(&self) -> bool {
        !self.disabled.load(std::sync::atomic::Ordering::Relaxed)
    }
    pub fn enable(&self) {
        self.disabled
            .store(false, std::sync::atomic::Ordering::Relaxed);
    }
    pub fn disable(&self) {
        self.disabled
            .store(true, std::sync::atomic::Ordering::Relaxed);
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

            pub disabled: Option<bool>,
            #[serde(rename = "riskScore")]
            pub risk_score: Option<u32>,
            #[serde(rename = "notificationNames")]
            pub notification_names: Option<Vec<String>>,
            #[serde(rename = "notificationTemplate")]
            pub notification_template: Option<String>,

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
            disabled: AtomicBool::new(helper.disabled.unwrap_or(false)),
            risk_score: helper.risk_score,
            notification_names: helper.notification_names,
            notification_template: helper.notification_template,
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

#[cfg(not(feature = "correlation"))]
impl CorrelationRule {
    pub fn rules(&self) -> Vec<String> {
        vec![]
    }
}
