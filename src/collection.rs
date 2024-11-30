#[cfg(feature = "correlation")]
use crate::correlation;

use crate::{detection, RuleType, SigmaRule};
use glob;
use serde::Deserialize;
use std::{collections::HashMap, str::FromStr, sync::Arc};

use super::Event;

/// A collection of Sigma detection and correlation rules
#[derive(Debug, Default)]
pub struct SigmaCollection {
    #[cfg(feature = "correlation")]
    pub correlations: correlation::RuleSet,
    #[cfg(not(feature = "correlation"))]
    #[allow(dead_code)]
    correlations: (),
    detections: detection::RuleSet,
    rules: HashMap<String, Arc<SigmaRule>>,
}

impl SigmaCollection {
    pub fn new_from_dir(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let mut collection = SigmaCollection::default();
        collection.load_from_dir(path)?;
        Ok(collection)
    }

    #[cfg(feature = "correlation")]
    pub async fn init_correlation(&self) -> Result<(), Box<dyn std::error::Error>> {
        for rule in Into::<Vec<_>>::into(&self.correlations) {
            if let RuleType::Correlation(ref c) = rule.rule {
                c.inner.init().await.unwrap_or_else(|e| {
                    eprintln!("error initializing correlation rule: {}", e);
                });
            }
        }
        Ok(())
    }

    pub fn load_from_dir(&mut self, path: &str) -> Result<u32, Box<dyn std::error::Error>> {
        let collection = glob::glob(format!("{}/**/*.yml", path).as_str())?
            .filter_map(Result::ok)
            .into_iter()
            .filter_map(|entry| {
                std::fs::read_to_string(&entry)
                    .map_err(|e| {
                        eprintln!("error reading file: {}", e);
                        e
                    })
                    .ok()
            })
            .filter_map(|s| {
                s.parse::<SigmaCollection>()
                    .map_err(|e| {
                        eprintln!("error parsing rule: {}", e);
                        e
                    })
                    .ok()
            })
            .fold(SigmaCollection::default(), |mut acc, f| {
                acc.extend(f.rules.values().map(|r| r.clone()));
                acc
            });

        let count = collection.rules.len() as u32;

        self.extend(collection);

        Ok(count)
    }

    /// Returns the number of rules in the collection.
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    /// Evaluates the collection of rules against a log event
    ///
    /// Uses the logsource property in event metadata
    /// ( `%logsource` ) as the Sigma logsource taxonomy to filter the ruleset.
    ///
    /// The event is responsible for declaring its filters, to capture the widest
    /// set of detections
    pub fn eval(&self, event: &Event) -> Vec<Arc<SigmaRule>> {
        self.detections.eval(&event)
    }

    #[cfg(feature = "correlation")]
    pub async fn eval_correlation(&self, event: &Event, detections: Option<Vec<Arc<SigmaRule>>>) -> Vec<Arc<SigmaRule>> {
        let mut detections = detections.unwrap_or_else(|| {
            self.eval(event)
        });
        self.correlations.eval(&event, &mut detections).await;
        detections
    }
}

impl Extend<Arc<SigmaRule>> for SigmaCollection {
    fn extend<T: IntoIterator<Item = Arc<SigmaRule>>>(&mut self, iter: T) {
        let mut rules = self
            .rules
            .iter()
            .map(|(_, rule)| rule.clone())
            .collect::<Vec<_>>();

        rules.extend(iter);

        *self = rules.into();
    }
}

impl IntoIterator for SigmaCollection {
    type Item = Arc<SigmaRule>;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.rules.into_values().collect::<Vec<_>>().into_iter()
    }
}

impl FromStr for SigmaCollection {
    type Err = Box<dyn std::error::Error>;

    /// Parses a `SigmaCollection` from YAML (may contain multiple documents)
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(serde_yml::Deserializer::from_str(&s)
            .map(|de| SigmaRule::deserialize(de).map_err(|e| e.into()))
            .collect::<Result<Vec<_>, Self::Err>>()?
            .into_iter()
            .map(|r| Arc::new(r))
            .collect::<Vec<_>>()
            .into())
    }
}

impl From<Vec<Arc<SigmaRule>>> for SigmaCollection {
    fn from(rules: Vec<Arc<SigmaRule>>) -> Self {
        let rules = rules
            .into_iter()
            .map(|rule| (rule.id.clone(), rule))
            .collect::<HashMap<_, _>>();

        let detections: detection::RuleSet = rules
            .values()
            .filter(|r| matches!(r.rule, RuleType::Detection(_)))
            .collect::<Vec<_>>()
            .into();

        #[cfg(feature = "correlation")]
        let correlations: correlation::RuleSet = rules.values().collect::<Vec<_>>().into();
        #[cfg(not(feature = "correlation"))]
        let correlations = ();

        Self {
            detections,
            correlations,
            rules,
        }
    }
}

impl ToString for SigmaCollection {
    /// Converts the `SigmaCollection` to a multi-document YAML String
    fn to_string(&self) -> String {
        self.rules
            .values()
            .filter_map(|rule| serde_yml::to_string(rule.as_ref()).ok())
            .collect::<Vec<String>>()
            .join("---\n")
    }
}
