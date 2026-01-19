use crate::detection::filter::Filter;
use crate::event::{Event, RefEvent};

use anyhow::Result;

#[cfg(feature = "correlation")]
use crate::correlation;

use log::warn;
use petgraph::{Directed, Graph, graph};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

use crate::rule::{RuleType, SigmaRule};

#[derive(Error, Debug)]
pub enum CollectionError {
    #[error("dependency for {0} not present in collection: {1}")]
    DependencyMissing(String, String),
    #[error("cycle detected in dependencies")]
    DependencyCycle,
    #[error("error parsing rule: {0}")]
    ParseError(String),
    #[error("error reading file: {0}")]
    IoError(#[from] std::io::Error),
}

#[derive(Debug, Default)]
pub(crate) struct DependencyGraph {
    graph: Graph<String, (), Directed>,
    idx: HashMap<String, graph::NodeIndex>,
    sorted: Vec<graph::NodeIndex>,
}

impl DependencyGraph {
    fn add_node(&mut self, id: &String) -> graph::NodeIndex {
        match self.idx.get(id) {
            Some(idx) => *idx,
            None => {
                let idx = self.graph.add_node(id.clone());
                self.idx.insert(id.clone(), idx);
                idx
            }
        }
    }
    fn add_edge(&mut self, from: &String, to: &String) -> Result<(), CollectionError> {
        let from = self.add_node(from);
        let to = self.add_node(to);
        self.graph.add_edge(from, to, ());
        self.sort()?;
        Ok(())
    }

    fn sort(&mut self) -> Result<(), CollectionError> {
        self.sorted = petgraph::algo::toposort(&self.graph, None)
            .map_err(|_| CollectionError::DependencyCycle)?;
        Ok(())
    }
}

/// A collection of Sigma rules, with dependency resolution
/// and log source filtering
#[derive(Debug, Default)]
pub struct SigmaCollection {
    rules: HashMap<String, SigmaRule>,
    filters: Filter,
    named: HashMap<String, String>,
    deps: DependencyGraph,
}

impl SigmaCollection {
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a new `SigmaCollection` from a directory of Sigma rules
    ///
    /// Rules must be in YAML format
    pub fn new_from_dir(path: &str) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let mut collection = Self::default();
        collection.load_from_dir(path)?;
        Ok(collection)
    }

    /// Load and add Sigma rules from a directory of YAML files
    pub fn load_from_dir(
        &mut self,
        path: &str,
    ) -> Result<u32, Box<dyn std::error::Error + Send + Sync>> {
        let rules = glob::glob(format!("{}/**/*.yml", path).as_str())?
            .into_iter()
            .chain(glob::glob(format!("{}/**/*.yaml", path).as_str())?.into_iter())
            .flatten()
            .filter_map(|entry| {
                std::fs::read_to_string(&entry)
                    .ok()
                    .and_then(move |s| Some((entry.to_str().unwrap_or_default().to_owned(), s)))
            })
            .map(|(fname, s)| {
                s.split("---")
                    .map(|part| (fname.clone(), part.to_string()))
                    .collect::<Vec<_>>()
            })
            .flatten()
            .filter_map(|(fname, s)| {
                serde_yaml::from_str::<SigmaRule>(&s)
                    .map_err(|e| {
                        warn!("Error parsing rule: {}, skipping: {}", fname, e);
                        e
                    })
                    .ok()
            })
            .collect::<Vec<_>>();

        let count = rules.len() as u32;
        rules.into_iter().for_each(|rule| {
            self.filters.add(&rule);
            self.insert(rule);
        });
        self.solve()?;

        Ok(count)
    }

    /// apply Sigma rules to an [`Event`], returning a list of rule IDs
    /// that match
    ///
    /// [`LogSource`] fields set in the [`Event`] act as a filter: `None` is a wildcard,
    /// and any field set in the [`Event`] must match the corresponding field in the
    /// [`LogSource`] for the rule to match
    ///
    /// [`LogSource`]: event/struct.LogSource.html
    /// [`Event`]: event/struct.Event.html
    ///
    /// ```rust
    /// # use std::error::Error;
    /// # use serde_json::json;
    /// # use sigmars::event::{Event, LogSource};
    /// # use sigmars::SigmaCollection;
    /// static RULES: &str = r#"
    /// title: test rule
    /// id: test-rule
    /// logsource:
    ///   category: test
    /// detection:
    ///   selection:
    ///     foo: bar
    ///   condition: selection
    /// ---
    /// title: test rule 2
    /// id: test-rule-2
    /// logsource:
    ///   category: nomatch
    /// detection:
    ///   selection:
    ///     foo: bar
    ///   condition: selection
    /// "#;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// let rules: SigmaCollection = RULES.parse()?;
    /// let event = Event::new(json!({"foo": "bar"}))
    ///            .logsource(LogSource::default().category("test"));
    /// let res = rules.get_detection_matches(&event);
    /// assert!(res.len() == 1);
    /// assert_eq!(res[0], "test-rule");
    /// # Ok(())
    /// # }
    ///
    pub fn get_detection_matches(&self, event: &Event) -> Vec<String> {
        self.get_detection_matches_from_ref(&event.into())
    }

    pub fn get_detection_matches_from_ref(&self, event: &RefEvent) -> Vec<String> {
        self.filters
            .filter(&event.logsource)
            .iter()
            .filter_map(|id| self.rules.get(id))
            .filter(|rule| {
                if let RuleType::Detection(ref d) = rule.rule {
                    d.is_match(&event.data)
                } else {
                    false
                }
            })
            .map(|rule| rule.id.clone())
            .collect()
    }

    /// apply all Sigma rules to an `Event`, returning a list of rule IDs
    /// that match, without filtering by `LogSource`
    ///
    /// ```rust
    /// # use std::error::Error;
    /// # use serde_json::json;
    /// # use sigmars::event::{Event, LogSource};
    /// # use sigmars::SigmaCollection;
    /// static RULES: &str = r#"
    /// title: test rule
    /// id: test-rule
    /// logsource:
    ///   category: test
    /// detection:
    ///   selection:
    ///     foo: bar
    ///   condition: selection
    /// ---
    /// title: test rule 2
    /// id: test-rule-2
    /// logsource:
    ///   category: nomatch
    /// detection:
    ///   selection:
    ///     foo: bar
    ///   condition: selection
    /// "#;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// let rules: SigmaCollection = RULES.parse()?;
    /// let event = Event::new(json!({"foo": "bar"}))
    ///            .logsource(LogSource::default().category("test"));
    /// let res = rules.get_detection_matches_unfiltered(&event);
    /// assert!(res.len() == 2);
    /// # Ok(())
    /// # }
    ///
    pub fn get_detection_matches_unfiltered(&self, event: &Event) -> Vec<String> {
        self.rules
            .values()
            .filter(|rule| {
                if let RuleType::Detection(ref d) = rule.rule {
                    d.is_match(&event.data)
                } else {
                    false
                }
            })
            .map(|rule| rule.id.clone())
            .collect()
    }

    /// Add a Sigma rule to the collection
    pub fn add(&mut self, rule: SigmaRule) -> Result<(), CollectionError> {
        self.insert(rule);
        self.solve()
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    // retrieve a Sigma rule by ID
    pub fn get(&self, id: &str) -> Option<&SigmaRule> {
        self.rules.get(id)
    }

    fn insert(&mut self, rule: SigmaRule) {
        if let Some(name) = rule.name.clone() {
            self.named.insert(name, rule.id.clone());
        }
        self.filters.add(&rule);
        self.rules.insert(rule.id.clone(), rule);
    }

    fn solve(&mut self) -> Result<(), CollectionError> {
        let mut graph = DependencyGraph::default();
        self.rules
            .iter()
            .map(|(id, rule)| -> Result<_, CollectionError> {
                if let RuleType::Correlation(ref corr) = rule.rule {
                    let _ = corr
                        .rules()
                        .iter()
                        .map(|dep| {
                            let dep = match self.named.get(dep) {
                                Some(id) => id,
                                None => dep,
                            };
                            if self.rules.contains_key(dep) {
                                Ok(dep)
                            } else {
                                Err(CollectionError::DependencyMissing(id.clone(), dep.clone()))
                            }
                        })
                        .collect::<Result<Vec<_>, _>>()?
                        .into_iter()
                        .map(|dep| graph.add_edge(dep, id))
                        .collect::<Result<Vec<_>, _>>()?;
                };
                Ok(())
            })
            .collect::<Result<Vec<_>, _>>()?;

        graph.sort()?;
        self.deps = graph;
        Ok(())
    }
}

#[cfg(all(feature = "correlation", feature = "tsink"))]
impl SigmaCollection {
    /// Initialize a `SigmaCollection` correlation rule backend
    /// ``` rust
    /// # use std::error::Error;
    /// # use serde_json::json;
    /// # use sigmars::event::{Event, LogSource};
    /// # use sigmars::SigmaCollection;
    /// # use sigmars::correlation::Backend;
    /// # use sigmars::correlation::backend::tsink::TSinkStore;
    /// # static RULES: &str = r#"
    /// # title: test rule
    /// # id: test-rule
    /// # logsource:
    /// #   category: test
    /// # detection:
    /// #   selection:
    /// #     foo: bar
    /// #   condition: selection
    /// # "#;
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn Error>> {
    /// let mut rules: SigmaCollection = RULES.parse()?;
    /// # Ok(())
    /// # }
    ///
    pub fn with_backend(&mut self) -> Result<()> {
        for rule in self.rules.values() {
            if let RuleType::Correlation(ref corr) = rule.rule {
                let engine = correlation::engine::CorrelationEngine::new(&corr);
                corr.inner.set_engine(Box::new(engine?))?;
            }
        }
        Ok(())
    }
}

impl SigmaCollection {
    pub fn matches(&self, event: &RefEvent) -> Result<Vec<String>, Box<dyn std::error::Error>> {
        let mut prior = self.get_detection_matches_from_ref(&event);
        let rules = self
            .deps
            .sorted
            .iter()
            .filter_map(|idx| {
                if prior.iter().filter_map(|r| self.deps.idx.get(r)).any(|n| {
                    petgraph::algo::has_path_connecting(&self.deps.graph, *n, *idx, None)
                        || n == idx
                }) {
                    Some(self.rules.get(&self.deps.graph[*idx])?)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        for rule in rules {
            if let RuleType::Correlation(ref correlation) = rule.rule {
                if correlation.matches(&event, &prior)? {
                    prior.push(rule.id.clone());
                }
            }
        }
        Ok(prior)
    }
}

impl TryFrom<Vec<SigmaRule>> for SigmaCollection {
    type Error = Box<dyn std::error::Error>;

    fn try_from(rules: Vec<SigmaRule>) -> Result<Self, Self::Error> {
        let mut ruleset = Self::default();
        rules.into_iter().for_each(|rule| ruleset.insert(rule));
        ruleset.solve()?;
        Ok(ruleset)
    }
}

impl Into<Vec<SigmaRule>> for SigmaCollection {
    fn into(self) -> Vec<SigmaRule> {
        self.rules.into_values().collect()
    }
}

impl std::str::FromStr for SigmaCollection {
    type Err = Box<dyn std::error::Error>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        serde_yaml::Deserializer::from_str(&s)
            .map(|de| SigmaRule::deserialize(de).map_err(|e| e.into()))
            .collect::<Result<Vec<_>, Self::Err>>()?
            .try_into()
    }
}

impl ToString for SigmaCollection {
    fn to_string(&self) -> String {
        self.rules
            .values()
            .filter_map(|rule| serde_yaml::to_string(rule).ok())
            .collect::<Vec<String>>()
            .join("---\n")
    }
}

impl Serialize for SigmaCollection {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let rules: Vec<&SigmaRule> = self.rules.values().collect();
        rules.serialize(serializer)
    }
}
