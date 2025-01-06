use crate::detection::filter::Filter;
use crate::{correlation, event::Event};

use petgraph::{graph, Directed, Graph};
use serde::Deserialize;
use std::{collections::HashMap, str::FromStr};
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

    pub fn new_from_dir(path: &str) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let mut collection = Self::default();
        collection.load_from_dir(path)?;
        Ok(collection)
    }

    pub fn load_from_dir(
        &mut self,
        path: &str,
    ) -> Result<u32, Box<dyn std::error::Error + Send + Sync>> {
        let newrules: Vec<SigmaRule> = glob::glob(format!("{}/**/*.yml", path).as_str())?
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .map(|entry| std::fs::read_to_string(&entry))
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .map(|s| {
                s.parse::<SigmaCollection>()
                    .map(|r| Into::<Vec<SigmaRule>>::into(r))
                    .map_err(|e| CollectionError::ParseError(e.to_string()))
            })
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .flatten()
            .collect();

        let count = newrules.len() as u32;
        newrules.into_iter().for_each(|rule| {
            self.filters.add(&rule);
            self.insert(rule);
        });
        self.solve()?;

        Ok(count)
    }

    pub fn add(&mut self, rule: SigmaRule) -> Result<(), CollectionError> {
        self.insert(rule);
        self.solve()
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn get(&self, id: &str) -> Option<&SigmaRule> {
        self.rules.get(id)
    }

    pub fn get_detection_matches(&self, event: &Event) -> Vec<String> {
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

    fn insert(&mut self, rule: SigmaRule) {
        if let Some(name) = rule.name.clone() {
            self.named.insert(name, rule.id.clone());
        }
        self.filters.add(&rule);
        self.rules.insert(rule.id.clone(), rule);
    }

    fn solve(&mut self) -> Result<(), CollectionError> {
        let mut graph = DependencyGraph::default();
        self.rules.iter().map(|(id, rule)| -> Result<_, CollectionError> {
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

#[cfg(feature = "correlation")]
impl SigmaCollection {
    pub async fn init(&mut self, backend: &mut impl correlation::Backend) {
        for rule in self.rules.values_mut() {
            if let RuleType::Correlation(ref mut corr) = rule.rule {
                backend.register(corr).await.unwrap();
            }
        }
    }

    pub async fn push_correlation_matches(
        &self,
        event: &Event,
        prior: &mut Vec<String>,
    ) -> Result<(), Box<dyn std::error::Error>> {
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
                if correlation.is_match(event, prior).await? {
                    prior.push(rule.id.clone());
                }
            }
        }
        Ok(())
    }

    pub async fn get_matches_unfiltered(
        &self,
        event: &Event,
    ) -> Result<Vec<String>, Box<dyn std::error::Error>> {
        let mut prior = self.get_detection_matches_unfiltered(event);
        self.push_correlation_matches(event, &mut prior).await?;
        Ok(prior)
    }

    pub async fn get_matches(
        &self,
        event: &Event,
    ) -> Result<Vec<String>, Box<dyn std::error::Error>> {
        let mut prior = self.get_detection_matches(event);
        self.push_correlation_matches(event, &mut prior).await?;
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

impl FromStr for SigmaCollection {
    type Err = Box<dyn std::error::Error>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        serde_yml::Deserializer::from_str(&s)
            .map(|de| SigmaRule::deserialize(de).map_err(|e| e.into()))
            .collect::<Result<Vec<_>, Self::Err>>()?
            .try_into()
    }
}

impl ToString for SigmaCollection {
    fn to_string(&self) -> String {
        self.rules
            .values()
            .filter_map(|rule| serde_yml::to_string(rule).ok())
            .collect::<Vec<String>>()
            .join("---\n")
    }
}
