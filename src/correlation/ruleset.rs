use crate::{Event, RuleType, SigmaRule};
use petgraph::graph::{self, DiGraph, Graph};
use petgraph::Directed;
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct RuleSet {
    graph: Graph<Arc<SigmaRule>, (), Directed>,
    ruleidx: HashMap<String, graph::NodeIndex>,
}

impl RuleSet {
    pub async fn eval(&self, event: &Event, matched: &mut Vec<Arc<SigmaRule>>) {
        let candidates = self.graph.filter_map(
            |idx, rule| {
                matched
                    .iter()
                    .filter_map(|r| self.ruleidx.get(&r.id))
                    .any(|n| petgraph::algo::has_path_connecting(&self.graph, *n, idx, None) || n == &idx)
                    .then(|| rule)
            },
            |_, _| Some(()),
        );

        let sorted = petgraph::algo::toposort(&candidates, None)
        .map(|rules| {
            rules
                .into_iter()
                .map(|idx| &self.graph[idx])
                .filter_map(|rule| {
                    if let RuleType::Correlation(_) = rule.rule {
                        Some(rule)
                    } else { None }
                }).collect::<Vec<_>>()
            }).unwrap_or_default();

            for rule in sorted {
                if let RuleType::Correlation(correlation) = &rule.rule {
                    if correlation.eval(&event.data, matched).await {
                        matched.push(rule.clone());
                    }
                }
            }
    }
}

/*
impl Iterator for &RuleSet {
    type Item = Arc<SigmaRule>;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(idx) = self.graph.node_indices().next() {
            Some(self.graph[idx].clone())
        } else {
            None
        }
    }
}
*/
impl From<&RuleSet> for Vec<Arc<SigmaRule>> {
    fn from(ruleset: &RuleSet) -> Vec<Arc<SigmaRule>> {
        ruleset.graph.node_indices().map(|idx| ruleset.graph[idx].clone()).collect()
    }
}

impl From<Vec<Arc<SigmaRule>>> for RuleSet {
    fn from(rules: Vec<Arc<SigmaRule>>) -> Self {
        let mut graph = DiGraph::<Arc<SigmaRule>, ()>::new();

        let ruleidx = rules
            .iter()
            .map(|rule| (rule.id.clone(), graph.add_node(rule.clone())))
            .collect::<HashMap<_, _>>();

        // rules can declare their dependencies by name or id
        let rule_names = &rules
            .iter()
            .filter_map(|r| match r.name {
                Some(ref name) => Some((name.clone(), &r.id)),
                None => None,
            })
            .collect::<HashMap<_, _>>();

        rules.iter().for_each(|rule| match rule.rule {
            RuleType::Correlation(ref correlation) => {
                correlation
                    .dependencies()
                    .iter()
                    .filter_map(|dep| {
                        rule_names
                            .get(dep)
                            .and_then(|dep| ruleidx.get(*dep))
                            .or_else(|| ruleidx.get(dep))
                    })
                    .for_each(|dep| {
                        ruleidx
                            .get(&rule.id)
                            .and_then(|node| Some(graph.add_edge(*dep, *node, ())));
                    });
            }
            _ => {}
        });

        RuleSet { graph, ruleidx }
    }
}

impl From<Vec<&Arc<SigmaRule>>> for RuleSet {
    fn from(rules: Vec<&Arc<SigmaRule>>) -> Self {
        RuleSet::from(rules.into_iter().map(|r| r.clone()).collect::<Vec<_>>())
    }
}
