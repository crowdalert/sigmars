use super::rule::Rule;
use glob;
use std::collections::{HashMap, HashSet};

use crate::event::Event;

#[derive(Debug, Default)]
struct LogSource {
    category: HashMap<Option<String>, HashSet<String>>,
    product: HashMap<Option<String>, HashSet<String>>,
    service: HashMap<Option<String>, HashSet<String>>,
    extra: HashMap<String, HashMap<Option<String>, HashSet<String>>>,
}

impl LogSource {
    fn extend(&mut self, other: LogSource) {
        self.category.extend(other.category);
        self.product.extend(other.product);
        self.service.extend(other.service);
    }

    fn get(&self, key: &str) -> Option<&HashMap<Option<String>, HashSet<String>>> {
        match key {
            "category" => Some(&self.category),
            "product" => Some(&self.product),
            "service" => Some(&self.service),
            k => self.extra.get(k),
        }
    }
}

#[derive(Debug, Default)]
pub struct SigmaCollection {
    rules: HashMap<String, Rule>,
    logsource: LogSource,
}

impl SigmaCollection {
    pub fn load_ruleset(&mut self, path: &str) -> Result<usize, Box<dyn std::error::Error>> {
        let rules = glob::glob(format!("{}/**/*.yml", path).as_str())?
            .filter_map(Result::ok)
            .into_iter()
            .filter_map(|entry| {
                std::fs::read_to_string(&entry)
                    .map_err(|e| {
                        eprintln!("error reading file: {}", e);
                        e
                    })
                    .ok()
                    .and_then(|s| {
                        serde_yml::from_str::<Rule>(s.as_str())
                            .map_err(|e| {
                                eprintln!(
                                    "error parsing rule: {} ({})",
                                    entry.to_string_lossy(),
                                    e
                                );
                                e
                            })
                            .ok()
                    })
            })
            .map(|rule| (rule.id.clone(), rule))
            .collect::<HashMap<String, Rule>>();

        rules.values().for_each(|rule| {
            self.logsource
                .category
                .entry(rule.logsource.category.clone())
                .or_insert_with(|| HashSet::new())
                .insert(rule.id.clone());

            self.logsource
                .product
                .entry(rule.logsource.product.clone())
                .or_insert_with(|| HashSet::new())
                .insert(rule.id.clone());

            self.logsource
                .service
                .entry(rule.logsource.service.clone())
                .or_insert_with(|| HashSet::new())
                .insert(rule.id.clone());
        });

        let additions = rules.len();

        self.rules.extend(rules);

        Ok(additions)
    }

    pub fn extend(&mut self, other: SigmaCollection) {
        self.rules.extend(other.rules);
        self.logsource.extend(other.logsource);
    }

    pub fn eval<'a>(&'a self, event: &'a Event) -> Vec<&'a Rule> {
        /*
         * evaluates a filtered ruleset against an Event with metadata
         * using the 'logsource' taxonomy to filter the ruleset
         */
        let filters = event
            .metadata
            .get("logsource")
            .map(|logsource| {
                logsource
                    .as_object()
                    .map(|logsource| {
                        logsource
                            .iter()
                            .filter_map(|(k, v)| {
                                v.as_str().and_then(|taxonomy| Some((k.clone(), taxonomy)))
                            })
                            .collect::<HashMap<String, &str>>()
                    })
                    .unwrap_or_default()
            })
            .unwrap_or_default();

        let mut rules: HashSet<&String> = self.rules.keys().collect();

        filters
            .iter()
            .for_each(|(k, v)| match self.logsource.get(k) {
                Some(filter) => {
                    filter.get(&Some(v.to_string())).map(|f| {
                        rules.retain(|r| f.contains(*r));
                    });
                }
                _ => {}
            });

        rules
            .into_iter()
            .filter_map(|rule| {
                self.rules
                    .get(rule)
                    .and_then(|r| if r.eval(&event.data) { Some(r) } else { None })
            })
            .collect()
    }

    pub fn eval_json<'a>(&'a self, log: &'a serde_json::Value) -> Vec<&'a Rule> {
        self.rules.values().filter(|rule| rule.eval(log)).collect()
    }
}
