use super::LogSource;
use crate::{Eval, Event, RuleType, SigmaRule};
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

#[derive(Debug, Default)]
pub struct RuleSet {
    category: HashMap<Option<String>, HashSet<Arc<SigmaRule>>>,
    product: HashMap<Option<String>, HashSet<Arc<SigmaRule>>>,
    service: HashMap<Option<String>, HashSet<Arc<SigmaRule>>>,

    all: HashSet<Arc<SigmaRule>>,
}

impl RuleSet {
    pub fn insert(&mut self, rule: &Arc<SigmaRule>) {
        if let RuleType::Detection(detection) = &rule.rule {
            self.category
                .entry(detection.logsource.category.clone())
                .or_insert_with(|| HashSet::new())
                .insert(rule.clone());

            self.product
                .entry(detection.logsource.product.clone())
                .or_insert_with(|| HashSet::new())
                .insert(rule.clone());

            self.service
                .entry(detection.logsource.service.clone())
                .or_insert_with(|| HashSet::new())
                .insert(rule.clone());

            self.all.insert(rule.clone());
        };
    }

    pub fn logsource_filtered_rules(&self, target: &LogSource) -> Vec<Arc<SigmaRule>> {
        let empty = HashSet::new();
        self.category
            .get(&target.category)
            .unwrap_or_else(|| {
                if target.category.is_some() {
                    self.category.get(&None).unwrap_or(&empty)
                } else {
                    &self.all
                }
            })
            .intersection(self.product.get(&target.product).unwrap_or_else(|| {
                if target.product.is_some() {
                    self.product.get(&None).unwrap_or(&empty)
                } else {
                    &self.all
                }
            }))
            .collect::<HashSet<_>>()
            .intersection(
                &self
                    .service
                    .get(&target.service)
                    .unwrap_or_else(|| {
                        if target.service.is_some() {
                            self.service.get(&None).unwrap_or(&empty)
                        } else {
                            &self.all
                        }
                    })
                    .iter()
                    .collect::<HashSet<_>>(),
            )
            .map(|r| (*r).clone())
            .collect::<Vec<_>>()
    }

    pub fn eval(&self, event: &Event) -> Vec<Arc<SigmaRule>> {
        let filters: LogSource = event
            .metadata
            .get("logsource")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_default();

        self.logsource_filtered_rules(&filters)
            .iter()
            .filter_map(|r| (*r).eval(&event.data, None).then(|| r.clone()))
            .collect::<Vec<_>>()
    }
}

impl From<Vec<&Arc<SigmaRule>>> for RuleSet {
    fn from(rules: Vec<&Arc<SigmaRule>>) -> Self {
        let mut filter = RuleSet::default();
        rules.into_iter().for_each(|rule| filter.insert(rule));
        filter
    }
}
