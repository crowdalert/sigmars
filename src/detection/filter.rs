use std::collections::{HashMap, HashSet};

use crate::{event::LogSource, rule::{RuleType, SigmaRule}};

#[derive(Debug, Default)]
pub struct Filter {
    category: HashMap<Option<String>, HashSet<String>>,
    product: HashMap<Option<String>, HashSet<String>>,
    service: HashMap<Option<String>, HashSet<String>>,

    all: HashSet<String>,
}

impl Filter {
    pub fn add(&mut self, rule: &SigmaRule) {
        let RuleType::Detection(detection) = &rule.rule else {
            return;
        };

        self.category
            .entry(detection.logsource.category.clone())
            .or_insert_with(|| HashSet::new())
            .insert(rule.id.clone());

        self.product
            .entry(detection.logsource.product.clone())
            .or_insert_with(|| HashSet::new())
            .insert(rule.id.clone());

        self.service
            .entry(detection.logsource.service.clone())
            .or_insert_with(|| HashSet::new())
            .insert(rule.id.clone());

        self.all.insert(rule.id.clone());
    }

    pub fn filter(&self, target: &LogSource) -> Vec<String> {
        let empty = HashSet::new();
        let all = self.all.iter().collect::<HashSet<_>>();

        let category = match target.category {
            Some(_) => &self
                .category
                .get(&target.category)
                .unwrap_or_else(|| &empty)
                .union(self.category.get(&None).unwrap_or_else(|| &empty))
                .collect::<HashSet<_>>(),
            None => &all,
        };

        let product = match target.product {
            Some(_) => &self
                .product
                .get(&target.product)
                .unwrap_or_else(|| &empty)
                .union(self.product.get(&None).unwrap_or_else(|| &empty))
                .collect::<HashSet<_>>(),
            None => &all,
        };

        let service = match target.service {
            Some(_) => &self
                .service
                .get(&target.service)
                .unwrap_or_else(|| &empty)
                .union(self.service.get(&None).unwrap_or_else(|| &empty))
                .collect::<HashSet<_>>(),
            None => &all,
        };

        all.intersection(&category)
            .map(|r| *r)
            .collect::<HashSet<_>>()
            .intersection(&product)
            .map(|r| *r)
            .collect::<HashSet<_>>()
            .intersection(&service)
            .map(|r| *r)
            .cloned()
            .collect()
    }
}
