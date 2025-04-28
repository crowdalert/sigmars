use std::collections::HashSet;

use super::{
    serde::{ConditionOrList, Correlation, CorrelationRule, CorrelationType},
    state,
};
use crate::event::RefEvent;

impl Correlation {
    async fn is_match(
        &self,
        event: &RefEvent<'_>,
        prior: &Vec<String>,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        let hashed = prior.iter().map(|r| r).collect::<HashSet<_>>();

        // The sigma sepecification does not define matching behaviour for empty group_by fields
        // So we assume that the rule does not match if the group_by field is empty
        let Ok(group_by) = self
            .group_by
            .iter()
            .map(|k| Ok((k.clone(), event.data.get(k).ok_or_else(|| ())?.clone())))
            .collect::<Result<Vec<_>, ()>>()
        else {
            return Ok(false);
        };

        let state = self.state.get().ok_or_else(|| "state not initialized")?;

        Ok(match self.correlation_type {
            CorrelationType::EventCount(ref c) => {

                if !self.rules.iter().all(|d| hashed.contains(d)) {
                    return Ok(false);
                };
                let count = state.incr(&state::Key::EventCount(group_by)).await as i64;
                match &c.condition {
                    ConditionOrList::Condition(c) => c.is_match(count),
                    ConditionOrList::List(conditions) => conditions.iter().all(|c| c.is_match(count)),
                }
            },
            CorrelationType::ValueCount(ref c) => {

                if !self.rules.iter().all(|d| hashed.contains(d)) {
                    return Ok(false);
                };
                if let Some(field_value) = event.data.get(&c.condition.field) {
                    let count = state.incr(
                    &state::Key::ValueCount(
                        group_by,
                        format!("{}:{}", c.condition.field, field_value),
                    )).await as i64;
                    c.condition.condition.is_match(count)
                } else { false }
            },
            CorrelationType::Temporal => {
                let mut ret = true;
                for r in self
                .rules
                .iter()
                .map(|r| async {
                    if hashed.contains(r) {
                        state.incr(&state::Key::ValueCount(group_by.clone(), r.clone())).await
                    } else { 
                        state.count(&state::Key::ValueCount(group_by.clone(), r.clone())).await
                    }
                })
                .collect::<Vec<_>>() {
                    if r.await == 0 {
                        ret = false;
                    }
                }
                ret
            },
            CorrelationType::TemporalOrdered => {
                for r in self
                .rules
                .iter()
                .map(|r| async {
                    if hashed.contains(r) {
                        state.incr(&state::Key::ValueCount(group_by.clone(), r.clone())).await
                    } else { 
                        state.count(&state::Key::ValueCount(group_by.clone(), r.clone())).await
                    }
                })
                .collect::<Vec<_>>() {
                    if r.await == 0 {
                        return Ok(false);
                    }
                }
                true
            }
        })
    }
}

impl CorrelationRule {
    pub fn id(&self) -> &String {
        &self.inner.id
    }

    pub fn rules(&self) -> &Vec<String> {
        &self.inner.rules
    }

    pub async fn is_match(
        &self,
        event: &RefEvent<'_>,
        prior: &Vec<String>,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        self.inner.is_match(event, prior).await
    }
}
