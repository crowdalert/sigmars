use super::serde::CorrelationRule;

use crate::event::RefEvent;
use anyhow::Result;

impl CorrelationRule {
    pub fn id(&self) -> &String {
        &self.inner.id
    }
    pub fn rules(&self) -> &Vec<String> {
        &self.inner.rules
    }
    pub fn matches(&self, event: &RefEvent<'_>, prior: &Vec<String>) -> Result<bool> {
        if let Some(engine) = self.inner.state.get() {
            engine.matches(event, prior)
        } else {
            Err(anyhow::anyhow!("correlation engine not initialized"))
        }
    }
}
