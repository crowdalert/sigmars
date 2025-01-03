use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct LogSource {
    pub category: Option<String>,
    pub product: Option<String>,
    pub service: Option<String>,
    /// Additional log source information
    #[serde(flatten)]
    pub(crate) extra: HashMap<String, String>,
}

#[derive(Clone, Debug, Default)]
pub struct Event {
    pub data: Value,
    pub logsource: LogSource,
    pub metadata: HashMap<String, Value>,
}

impl From<&Value> for LogSource {
    fn from(value: &Value) -> Self {
        let mut logsource = LogSource::default();
        if let Some(category) = value.get("category") {
            logsource.category = category.as_str().map(|s| s.to_string());
        }
        if let Some(product) = value.get("product") {
            logsource.product = product.as_str().map(|s| s.to_string());
        }
        if let Some(service) = value.get("service") {
            logsource.service = service.as_str().map(|s| s.to_string());
        }
        logsource
    }
}

impl Event {
    pub fn new(data: Value) -> Self {
        Event {
            data,
            ..Default::default()
        }
    }
    pub fn with_logsource(mut self, logsource: LogSource) -> Self {
        self.logsource = logsource;
        self
    }
    pub fn with_metadata(mut self, metadata: HashMap<String, Value>) -> Self {
        self.metadata = metadata;
        self
    }
}

impl From<Value> for Event {
    fn from(data: Value) -> Self {
        Event {
            data,
            ..Default::default()
        }
    }
}
