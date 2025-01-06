use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;


/// Encapsulates log source information from the Sigma
/// taxonomy
/// 
/// implements `From<serde_json::Value>` using
/// the "category", "product", and "service" top level
/// fields with `String` values (if present).
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct LogSource {
    pub category: Option<String>,
    pub product: Option<String>,
    pub service: Option<String>,
    /// Additional log source information
    #[serde(flatten)]
    pub extra: HashMap<String, String>,
}

/// Encapsulates data for a log event
/// 
/// includes log source (used to filter Sigma rules),
/// and additional metadata that can be used for enrichment
/// 
/// Implements `From<serde_json::Value>` for easy
/// construction from JSON.
/// 
/// ```rust
/// # use std::error::Error;
/// # use serde_json::{json, Value};
/// # use sigmars::{Event, LogSource};
/// # fn main() -> Result<(), Box<dyn Error>> {
/// #
///  let event: Event = Event::new(json!({"foo": "bar"}))
///                     .with_logsource(LogSource::default()); // logsource is optional
///
///  assert_eq!(event.data.get("foo").unwrap(), &json!("bar"));
/// 
/// // from JSON
///  let mut event: Event = json!({"foo": "bar"}).into();
///  event.logsource = LogSource { category: Some("linux".to_string()), ..Default::default() };
/// 
///  // logsource can also be constructed from JSON
///  let mut event: Event = json!({"foo": "bar"}).into();
///  event.logsource = json!({ "category": "linux" }).into();
///  assert_eq!(event.logsource.category, Some("linux".to_string()));
/// 
///  // metadata can be added to the event
///  event.metadata.insert("environment".to_string(), json!("prod"));
///  assert_eq!(event.metadata.get("environment"), Some(&json!("prod")));
/// 
/// #   Ok(())
/// # }
/// ```
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

impl From<Value> for LogSource {
    fn from(value: Value) -> Self {
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
