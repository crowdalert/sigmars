use serde_json::Value;
use std::collections::HashMap;

#[derive(Clone, Debug, Default)]
pub struct Event {
    pub data: Value,
    pub metadata: HashMap<String, Value>,
}
