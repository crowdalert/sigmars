use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use uuid::Uuid;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Event {
    pub id: Uuid,
    pub data: Value,
    pub metadata: HashMap<String, Value>,
}

impl Event {
    pub fn new(data: Value, metadata: HashMap<String, Value>) -> Self {
        Self {
            id: Uuid::new_v4(),
            data,
            metadata,
        }
    }
}
