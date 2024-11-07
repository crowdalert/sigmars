use super::condition::Condition;
use super::selection;
use std::collections::HashMap;

#[derive(Debug)]
pub struct Detection {
    selections: HashMap<String, selection::Selection>,
    condition: Condition,
}

impl Detection {
    pub fn new(detection: &serde_yml::Value) -> Result<Self, Box<dyn std::error::Error>> {
        let mut detection = detection.clone();
        let rules = detection
            .as_mapping_mut()
            .ok_or_else(|| "invalid detection")?;

        let condition = rules
            .remove("condition")
            .ok_or_else(|| "invalid detection")?
            .as_str()
            .ok_or_else(|| "invalid detection")?
            .to_string();

        let selections: HashMap<String, selection::Selection> = rules
            .iter()
            .map(|(key, value)| {
                let key = key.as_str().ok_or_else(|| "invalid detection")?.to_string();
                let selection = selection::Selection::new(value)?;
                Ok((key, selection))
            })
            .collect::<Result<HashMap<String, selection::Selection>, Box<dyn std::error::Error>>>(
            )?;

        Ok(Detection {
            selections,
            condition: Condition::new(&condition)?,
        })
    }

    pub fn eval(&self, log: &serde_json::Value) -> bool {
        let results = self
            .selections
            .iter()
            .map(|(key, selection)| (key, selection.eval(log)))
            .collect::<HashMap<&String, bool>>();
        self.condition.eval(&results)
    }
}
