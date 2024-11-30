
use crate::collection::*;
use super::collection::COLLECTION;
use std::collections::HashMap;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_correlation() {
    let collection: SigmaCollection = COLLECTION.parse().unwrap();
    collection.init_correlation().await.unwrap();

    let log = serde_json::json!({
        "EventID": 4625,
        "User": "test"});

    let event = crate::Event {
        metadata: HashMap::from([(
            "logsource".to_string(),
            serde_json::json!({"product": "windows"}),
        )]),
        data: log,
    };
    let res = collection.eval_correlation(&event, None).await;
    assert!(res.len() == 1);

    let res = collection.eval_correlation(&event, None).await;
    assert!(res.len() == 2);
}
