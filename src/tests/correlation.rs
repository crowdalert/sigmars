use serde_json::json;
use tokio::test;

use super::collection::COLLECTION;
use crate::collection::*;
use std::collections::HashMap;

#[test(flavor = "multi_thread", worker_threads = 2)]
async fn test_event_count() {
    let collection: SigmaCollection = COLLECTION.parse().unwrap();
    collection.init_correlation().await.unwrap();

    let event = crate::Event {
        metadata: HashMap::new(),
        data: json!({
                "EventID": 4625,
                "User": "test"
            }
        ),
    };

    let res = collection.eval_correlation(&event, None).await;
    assert!(res.len() == 1);

    let res = collection.eval_correlation(&event, None).await;
    assert!(res.len() == 2);
}

#[test]//(flavor = "multi_thread", worker_threads = 2)]
async fn test_event_count_no_matching_groupby() {
    let collection: SigmaCollection = COLLECTION.parse().unwrap();
    collection.init_correlation().await.unwrap();

    let event = crate::Event {
        metadata: HashMap::new(),
        data: json!({
                "EventID": 4625,
                "User": "test"
            }
        ),
    };

    let res = collection.eval_correlation(&event, None).await;
    assert!(res.len() == 1);

    let event = crate::Event {
        metadata: HashMap::new(),
        data: json!({
                "EventID": 4625,
                "User": "test2"
            }
        ),
    };

    let res = collection.eval_correlation(&event, None).await;
    assert!(res.len() == 1);
}

#[test(flavor = "multi_thread", worker_threads = 1)]
async fn test_event_count_no_groupby() {
    let collection: SigmaCollection = COLLECTION.parse().unwrap();
    collection.init_correlation().await.unwrap();

    let event = crate::Event {
        metadata: HashMap::new(),
        data: json!({
                "EventID": 4625
            }
        ),
    };

    let res = collection.eval_correlation(&event, None).await;
    assert!(res.len() == 1);

    let res = collection.eval_correlation(&event, None).await;
    assert!(res.len() == 1);
}

#[test(flavor = "multi_thread", worker_threads = 2)]
async fn test_value_count() {
    let collection: SigmaCollection = COLLECTION.parse().unwrap();
    collection.init_correlation().await.unwrap();

    let event = crate::Event {
        metadata: HashMap::new(),
        data: json!({
                "EventID": 4625,
                "User": "test",
                "Host": "test"
            }
        ),
    };

    let res = collection.eval_correlation(&event, None).await;
    assert!(res.len() == 1);

    let event = crate::Event {
        metadata: HashMap::new(),
        data: json!({
                "EventID": 4625,
                "User": "test2",
                "Host": "test"
            }
        ),
    };

    let res = collection.eval_correlation(&event, None).await;
    assert!(res.len() == 2);
}

#[test(flavor = "multi_thread", worker_threads = 2)]
async fn test_value_count_unmatched_groupby() {
    let collection: SigmaCollection = COLLECTION.parse().unwrap();
    collection.init_correlation().await.unwrap();

    let event = crate::Event {
        metadata: HashMap::new(),
        data: json!({
                "EventID": 4625,
                "User": "test",
                "Host": "test"
            }
        ),
    };

    let res = collection.eval_correlation(&event, None).await;
    assert!(res.len() == 1);

    let event = crate::Event {
        metadata: HashMap::new(),
        data: json!({
                "EventID": 4625,
                "User": "test2",
                "Host": "test2"
            }
        ),
    };

    let res = collection.eval_correlation(&event, None).await;

    assert!(res.len() == 1);
}
