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

#[test(flavor = "multi_thread", worker_threads = 2)]
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

#[test(flavor = "multi_thread", worker_threads = 2)]
async fn test_temporal() {
    let collection: SigmaCollection = COLLECTION.parse().unwrap();
    collection.init_correlation().await.unwrap();

    let firstevent = crate::Event {
        metadata: HashMap::new(),
        data: json!({
            "EventID": 7045,
            "ServiceName": "Google Update",
            "Host": "test"
            }
        ),
    };

    let res = collection.eval_correlation(&firstevent, None).await;
    assert!(res.len() == 1);

    let secondevent = crate::Event {
        metadata: HashMap::new(),
        data: json!({
                "Image": "C:\\Program Files(x86)\\Google\\GoogleUpdate.exe",
                "Host": "test"
            }
        ),
    };

    let res = collection.eval_correlation(&secondevent, None).await;
    assert!(res.len() == 2);


    let collection: SigmaCollection = COLLECTION.parse().unwrap();
    collection.init_correlation().await.unwrap();

    let res = collection.eval_correlation(&secondevent, None).await;
    assert!(res.len() == 1);

    let res = collection.eval_correlation(&firstevent, None).await;
    assert!(res.len() == 2, "order of events does not matter in temporal correlations");
}

#[test(flavor = "multi_thread", worker_threads = 2)]
async fn test_temporal_ordered() {
    let rules = r#"
title: Temporal ordered final
id: ba5f2f8d-9446-4703-b29e-0b576d0b418a
description: Final rule
name: final
correlation:
    type: temporal_ordered
    rules:
        - 8ff4fb25-c92c-475e-a3d7-3b13c0b879cf
        - 36b4c55f-fe9b-4454-858d-7ce8a38f6126
    group-by:
        - test
    timespan: 10m
---
title: Temporal ordered second
id: 36b4c55f-fe9b-4454-858d-7ce8a38f6126
description: second rule
name: second
logsource:
    category: test
detection:
    selection:
        second: secondvalue
    condition: selection
---
title: Temporal ordered first
id: 8ff4fb25-c92c-475e-a3d7-3b13c0b879cf
description: first rule
name: first
logsource:
    category: test
detection:
    selection:
        first: firstvalue
    condition: selection
"#;
    let collection: SigmaCollection = rules.parse().unwrap();
    collection.init_correlation().await.unwrap();

    let firstevent = crate::Event {
        metadata: HashMap::new(),
        data: json!({
                "test": "yes",
                "first": "firstvalue"
            }
        ),
    };

    let res = collection.eval_correlation(&firstevent, None).await;
    assert!(res.len() == 1);

    let secondevent = crate::Event {
        metadata: HashMap::new(),
        data: json!({
                "test": "yes",
                "second": "secondvalue"
            }
        ),
    };

    let res = collection.eval_correlation(&secondevent, None).await;
    assert!(res.len() == 2);

    let collection: SigmaCollection = rules.parse().unwrap();
    collection.init_correlation().await.unwrap();

    let res = collection.eval_correlation(&secondevent, None).await;
    assert!(res.len() == 1);

    let res = collection.eval_correlation(&firstevent, None).await;
    assert!(res.len() == 1, "out-of-order events should not match temporal correlations");

}
