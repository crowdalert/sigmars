use serde_json::json;
use tokio::test;

//use super::collection::COLLECTION;
use crate::{collection::*, event::LogSource};
use std::collections::HashMap;

pub static COLLECTION: &str = r#"
title: event count detection
id: 0
description: event count detection
name: event_count_detection
date: 2023-06-16
logsource:
  category: correlation
detection:
  selection:
    foo: bar
  condition: selection
---
title: value count detection
id: 1
description: value count detection
name: value_count_detection
date: 2023-06-16
logsource:
  category: correlation
detection:
  selection:
    baz: quux
  condition: selection
---
title: event correlation
id: 2
description: event correlation
name: event_correlation
correlation:
    type: event_count
    rules:
        - "0"
    group-by:
        - correlation_group_by
    timespan: 10m
    condition:
        gte: 2
---
title: value correlation
id: 3
description: value correlation
name: value_correlation
correlation:
    type: value_count
    rules:
        - "1"
    group-by:
        - correlation_group_by
    timespan: 10m
    condition:
        field: correlation_field
        gte: 2
"#;

#[test(flavor = "multi_thread", worker_threads = 2)]
async fn test_event_count() {
    let mut backend = crate::correlation::state::mem::MemBackend::new().await;
    let mut collection: SigmaCollection = COLLECTION.parse().unwrap();
    collection.init(&mut backend).await;

    let event = crate::Event {
        data: json!({
                "foo": "bar",
                "correlation_group_by": "test"
            }
        ),
        ..Default::default()
    };

    let res = collection.get_matches(&event).await.unwrap();
    assert!(res.len() == 1);

    let res = collection.get_matches(&event).await.unwrap();
    assert!(res.len() == 2);
}

#[test(flavor = "multi_thread", worker_threads = 2)]
async fn test_event_count_no_matching_groupby() {
    let mut backend = crate::correlation::state::mem::MemBackend::new().await;
    let mut collection: SigmaCollection = COLLECTION.parse().unwrap();
    collection.init(&mut backend).await;

    let event = crate::Event {
        data: json!({
                "foo": "bar",
                "correlation_group_by": "test"
            }
        ),
        ..Default::default()
    };

    let res = collection.get_matches(&event).await.unwrap();
    assert!(res.len() == 1);

    let event = crate::Event {
        data: json!({
                "foo": "bar",
                "correlation_group_by": "test2"
            }
        ),
        ..Default::default()
    };

    let res = collection.get_matches(&event).await.unwrap();
    assert!(res.len() == 1);
}

#[test(flavor = "multi_thread", worker_threads = 1)]
async fn test_event_count_no_groupby() {
    
    let mut backend = crate::correlation::state::mem::MemBackend::new().await;
    let mut collection: SigmaCollection = COLLECTION.parse().unwrap();
    collection.init(&mut backend).await;

    let event = crate::Event {
        data: json!({
                "foo": "bar"
            }
        ),
        ..Default::default()
    };

    let res = collection.get_matches(&event).await.unwrap();
    assert!(res.len() == 1);

    let res = collection.get_matches(&event).await.unwrap();
    assert!(res.len() == 1);
}

#[test(flavor = "multi_thread", worker_threads = 2)]
async fn test_value_count() {
    let mut backend = crate::correlation::state::mem::MemBackend::new().await;
    let mut collection: SigmaCollection = COLLECTION.parse().unwrap();
    collection.init(&mut backend).await;

    let event = crate::Event {
        data: json!({
                "baz": "quux",
                "correlation_group_by": "test",
                "correlation_field": "first"
            }
        ),
        ..Default::default()
    };

    let res = collection.get_matches(&event).await.unwrap();
    assert!(res.len() == 1);

    let event = crate::Event {
        data: json!({
                "baz": "quux",
                "correlation_group_by": "test",
                "correlation_field": "second"
            }
        ),
        ..Default::default()
    };

    let res = collection.get_matches(&event).await.unwrap();

    assert!(res.len() == 2);
}

#[test(flavor = "multi_thread", worker_threads = 2)]
async fn test_value_count_unmatched_groupby() {
    let mut backend = crate::correlation::state::mem::MemBackend::new().await;
    let mut collection: SigmaCollection = COLLECTION.parse().unwrap();
    collection.init(&mut backend).await;

    let event = crate::Event {
        data: json!({
                "baz": "quux",
                "correlation_group_by": "first",
                "correlation_field": "first"
            }
        ),
        ..Default::default()
    };

    let res = collection.get_matches(&event).await.unwrap();
    assert!(res.len() == 1);

    let event = crate::Event {
        data: json!({
                "baz": "quux",
                "correlation_group_by": "second",
                "correlation_field": "second"
            }
        ),
        ..Default::default()
    };

    let res = collection.get_matches(&event).await.unwrap();

    assert!(res.len() == 1);
}


#[test(flavor = "multi_thread", worker_threads = 2)]
async fn test_temporal() {
    let rules = r#"
title: Temporal ordered final
id: ba5f2f8d-9446-4703-b29e-0b576d0b418a
description: Final rule
name: final
correlation:
    type: temporal
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
    let mut backend = crate::correlation::state::mem::MemBackend::new().await;
    let mut collection: SigmaCollection = rules.parse().unwrap();
    collection.init(&mut backend).await;

    let firstevent = crate::Event {
        logsource: LogSource::default(),
        metadata: HashMap::new(),
        data: json!({
                "test": "yes",
                "first": "firstvalue"
            }
        ),
    };

    let res = collection.get_matches(&firstevent).await.unwrap();
    assert!(res.len() == 1);

    let secondevent = crate::Event {
        logsource: LogSource::default(),
        metadata: HashMap::new(),
        data: json!({
                "test": "yes",
                "second": "secondvalue"
            }
        ),
    };

    let res = collection.get_matches(&secondevent).await.unwrap();
    assert!(res.len() == 2);

    let mut collection: SigmaCollection = rules.parse().unwrap();
    let mut backend = crate::correlation::state::mem::MemBackend::new().await;
    collection.init(&mut backend).await;

    let res = collection.get_matches(&secondevent).await.unwrap();
    assert!(res.len() == 1);

    let res = collection.get_matches(&firstevent).await.unwrap();
    assert!(
        res.len() == 2,
        "out-of-order events should match temporal correlations"
    );
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
    let mut backend = crate::correlation::state::mem::MemBackend::new().await;
    let mut collection: SigmaCollection = rules.parse().unwrap();
    collection.init(&mut backend).await;

    let firstevent = crate::Event {
        logsource: LogSource::default(),
        metadata: HashMap::new(),
        data: json!({
                "test": "yes",
                "first": "firstvalue"
            }
        ),
    };

    let res = collection.get_matches(&firstevent).await.unwrap();
    assert!(res.len() == 1);

    let secondevent = crate::Event {
        logsource: LogSource::default(),
        metadata: HashMap::new(),
        data: json!({
                "test": "yes",
                "second": "secondvalue"
            }
        ),
    };

    let res = collection.get_matches(&secondevent).await.unwrap();
    assert!(res.len() == 2);

    let mut collection: SigmaCollection = rules.parse().unwrap();
    let mut backend = crate::correlation::state::mem::MemBackend::new().await;
    collection.init(&mut backend).await;

    let res = collection.get_matches(&secondevent).await.unwrap();
    assert!(res.len() == 1);

    let res = collection.get_matches(&firstevent).await.unwrap();
    assert!(
        res.len() == 1,
        "out-of-order events should not match temporal ordered correlations"
    );
}
