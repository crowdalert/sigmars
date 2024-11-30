use std::collections::HashMap;

use crate::collection::*;

pub static COLLECTION: &str = r#"
title: Correlation - Multiple Failed Logins Followed by Successful Login
id: b180ead8-d58f-40b2-ae54-c8940995b9b6
status: experimental
description: Detects multiple failed logins by a single user followed by a successful login of that user
references:
    - https://reference.com
author: Florian Roth (Nextron Systems)
date: 2023-06-16
correlation:
    type: temporal_ordered
    rules:
        - a8418a5a-5fc4-46b5-b23b-6c73beb19d41
        - successful_login
    group-by:
        - User
    timespan: 10m
falsepositives:
    - Unlikely
level: high
---
title: Multiple failed logons
id: a8418a5a-5fc4-46b5-b23b-6c73beb19d41
description: Detects multiple failed logins within a certain amount of time
name: multiple_failed_login
correlation:
    type: event_count
    rules:
        - 53ba33fd-3a50-4468-a5ef-c583635cfa92
    group-by:
        - User
    timespan: 10m
    condition:
        gte: 2
---
title: Single failed login
id: 53ba33fd-3a50-4468-a5ef-c583635cfa92
name: failed_login
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID:
            - 529
            - 4625
    condition: selection
---
title: Successful login
id: 4d0a2c83-c62c-4ed4-b475-c7e23a9269b8
description: Detects a successful login
name: successful_login
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID:
            - 528
            - 4624
    condition: selection"#;

#[test]
fn test_collection() {
    let collection: SigmaCollection = COLLECTION.parse().unwrap();
    assert!(collection.len() == 4);
}
#[test]
fn test_filtered_match() {
    let collection: SigmaCollection = COLLECTION.parse().unwrap();

    let log = serde_json::json!({
        "EventID": 4624,
        "User": "test"});

    let event = crate::Event {
        metadata: HashMap::from([(
            "logsource".to_string(),
            serde_json::json!({"product": "windows"}),
        )]),
        data: log,
    };
    let res = collection.eval(&event);
    assert!(res.len() == 1);
}

#[test]
fn test_filtered_no_match() {
    let collection: SigmaCollection = COLLECTION.parse().unwrap();

    let log = serde_json::json!({
        "EventID": 4624,
        "User": "test"});

    let event = crate::Event {
        metadata: HashMap::from([(
            "logsource".to_string(),
            serde_json::json!({"product": "linux"}),
        )]),
        data: log,
    };
    let res = collection.eval(&event);
    assert!(res.len() == 0);
}

#[test]
fn test_filter_without_metadata() {
    let collection: SigmaCollection = COLLECTION.parse().unwrap();

    let log = serde_json::json!({
        "EventID": 4624,
        "User": "test"});

    let event = crate::Event {
        metadata: HashMap::new(),
        data: log,
    };
    let res = collection.eval(&event);
    assert!(res.len() == 1);
}

#[test]
fn test_filter_without_filters() {
    let collection: SigmaCollection = r#"
        title: Successful login
        id: 4d0a2c83-c62c-4ed4-b475-c7e23a9269b8
        description: Detects a successful login
        name: successful_login
        logsource:
            category: something
        detection:
            selection:
                EventID:
                    - 528
                    - 4624
            condition: selection"#
        .parse()
        .unwrap();

    let log = serde_json::json!({
        "EventID": 4624,
        "User": "test"});

    let event = crate::Event {
        metadata: HashMap::from([(
            "logsource".to_string(),
            serde_json::json!({"product": "windows"}),
        )]),
        data: log,
    };
    let res = collection.eval(&event);
    assert!(res.len() == 1);
}
