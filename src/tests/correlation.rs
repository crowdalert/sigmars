use serde_json::json;
use std::time::Duration;

use crate::{
    collection::SigmaCollection,
    correlation::{
        backend::{tsink::TSinkStore, CorrelationStore},
        engine::CorrelationEngine,
        CorrelationRule,
    },
    event::Event,
    rule::SigmaRule,
};

// ============================================================================
// PARSING TESTS
// ============================================================================

#[test]
fn test_parse_event_count_rule() {
    let rule = r#"
title: Event Count Correlation
id: test-event-count
description: Tests event count correlation parsing
correlation:
    type: event_count
    rules:
        - rule-1
        - rule-2
    group-by:
        - host
    timespan: 5m
    condition:
        gte: 3
"#;
    let parsed: SigmaRule = serde_yaml::from_str(rule).unwrap();
    assert_eq!(parsed.id, "test-event-count");
}

#[test]
fn test_parse_value_count_rule() {
    let rule = r#"
title: Value Count Correlation
id: test-value-count
description: Tests value count correlation parsing
correlation:
    type: value_count
    rules:
        - rule-1
    group-by:
        - host
    timespan: 10m
    condition:
        field: username
        gte: 5
"#;
    let parsed: SigmaRule = serde_yaml::from_str(rule).unwrap();
    assert_eq!(parsed.id, "test-value-count");
}

#[test]
fn test_parse_temporal_rule() {
    let rule = r#"
title: Temporal Correlation
id: test-temporal
description: Tests temporal correlation parsing
correlation:
    type: temporal
    rules:
        - rule-1
        - rule-2
    group-by:
        - host
    timespan: 30s
"#;
    let parsed: SigmaRule = serde_yaml::from_str(rule).unwrap();
    assert_eq!(parsed.id, "test-temporal");
}

#[test]
fn test_parse_temporal_ordered_rule() {
    let rule = r#"
title: Temporal Ordered Correlation
id: test-temporal-ordered
description: Tests temporal ordered correlation parsing
correlation:
    type: temporal_ordered
    rules:
        - rule-1
        - rule-2
        - rule-3
    group-by:
        - host
    timespan: 1m
"#;
    let parsed: SigmaRule = serde_yaml::from_str(rule).unwrap();
    assert_eq!(parsed.id, "test-temporal-ordered");
}

// ============================================================================
// EVENT COUNT CORRELATION TESTS
// ============================================================================

#[test]
fn test_event_count_below_threshold() {
    let rule_yaml = r#"
correlation:
    type: event_count
    rules:
        - source-rule
    group-by:
        - host
    timespan: 5m
    condition:
        gte: 3
"#;
    let corr_rule: CorrelationRule = serde_yaml::from_str(rule_yaml).unwrap();
    let store = Box::new(TSinkStore::new_with_expiry(Duration::from_secs(300)).unwrap());
    let engine = CorrelationEngine::new_with_storage(store, corr_rule);

    let event = Event::new(json!({"host": "server1", "action": "login"}));
    let ref_event = (&event).into();

    // First event - should not match (count=1, need >=3)
    let result = engine.matches(&ref_event, &vec!["source-rule".to_string()]).unwrap();
    assert!(!result, "Should not match with only 1 event");

    // Second event - should not match (count=2, need >=3)
    let result = engine.matches(&ref_event, &vec!["source-rule".to_string()]).unwrap();
    assert!(!result, "Should not match with only 2 events");
}

#[test]
fn test_event_count_meets_threshold() {
    let rule_yaml = r#"
correlation:
    type: event_count
    rules:
        - source-rule
    group-by:
        - host
    timespan: 5m
    condition:
        gte: 3
"#;
    let corr_rule: CorrelationRule = serde_yaml::from_str(rule_yaml).unwrap();
    let store = Box::new(TSinkStore::new_with_expiry(Duration::from_secs(300)).unwrap());
    let engine = CorrelationEngine::new_with_storage(store, corr_rule);

    let event = Event::new(json!({"host": "server1", "action": "login"}));
    let ref_event = (&event).into();
    let prior = vec!["source-rule".to_string()];

    // Add events until threshold is met
    engine.matches(&ref_event, &prior).unwrap();
    engine.matches(&ref_event, &prior).unwrap();
    let result = engine.matches(&ref_event, &prior).unwrap();
    
    assert!(result, "Should match when event count reaches threshold");
}

#[test]
fn test_event_count_different_groups() {
    let rule_yaml = r#"
correlation:
    type: event_count
    rules:
        - source-rule
    group-by:
        - host
    timespan: 5m
    condition:
        gte: 2
"#;
    let corr_rule: CorrelationRule = serde_yaml::from_str(rule_yaml).unwrap();
    let store = Box::new(TSinkStore::new_with_expiry(Duration::from_secs(300)).unwrap());
    let engine = CorrelationEngine::new_with_storage(store, corr_rule);

    let event1 = Event::new(json!({"host": "server1", "action": "login"}));
    let event2 = Event::new(json!({"host": "server2", "action": "login"}));
    let ref_event1 = (&event1).into();
    let ref_event2 = (&event2).into();
    let prior = vec!["source-rule".to_string()];

    // Add event for server1
    engine.matches(&ref_event1, &prior).unwrap();
    
    // Add event for server2 - different group, should not trigger
    let result = engine.matches(&ref_event2, &prior).unwrap();
    assert!(!result, "Different groups should not accumulate");

    // Add second event for server1 - should now match
    let result = engine.matches(&ref_event1, &prior).unwrap();
    assert!(result, "Same group should accumulate and match");
}

#[test]
fn test_event_count_multiple_rules() {
    let rule_yaml = r#"
correlation:
    type: event_count
    rules:
        - rule-a
        - rule-b
    group-by:
        - host
    timespan: 5m
    condition:
        gte: 3
"#;
    let corr_rule: CorrelationRule = serde_yaml::from_str(rule_yaml).unwrap();
    let store = Box::new(TSinkStore::new_with_expiry(Duration::from_secs(300)).unwrap());
    let engine = CorrelationEngine::new_with_storage(store, corr_rule);

    let event = Event::new(json!({"host": "server1"}));
    let ref_event = (&event).into();

    // Add events from different source rules
    engine.matches(&ref_event, &vec!["rule-a".to_string()]).unwrap();
    engine.matches(&ref_event, &vec!["rule-b".to_string()]).unwrap();
    let result = engine.matches(&ref_event, &vec!["rule-a".to_string()]).unwrap();
    
    assert!(result, "Events from multiple source rules should accumulate");
}

#[test]
fn test_event_count_ignores_non_matching_rules() {
    let rule_yaml = r#"
correlation:
    type: event_count
    rules:
        - source-rule
    group-by:
        - host
    timespan: 5m
    condition:
        gte: 2
"#;
    let corr_rule: CorrelationRule = serde_yaml::from_str(rule_yaml).unwrap();
    let store = Box::new(TSinkStore::new_with_expiry(Duration::from_secs(300)).unwrap());
    let engine = CorrelationEngine::new_with_storage(store, corr_rule);

    let event = Event::new(json!({"host": "server1"}));
    let ref_event = (&event).into();

    // Add event from non-matching rule
    engine.matches(&ref_event, &vec!["other-rule".to_string()]).unwrap();
    engine.matches(&ref_event, &vec!["other-rule".to_string()]).unwrap();
    
    // Should not match because source-rule was never triggered
    let result = engine.matches(&ref_event, &vec!["source-rule".to_string()]).unwrap();
    assert!(!result, "Should only count events from specified rules");
}

// ============================================================================
// VALUE COUNT CORRELATION TESTS
// ============================================================================

#[test]
fn test_value_count_below_threshold() {
    let rule_yaml = r#"
correlation:
    type: value_count
    rules:
        - source-rule
    group-by:
        - host
    timespan: 5m
    condition:
        field: username
        gte: 3
"#;
    let corr_rule: CorrelationRule = serde_yaml::from_str(rule_yaml).unwrap();
    let store = Box::new(TSinkStore::new_with_expiry(Duration::from_secs(300)).unwrap());
    let engine = CorrelationEngine::new_with_storage(store, corr_rule);

    let event1 = Event::new(json!({"host": "server1", "username": "alice"}));
    let event2 = Event::new(json!({"host": "server1", "username": "bob"}));
    let ref_event1 = (&event1).into();
    let ref_event2 = (&event2).into();
    let prior = vec!["source-rule".to_string()];

    // Two distinct values - should not match (need >=3)
    engine.matches(&ref_event1, &prior).unwrap();
    let result = engine.matches(&ref_event2, &prior).unwrap();
    
    assert!(!result, "Should not match with only 2 distinct values");
}

#[test]
fn test_value_count_meets_threshold() {
    let rule_yaml = r#"
correlation:
    type: value_count
    rules:
        - source-rule
    group-by:
        - host
    timespan: 5m
    condition:
        field: username
        gte: 3
"#;
    let corr_rule: CorrelationRule = serde_yaml::from_str(rule_yaml).unwrap();
    let store = Box::new(TSinkStore::new_with_expiry(Duration::from_secs(300)).unwrap());
    let engine = CorrelationEngine::new_with_storage(store, corr_rule);

    let event1 = Event::new(json!({"host": "server1", "username": "alice"}));
    let event2 = Event::new(json!({"host": "server1", "username": "bob"}));
    let event3 = Event::new(json!({"host": "server1", "username": "charlie"}));
    let prior = vec!["source-rule".to_string()];

    engine.matches(&(&event1).into(), &prior).unwrap();
    engine.matches(&(&event2).into(), &prior).unwrap();
    let result = engine.matches(&(&event3).into(), &prior).unwrap();
    
    assert!(result, "Should match when distinct value count reaches threshold");
}

#[test]
fn test_value_count_duplicate_values() {
    let rule_yaml = r#"
correlation:
    type: value_count
    rules:
        - source-rule
    group-by:
        - host
    timespan: 5m
    condition:
        field: username
        gte: 3
"#;
    let corr_rule: CorrelationRule = serde_yaml::from_str(rule_yaml).unwrap();
    let store = Box::new(TSinkStore::new_with_expiry(Duration::from_secs(300)).unwrap());
    let engine = CorrelationEngine::new_with_storage(store, corr_rule);

    let event = Event::new(json!({"host": "server1", "username": "alice"}));
    let ref_event = (&event).into();
    let prior = vec!["source-rule".to_string()];

    // Same value multiple times - should only count as 1 distinct value
    engine.matches(&ref_event, &prior).unwrap();
    engine.matches(&ref_event, &prior).unwrap();
    let result = engine.matches(&ref_event, &prior).unwrap();
    
    assert!(!result, "Duplicate values should not increase distinct count");
}

#[test]
fn test_value_count_different_groups() {
    let rule_yaml = r#"
correlation:
    type: value_count
    rules:
        - source-rule
    group-by:
        - host
    timespan: 5m
    condition:
        field: username
        gte: 2
"#;
    let corr_rule: CorrelationRule = serde_yaml::from_str(rule_yaml).unwrap();
    let store = Box::new(TSinkStore::new_with_expiry(Duration::from_secs(300)).unwrap());
    let engine = CorrelationEngine::new_with_storage(store, corr_rule);

    let event1 = Event::new(json!({"host": "server1", "username": "alice"}));
    let event2 = Event::new(json!({"host": "server2", "username": "bob"}));
    let prior = vec!["source-rule".to_string()];

    engine.matches(&(&event1).into(), &prior).unwrap();
    let result = engine.matches(&(&event2).into(), &prior).unwrap();
    
    assert!(!result, "Different groups should not share value counts");
}

// ============================================================================
// TEMPORAL CORRELATION TESTS
// ============================================================================

#[test]
fn test_temporal_single_rule_present() {
    let rule_yaml = r#"
correlation:
    type: temporal
    rules:
        - rule-a
        - rule-b
    group-by:
        - host
    timespan: 5m
"#;
    let corr_rule: CorrelationRule = serde_yaml::from_str(rule_yaml).unwrap();
    let store = Box::new(TSinkStore::new_with_expiry(Duration::from_secs(300)).unwrap());
    let engine = CorrelationEngine::new_with_storage(store, corr_rule);

    let event = Event::new(json!({"host": "server1"}));
    let ref_event = (&event).into();

    // Only rule-a present - should not match
    let result = engine.matches(&ref_event, &vec!["rule-a".to_string()]).unwrap();
    assert!(!result, "Should not match when only one rule is present");
}

#[test]
fn test_temporal_all_rules_present() {
    let rule_yaml = r#"
correlation:
    type: temporal
    rules:
        - rule-a
        - rule-b
    group-by:
        - host
    timespan: 5m
"#;
    let corr_rule: CorrelationRule = serde_yaml::from_str(rule_yaml).unwrap();
    let store = Box::new(TSinkStore::new_with_expiry(Duration::from_secs(300)).unwrap());
    let engine = CorrelationEngine::new_with_storage(store, corr_rule);

    let event = Event::new(json!({"host": "server1"}));
    let ref_event = (&event).into();

    // Add rule-a event
    engine.matches(&ref_event, &vec!["rule-a".to_string()]).unwrap();
    
    // Add rule-b event - should now match since both are present
    let result = engine.matches(&ref_event, &vec!["rule-b".to_string()]).unwrap();
    assert!(result, "Should match when all rules are present");
}

#[test]
fn test_temporal_order_does_not_matter() {
    let rule_yaml = r#"
correlation:
    type: temporal
    rules:
        - rule-a
        - rule-b
    group-by:
        - host
    timespan: 5m
"#;
    let corr_rule: CorrelationRule = serde_yaml::from_str(rule_yaml).unwrap();
    let store = Box::new(TSinkStore::new_with_expiry(Duration::from_secs(300)).unwrap());
    let engine = CorrelationEngine::new_with_storage(store, corr_rule);

    let event = Event::new(json!({"host": "server1"}));
    let ref_event = (&event).into();

    // Add rule-b first, then rule-a (reverse order)
    engine.matches(&ref_event, &vec!["rule-b".to_string()]).unwrap();
    let result = engine.matches(&ref_event, &vec!["rule-a".to_string()]).unwrap();
    
    assert!(result, "Temporal correlation should match regardless of order");
}

#[test]
fn test_temporal_three_rules() {
    let rule_yaml = r#"
correlation:
    type: temporal
    rules:
        - rule-a
        - rule-b
        - rule-c
    group-by:
        - host
    timespan: 5m
"#;
    let corr_rule: CorrelationRule = serde_yaml::from_str(rule_yaml).unwrap();
    let store = Box::new(TSinkStore::new_with_expiry(Duration::from_secs(300)).unwrap());
    let engine = CorrelationEngine::new_with_storage(store, corr_rule);

    let event = Event::new(json!({"host": "server1"}));
    let ref_event = (&event).into();

    // Add only two rules - should not match
    engine.matches(&ref_event, &vec!["rule-a".to_string()]).unwrap();
    let result = engine.matches(&ref_event, &vec!["rule-b".to_string()]).unwrap();
    assert!(!result, "Should not match with only 2 of 3 rules");

    // Add third rule - should now match
    let result = engine.matches(&ref_event, &vec!["rule-c".to_string()]).unwrap();
    assert!(result, "Should match when all 3 rules are present");
}

#[test]
fn test_temporal_different_groups() {
    let rule_yaml = r#"
correlation:
    type: temporal
    rules:
        - rule-a
        - rule-b
    group-by:
        - host
    timespan: 5m
"#;
    let corr_rule: CorrelationRule = serde_yaml::from_str(rule_yaml).unwrap();
    let store = Box::new(TSinkStore::new_with_expiry(Duration::from_secs(300)).unwrap());
    let engine = CorrelationEngine::new_with_storage(store, corr_rule);

    let event1 = Event::new(json!({"host": "server1"}));
    let event2 = Event::new(json!({"host": "server2"}));
    let ref_event1 = (&event1).into();
    let ref_event2 = (&event2).into();

    // rule-a on server1, rule-b on server2 - should not match
    engine.matches(&ref_event1, &vec!["rule-a".to_string()]).unwrap();
    let result = engine.matches(&ref_event2, &vec!["rule-b".to_string()]).unwrap();
    
    assert!(!result, "Different groups should not combine for temporal correlation");
}

// ============================================================================
// TEMPORAL ORDERED CORRELATION TESTS
// ============================================================================

#[test]
fn test_temporal_ordered_correct_order() {
    let rule_yaml = r#"
correlation:
    type: temporal_ordered
    rules:
        - rule-first
        - rule-second
    group-by:
        - host
    timespan: 5m
"#;
    let corr_rule: CorrelationRule = serde_yaml::from_str(rule_yaml).unwrap();
    let store = Box::new(TSinkStore::new_with_expiry(Duration::from_secs(300)).unwrap());
    let engine = CorrelationEngine::new_with_storage(store, corr_rule);

    let event = Event::new(json!({"host": "server1"}));
    let ref_event = (&event).into();

    // Add in correct order: first, then second
    engine.matches(&ref_event, &vec!["rule-first".to_string()]).unwrap();
    
    // Small delay to ensure timestamp ordering
    std::thread::sleep(std::time::Duration::from_millis(10));
    
    let result = engine.matches(&ref_event, &vec!["rule-second".to_string()]).unwrap();
    assert!(result, "Should match when rules appear in correct order");
}

#[test]
fn test_temporal_ordered_wrong_order() {
    let rule_yaml = r#"
correlation:
    type: temporal_ordered
    rules:
        - rule-first
        - rule-second
    group-by:
        - host
    timespan: 5m
"#;
    let corr_rule: CorrelationRule = serde_yaml::from_str(rule_yaml).unwrap();
    let store = Box::new(TSinkStore::new_with_expiry(Duration::from_secs(300)).unwrap());
    let engine = CorrelationEngine::new_with_storage(store, corr_rule);

    let event = Event::new(json!({"host": "server1"}));
    let ref_event = (&event).into();

    // Add in wrong order: second first, then first
    engine.matches(&ref_event, &vec!["rule-second".to_string()]).unwrap();
    
    std::thread::sleep(std::time::Duration::from_millis(10));
    
    let result = engine.matches(&ref_event, &vec!["rule-first".to_string()]).unwrap();
    assert!(!result, "Should NOT match when rules appear in wrong order");
}

#[test]
fn test_temporal_ordered_single_rule_present() {
    let rule_yaml = r#"
correlation:
    type: temporal_ordered
    rules:
        - rule-first
        - rule-second
    group-by:
        - host
    timespan: 5m
"#;
    let corr_rule: CorrelationRule = serde_yaml::from_str(rule_yaml).unwrap();
    let store = Box::new(TSinkStore::new_with_expiry(Duration::from_secs(300)).unwrap());
    let engine = CorrelationEngine::new_with_storage(store, corr_rule);

    let event = Event::new(json!({"host": "server1"}));
    let ref_event = (&event).into();

    // Only first rule present
    let result = engine.matches(&ref_event, &vec!["rule-first".to_string()]).unwrap();
    assert!(!result, "Should not match with only one rule present");
}

#[test]
fn test_temporal_ordered_three_rules_correct() {
    let rule_yaml = r#"
correlation:
    type: temporal_ordered
    rules:
        - rule-1
        - rule-2
        - rule-3
    group-by:
        - host
    timespan: 5m
"#;
    let corr_rule: CorrelationRule = serde_yaml::from_str(rule_yaml).unwrap();
    let store = Box::new(TSinkStore::new_with_expiry(Duration::from_secs(300)).unwrap());
    let engine = CorrelationEngine::new_with_storage(store, corr_rule);

    let event = Event::new(json!({"host": "server1"}));
    let ref_event = (&event).into();

    // Add in correct order
    engine.matches(&ref_event, &vec!["rule-1".to_string()]).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(10));
    
    engine.matches(&ref_event, &vec!["rule-2".to_string()]).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(10));
    
    let result = engine.matches(&ref_event, &vec!["rule-3".to_string()]).unwrap();
    assert!(result, "Should match when all 3 rules appear in correct order");
}

#[test]
fn test_temporal_ordered_three_rules_wrong() {
    let rule_yaml = r#"
correlation:
    type: temporal_ordered
    rules:
        - rule-1
        - rule-2
        - rule-3
    group-by:
        - host
    timespan: 5m
"#;
    let corr_rule: CorrelationRule = serde_yaml::from_str(rule_yaml).unwrap();
    let store = Box::new(TSinkStore::new_with_expiry(Duration::from_secs(300)).unwrap());
    let engine = CorrelationEngine::new_with_storage(store, corr_rule);

    let event = Event::new(json!({"host": "server1"}));
    let ref_event = (&event).into();

    // Add in wrong order: 1, 3, 2
    engine.matches(&ref_event, &vec!["rule-1".to_string()]).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(10));
    
    engine.matches(&ref_event, &vec!["rule-3".to_string()]).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(10));
    
    let result = engine.matches(&ref_event, &vec!["rule-2".to_string()]).unwrap();
    assert!(!result, "Should NOT match when rules are out of order");
}

#[test]
fn test_temporal_ordered_different_groups() {
    let rule_yaml = r#"
correlation:
    type: temporal_ordered
    rules:
        - rule-first
        - rule-second
    group-by:
        - host
    timespan: 5m
"#;
    let corr_rule: CorrelationRule = serde_yaml::from_str(rule_yaml).unwrap();
    let store = Box::new(TSinkStore::new_with_expiry(Duration::from_secs(300)).unwrap());
    let engine = CorrelationEngine::new_with_storage(store, corr_rule);

    let event1 = Event::new(json!({"host": "server1"}));
    let event2 = Event::new(json!({"host": "server2"}));
    let ref_event1 = (&event1).into();
    let ref_event2 = (&event2).into();

    // rule-first on server1, rule-second on server2
    engine.matches(&ref_event1, &vec!["rule-first".to_string()]).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(10));
    
    let result = engine.matches(&ref_event2, &vec!["rule-second".to_string()]).unwrap();
    assert!(!result, "Different groups should not combine for temporal ordered correlation");
}

#[test]
fn test_temporal_ordered_recovery_after_wrong_order() {
    let rule_yaml = r#"
correlation:
    type: temporal_ordered
    rules:
        - rule-first
        - rule-second
    group-by:
        - host
    timespan: 5m
"#;
    let corr_rule: CorrelationRule = serde_yaml::from_str(rule_yaml).unwrap();
    let store = Box::new(TSinkStore::new_with_expiry(Duration::from_secs(300)).unwrap());
    let engine = CorrelationEngine::new_with_storage(store, corr_rule);

    let event = Event::new(json!({"host": "server1"}));
    let ref_event = (&event).into();

    // Wrong order first
    engine.matches(&ref_event, &vec!["rule-second".to_string()]).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(10));
    
    engine.matches(&ref_event, &vec!["rule-first".to_string()]).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(10));

    // Add rule-second again after rule-first - should now match
    let result = engine.matches(&ref_event, &vec!["rule-second".to_string()]).unwrap();
    assert!(result, "Should match after correct sequence is established");
}

// ============================================================================
// EDGE CASES AND INTEGRATION TESTS
// ============================================================================

#[test]
fn test_missing_group_by_field() {
    let rule_yaml = r#"
correlation:
    type: event_count
    rules:
        - source-rule
    group-by:
        - host
    timespan: 5m
    condition:
        gte: 2
"#;
    let corr_rule: CorrelationRule = serde_yaml::from_str(rule_yaml).unwrap();
    let store = Box::new(TSinkStore::new_with_expiry(Duration::from_secs(300)).unwrap());
    let engine = CorrelationEngine::new_with_storage(store, corr_rule);

    // Event without required group-by field
    let event = Event::new(json!({"action": "login"}));
    let ref_event = (&event).into();

    let result = engine.matches(&ref_event, &vec!["source-rule".to_string()]).unwrap();
    assert!(!result, "Should not match when group-by field is missing");
}

#[test]
fn test_empty_prior_matches() {
    let rule_yaml = r#"
correlation:
    type: event_count
    rules:
        - source-rule
    group-by:
        - host
    timespan: 5m
    condition:
        gte: 1
"#;
    let corr_rule: CorrelationRule = serde_yaml::from_str(rule_yaml).unwrap();
    let store = Box::new(TSinkStore::new_with_expiry(Duration::from_secs(300)).unwrap());
    let engine = CorrelationEngine::new_with_storage(store, corr_rule);

    let event = Event::new(json!({"host": "server1"}));
    let ref_event = (&event).into();

    // No prior matches
    let result = engine.matches(&ref_event, &vec![]).unwrap();
    assert!(!result, "Should not match with no prior rule matches");
}

#[test]
fn test_multiple_group_by_fields() {
    let rule_yaml = r#"
correlation:
    type: event_count
    rules:
        - source-rule
    group-by:
        - host
        - user
    timespan: 5m
    condition:
        gte: 2
"#;
    let corr_rule: CorrelationRule = serde_yaml::from_str(rule_yaml).unwrap();
    let store = Box::new(TSinkStore::new_with_expiry(Duration::from_secs(300)).unwrap());
    let engine = CorrelationEngine::new_with_storage(store, corr_rule);

    let event1 = Event::new(json!({"host": "server1", "user": "alice"}));
    let event2 = Event::new(json!({"host": "server1", "user": "bob"}));
    let event3 = Event::new(json!({"host": "server1", "user": "alice"}));
    let prior = vec!["source-rule".to_string()];

    // First event for (server1, alice)
    engine.matches(&(&event1).into(), &prior).unwrap();
    
    // Event for different group (server1, bob)
    engine.matches(&(&event2).into(), &prior).unwrap();
    
    // Second event for (server1, alice) - should match
    let result = engine.matches(&(&event3).into(), &prior).unwrap();
    assert!(result, "Should match when same composite group reaches threshold");
}

// ============================================================================
// COLLECTION INTEGRATION TESTS
// ============================================================================

#[test]
fn test_collection_event_count_integration() {
    let rules = r#"
title: Login Event
id: login-event
logsource:
    category: auth
detection:
    selection:
        action: login
    condition: selection
---
title: Brute Force Detection
id: brute-force
correlation:
    type: event_count
    rules:
        - login-event
    group-by:
        - source_ip
    timespan: 5m
    condition:
        gte: 3
"#;
    let mut collection: SigmaCollection = rules.parse().unwrap();
    collection.with_backend().unwrap();

    let event = Event::new(json!({"action": "login", "source_ip": "192.168.1.1"}));
    
    // First two events - only login-event matches
    let res = collection.matches(&(&event).into()).unwrap();
    assert_eq!(res.len(), 1, "First event: only detection rule should match");
    
    let res = collection.matches(&(&event).into()).unwrap();
    assert_eq!(res.len(), 1, "Second event: only detection rule should match");
    
    // Third event - both rules should match
    let res = collection.matches(&(&event).into()).unwrap();
    assert_eq!(res.len(), 2, "Third event: both detection and correlation should match");
    assert!(res.contains(&"login-event".to_string()));
    assert!(res.contains(&"brute-force".to_string()));
}

#[test]
fn test_collection_temporal_integration() {
    let rules = r#"
title: Vulnerability Access
id: vuln-access
logsource:
    category: web
detection:
    selection:
        uri: "/api/vulnerable"
    condition: selection
---
title: Suspicious Process
id: susp-process
logsource:
    category: process
detection:
    selection:
        process: "cmd.exe"
    condition: selection
---
title: Exploit Chain
id: exploit-chain
correlation:
    type: temporal
    rules:
        - vuln-access
        - susp-process
    group-by:
        - host
    timespan: 30s
"#;
    let mut collection: SigmaCollection = rules.parse().unwrap();
    collection.with_backend().unwrap();

    let web_event = Event::new(json!({"uri": "/api/vulnerable", "host": "server1"}));
    let process_event = Event::new(json!({"process": "cmd.exe", "host": "server1"}));

    // First event - only web rule matches
    let res = collection.matches(&(&web_event).into()).unwrap();
    assert!(res.contains(&"vuln-access".to_string()));
    assert!(!res.contains(&"exploit-chain".to_string()));

    // Second event - correlation should now match
    let res = collection.matches(&(&process_event).into()).unwrap();
    assert!(res.contains(&"susp-process".to_string()));
    assert!(res.contains(&"exploit-chain".to_string()), "Temporal correlation should match");
}

#[test]
fn test_collection_temporal_ordered_integration() {
    let rules = r#"
title: Failed Login
id: failed-login
logsource:
    category: auth
detection:
    selection:
        action: login
        status: failed
    condition: selection
---
title: Successful Login
id: success-login
logsource:
    category: auth
detection:
    selection:
        action: login
        status: success
    condition: selection
---
title: Brute Force Success
id: brute-force-success
correlation:
    type: temporal_ordered
    rules:
        - failed-login
        - success-login
    group-by:
        - source_ip
    timespan: 5m
"#;
    let mut collection: SigmaCollection = rules.parse().unwrap();
    collection.with_backend().unwrap();

    let failed = Event::new(json!({"action": "login", "status": "failed", "source_ip": "10.0.0.1"}));
    let success = Event::new(json!({"action": "login", "status": "success", "source_ip": "10.0.0.1"}));

    // Failed login first
    let res = collection.matches(&(&failed).into()).unwrap();
    assert!(res.contains(&"failed-login".to_string()));
    assert!(!res.contains(&"brute-force-success".to_string()));

    std::thread::sleep(std::time::Duration::from_millis(10));

    // Then successful login - correlation should match
    let res = collection.matches(&(&success).into()).unwrap();
    assert!(res.contains(&"success-login".to_string()));
    assert!(res.contains(&"brute-force-success".to_string()), 
        "Temporal ordered correlation should match when failed comes before success");
}

#[test]
fn test_collection_temporal_ordered_wrong_order_integration() {
    let rules = r#"
title: Failed Login
id: failed-login
logsource:
    category: auth
detection:
    selection:
        action: login
        status: failed
    condition: selection
---
title: Successful Login
id: success-login
logsource:
    category: auth
detection:
    selection:
        action: login
        status: success
    condition: selection
---
title: Brute Force Success
id: brute-force-success
correlation:
    type: temporal_ordered
    rules:
        - failed-login
        - success-login
    group-by:
        - source_ip
    timespan: 5m
"#;
    let mut collection: SigmaCollection = rules.parse().unwrap();
    collection.with_backend().unwrap();

    let failed = Event::new(json!({"action": "login", "status": "failed", "source_ip": "10.0.0.1"}));
    let success = Event::new(json!({"action": "login", "status": "success", "source_ip": "10.0.0.1"}));

    // Success first (wrong order)
    let res = collection.matches(&(&success).into()).unwrap();
    assert!(res.contains(&"success-login".to_string()));
    
    std::thread::sleep(std::time::Duration::from_millis(10));

    // Then failed login - correlation should NOT match (wrong order)
    let res = collection.matches(&(&failed).into()).unwrap();
    assert!(res.contains(&"failed-login".to_string()));
    assert!(!res.contains(&"brute-force-success".to_string()), 
        "Temporal ordered correlation should NOT match when order is wrong");
}


#[test]
fn test_collection_temporal_ordered_wrong_group_by() {
    let rules = r#"
title: Failed Login
id: failed-login
logsource:
    category: auth
detection:
    selection:
        action: login
        status: failed
    condition: selection
---
title: Successful Login
id: success-login
logsource:
    category: auth
detection:
    selection:
        action: login
        status: success
    condition: selection
---
title: Brute Force Success
id: brute-force-success
correlation:
    type: temporal_ordered
    rules:
        - failed-login
        - success-login
    group-by:
        - source_ip
    timespan: 5m
"#;
    let mut collection: SigmaCollection = rules.parse().unwrap();
    collection.with_backend().unwrap();

    let failed = Event::new(json!({"action": "login", "status": "failed", "source_ip": "10.0.0.1"}));
    let success = Event::new(json!({"action": "login", "status": "success", "source_ip": "10.0.0.2"}));


    let res = collection.matches(&(&failed).into()).unwrap();
    assert!(res.contains(&"failed-login".to_string()));
    
    std::thread::sleep(std::time::Duration::from_millis(10));

    let res = collection.matches(&(&success).into()).unwrap();
    assert!(res.contains(&"success-login".to_string()));
    assert!(!res.contains(&"brute-force-success".to_string()), 
        "correlation should NOT match when group-by does not match");
}
