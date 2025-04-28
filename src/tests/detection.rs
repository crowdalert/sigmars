use crate::detection::detection::Detection;

#[test]
fn test_detection() {
    let detection = r#"
        selection:
            foo: bar
        condition: selection
        "#;

    let detection =
        Detection::new(&serde_yaml::from_str::<serde_yaml::Value>(detection).unwrap()).unwrap();

    let log = serde_json::json!({
        "foo": "bar"
    });

    assert_eq!(detection.is_match(&log), true);
}

#[test]
fn test_detection_fail() {
    let detection = r#"
        selection:
            foo: bar
        condition: selection
        "#;

    let detection =
        Detection::new(&serde_yaml::from_str::<serde_yaml::Value>(detection).unwrap()).unwrap();

    let log = serde_json::json!({
        "foo": "baz"
    });

    assert_eq!(detection.is_match(&log), false);
}

#[test]
fn test_detection_nested() {
    let detection = r#"
        selection:
            foo.bar: baz
        condition: selection
        "#;

    let detection =
        Detection::new(&serde_yaml::from_str::<serde_yaml::Value>(detection).unwrap()).unwrap();

    let log = serde_json::json!({
        "foo": {
            "bar": "baz"
        }
    });

    assert_eq!(detection.is_match(&log), true);
}

#[test]
fn test_detection_list() {
    let detection = r#"
        selection:
            foo:
                - bar
                - baz
        condition: selection
        "#;

    let detection =
        Detection::new(&serde_yaml::from_str::<serde_yaml::Value>(detection).unwrap()).unwrap();

    let log = serde_json::json!({
        "foo": "bar"
    });

    assert_eq!(detection.is_match(&log), true);
}

#[test]
fn test_detection_map_is_and() {
    let detection = r#"
        selection:
            foo: bar
            baz: quux
        condition: selection
        "#;

    let detection =
        Detection::new(&serde_yaml::from_str::<serde_yaml::Value>(detection).unwrap()).unwrap();

    let log = serde_json::json!({
        "foo": "bar"
    });

    assert_eq!(detection.is_match(&log), false);

    let log = serde_json::json!({
        "foo": "bar",
        "baz": "quux"
    });

    assert_eq!(detection.is_match(&log), true);
}

#[test]
fn test_modifiers() {
    let detection = r#"
        selection:
            foo|contains: baz
        condition: selection
        "#;

    let detection =
        Detection::new(&serde_yaml::from_str::<serde_yaml::Value>(detection).unwrap()).unwrap();

    let log = serde_json::json!({
        "foo": "barbaz"
    });

    assert_eq!(detection.is_match(&log), true);
}

#[test]
fn test_wildcards() {
    let detection = r#"
        selection1:
            foo: bar*
        selection2:
            bar: "*foo"
        selection3:
            baz: "*bar*"
        condition: selection1 and selection2 and selection3
        "#;

    let detection =
        Detection::new(&serde_yaml::from_str::<serde_yaml::Value>(detection).unwrap()).unwrap();

    let log = serde_json::json!({
        "foo": "barbaz",
        "bar": "bazfoo",
        "baz": "foobarbaz"
    });

    assert_eq!(detection.is_match(&log), true);
}

#[test]
fn test_invalid_modifiers() {
    let detection = r#"
        selection:
            foo|bar: baz
        condition: selection
        "#;

    let detection = Detection::new(&serde_yaml::from_str::<serde_yaml::Value>(detection).unwrap());

    assert_eq!(detection.is_err(), true);
}

#[test]
fn test_fieldref() {
    let detection = r#"
        selection:
            foo.bar|fieldref: baz.quux
        condition: selection
        "#;

    let detection =
        Detection::new(&serde_yaml::from_str::<serde_yaml::Value>(detection).unwrap()).unwrap();

    let log = serde_json::json!({
        "foo": {
            "bar": "abc"
        },
        "baz": {
            "quux": "abc"
        }
    });
    assert_eq!(detection.is_match(&log), true);
}

#[test]
fn test_cidr() {
    let detection = r#"
        selection:
            foo|cidr: 10.0.0.0/16
        condition: selection
        "#;

    let detection =
        Detection::new(&serde_yaml::from_str::<serde_yaml::Value>(detection).unwrap()).unwrap();

    let log = serde_json::json!({
        "foo": "10.0.1.2"
    });
    assert_eq!(detection.is_match(&log), true);

    let log = serde_json::json!({
        "foo": "10.1.2.3"
    });
    assert_eq!(detection.is_match(&log), false);
}

#[test]
fn test_cidr_to_cidr() {
    let detection = r#"
        selection:
            foo|cidr: 10.0.0.0/16
        condition: selection
        "#;

    let detection =
        Detection::new(&serde_yaml::from_str::<serde_yaml::Value>(detection).unwrap()).unwrap();

    let log = serde_json::json!({
        "foo": "10.0.1.0/24"
    });
    assert_eq!(detection.is_match(&log), true);

    let log = serde_json::json!({
        "foo": "10.1.0.0/24"
    });
    assert_eq!(detection.is_match(&log), false);
}

#[test]
fn test_all() {
    let detection = r#"
        selection:
            foo|all:
                - bar
                - baz
        condition: selection
        "#;

    let detection =
        Detection::new(&serde_yaml::from_str::<serde_yaml::Value>(detection).unwrap()).unwrap();

    let log = serde_json::json!({
        "foo": ["bar", "baz"]
    });
    assert_eq!(detection.is_match(&log), true);

    let log = serde_json::json!({
        "foo": ["bar", "quux"]
    });
    assert_eq!(detection.is_match(&log), false);

    let log = serde_json::json!({
        "foo": ["bar"]
    });
    assert_eq!(detection.is_match(&log), false);
}

#[test]
fn test_all_map_implicit() {
    let detection = r#"
        selection:
            foo: test1
            bar: test2
            baz: test3
        condition: selection
        "#;

    let detection =
        Detection::new(&serde_yaml::from_str::<serde_yaml::Value>(detection).unwrap()).unwrap();

    let log = serde_json::json!({
        "foo": "test1",
        "bar": "test2",
        "baz": "test3"
    });
    assert_eq!(detection.is_match(&log), true);

    let log = serde_json::json!({
        "foo": "test1",
        "bar": "test2",
        "baz": "test4"
    });
    assert_eq!(detection.is_match(&log), false);

    let log = serde_json::json!({
        "foo": "test1",
        "bar": "test2"
    });
    assert_eq!(detection.is_match(&log), false);
}

#[test]
fn test_numbers() {
    let detection = r#"
        selection1:
            foo: 42
        selection2:
            bar: 4.2
        condition: selection1 and selection2
        "#;

    let detection =
        Detection::new(&serde_yaml::from_str::<serde_yaml::Value>(detection).unwrap()).unwrap();

    let log = serde_json::json!({
        "foo": 42,
        "bar": 4.2
    });
    assert_eq!(detection.is_match(&log), true);
}

#[test]
fn test_gt() {
    let detection = r#"
        selection:
            foo|gt: 42
        condition: selection
        "#;

    let detection =
        Detection::new(&serde_yaml::from_str::<serde_yaml::Value>(detection).unwrap()).unwrap();

    let log = serde_json::json!({
        "foo": 56
    });
    assert_eq!(detection.is_match(&log), true);
}

#[test]
fn test_regex() {
    let detection = r#"
        selection:
            foo|re: ^[a-z]+$
        condition: selection
        "#;

    let detection =
        Detection::new(&serde_yaml::from_str::<serde_yaml::Value>(detection).unwrap()).unwrap();

    let log = serde_json::json!({
        "foo": "bar"
    });
    assert_eq!(detection.is_match(&log), true);
}

#[test]
fn test_regex_is_case_sensitive() {
    let detection = r#"
        selection:
            foo|re: ^[a-z]+$
        condition: selection
        "#;

    let detection =
        Detection::new(&serde_yaml::from_str::<serde_yaml::Value>(detection).unwrap()).unwrap();

    let log = serde_json::json!({
        "foo": "BAR"
    });
    assert_eq!(detection.is_match(&log), false);
}

#[test]
fn test_case_insensitive_regex() {
    let detection = r#"
        selection:
            foo|re|i: ^[a-z]+$
        condition: selection
        "#;

    let detection =
        Detection::new(&serde_yaml::from_str::<serde_yaml::Value>(detection).unwrap()).unwrap();

    let log = serde_json::json!({
        "foo": "BAR"
    });
    assert_eq!(detection.is_match(&log), true);
}

#[test]
fn test_regex_invalid_modifier() {
    let detection = r#"
        selection:
            foo|re|q: ^[a-z]+$
        condition: selection
        "#;

    let detection = Detection::new(&serde_yaml::from_str::<serde_yaml::Value>(detection).unwrap());

    assert_eq!(detection.is_err(), true);
}

#[test]
fn test_nof() {
    let log = serde_json::json!({
        "foo": "bar"
    });

    let detection = r#"
        selection1:
            foo: bar
        selection2:
            foo: baz
        condition: 1 of selection*
        "#;

    let detection =
        Detection::new(&serde_yaml::from_str::<serde_yaml::Value>(detection).unwrap()).unwrap();

    assert_eq!(detection.is_match(&log), true);

    let detection = r#"
    selection1:
        foo: bar
    selection2:
        foo: baz
    selection3:
        foo: quux
    condition: 2 of selection*
    "#;

    let detection =
        Detection::new(&serde_yaml::from_str::<serde_yaml::Value>(detection).unwrap()).unwrap();

    assert_eq!(detection.is_match(&log), false);

    let detection = r#"
    selection1:
        foo: x
    selection2:
        foo: y
    condition: 1 of selection*
    "#;

    let detection =
        Detection::new(&serde_yaml::from_str::<serde_yaml::Value>(detection).unwrap()).unwrap();

    assert_eq!(detection.is_match(&log), false);
}

#[test]
fn test_allof() {
    let log = serde_json::json!({
        "foo": "bar",
        "baz": "quux"
    });

    let detection = r#"
        selection1:
            foo: bar
        selection2:
            baz: quux
        condition: all of selection*
        "#;

    let detection =
        Detection::new(&serde_yaml::from_str::<serde_yaml::Value>(detection).unwrap()).unwrap();

    assert_eq!(detection.is_match(&log), true);

    let detection = r#"
    selection1:
        foo: bar
    selection2:
        baz: x
    condition: all of selection*
    "#;

    let detection =
        Detection::new(&serde_yaml::from_str::<serde_yaml::Value>(detection).unwrap()).unwrap();

    assert_eq!(detection.is_match(&log), false);
}

#[test]
fn test_null() {
    let log = serde_json::json!({
        "foo": "bar"
    });

    let detection = r#"
        selection:
            baz: null
        condition: selection
        "#;

    let detection =
        Detection::new(&serde_yaml::from_str::<serde_yaml::Value>(detection).unwrap()).unwrap();

    assert_eq!(detection.is_match(&log), true);
}
