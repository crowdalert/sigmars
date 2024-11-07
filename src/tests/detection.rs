use super::*;

#[test]
fn test_detection() {
    let detection = r#"
        selection:
            foo: bar
        condition: selection
        "#;

    let detection =
        Detection::new(&serde_yml::from_str::<serde_yml::Value>(detection).unwrap()).unwrap();

    let log = serde_json::json!({
        "foo": "bar"
    });

    assert_eq!(detection.eval(&log), true);
}

#[test]
fn test_detection_fail() {
    let detection = r#"
        selection:
            foo: bar
        condition: selection
        "#;

    let detection =
        Detection::new(&serde_yml::from_str::<serde_yml::Value>(detection).unwrap()).unwrap();

    let log = serde_json::json!({
        "foo": "baz"
    });

    assert_eq!(detection.eval(&log), false);
}

#[test]
fn test_detection_nested() {
    let detection = r#"
        selection:
            foo.bar: baz
        condition: selection
        "#;

    let detection =
        Detection::new(&serde_yml::from_str::<serde_yml::Value>(detection).unwrap()).unwrap();

    let log = serde_json::json!({
        "foo": {
            "bar": "baz"
        }
    });

    assert_eq!(detection.eval(&log), true);
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
        Detection::new(&serde_yml::from_str::<serde_yml::Value>(detection).unwrap()).unwrap();

    let log = serde_json::json!({
        "foo": "bar"
    });

    assert_eq!(detection.eval(&log), true);
}

#[test]
fn test_modifiers() {
    let detection = r#"
        selection:
            foo|contains: baz
        condition: selection
        "#;

    let detection =
        Detection::new(&serde_yml::from_str::<serde_yml::Value>(detection).unwrap()).unwrap();

    let log = serde_json::json!({
        "foo": "barbaz"
    });

    assert_eq!(detection.eval(&log), true);
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
        Detection::new(&serde_yml::from_str::<serde_yml::Value>(detection).unwrap()).unwrap();

    let log = serde_json::json!({
        "foo": "barbaz",
        "bar": "bazfoo",
        "baz": "foobarbaz"
    });

    assert_eq!(detection.eval(&log), true);
}

#[test]
fn test_invalid_modifiers() {
    let detection = r#"
        selection:
            foo|bar: baz
        condition: selection
        "#;

    let detection = Detection::new(&serde_yml::from_str::<serde_yml::Value>(detection).unwrap());

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
        Detection::new(&serde_yml::from_str::<serde_yml::Value>(detection).unwrap()).unwrap();

    let log = serde_json::json!({
        "foo": {
            "bar": "abc"
        },
        "baz": {
            "quux": "abc"
        }
    });
    assert_eq!(detection.eval(&log), true);
}

#[test]
fn test_cidr() {
    let detection = r#"
        selection:
            foo|cidr: 10.0.0.0/8
        condition: selection
        "#;

    let detection =
        Detection::new(&serde_yml::from_str::<serde_yml::Value>(detection).unwrap()).unwrap();

    let log = serde_json::json!({
        "foo": "10.2.3.4"
    });
    assert_eq!(detection.eval(&log), true);
}

#[test]
fn test_cidr_to_cidr() {
    let detection = r#"
        selection:
            foo|cidr: 10.0.0.0/16
        condition: selection
        "#;

    let detection =
        Detection::new(&serde_yml::from_str::<serde_yml::Value>(detection).unwrap()).unwrap();

    let log = serde_json::json!({
        "foo": "10.0.1.0/24"
    });
    assert_eq!(detection.eval(&log), true);
}

#[test]
fn test_cidr_to_cidr_fail() {
    let detection = r#"
        selection:
            foo|cidr: 10.0.0.0/16
        condition: selection
        "#;
    let detection =
        Detection::new(&serde_yml::from_str::<serde_yml::Value>(detection).unwrap()).unwrap();
    let log = serde_json::json!({
        "foo": "10.1.0.0/24"
    });
    assert_eq!(detection.eval(&log), false);
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
        Detection::new(&serde_yml::from_str::<serde_yml::Value>(detection).unwrap()).unwrap();

    let log = serde_json::json!({
        "foo": ["bar", "baz"]
    });
    assert_eq!(detection.eval(&log), true);
}

#[test]
fn test_all_fail() {
    let detection = r#"
        selection:
            foo|all:
                - bar
                - baz
        condition: selection
        "#;

    let detection =
        Detection::new(&serde_yml::from_str::<serde_yml::Value>(detection).unwrap()).unwrap();

    let log = serde_json::json!({
        "foo": ["bar", "quux"]
    });
    assert_eq!(detection.eval(&log), false);
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
        Detection::new(&serde_yml::from_str::<serde_yml::Value>(detection).unwrap()).unwrap();

    let log = serde_json::json!({
        "foo": 42,
        "bar": 4.2
    });
    assert_eq!(detection.eval(&log), true);
}

#[test]
fn test_gt() {
    let detection = r#"
        selection:
            foo|gt: 42
        condition: selection
        "#;

    let detection =
        Detection::new(&serde_yml::from_str::<serde_yml::Value>(detection).unwrap()).unwrap();

    let log = serde_json::json!({
        "foo": 56
    });
    assert_eq!(detection.eval(&log), true);
}

#[test]
fn test_regex() {
    let detection = r#"
        selection:
            foo|regex: ^[a-z]+$
        condition: selection
        "#;

    let detection =
        Detection::new(&serde_yml::from_str::<serde_yml::Value>(detection).unwrap()).unwrap();

    let log = serde_json::json!({
        "foo": "bar"
    });
    assert_eq!(detection.eval(&log), true);
}

#[test]
fn test_regex_is_case_sensitive() {
    let detection = r#"
        selection:
            foo|regex: ^[a-z]+$
        condition: selection
        "#;

    let detection =
        Detection::new(&serde_yml::from_str::<serde_yml::Value>(detection).unwrap()).unwrap();

    let log = serde_json::json!({
        "foo": "BAR"
    });
    assert_eq!(detection.eval(&log), false);
}

#[test]
fn test_case_insensitive_regex() {
    let detection = r#"
        selection:
            foo|regex|i: ^[a-z]+$
        condition: selection
        "#;

    let detection =
        Detection::new(&serde_yml::from_str::<serde_yml::Value>(detection).unwrap()).unwrap();

    let log = serde_json::json!({
        "foo": "BAR"
    });
    assert_eq!(detection.eval(&log), true);
}

#[test]
fn test_regex_invalid_modifier() {
    let detection = r#"
        selection:
            foo|regex|q: ^[a-z]+$
        condition: selection
        "#;

    let detection = Detection::new(&serde_yml::from_str::<serde_yml::Value>(detection).unwrap());

    assert_eq!(detection.is_err(), true);
}
