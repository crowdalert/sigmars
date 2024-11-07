# Sigmars

Sigmars is a Rust library for working with Sigma rules, which are used for describing log events in a generic format. This library provides functionality for parsing, evaluating, and managing Sigma rules.

## Features

- Evaluates Sigma rules against serde_json::Value
- Manage collections of Sigma rules (similar to pySigma)
- supports all Sigma 2.0 condition modifiers including fieldref
- supports the full Sigma condition syntax as a pest Pratt grammar

## Usage

```rust
use sigmars::Detection;
use serde_json::json;
use serde_yml::from_str;

fn main() {
    let detection_rule = r#"
    selection:
        foo: bar
    condition: selection
    "#;

    let detection = Detection::new(&from_str::<serde_yml::Value>(detection_rule).unwrap()).unwrap();

    let log = json!({
        "foo": "bar"
    });

    assert_eq!(detection.eval(&log), true);
}
```
or to load a full collection:

```rust
use sigmars::{Collection, Event, Rule};
use serde_json::json;

fn main() {
    let mut collection = Collection::default();
    collection::load_ruleset("/path/to/detections").unwrap();

    let log = json!({
        "foo": "bar"
    });

    // evaluate all rules against a json value
    let all_matches: Vec<&Rule> = collection.eval_json(log);
    ...

    // or only evaluate rules that match a logsource
    let metadata = HashMap::from([
        ("logsource".to_string(), json!({"product": "aws", "service": "cloudtrail"}))
    ]);

    let log = json!({
        "eventVersion" : "1.08",
        "eventCategory" : "Management",
        "etc": "..."
    });

    let event = Event::new(log, metadata);

    let filtered_matches = collection.eval(event);
    ...

}
```

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.

## References

- [Sigma](https://github.com/SigmaHQ/sigma)
