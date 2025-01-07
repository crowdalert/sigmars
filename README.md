# Sigmars

Sigmars is a Rust library for working with Sigma rules, which are used for describing log events in a generic format. This library provides functionality for parsing, evaluating, and managing Sigma rules.

## Features

- Manage collections of Sigma rules (similar to [pySigma](https://sigmahq-pysigma.readthedocs.io/en/latest/))
- supports all Sigma 2.0 condition modifiers including fieldref
- supports the full Sigma condition syntax (as a [pest](https://crates.io/crates/pest) Pratt grammar)
- supports correlation rules ()

## Usage

As a collection of simple detections:

```rust
use std::error::Error;
use sigmars::{Event, SigmaCollection};
fn main() -> Result<(), Box<dyn Error>> {
  let rules: SigmaCollection = SigmaCollection::new_from_dir("/path/to/sigma/rules/");
  let log = json!({"foo": "bar"});
  let matches = rules.get_detection_matches(&event.into());
  ...
}
```

or with correlations (requires tokio) using an in-memory backend

```rust
use std::error::Error;
use tokio;
use sigmars::{Event, MemBackend, SigmaCollection};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
  let rules: SigmaCollection = SigmaCollection::new_from_dir("/path/to/sigma/rules/");

  let mut backend = MemBackend::new().await;
  rules.init(&mut backend);

  let log = json!({"foo": "bar"});
  let matches = rules.get_matches(&event.into()).await?;
  ...
}
```

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.

## References

- [Sigma](https://github.com/SigmaHQ/sigma)
