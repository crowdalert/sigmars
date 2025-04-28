use cidr;
use regex::{Regex, RegexBuilder};
use serde_json::{json, Value as JsonValue};
use serde_yaml::Value as YamlValue;
use std::{net::IpAddr, str::FromStr};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
enum Modifier {
    All,
    StartsWith,
    EndsWith,
    Contains,
    Exists,
    Cased,
    Re(Option<Regex>),
    Base64(Option<Base64Modifier>),
    Base64Offset,
    Lt,
    Lte,
    Gt,
    Gte,
    Cidr,
    Expand,
    FieldRef,
}

impl Modifier {
    fn eval(&self, key: &String, value: &JsonValue, full_log: &JsonValue) -> bool {
        let log = get_terminal_from_dotted_path(key, full_log).unwrap_or(&JsonValue::Null);
        match self {
            Modifier::All => log.as_array().map_or(false, |log| {
                value
                    .as_array()
                    .map_or(false, |v| v.iter().all(|v| log.contains(v)))
            }),
            Modifier::StartsWith => value.as_str().map_or(false, |v| {
                log.as_str().map_or(false, |log| log.starts_with(v))
            }),
            Modifier::EndsWith => value.as_str().map_or(false, |v| {
                log.as_str().map_or(false, |log| log.ends_with(v))
            }),
            Modifier::Contains => value
                .as_str()
                .map_or(false, |v| log.as_str().map_or(false, |log| log.contains(v))),
            Modifier::Exists => !log.is_null(),
            Modifier::Cased => value
                .as_str()
                .map_or(false, |v| log.as_str().map_or(false, |log| log == v)),
            Modifier::Re(Some(re)) => log.as_str().map_or(false, |log| re.is_match(log)),
            Modifier::Re(None) => false,
            Modifier::Base64(b64mod) => {
                // TODO: Implement Base64
                match b64mod {
                    Some(Base64Modifier::Utf16Le) => false,
                    Some(Base64Modifier::Utf16Be) => false,
                    Some(Base64Modifier::Utf16) => false,
                    Some(Base64Modifier::Wide) => false,
                    None => false,
                }
            }
            Modifier::Base64Offset => false, // TODO: Implement Base64Offset
            Modifier::Lt => value.as_i64().map_or(false, |v| {
                log.as_i64()
                    .or_else(|| log.as_str().and_then(|s| s.parse::<i64>().ok()))
                    .map_or(false, |n| n < v)
            }),
            Modifier::Lte => value.as_i64().map_or(false, |v| {
                log.as_i64()
                    .or_else(|| log.as_str().and_then(|s| s.parse::<i64>().ok()))
                    .map_or(false, |n| n <= v)
            }),
            Modifier::Gt => value.as_i64().map_or(false, |v| {
                log.as_i64()
                    .or_else(|| log.as_str().and_then(|s| s.parse::<i64>().ok()))
                    .map_or(false, |n| n > v)
            }),
            Modifier::Gte => value.as_i64().map_or(false, |v| {
                log.as_i64()
                    .or_else(|| log.as_str().and_then(|s| s.parse::<i64>().ok()))
                    .map_or(false, |n| n >= v)
            }),
            Modifier::Cidr => value
                .as_str()
                .and_then(|v| cidr::AnyIpCidr::from_str(v).ok())
                .map_or(false, |v| {
                    log.as_str()
                        .map_or(false, |log| match IpAddr::from_str(&log) {
                            Ok(ip) => v.contains(&ip),
                            Err(_) => cidr::AnyIpCidr::from_str(log)
                                .ok()
                                .and_then(|target| {
                                    target.first_address().and_then(|first| {
                                        target.last_address().and_then(|last| {
                                            Some(v.contains(&first) && v.contains(&last))
                                        })
                                    })
                                })
                                .unwrap_or_else(|| false),
                        })
                }),
            Modifier::Expand => false, // TODO: Implement Expand
            Modifier::FieldRef => value.as_str().map_or(false, |rhs| {
                get_terminal_from_dotted_path(rhs, full_log)
                    .map_or(false, |rhs_value| log == rhs_value)
            }),
        }
    }
}

impl FromStr for Modifier {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "all" => Ok(Modifier::All),
            "startswith" => Ok(Modifier::StartsWith),
            "endswith" => Ok(Modifier::EndsWith),
            "contains" => Ok(Modifier::Contains),
            "exists" => Ok(Modifier::Exists),
            "cased" => Ok(Modifier::Cased),
            "re" => Ok(Modifier::Re(None)),
            "base64" => Ok(Modifier::Base64(None)), // TODO: Add Base64Modifier
            "base64offset" => Ok(Modifier::Base64Offset),
            "lt" => Ok(Modifier::Lt),
            "lte" => Ok(Modifier::Lte),
            "gt" => Ok(Modifier::Gt),
            "gte" => Ok(Modifier::Gte),
            "cidr" => Ok(Modifier::Cidr),
            "expand" => Ok(Modifier::Expand),
            "fieldref" => Ok(Modifier::FieldRef),
            _ => Err(()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum Base64Modifier {
    Utf16Le,
    Utf16Be,
    Utf16,
    Wide,
}

#[derive(Debug, Clone)]
struct Field {
    key: String,
    values: Vec<JsonValue>,
    modifiers: Vec<Modifier>,
}

impl Field {
    pub fn new(key: String, value: &YamlValue) -> Result<Self, Box<dyn std::error::Error>> {
        let mut key_modifiers = key.split("|");
        let key = key_modifiers
            .next()
            .ok_or_else(|| "invalid Key")?
            .to_string();

        let mut modifiers = Vec::new();

        match key_modifiers.next() {
            Some("regex") => {
                let re = value
                    .as_str()
                    .map(|re| RegexBuilder::new(re))
                    .map(|mut builder| {
                        for modifier in key_modifiers {
                            match modifier {
                                "i" => builder.case_insensitive(true),
                                "m" => builder.multi_line(true),
                                "s" => builder.dot_matches_new_line(true),
                                _ => {
                                    return Err(regex::Error::Syntax(
                                        format!("invalid modifier: {}", modifier).into(),
                                    ))
                                }
                            };
                        }
                        builder.build()
                    })
                    .transpose()?
                    .ok_or_else(|| "invalid regex")?;
                modifiers.push(Modifier::Re(Some(re)));
            }
            Some(m) => modifiers
                .push(Modifier::from_str(m).map_err(|_| format!("invalid modifier: {}", m))?),
            None => (),
        };

        let values: Vec<JsonValue> = match value {
            YamlValue::Null => vec![JsonValue::Null],
            YamlValue::String(s) => vec![JsonValue::String(s.clone())],
            YamlValue::Number(n) => vec![n.as_i64().map_or_else(
                || n.as_f64().map_or_else(|| JsonValue::Null, |f| json!(f)),
                |i| json!(i),
            )],
            YamlValue::Bool(b) => vec![JsonValue::Bool(*b)],
            YamlValue::Sequence(seq) => seq
                .iter()
                .map(|v| match v {
                    YamlValue::String(s) => Ok(JsonValue::String(s.as_str().to_string())),
                    YamlValue::Number(n) => n.as_i64().map_or_else(
                        || {
                            n.as_f64().map_or_else(
                                || Err(format!("invalid numeric value: {}", n).into()),
                                |f| Ok(json!(f)),
                            )
                        },
                        |i| Ok(json!(i)),
                    ),
                    YamlValue::Bool(b) => Ok(JsonValue::Bool(*b)),
                    _ => Err("invalid value type")?,
                })
                .collect::<Result<Vec<JsonValue>, Box<dyn std::error::Error>>>()?,
            _ => Err("invalid value type")?,
        };

        Ok(Field {
            key,
            values,
            modifiers,
        })
    }
}

#[derive(Debug, Clone)]
enum MatchType {
    Field(Field),
    Exact(String),
}

fn get_terminal_from_dotted_path<'a>(path: &str, log: &'a JsonValue) -> Option<&'a JsonValue> {
    let mut current = log;
    for key in path.split(".") {
        current = current.get(key)?;
    }
    Some(current)
}

#[derive(Debug, Clone)]
pub struct Selection {
    items: Vec<MatchType>,
}

impl Selection {
    pub fn new(value: &YamlValue) -> Result<Self, Box<dyn std::error::Error>> {
        let items: Vec<MatchType> = match value {
            YamlValue::Sequence(keys) => keys
                .iter()
                .map(|key| match key {
                    YamlValue::String(s) => Ok(vec![MatchType::Exact(s.to_string())]),
                    YamlValue::Mapping(m) => m
                        .iter()
                        .map(|(k, v)| {
                            let key = k.as_str().ok_or_else(|| "invalid key")?.to_string();
                            Ok(MatchType::Field(Field::new(key, v)?))
                        })
                        .collect::<Result<Vec<MatchType>, Box<dyn std::error::Error>>>(),
                    _ => Err("invalid selection".into()),
                })
                .collect::<Result<Vec<_>, _>>()?
                .into_iter()
                .flatten()
                .collect(),

            YamlValue::Mapping(m) => m
                .iter()
                .map(|(k, v)| {
                    let key = k.as_str().ok_or_else(|| "not a string")?.to_string();
                    Ok(MatchType::Field(Field::new(key, v)?))
                })
                .collect::<Result<Vec<MatchType>, Box<dyn std::error::Error>>>()?,
            _ => panic!("invalid value type"),
        };
        Ok(Selection { items })
    }

    pub fn is_match(&self, log: &JsonValue) -> bool {
        self.items.iter().all(|item| match item {
            MatchType::Exact(s) => log
                .as_str()
                .map(|field| field.contains(s))
                .unwrap_or_else(|| false),

            MatchType::Field(f) => {
                match &f.modifiers.len() {
                    0 => f.values.iter().any(|value| {
                        match get_terminal_from_dotted_path(&f.key, log) {
                            /*
                             * Sigma specifies case-insensitive matching
                             * and allows wildcards
                             */
                            Some(&JsonValue::String(ref logvalue)) => value.as_str().map_or_else(
                                || false,
                                |v| {
                                    if v.starts_with("*") {
                                        if v.ends_with("*") {
                                            logvalue
                                                .to_lowercase()
                                                .contains(&v[1..v.len() - 1].to_lowercase())
                                        } else {
                                            logvalue
                                                .to_lowercase()
                                                .ends_with(&v[1..].to_lowercase())
                                        }
                                    } else if v.ends_with("*") {
                                        logvalue
                                            .to_lowercase()
                                            .starts_with(&v[..v.len() - 1].to_lowercase())
                                    } else {
                                        logvalue.to_lowercase() == v.to_lowercase()
                                    }
                                },
                            ),
                            Some(&JsonValue::Number(ref logvalue)) => {
                                value.as_number().map_or_else(|| false, |v| logvalue == v)
                            }
                            None => value.is_null(),
                            _ => false,
                        }
                    }),

                    _ => f.modifiers.iter().all(|modifier| match &f.values.len() {
                        0 => false,
                        1 => f
                            .values
                            .iter()
                            .next()
                            .map_or_else(|| false, |v| modifier.eval(&f.key, v, &log)),
                        _ => modifier.eval(&f.key, &json!(&f.values), &log),
                    }),
                }
            }
        })
    }
}
