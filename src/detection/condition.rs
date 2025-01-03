//! This module provides the `Condition` struct and related implementations for parsing and evaluating conditions in Sigma rules.

use std::collections::HashMap;

use glob;

use pest::iterators::Pairs;
use pest::pratt_parser::PrattParser;
use pest::Parser;

/// The parser for Sigma conditions.
#[derive(pest_derive::Parser)]
#[grammar = "detection/condition.pest"]
pub struct ConditionParser;

lazy_static::lazy_static! {
    static ref PRATT_PARSER: PrattParser<Rule> = {
        use pest::pratt_parser::{Assoc::*, Op};
        use Rule::*;

        // Precedence is defined lowest to highest
        PrattParser::new()
            .op(Op::infix(or, Left))
            .op(Op::infix(and, Left))
            .op(Op::prefix(not))
            .op(Op::prefix(xof))
    };
}

/// Represents a node in the condition abstract syntax tree (AST).
#[derive(Debug, PartialEq, Clone)]
enum ConditionNode {
    Identifier(String),
    Not(Box<ConditionNode>),
    XOf(XOfType, Box<ConditionNode>),
    BoolOp {
        lhs: Box<ConditionNode>,
        op: BoolOp,
        rhs: Box<ConditionNode>,
    },
}

/// Represents a boolean operator in a condition.
#[derive(Debug, PartialEq, Clone)]
pub enum BoolOp {
    Or,
    And,
}

/// Represents the type of an XOf condition.
#[derive(Debug, PartialEq, Clone)]
pub enum XOfType {
    NOf(i64),
    AllOf(),
}

impl ConditionNode {
    /// Parses a condition string into a `ConditionNode`.
    pub fn from_str(input: &str) -> Result<ConditionNode, Box<dyn std::error::Error>> {
        let parsed = ConditionParser::parse(Rule::expr, input)?;
        ConditionNode::parse(parsed)
    }

    fn parse(pairs: Pairs<Rule>) -> Result<ConditionNode, Box<dyn std::error::Error>> {
        PRATT_PARSER
            .map_primary(|primary| match primary.as_rule() {
                Rule::identifier => Ok(ConditionNode::Identifier(
                    primary.as_str().parse::<String>()?,
                )),

                Rule::expr => ConditionNode::parse(primary.into_inner()),
                _ => Err(format!(
                    "Condition::parse expected expr or identifier, found rule {:?}",
                    primary
                )
                .into()),
            })
            .map_prefix(|op, rhs| {
                let rhs = rhs?;
                match op.as_rule() {
                    Rule::not => Ok(ConditionNode::Not(Box::new(rhs))),
                    Rule::xof => {
                        let mut inner_rules = op.into_inner();
                        let count = match inner_rules.next() {
                            Some(rule) => XOfType::NOf(rule.as_str().parse()?),
                            None => XOfType::AllOf(),
                        };
                        Ok(ConditionNode::XOf(count, Box::new(rhs)))
                    }
                    _ => Err(
                        format!("Condition::parse expected prefix, found rule {:?}", rhs).into(),
                    ),
                }
            })
            .map_infix(|lhs, op, rhs| {
                let lhs = lhs?;
                let rhs = rhs?;
                let op = match op.as_rule() {
                    Rule::and => Ok(BoolOp::And),
                    Rule::or => Ok(BoolOp::Or),
                    _ => Err(format!(
                        "Condition::parse expected infix, found op {:?}",
                        op
                    )),
                }?;
                Ok(ConditionNode::BoolOp {
                    lhs: Box::new(lhs),
                    op,
                    rhs: Box::new(rhs),
                })
            })
            .parse(pairs)
    }
}

/// Evaluates a condition node against a statement.
fn is_match(statement: &HashMap<&String, bool>, begin: &ConditionNode) -> bool {
    match begin {
        ConditionNode::Identifier(id) => *(statement.get(id).unwrap_or(&false)),
        ConditionNode::Not(inner) => !is_match(statement, inner),
        ConditionNode::XOf(xoftype, inner) => match xoftype {
            XOfType::NOf(n) => {
                if let ConditionNode::Identifier(id) = inner.as_ref() {
                    glob::Pattern::new(id)
                        .and_then(|pattern| {
                            Ok(statement
                                .keys()
                                .filter(|k| {
                                    pattern.matches(*k)
                                        && statement.get(*k).copied().unwrap_or(false)
                                })
                                .count() as i64
                                >= *n)
                        })
                        .unwrap_or(false)
                } else {
                    false
                }
            }
            XOfType::AllOf() => {
                if let ConditionNode::Identifier(id) = inner.as_ref() {
                    glob::Pattern::new(id)
                        .and_then(|pattern| {
                            Ok(statement
                                .keys()
                                .filter(|k| pattern.matches(*k))
                                .all(|k| statement.get(k).copied().unwrap_or(false)))
                        })
                        .unwrap_or(false)
                } else {
                    false
                }
            }
        },
        ConditionNode::BoolOp { lhs, op, rhs } => match op {
            BoolOp::Or => is_match(statement, lhs) || is_match(statement, rhs),
            BoolOp::And => is_match(statement, lhs) && is_match(statement, rhs),
        },
    }
}

/// Represents a condition in a Sigma rule.
#[derive(Debug)]
pub struct Condition {
    ast: ConditionNode,
}

impl Condition {
    /// Creates a new `Condition` from a string input.
    pub fn new(input: &str) -> Result<Condition, Box<dyn std::error::Error>> {
        let parsed = ConditionNode::from_str(input)?;
        Ok(Condition { ast: parsed })
    }

    /// Evaluates the condition against a statement.
    pub fn is_match(&self, statement: &HashMap<&String, bool>) -> bool {
        is_match(statement, &self.ast)
    }
}
