use std::collections::HashMap;

use pest::iterators::Pairs;
use pest::pratt_parser::PrattParser;
use pest::Parser;

#[derive(pest_derive::Parser)]
#[grammar = "sigma_condition.pest"]
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

#[derive(Debug, PartialEq, Clone)]
pub enum BoolOp {
    Or,
    And,
}

#[derive(Debug, PartialEq, Clone)]
pub enum XOfType {
    NOf(i64),
    AllOf(),
}

impl ConditionNode {
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

fn eval(statement: &HashMap<&String, bool>, begin: &ConditionNode) -> bool {
    match begin {
        ConditionNode::Identifier(id) => *(statement.get(id).unwrap_or(&false)),
        ConditionNode::Not(inner) => !eval(statement, inner),
        ConditionNode::XOf(xoftype, _inner) => {
            match xoftype {
                XOfType::NOf(_n) => {
                    //inner.iter().filter(|i| eval(statement, i)).count() as i64 == n
                    false
                }
                XOfType::AllOf() => {
                    //inner.iter().all(|i| eval(statement, i))
                    false
                }
            }
        }
        ConditionNode::BoolOp { lhs, op, rhs } => match op {
            BoolOp::Or => eval(statement, lhs) || eval(statement, rhs),
            BoolOp::And => eval(statement, lhs) && eval(statement, rhs),
        },
    }
}

#[derive(Debug)]
pub struct Condition {
    ast: ConditionNode,
}

impl Condition {
    pub fn new(input: &str) -> Result<Condition, Box<dyn std::error::Error>> {
        let parsed = ConditionNode::from_str(input)?;
        Ok(Condition { ast: parsed })
    }
    pub fn eval(&self, statement: &HashMap<&String, bool>) -> bool {
        eval(statement, &self.ast)
    }
}
