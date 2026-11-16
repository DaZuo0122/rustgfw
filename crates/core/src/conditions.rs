//! Declarative, ordered flow rules shared by all packet I/O backends.
use crate::{
    inspect::{FlowAction, FlowContext, FlowRule},
    packet::Protocol,
};
use std::{
    net::{IpAddr, SocketAddr},
    str::FromStr,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Endpoint {
    Source,
    Destination,
    Origin,
    Target,
}
impl Endpoint {
    fn address(self, context: &FlowContext<'_>) -> std::net::SocketAddr {
        match self {
            Self::Source => context.source,
            Self::Destination => context.destination,
            Self::Origin => context.origin,
            Self::Target => context.target,
        }
    }

    fn possible_addresses(
        self,
        source: SocketAddr,
        destination: SocketAddr,
    ) -> (SocketAddr, SocketAddr) {
        match self {
            Self::Source | Self::Destination => (source, destination),
            Self::Origin => (source, source),
            Self::Target => (destination, destination),
        }
    }
}

fn endpoint_possibilities(
    endpoint: Endpoint,
    source: SocketAddr,
    destination: SocketAddr,
    matches: impl Fn(SocketAddr) -> bool,
) -> (bool, bool) {
    let (first, second) = endpoint.possible_addresses(source, destination);
    let first = matches(first);
    let second = matches(second);
    (!first || !second, first || second)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IpNetwork {
    network: IpAddr,
    prefix: u8,
}
impl IpNetwork {
    pub fn contains(self, address: IpAddr) -> bool {
        match (self.network, address) {
            (IpAddr::V4(network), IpAddr::V4(ip)) => {
                let mask = u32::MAX
                    .checked_shl(u32::from(32 - self.prefix))
                    .unwrap_or(0);
                u32::from(ip) & mask == u32::from(network)
            }
            (IpAddr::V6(network), IpAddr::V6(ip)) => {
                let mask = u128::MAX
                    .checked_shl(u32::from(128 - self.prefix))
                    .unwrap_or(0);
                u128::from(ip) & mask == u128::from(network)
            }
            _ => false,
        }
    }
}
impl FromStr for IpNetwork {
    type Err = String;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let (ip, prefix) = input
            .split_once('/')
            .ok_or_else(|| format!("CIDR requires an address and prefix: {input}"))?;
        let ip: IpAddr = ip
            .parse()
            .map_err(|_| format!("invalid CIDR address: {ip}"))?;
        let prefix: u8 = prefix
            .parse()
            .map_err(|_| format!("invalid CIDR prefix: {prefix}"))?;
        match ip {
            IpAddr::V4(ip) if prefix <= 32 => {
                let mask = u32::MAX.checked_shl(u32::from(32 - prefix)).unwrap_or(0);
                Ok(Self {
                    network: IpAddr::V4((u32::from(ip) & mask).into()),
                    prefix,
                })
            }
            IpAddr::V6(ip) if prefix <= 128 => {
                let mask = u128::MAX.checked_shl(u32::from(128 - prefix)).unwrap_or(0);
                Ok(Self {
                    network: IpAddr::V6((u128::from(ip) & mask).into()),
                    prefix,
                })
            }
            _ => Err(format!("CIDR prefix exceeds address width: {input}")),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TextOperator {
    Equals,
    Contains,
    StartsWith,
    EndsWith,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NumberOperator {
    Equals,
    NotEquals,
    Less,
    LessEqual,
    Greater,
    GreaterEqual,
}
impl NumberOperator {
    fn matches(self, actual: u64, expected: u64) -> bool {
        match self {
            Self::Equals => actual == expected,
            Self::NotEquals => actual != expected,
            Self::Less => actual < expected,
            Self::LessEqual => actual <= expected,
            Self::Greater => actual > expected,
            Self::GreaterEqual => actual >= expected,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NumberField {
    Port(Endpoint),
    PayloadLength,
}
impl TextOperator {
    fn matches(self, actual: &[u8], expected: &[u8], ignore_ascii_case: bool) -> bool {
        let equals = |part: &[u8]| {
            if ignore_ascii_case {
                part.eq_ignore_ascii_case(expected)
            } else {
                part == expected
            }
        };
        match self {
            Self::Equals => equals(actual),
            Self::Contains => expected.is_empty() || actual.windows(expected.len()).any(equals),
            Self::StartsWith => actual.get(..expected.len()).is_some_and(equals),
            Self::EndsWith => actual
                .get(actual.len().saturating_sub(expected.len())..)
                .is_some_and(equals),
        }
    }
}

pub fn parse_hex_bytes(value: &str) -> Result<Vec<u8>, String> {
    let digits = value.strip_prefix("0x").unwrap_or(value);
    if !digits.len().is_multiple_of(2) {
        return Err("hex value must have an even number of digits".into());
    }
    digits
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .enumerate()
        .map(|(index, pair)| {
            let pair = std::str::from_utf8(pair)
                .map_err(|_| format!("invalid hex byte at offset {}", index * 2))?;
            u8::from_str_radix(pair, 16).map_err(|_| format!("invalid hex byte {pair}"))
        })
        .collect()
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Condition {
    All(Vec<Self>),
    Any(Vec<Self>),
    Not(Box<Self>),
    Protocol(Protocol),
    Port {
        endpoint: Endpoint,
        value: u16,
    },
    Number {
        field: NumberField,
        operator: NumberOperator,
        value: u64,
    },
    IpIn {
        endpoint: Endpoint,
        network: IpNetwork,
    },
    Reverse(bool),
    FieldMatch {
        field: String,
        value: String,
        fresh: bool,
        operator: TextOperator,
    },
    FieldNumber {
        field: String,
        value: u64,
        fresh: bool,
        operator: NumberOperator,
    },
    FieldIpIn {
        field: String,
        network: IpNetwork,
        fresh: bool,
    },
    FieldExists {
        field: String,
        fresh: bool,
    },
    PayloadMatch {
        value: Vec<u8>,
        operator: TextOperator,
    },
}
impl Condition {
    pub fn matches(&self, context: &FlowContext<'_>) -> bool {
        match self {
            Self::All(items) => items.iter().all(|item| item.matches(context)),
            Self::Any(items) => items.iter().any(|item| item.matches(context)),
            Self::Not(item) => !item.matches(context),
            Self::Protocol(protocol) => context.protocol == *protocol,
            Self::Port { endpoint, value } => endpoint.address(context).port() == *value,
            Self::Number {
                field,
                operator,
                value,
            } => {
                let actual = match field {
                    NumberField::Port(endpoint) => u64::from(endpoint.address(context).port()),
                    NumberField::PayloadLength => context.payload.len() as u64,
                };
                operator.matches(actual, *value)
            }
            Self::IpIn { endpoint, network } => network.contains(endpoint.address(context).ip()),
            Self::Reverse(value) => context.reverse == *value,
            Self::FieldMatch {
                field,
                value,
                fresh,
                operator,
            } => {
                (!fresh || context.updated(field))
                    && context.values(field).is_some_and(|values| {
                        values.iter().any(|actual| {
                            let insensitive = !matches!(
                                field.as_str(),
                                "http.method"
                                    | "http.target"
                                    | "http2.method"
                                    | "http2.path"
                                    | "tls.alpn"
                                    | "tls.server_alpn"
                                    | "quic.alpn"
                            );
                            operator.matches(actual.as_bytes(), value.as_bytes(), insensitive)
                        })
                    })
            }
            Self::FieldNumber {
                field,
                value,
                fresh,
                operator,
            } => {
                (!fresh || context.updated(field))
                    && context.values(field).is_some_and(|values| {
                        values.iter().any(|actual| {
                            actual
                                .parse::<u64>()
                                .is_ok_and(|actual| operator.matches(actual, *value))
                        })
                    })
            }
            Self::FieldIpIn {
                field,
                network,
                fresh,
            } => {
                (!fresh || context.updated(field))
                    && context.values(field).is_some_and(|values| {
                        values.iter().any(|value| {
                            value
                                .parse::<IpAddr>()
                                .is_ok_and(|address| network.contains(address))
                        })
                    })
            }
            Self::FieldExists { field, fresh } => {
                (!fresh || context.updated(field))
                    && context
                        .values(field)
                        .is_some_and(|values| !values.is_empty())
            }
            Self::PayloadMatch { value, operator } => {
                operator.matches(context.payload, value, false)
            }
        }
    }

    pub fn references_field(&self, field: &str) -> bool {
        match self {
            Self::All(items) | Self::Any(items) => {
                items.iter().any(|item| item.references_field(field))
            }
            Self::Not(item) => item.references_field(field),
            Self::FieldMatch { field: name, .. }
            | Self::FieldNumber { field: name, .. }
            | Self::FieldIpIn { field: name, .. }
            | Self::FieldExists { field: name, .. } => name == field,
            _ => false,
        }
    }

    pub fn fields(&self) -> Vec<&str> {
        let mut fields = Vec::new();
        self.collect_fields(&mut fields);
        fields
    }

    fn collect_fields<'a>(&'a self, fields: &mut Vec<&'a str>) {
        match self {
            Self::All(items) | Self::Any(items) => {
                for item in items {
                    item.collect_fields(fields);
                }
            }
            Self::Not(item) => item.collect_fields(fields),
            Self::FieldMatch { field, .. }
            | Self::FieldNumber { field, .. }
            | Self::FieldIpIn { field, .. }
            | Self::FieldExists { field, .. } => fields.push(field),
            _ => {}
        }
    }

    /// Conservative protocol eligibility. Unknown fields remain possible;
    /// the caller supplies protocol support for its registered analyzers.
    pub fn can_match_protocol(
        &self,
        protocol: Protocol,
        field_possible: &impl Fn(&str, Protocol) -> bool,
    ) -> bool {
        self.possibilities(protocol, None, field_possible).1
    }

    /// Whether a rule may match this flow now or after traffic reverses.
    /// Payloads, observations and direction are treated as unknown future values.
    pub fn can_match_new_flow(
        &self,
        protocol: Protocol,
        source: SocketAddr,
        destination: SocketAddr,
    ) -> bool {
        self.possibilities(protocol, Some((source, destination)), &|_, _| true)
            .1
    }

    // (false is possible, true is possible). Keeping both outcomes for
    // non-protocol terms makes negation and mixed Boolean expressions sound.
    fn possibilities(
        &self,
        protocol: Protocol,
        endpoints: Option<(SocketAddr, SocketAddr)>,
        field_possible: &impl Fn(&str, Protocol) -> bool,
    ) -> (bool, bool) {
        match self {
            Self::All(items) => {
                let mut false_possible = false;
                let mut true_possible = true;
                for item in items {
                    let (false_item, true_item) =
                        item.possibilities(protocol, endpoints, field_possible);
                    false_possible |= false_item;
                    true_possible &= true_item;
                }
                (false_possible, true_possible)
            }
            Self::Any(items) => {
                let mut false_possible = true;
                let mut true_possible = false;
                for item in items {
                    let (false_item, true_item) =
                        item.possibilities(protocol, endpoints, field_possible);
                    false_possible &= false_item;
                    true_possible |= true_item;
                }
                (false_possible, true_possible)
            }
            Self::Not(item) => {
                let (false_possible, true_possible) =
                    item.possibilities(protocol, endpoints, field_possible);
                (true_possible, false_possible)
            }
            Self::Protocol(expected) => {
                if *expected == protocol {
                    (false, true)
                } else {
                    (true, false)
                }
            }
            Self::Port { endpoint, value } if let Some((source, destination)) = endpoints => {
                endpoint_possibilities(*endpoint, source, destination, |address| {
                    address.port() == *value
                })
            }
            Self::Number {
                field: NumberField::Port(endpoint),
                operator,
                value,
            } if let Some((source, destination)) = endpoints => {
                endpoint_possibilities(*endpoint, source, destination, |address| {
                    operator.matches(u64::from(address.port()), *value)
                })
            }
            Self::IpIn { endpoint, network } if let Some((source, destination)) = endpoints => {
                endpoint_possibilities(*endpoint, source, destination, |address| {
                    network.contains(address.ip())
                })
            }
            Self::FieldMatch { field, .. }
            | Self::FieldNumber { field, .. }
            | Self::FieldIpIn { field, .. }
            | Self::FieldExists { field, .. }
                if !field_possible(field, protocol) =>
            {
                (true, false)
            }
            _ => (true, true),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Token {
    Word(String),
    And,
    Or,
    Not,
    Eq,
    NotEq,
    Less,
    LessEqual,
    Greater,
    GreaterEqual,
    Open,
    Close,
}

fn tokenize(input: &str) -> Result<Vec<Token>, String> {
    let bytes = input.as_bytes();
    let mut tokens = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b' ' | b'\t' | b'\r' | b'\n' => index += 1,
            b'(' => {
                tokens.push(Token::Open);
                index += 1;
            }
            b')' => {
                tokens.push(Token::Close);
                index += 1;
            }
            b'!' if bytes.get(index + 1) == Some(&b'=') => {
                tokens.push(Token::NotEq);
                index += 2;
            }
            b'!' => {
                tokens.push(Token::Not);
                index += 1;
            }
            b'<' => {
                if bytes.get(index + 1) == Some(&b'=') {
                    tokens.push(Token::LessEqual);
                    index += 2;
                } else {
                    tokens.push(Token::Less);
                    index += 1;
                }
            }
            b'>' => {
                if bytes.get(index + 1) == Some(&b'=') {
                    tokens.push(Token::GreaterEqual);
                    index += 2;
                } else {
                    tokens.push(Token::Greater);
                    index += 1;
                }
            }
            b'&' if bytes.get(index + 1) == Some(&b'&') => {
                tokens.push(Token::And);
                index += 2;
            }
            b'|' if bytes.get(index + 1) == Some(&b'|') => {
                tokens.push(Token::Or);
                index += 2;
            }
            b'=' if bytes.get(index + 1) == Some(&b'=') => {
                tokens.push(Token::Eq);
                index += 2;
            }
            b'"' => {
                index += 1;
                let mut value = Vec::new();
                let mut closed = false;
                while index < bytes.len() {
                    match bytes[index] {
                        b'"' => {
                            index += 1;
                            closed = true;
                            break;
                        }
                        b'\\' => {
                            index += 1;
                            let byte = match bytes.get(index) {
                                Some(b'"') => b'"',
                                Some(b'\\') => b'\\',
                                Some(b'n') => b'\n',
                                Some(b'r') => b'\r',
                                Some(b't') => b'\t',
                                _ => return Err(format!("invalid string escape at byte {index}")),
                            };
                            value.push(byte);
                            index += 1;
                        }
                        byte => {
                            value.push(byte);
                            index += 1;
                        }
                    }
                }
                if !closed {
                    return Err("unterminated string".into());
                }
                tokens.push(Token::Word(
                    String::from_utf8(value).map_err(|_| "invalid UTF-8 string")?,
                ));
            }
            b'&' | b'|' | b'=' => {
                return Err(format!("invalid operator at byte {index}"));
            }
            _ => {
                let start = index;
                while index < bytes.len()
                    && !matches!(
                        bytes[index],
                        b' ' | b'\t'
                            | b'\r'
                            | b'\n'
                            | b'('
                            | b')'
                            | b'!'
                            | b'&'
                            | b'|'
                            | b'='
                            | b'<'
                            | b'>'
                            | b'"'
                    )
                {
                    index += 1;
                }
                tokens.push(Token::Word(input[start..index].to_owned()));
            }
        }
    }
    Ok(tokens)
}

struct Parser<'a> {
    tokens: Vec<Token>,
    index: usize,
    resolve: &'a mut dyn FnMut(&str) -> Result<Condition, String>,
}
impl Parser<'_> {
    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.index)
    }

    fn take(&mut self) -> Option<Token> {
        let token = self.peek()?.clone();
        self.index += 1;
        Some(token)
    }

    fn word(&mut self) -> Result<String, String> {
        match self.take() {
            Some(Token::Word(word)) => Ok(word),
            other => Err(format!("expected a value, found {other:?}")),
        }
    }

    fn or(&mut self) -> Result<Condition, String> {
        let mut items = vec![self.and()?];
        while self.peek() == Some(&Token::Or) {
            self.take();
            items.push(self.and()?);
        }
        Ok(if items.len() == 1 {
            items.remove(0)
        } else {
            Condition::Any(items)
        })
    }

    fn and(&mut self) -> Result<Condition, String> {
        let mut items = vec![self.unary()?];
        while self.peek() == Some(&Token::And) {
            self.take();
            items.push(self.unary()?);
        }
        Ok(if items.len() == 1 {
            items.remove(0)
        } else {
            Condition::All(items)
        })
    }

    fn unary(&mut self) -> Result<Condition, String> {
        if self.peek() == Some(&Token::Not) {
            self.take();
            return Ok(Condition::Not(Box::new(self.unary()?)));
        }
        if self.peek() == Some(&Token::Open) {
            self.take();
            let condition = self.or()?;
            if self.take() != Some(Token::Close) {
                return Err("missing closing parenthesis".into());
            }
            return Ok(condition);
        }
        if let Some(Token::Word(reference)) = self.peek()
            && let Some(name) = reference.strip_prefix('@')
        {
            let name = name.to_owned();
            self.take();
            if name.is_empty() {
                return Err("empty expression reference".into());
            }
            return (self.resolve)(&name);
        }
        self.comparison()
    }

    fn comparison(&mut self) -> Result<Condition, String> {
        let field = self.word()?;
        let operator = self.take().ok_or("missing comparison operator")?;
        if operator == Token::Word("exists".into()) {
            if matches!(
                field.as_str(),
                "proto"
                    | "reverse"
                    | "payload"
                    | "payload_hex"
                    | "payload.len"
                    | "src.port"
                    | "dst.port"
                    | "origin.port"
                    | "target.port"
                    | "src.ip"
                    | "dst.ip"
                    | "origin.ip"
                    | "target.ip"
            ) {
                return Err(format!("unsupported comparison for {field}"));
            }
            let (fresh, field) = field
                .strip_prefix("fresh.")
                .map_or((false, field.as_str()), |name| (true, name));
            return Ok(Condition::FieldExists {
                field: field.to_owned(),
                fresh,
            });
        }
        let value = self.word()?;
        let equality = matches!(operator, Token::Eq | Token::NotEq);
        let negate = operator == Token::NotEq;
        let number_operator = match operator {
            Token::Eq => Some(NumberOperator::Equals),
            Token::NotEq => Some(NumberOperator::NotEquals),
            Token::Less => Some(NumberOperator::Less),
            Token::LessEqual => Some(NumberOperator::LessEqual),
            Token::Greater => Some(NumberOperator::Greater),
            Token::GreaterEqual => Some(NumberOperator::GreaterEqual),
            _ => None,
        };
        let text_operator = match &operator {
            Token::Eq | Token::NotEq => Some(TextOperator::Equals),
            Token::Word(word) => match word.as_str() {
                "contains" => Some(TextOperator::Contains),
                "starts_with" => Some(TextOperator::StartsWith),
                "ends_with" => Some(TextOperator::EndsWith),
                _ => None,
            },
            _ => None,
        };
        let condition = match field.as_str() {
            "proto" if equality => match value.as_str() {
                "tcp" => Ok(Condition::Protocol(Protocol::Tcp)),
                "udp" => Ok(Condition::Protocol(Protocol::Udp)),
                _ => Err(format!("unknown protocol {value}")),
            },
            "reverse" if equality => match value.as_str() {
                "true" => Ok(Condition::Reverse(true)),
                "false" => Ok(Condition::Reverse(false)),
                _ => Err(format!("reverse expects true or false: {value}")),
            },
            "payload" if let Some(operator) = text_operator => Ok(Condition::PayloadMatch {
                value: value.into_bytes(),
                operator,
            }),
            "payload_hex" if let Some(operator) = text_operator => Ok(Condition::PayloadMatch {
                value: parse_hex_bytes(&value)?,
                operator,
            }),
            "src.port" | "dst.port" | "origin.port" | "target.port" if operator == Token::Eq => {
                let endpoint = parse_endpoint(field.split('.').next().unwrap());
                let value = value.parse().map_err(|_| format!("invalid port {value}"))?;
                Ok(Condition::Port { endpoint, value })
            }
            "src.port" | "dst.port" | "origin.port" | "target.port"
                if let Some(operator) = number_operator =>
            {
                let endpoint = parse_endpoint(field.split('.').next().unwrap());
                let value = value.parse().map_err(|_| format!("invalid port {value}"))?;
                Ok(Condition::Number {
                    field: NumberField::Port(endpoint),
                    operator,
                    value,
                })
            }
            "payload.len" if let Some(operator) = number_operator => {
                let value = value
                    .parse()
                    .map_err(|_| format!("invalid payload length {value}"))?;
                Ok(Condition::Number {
                    field: NumberField::PayloadLength,
                    operator,
                    value,
                })
            }
            "src.ip" | "dst.ip" | "origin.ip" | "target.ip"
                if equality || operator == Token::Word("in".into()) =>
            {
                let endpoint = parse_endpoint(field.split('.').next().unwrap());
                let cidr = if equality {
                    if value.contains(':') {
                        format!("{value}/128")
                    } else {
                        format!("{value}/32")
                    }
                } else {
                    value
                };
                Ok(Condition::IpIn {
                    endpoint,
                    network: cidr.parse()?,
                })
            }
            "proto" | "reverse" | "payload" | "payload_hex" | "payload.len" | "src.port"
            | "dst.port" | "origin.port" | "target.port" | "src.ip" | "dst.ip" | "origin.ip"
            | "target.ip" => Err(format!("unsupported comparison for {field}")),
            _ if operator == Token::Word("in".into()) => {
                let (fresh, field) = field
                    .strip_prefix("fresh.")
                    .map_or((false, field.as_str()), |name| (true, name));
                Ok(Condition::FieldIpIn {
                    field: field.to_owned(),
                    network: value.parse()?,
                    fresh,
                })
            }
            _ if let Some(operator) = text_operator => {
                let (fresh, field) = field
                    .strip_prefix("fresh.")
                    .map_or((false, field.as_str()), |name| (true, name));
                Ok(Condition::FieldMatch {
                    field: field.to_owned(),
                    value,
                    fresh,
                    operator,
                })
            }
            _ if let Some(operator) = number_operator => {
                let (fresh, field) = field
                    .strip_prefix("fresh.")
                    .map_or((false, field.as_str()), |name| (true, name));
                let value = value
                    .parse()
                    .map_err(|_| format!("invalid numeric observation value {value}"))?;
                Ok(Condition::FieldNumber {
                    field: field.to_owned(),
                    value,
                    fresh,
                    operator,
                })
            }
            _ => Err(format!("unsupported comparison for {field}")),
        }?;
        Ok(
            if negate && !matches!(condition, Condition::Number { .. }) {
                Condition::Not(Box::new(condition))
            } else {
                condition
            },
        )
    }
}

fn parse_endpoint(name: &str) -> Endpoint {
    match name {
        "src" => Endpoint::Source,
        "dst" => Endpoint::Destination,
        "origin" => Endpoint::Origin,
        "target" => Endpoint::Target,
        _ => unreachable!(),
    }
}

pub fn parse_expression(input: &str) -> Result<Condition, String> {
    parse_expression_with(input, &mut |name| {
        Err(format!("unknown expression reference @{name}"))
    })
}

/// Parse an expression with reusable named conditions resolved by the caller.
/// The resolver returns an expanded condition, so matching has no lookup step.
pub fn parse_expression_with(
    input: &str,
    resolve: &mut dyn FnMut(&str) -> Result<Condition, String>,
) -> Result<Condition, String> {
    let mut parser = Parser {
        tokens: tokenize(input)?,
        index: 0,
        resolve,
    };
    let condition = parser.or()?;
    if parser.peek().is_some() {
        return Err(format!("unexpected token {:?}", parser.peek()));
    }
    Ok(condition)
}

#[derive(Clone, Debug)]
pub struct MatchRule {
    pub condition: Condition,
    pub action: FlowAction,
}
impl MatchRule {
    pub fn into_flow_rule(self) -> FlowRule {
        let candidate = self.condition.clone();
        FlowRule::with_candidate(
            move |context| self.condition.matches(context).then(|| self.action.clone()),
            move |protocol, source, destination| {
                candidate.can_match_new_flow(protocol, source, destination)
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cidr_masks_host_bits_and_keeps_ip_families_separate() {
        let v4: IpNetwork = "192.0.2.99/24".parse().unwrap();
        assert!(v4.contains("192.0.2.1".parse().unwrap()));
        assert!(!v4.contains("192.0.3.1".parse().unwrap()));
        assert!(!v4.contains("2001:db8::1".parse().unwrap()));
        let v6: IpNetwork = "2001:db8::1234/32".parse().unwrap();
        assert!(v6.contains("2001:db8:1::1".parse().unwrap()));
        assert!(!v6.contains("2001:db9::1".parse().unwrap()));
        assert!(
            "0.0.0.0/0"
                .parse::<IpNetwork>()
                .unwrap()
                .contains("203.0.113.2".parse().unwrap())
        );
        assert!(
            "::/0"
                .parse::<IpNetwork>()
                .unwrap()
                .contains("2001:db8::1".parse().unwrap())
        );
        assert!("192.0.2.0/33".parse::<IpNetwork>().is_err());
        assert!("2001:db8::/129".parse::<IpNetwork>().is_err());
    }

    #[test]
    fn expression_parses_boolean_chains_fields_and_networks() {
        let condition = parse_expression(
            r#"proto == tcp && src.ip in 10.0.0.0/8 && (http.host == "blocked.test" || tls.sni == "blocked.test") && !reverse == true"#,
        )
        .unwrap();
        assert!(condition.references_field("http.host"));
        assert!(condition.references_field("tls.sni"));
        assert!(!condition.references_field("dns.qname"));
        assert!(matches!(condition, Condition::All(_)));
        assert_eq!(
            parse_expression("fresh.dns.qname == blocked.test").unwrap(),
            Condition::FieldMatch {
                field: "dns.qname".into(),
                value: "blocked.test".into(),
                fresh: true,
                operator: TextOperator::Equals,
            }
        );
        assert_eq!(
            parse_expression("fresh.dns.answer_ipv4 in 203.0.113.0/24").unwrap(),
            Condition::FieldIpIn {
                field: "dns.answer_ipv4".into(),
                network: "203.0.113.0/24".parse().unwrap(),
                fresh: true,
            }
        );
        assert_eq!(
            parse_expression("proto == udp || proto == tcp && dst.port == 80").unwrap(),
            Condition::Any(vec![
                Condition::Protocol(Protocol::Udp),
                Condition::All(vec![
                    Condition::Protocol(Protocol::Tcp),
                    Condition::Port {
                        endpoint: Endpoint::Destination,
                        value: 80,
                    },
                ]),
            ])
        );
        assert!(parse_expression("src.ip in 10.0.0.0/99").is_err());
        assert!(parse_expression("dns.answer_ipv4 in 203.0.113.0/33").is_err());
        assert!(parse_expression("proto == tcp &&").is_err());
        assert!(parse_expression("(proto == udp").is_err());
        assert!(parse_expression("proto = udp").is_err());
    }

    #[test]
    fn protocol_eligibility_respects_boolean_negation() {
        let field_possible =
            |field: &str, protocol| field != "http.host" || protocol == Protocol::Tcp;
        let tcp_only = parse_expression("proto == tcp && http.host == blocked.test").unwrap();
        assert!(tcp_only.can_match_protocol(Protocol::Tcp, &field_possible));
        assert!(!tcp_only.can_match_protocol(Protocol::Udp, &field_possible));
        let negated = parse_expression("!(proto == udp)").unwrap();
        assert!(negated.can_match_protocol(Protocol::Tcp, &field_possible));
        assert!(!negated.can_match_protocol(Protocol::Udp, &field_possible));
        let mixed = parse_expression("proto == tcp || proto == udp").unwrap();
        assert!(mixed.can_match_protocol(Protocol::Tcp, &field_possible));
        assert!(mixed.can_match_protocol(Protocol::Udp, &field_possible));
        let absent_field = parse_expression("!(http.host == blocked.test)").unwrap();
        assert!(absent_field.can_match_protocol(Protocol::Udp, &field_possible));
        let present_field = parse_expression("http.host exists").unwrap();
        assert!(present_field.references_field("http.host"));
        assert!(present_field.can_match_protocol(Protocol::Tcp, &field_possible));
        assert!(!present_field.can_match_protocol(Protocol::Udp, &field_possible));
    }

    #[test]
    fn flow_candidate_keeps_future_reverse_direction_possible() {
        let source = "10.0.0.1:1234".parse().unwrap();
        let destination = "192.0.2.2:80".parse().unwrap();
        let possible = |expression| {
            parse_expression(expression).unwrap().can_match_new_flow(
                Protocol::Tcp,
                source,
                destination,
            )
        };
        assert!(possible("src.port == 80 && reverse == true"));
        assert!(possible("dst.port == 80 && reverse == false"));
        assert!(possible("src.ip in 192.0.2.0/24"));
        assert!(possible("!(origin.port == 80)"));
        assert!(!possible("dst.port == 443"));
        assert!(!possible("origin.port == 80"));
        assert!(!possible("!(target.port == 80)"));
        assert!(!possible("proto == udp"));
        assert!(possible("src.port >= 80 && src.port < 2000"));
        assert!(!possible("dst.port > 60000"));
        assert!(!possible("origin.port != 1234"));
        assert!(possible("payload.len > 100"));
    }

    #[test]
    fn presence_and_numeric_comparisons_validate_operands() {
        assert_eq!(
            parse_expression("fresh.wireguard.type exists").unwrap(),
            Condition::FieldExists {
                field: "wireguard.type".into(),
                fresh: true,
            }
        );
        assert!(parse_expression("payload.len >= 32").is_ok());
        assert!(parse_expression("src.port != 53").is_ok());
        assert!(parse_expression("src.port > many").is_err());
        assert!(parse_expression("payload.len > -1").is_err());
        assert!(parse_expression("http.status >= many").is_err());
        assert!(parse_expression("proto exists").is_err());
        assert!(parse_expression("payload.len exists").is_err());
        assert!(parse_expression("src.ip > 10.0.0.1").is_err());
    }

    #[test]
    fn named_conditions_expand_inside_boolean_expressions() {
        let mut resolve = |name: &str| match name {
            "web" => parse_expression("http.host == blocked.test || tls.sni == blocked.test"),
            _ => Err(format!("unknown expression reference @{name}")),
        };
        let actual = parse_expression_with("proto == tcp && @web", &mut resolve).unwrap();
        let expected = parse_expression(
            "proto == tcp && (http.host == blocked.test || tls.sni == blocked.test)",
        )
        .unwrap();
        assert_eq!(actual, expected);
        assert!(parse_expression("@web").is_err());
        assert!(parse_expression_with("@", &mut resolve).is_err());
    }
}
