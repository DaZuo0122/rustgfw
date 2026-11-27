//! Stateful dependencies between application rules.
use crate::{
    conditions::Condition,
    inspect::{FlowAction, FlowContext, action_label},
};
use std::collections::HashMap;

#[derive(Clone, Debug)]
pub struct RuleSpec {
    pub id: String,
    pub condition: Condition,
    pub requires: Option<String>,
    pub scope: Option<String>,
    pub action: Option<FlowAction>,
    /// One is the highest priority; five is the lowest.
    pub priority: u8,
}

#[derive(Clone, Debug)]
enum Requirement {
    Rule(usize),
    All(Vec<Self>),
    Any(Vec<Self>),
}
impl Requirement {
    fn satisfied(&self, hit: &impl Fn(usize) -> bool) -> bool {
        match self {
            Self::Rule(index) => hit(*index),
            Self::All(items) => items.iter().all(|item| item.satisfied(hit)),
            Self::Any(items) => items.iter().any(|item| item.satisfied(hit)),
        }
    }

    fn references(&self, output: &mut Vec<usize>) {
        match self {
            Self::Rule(index) => output.push(*index),
            Self::All(items) | Self::Any(items) => {
                for item in items {
                    item.references(output);
                }
            }
        }
    }

    fn fulfilled_by(&self, hit: &impl Fn(usize) -> bool, output: &mut Vec<usize>) {
        match self {
            Self::Rule(index) => output.push(*index),
            Self::All(items) => {
                for item in items {
                    item.fulfilled_by(hit, output);
                }
            }
            Self::Any(items) => {
                if let Some(item) = items.iter().find(|item| item.satisfied(hit)) {
                    item.fulfilled_by(hit, output);
                }
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RuleScope {
    Flow,
    Stream(&'static str),
}
impl RuleScope {
    fn parse(source: Option<&str>) -> Result<Self, String> {
        match source.unwrap_or("flow") {
            "flow" => Ok(Self::Flow),
            "http2.stream_id" => Ok(Self::Stream("http2.stream_id")),
            "sing_mux.stream_id" => Ok(Self::Stream("sing_mux.stream_id")),
            "mux_cool.session_id" => Ok(Self::Stream("mux_cool.session_id")),
            "http3.stream_id" => Ok(Self::Stream("http3.stream_id")),
            other => Err(format!("unknown rule scope {other:?}")),
        }
    }

    fn event_key<'a>(
        self,
        context: &'a FlowContext<'_>,
    ) -> Option<Option<(&'static str, &'a str)>> {
        match self {
            Self::Flow => Some(None),
            Self::Stream(field) if context.updated(field) => {
                context.get(field).map(|value| Some((field, value)))
            }
            Self::Stream(_) => None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct RuleNode {
    pub id: String,
    pub condition: Condition,
    requires: Option<Requirement>,
    scope: RuleScope,
    pub action: Option<FlowAction>,
    pub priority: u8,
}

#[derive(Clone, Debug, Default)]
pub struct RuleGraph {
    nodes: Vec<RuleNode>,
    order: Vec<usize>,
}
impl RuleGraph {
    pub fn compile(specs: Vec<RuleSpec>) -> Result<Self, String> {
        let mut ids = HashMap::new();
        for (index, spec) in specs.iter().enumerate() {
            if !valid_id(&spec.id) {
                return Err(format!(
                    "invalid rule id {:?}: use letters, digits, '_' or '-'",
                    spec.id
                ));
            }
            if ids.insert(spec.id.clone(), index).is_some() {
                return Err(format!("duplicate rule id {:?}", spec.id));
            }
            if !(1..=5).contains(&spec.priority) {
                return Err(format!("rule {:?}: priority must be 1..5", spec.id));
            }
        }
        let nodes = specs
            .into_iter()
            .map(|spec| {
                let requires = spec
                    .requires
                    .as_deref()
                    .map(|source| parse_requirements(source, &ids))
                    .transpose()
                    .map_err(|error| format!("rule {:?}: {error}", spec.id))?;
                let scope = RuleScope::parse(spec.scope.as_deref())
                    .map_err(|error| format!("rule {:?}: {error}", spec.id))?;
                Ok(RuleNode {
                    id: spec.id,
                    condition: spec.condition,
                    requires,
                    scope,
                    action: spec.action,
                    priority: spec.priority,
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        for node in &nodes {
            if let Some(requires) = &node.requires {
                let mut references = Vec::new();
                requires.references(&mut references);
                for dependency in references {
                    let parent = &nodes[dependency];
                    if !matches!(
                        (node.scope, parent.scope),
                        (RuleScope::Flow, RuleScope::Flow)
                            | (RuleScope::Stream(_), RuleScope::Flow)
                    ) && node.scope != parent.scope
                    {
                        return Err(format!(
                            "rule {:?}: incompatible dependency scope {:?} in {:?}",
                            node.id, parent.scope, parent.id
                        ));
                    }
                }
            }
        }
        let mut states = vec![0u8; nodes.len()];
        let mut stack = Vec::new();
        let mut order = Vec::with_capacity(nodes.len());
        for index in 0..nodes.len() {
            visit(index, &nodes, &mut states, &mut stack, &mut order)?;
        }
        Ok(Self { nodes, order })
    }

    pub fn nodes(&self) -> &[RuleNode] {
        &self.nodes
    }

    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    pub fn evaluate(
        &self,
        context: &FlowContext<'_>,
        state: &mut RuleState,
        stream_id: Option<u64>,
        supports_replacement: bool,
    ) -> Option<RuleDecision> {
        state.event_seq += 1;
        let mut selected = None;
        let mut candidates = 0;
        for &index in &self.order {
            let node = &self.nodes[index];
            let Some(scope_key) = node.scope.event_key(context) else {
                continue;
            };
            let hit = |dependency: usize| {
                let key = match self.nodes[dependency].scope {
                    RuleScope::Flow => None,
                    RuleScope::Stream(_) => scope_key,
                };
                state.hit(dependency, key)
            };
            if !node
                .requires
                .as_ref()
                .is_none_or(|requires| requires.satisfied(&hit))
                || !node.condition.matches(context)
            {
                continue;
            }
            if state.mark(index, scope_key) {
                let event_stream_id = stream_id
                    .or_else(|| scope_key.and_then(|(_, value)| value.parse::<u64>().ok()));
                let stream_scope = scope_key
                    .map(|(field, value)| format!("{field}:{value}"))
                    .unwrap_or_default();
                tracing::debug!(flow_id = state.flow_id, scope = context.scope.0,
                    stream_id = event_stream_id, stream_scope = %stream_scope,
                    event_seq = state.event_seq, rule_id = %node.id,
                    origin = %context.origin, target = %context.target,
                    "rule hit recorded");
            }
            if node.action.as_ref().is_some_and(|action| {
                !matches!(action, FlowAction::ReplaceUdpPayload(_)) || supports_replacement
            }) {
                candidates += 1;
                if selected.is_none_or(|other: usize| {
                    let previous = &self.nodes[other];
                    (node.priority, index) < (previous.priority, other)
                }) {
                    selected = Some(index);
                }
            }
        }
        let index = selected?;
        let node = &self.nodes[index];
        let scope_key = node.scope.event_key(context).flatten();
        let hit = |dependency: usize| {
            let key = match self.nodes[dependency].scope {
                RuleScope::Flow => None,
                RuleScope::Stream(_) => scope_key,
            };
            state.hit(dependency, key)
        };
        let mut fulfilled = Vec::new();
        if let Some(requires) = &node.requires {
            requires.fulfilled_by(&hit, &mut fulfilled);
        }
        let via = fulfilled
            .into_iter()
            .map(|index| self.nodes[index].id.as_str())
            .collect::<Vec<_>>()
            .join(",");
        let stream_scope = scope_key.map(|(field, value)| format!("{field}:{value}"));
        tracing::debug!(flow_id = state.flow_id, scope = context.scope.0,
            stream_id, stream_scope = ?stream_scope,
            event_seq = state.event_seq, rule_id = %node.id,
            priority = node.priority, candidates,
            action = action_label(node.action.as_ref().unwrap()), via = %via,
            "application rule matched");
        Some(RuleDecision {
            id: node.id.clone(),
            action: node.action.clone().expect("selected rule has an action"),
            priority: node.priority,
            via,
            stream_scope,
            flow_id: state.flow_id,
            event_seq: state.event_seq,
        })
    }
}
impl std::ops::Deref for RuleGraph {
    type Target = [RuleNode];

    fn deref(&self) -> &Self::Target {
        &self.nodes
    }
}

#[derive(Clone, Debug)]
pub struct RuleState {
    hits: Vec<bool>,
    stream_hits: HashMap<(&'static str, String), Vec<bool>>,
    pub flow_id: u64,
    event_seq: u64,
}
impl RuleState {
    pub fn new(rule_count: usize, flow_id: u64) -> Self {
        Self {
            hits: vec![false; rule_count],
            stream_hits: HashMap::new(),
            flow_id,
            event_seq: 0,
        }
    }

    pub fn clear_stream(&mut self, field: &'static str, value: &str) {
        self.stream_hits.remove(&(field, value.to_owned()));
    }

    fn hit(&self, index: usize, key: Option<(&'static str, &str)>) -> bool {
        match key {
            None => self.hits[index],
            Some((field, value)) => self
                .stream_hits
                .get(&(field, value.to_owned()))
                .is_some_and(|hits| hits[index]),
        }
    }

    fn mark(&mut self, index: usize, key: Option<(&'static str, &str)>) -> bool {
        let hits = match key {
            None => &mut self.hits,
            Some((field, value)) => self
                .stream_hits
                .entry((field, value.to_owned()))
                .or_insert_with(|| vec![false; self.hits.len()]),
        };
        if hits[index] {
            false
        } else {
            hits[index] = true;
            true
        }
    }
}

#[derive(Clone, Debug)]
pub struct RuleDecision {
    pub id: String,
    pub action: FlowAction,
    pub priority: u8,
    pub via: String,
    pub stream_scope: Option<String>,
    pub flow_id: u64,
    pub event_seq: u64,
}

fn visit(
    index: usize,
    nodes: &[RuleNode],
    states: &mut [u8],
    stack: &mut Vec<usize>,
    order: &mut Vec<usize>,
) -> Result<(), String> {
    match states[index] {
        2 => return Ok(()),
        1 => {
            let start = stack.iter().position(|item| *item == index).unwrap();
            let cycle = stack[start..]
                .iter()
                .chain(std::iter::once(&index))
                .map(|item| nodes[*item].id.as_str())
                .collect::<Vec<_>>()
                .join(" -> ");
            return Err(format!("cyclic rule dependency: {cycle}"));
        }
        _ => {}
    }
    states[index] = 1;
    stack.push(index);
    if let Some(requires) = &nodes[index].requires {
        let mut references = Vec::new();
        requires.references(&mut references);
        for dependency in references {
            visit(dependency, nodes, states, stack, order)?;
        }
    }
    stack.pop();
    states[index] = 2;
    order.push(index);
    Ok(())
}

fn valid_id(id: &str) -> bool {
    let mut chars = id.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

struct RequirementParser<'a> {
    source: &'a [u8],
    position: usize,
    ids: &'a HashMap<String, usize>,
}
impl RequirementParser<'_> {
    fn whitespace(&mut self) {
        while self
            .source
            .get(self.position)
            .is_some_and(u8::is_ascii_whitespace)
        {
            self.position += 1;
        }
    }

    fn consume(&mut self, token: &[u8]) -> bool {
        self.whitespace();
        if self.source[self.position..].starts_with(token) {
            self.position += token.len();
            true
        } else {
            false
        }
    }

    fn atom(&mut self) -> Result<Requirement, String> {
        if self.consume(b"(") {
            let value = self.any()?;
            if !self.consume(b")") {
                return Err("missing ')' in requires".into());
            }
            return Ok(value);
        }
        self.whitespace();
        let start = self.position;
        while self
            .source
            .get(self.position)
            .is_some_and(|c| c.is_ascii_alphanumeric() || *c == b'_' || *c == b'-')
        {
            self.position += 1;
        }
        let id = std::str::from_utf8(&self.source[start..self.position]).unwrap();
        if id.is_empty() {
            return Err(format!("expected rule id in requires at byte {start}"));
        }
        self.ids
            .get(id)
            .copied()
            .map(Requirement::Rule)
            .ok_or_else(|| format!("unknown required rule {id:?}"))
    }

    fn all(&mut self) -> Result<Requirement, String> {
        let mut items = vec![self.atom()?];
        while self.consume(b"&&") {
            items.push(self.atom()?);
        }
        Ok(if items.len() == 1 {
            items.pop().unwrap()
        } else {
            Requirement::All(items)
        })
    }

    fn any(&mut self) -> Result<Requirement, String> {
        let mut items = vec![self.all()?];
        while self.consume(b"||") {
            items.push(self.all()?);
        }
        Ok(if items.len() == 1 {
            items.pop().unwrap()
        } else {
            Requirement::Any(items)
        })
    }
}

fn parse_requirements(source: &str, ids: &HashMap<String, usize>) -> Result<Requirement, String> {
    let mut parser = RequirementParser {
        source: source.as_bytes(),
        position: 0,
        ids,
    };
    let result = parser.any()?;
    parser.whitespace();
    if parser.position != parser.source.len() {
        return Err(format!(
            "unexpected token in requires at byte {}",
            parser.position
        ));
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(id: &str, requires: Option<&str>) -> RuleSpec {
        RuleSpec {
            id: id.into(),
            condition: crate::conditions::parse_expression("proto == udp").unwrap(),
            requires: requires.map(str::to_owned),
            scope: None,
            action: None,
            priority: 3,
        }
    }

    #[test]
    fn dependencies_compile_independently_of_file_order() {
        let graph = RuleGraph::compile(vec![
            spec("decision", Some("first && (second || third)")),
            spec("third", None),
            spec("first", None),
            spec("second", None),
        ])
        .unwrap();
        assert_eq!(graph.order.last(), Some(&0));
        let mut hits = [false; 4];
        hits[1] = true;
        hits[2] = true;
        assert!(
            graph.nodes[0]
                .requires
                .as_ref()
                .unwrap()
                .satisfied(&|i| hits[i])
        );
        hits[1] = false;
        assert!(
            !graph.nodes[0]
                .requires
                .as_ref()
                .unwrap()
                .satisfied(&|i| hits[i])
        );
    }

    #[test]
    fn rejects_cycles_even_inside_or_branches() {
        let error = RuleGraph::compile(vec![
            spec("a", Some("b || c")),
            spec("b", Some("a")),
            spec("c", None),
        ])
        .unwrap_err();
        assert!(error.contains("a -> b -> a"), "{error}");
        assert!(RuleGraph::compile(vec![spec("a", Some("missing"))]).is_err());
        assert!(RuleGraph::compile(vec![spec("a", None), spec("a", None)]).is_err());
    }

    #[test]
    fn rejects_invalid_priority_and_cross_stream_dependencies() {
        let mut invalid = spec("a", None);
        invalid.priority = 6;
        assert!(
            RuleGraph::compile(vec![invalid])
                .unwrap_err()
                .contains("1..5")
        );

        let mut child = spec("child", Some("parent"));
        child.scope = Some("http2.stream_id".into());
        let mut parent = spec("parent", None);
        parent.scope = Some("mux_cool.session_id".into());
        assert!(
            RuleGraph::compile(vec![child, parent])
                .unwrap_err()
                .contains("incompatible dependency scope")
        );
    }
}
