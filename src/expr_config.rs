use rustgfw_core::{
    conditions::{Condition, MatchRule, parse_expression_with, parse_hex_bytes},
    inspect::FlowAction,
};
use serde::Deserialize;
use std::{collections::HashMap, error::Error, fs, path::Path};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleFile {
    #[serde(default)]
    expressions: HashMap<String, String>,
    rules: Vec<RuleSpec>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleSpec {
    name: String,
    expr: String,
    action: String,
    replacement: Option<String>,
    replacement_hex: Option<String>,
}

fn parse_with_expressions(
    source: &str,
    expressions: &HashMap<String, String>,
    active: &mut Vec<String>,
) -> Result<Condition, String> {
    parse_expression_with(source, &mut |name| {
        if active.iter().any(|item| item == name) {
            return Err(format!(
                "cyclic expression reference: {} -> {name}",
                active.join(" -> ")
            ));
        }
        let expression = expressions
            .get(name)
            .ok_or_else(|| format!("unknown expression reference @{name}"))?;
        active.push(name.to_owned());
        let result = parse_with_expressions(expression, expressions, active);
        active.pop();
        result
    })
}

pub fn compile(source: &str) -> Result<Vec<MatchRule>, String> {
    let file: RuleFile = serde_json::from_str(source).map_err(|error| error.to_string())?;
    file.rules
        .into_iter()
        .map(|spec| {
            let condition = parse_with_expressions(&spec.expr, &file.expressions, &mut Vec::new())
                .map_err(|error| format!("rule {:?}: {error}", spec.name))?;
            for field in condition.fields() {
                if !matches!(
                    field,
                    "http.host"
                        | "tls.sni"
                        | "dns.qname"
                        | "ssh.protocol"
                        | "ssh.software"
                        | "ssh.banner"
                ) && !rustgfw_core::wireguard::FIELDS.contains(&field)
                {
                    return Err(format!("rule {:?}: unknown observation field {field}", spec.name));
                }
            }
            let action = match spec.action.as_str() {
                "allow" => FlowAction::Allow,
                "block" => FlowAction::Block,
                "drop_packet" => FlowAction::DropPacket,
                "replace_udp_payload" => {
                    let payload = match (spec.replacement, spec.replacement_hex) {
                        (Some(value), None) => value.into_bytes(),
                        (None, Some(value)) => parse_hex_bytes(&value)
                            .map_err(|error| format!("rule {:?}: invalid replacement_hex: {error}", spec.name))?,
                        _ => {
                            return Err(format!(
                                "rule {:?}: replace_udp_payload requires one replacement or replacement_hex",
                                spec.name
                            ));
                        }
                    };
                    FlowAction::ReplaceUdpPayload(payload)
                }
                other => return Err(format!("rule {:?}: unknown action {other}", spec.name)),
            };
            Ok(MatchRule { condition, action })
        })
        .collect()
}

pub fn load(path: &Path) -> Result<Vec<MatchRule>, Box<dyn Error>> {
    let source = fs::read_to_string(path)?;
    compile(&source).map_err(|error| format!("{}: {error}", path.display()).into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compiles_ordered_expression_rules_and_rejects_invalid_fields() {
        let rules = compile(
            r#"{"rules":[
                {"name":"web","expr":"proto == tcp && (http.host == \"blocked.test\" || tls.sni == \"blocked.test\")","action":"block"},
                {"name":"rewrite","expr":"proto == udp && payload == \"old\"","action":"replace_udp_payload","replacement_hex":"0x6e6577"}
            ]}"#,
        )
        .unwrap();
        assert_eq!(rules.len(), 2);
        assert!(rules[0].condition.references_field("http.host"));
        assert_eq!(
            rules[1].action,
            FlowAction::ReplaceUdpPayload(b"new".to_vec())
        );
        assert!(
            compile(r#"{"rules":[{"name":"bad","expr":"typo.host == x","action":"block"}]}"#)
                .unwrap_err()
                .contains("unknown observation field")
        );
        assert!(compile(r#"{"rules":[{"name":"bad","expr":"proto == udp","action":"replace_udp_payload","replacement_hex":"z0"}]}"#)
            .unwrap_err()
            .contains("invalid replacement_hex"));
    }

    #[test]
    fn expands_reusable_expressions_and_rejects_reference_cycles() {
        let rules = compile(
            r#"{
                "expressions": {
                    "web": "http.host == blocked.test || tls.sni == blocked.test",
                    "restricted": "proto == tcp && @web"
                },
                "rules": [
                    {"name":"block web", "expr":"@restricted && !reverse == true", "action":"block"},
                    {"name":"allow web", "expr":"@web", "action":"allow"}
                ]
            }"#,
        )
        .unwrap();
        assert_eq!(rules.len(), 2);
        assert_eq!(
            rules[0].condition,
            rustgfw_core::conditions::parse_expression(
                "(proto == tcp && (http.host == blocked.test || tls.sni == blocked.test)) && !reverse == true"
            )
            .unwrap()
        );
        assert!(rules[1].condition.references_field("tls.sni"));

        let cycle = compile(
            r#"{"expressions":{"a":"@b","b":"@a"},"rules":[{"name":"loop","expr":"@a","action":"block"}]}"#,
        )
        .unwrap_err();
        assert!(cycle.contains("cyclic expression reference: a -> b -> a"));
        let unknown =
            compile(r#"{"rules":[{"name":"missing","expr":"@missing","action":"block"}]}"#)
                .unwrap_err();
        assert!(unknown.contains("unknown expression reference @missing"));
    }
}
