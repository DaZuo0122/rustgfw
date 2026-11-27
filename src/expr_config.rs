use rustgfw_core::{
    conditions::{Condition, parse_expression_with, parse_hex_bytes},
    inspect::FlowAction,
    rule_graph::{RuleGraph, RuleSpec as GraphRuleSpec},
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
    id: String,
    expr: String,
    requires: Option<String>,
    scope: Option<String>,
    action: Option<String>,
    priority: Option<u8>,
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

pub fn compile(source: &str) -> Result<RuleGraph, String> {
    let file: RuleFile = serde_json::from_str(source).map_err(|error| error.to_string())?;
    file.rules
        .into_iter()
        .map(|spec| {
            let condition = parse_with_expressions(&spec.expr, &file.expressions, &mut Vec::new())
                .map_err(|error| format!("rule {:?}: {error}", spec.id))?;
            for field in condition.fields() {
                if !matches!(
                    field,
                    "ssh.protocol"
                        | "ssh.software"
                        | "ssh.banner"
                ) && !rustgfw_core::dns::FIELDS.contains(&field)
                    && !rustgfw_core::http::FIELDS.contains(&field)
                    && !rustgfw_core::http2::FIELDS.contains(&field)
                    && !rustgfw_core::mux_cool::FIELDS.contains(&field)
                    && !rustgfw_core::http3::FIELDS.contains(&field)
                    && !rustgfw_core::tls::FIELDS.contains(&field)
                    && !rustgfw_core::trojan::FIELDS.contains(&field)
                    && !rustgfw_core::fet::FIELDS.contains(&field)
                    && !rustgfw_core::tcp_rtt::FIELDS.contains(&field)
                    && !rustgfw_core::tcp_shape::FIELDS.contains(&field)
                    && !rustgfw_core::wireguard::FIELDS.contains(&field)
                    && !rustgfw_core::openvpn::FIELDS.contains(&field)
                    && !rustgfw_core::socks::FIELDS.contains(&field)
                    && !rustgfw_core::vless::FIELDS.contains(&field)
                    && !rustgfw_core::sing_mux::FIELDS.contains(&field)
                    && !rustgfw_core::sing_mux_frames::FIELDS.contains(&field)
                    && !rustgfw_core::quic::FIELDS.contains(&field)
                    && !rustgfw_core::dtls::FIELDS.contains(&field)
                    && !rustgfw_core::udp_shape::FIELDS.contains(&field)
                {
                    return Err(format!("rule {:?}: unknown observation field {field}", spec.id));
                }
            }
            let action = match spec.action.as_deref() {
                None => None,
                Some("allow") => Some(FlowAction::Allow),
                Some("allow_flow") => Some(FlowAction::AllowFlow),
                Some("block") => Some(FlowAction::Block),
                Some("drop_packet") => Some(FlowAction::DropPacket),
                Some("replace_udp_payload") => {
                    let payload = match (spec.replacement, spec.replacement_hex) {
                        (Some(value), None) => value.into_bytes(),
                        (None, Some(value)) => parse_hex_bytes(&value)
                            .map_err(|error| format!("rule {:?}: invalid replacement_hex: {error}", spec.id))?,
                        _ => {
                            return Err(format!(
                                "rule {:?}: replace_udp_payload requires one replacement or replacement_hex",
                                spec.id
                            ));
                        }
                    };
                    Some(FlowAction::ReplaceUdpPayload(payload))
                }
                Some(other) => return Err(format!("rule {:?}: unknown action {other}", spec.id)),
            };
            Ok(GraphRuleSpec {
                id: spec.id,
                condition,
                requires: spec.requires,
                scope: spec.scope,
                action,
                priority: spec.priority.unwrap_or(3),
            })
        })
        .collect::<Result<Vec<_>, String>>()
        .and_then(RuleGraph::compile)
}

pub fn load(path: &Path) -> Result<RuleGraph, Box<dyn Error>> {
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
                {"id":"web","expr":"proto == tcp && (http.host == \"blocked.test\" || tls.sni == \"blocked.test\")","action":"block"},
                {"id":"rewrite","expr":"proto == udp && payload == \"old\"","action":"replace_udp_payload","replacement_hex":"0x6e6577"}
            ]}"#,
        )
        .unwrap();
        assert_eq!(rules.len(), 2);
        assert!(rules[0].condition.references_field("http.host"));
        assert_eq!(
            rules[1].action,
            Some(FlowAction::ReplaceUdpPayload(b"new".to_vec()))
        );
        assert!(
            compile(r#"{"rules":[{"id":"bad","expr":"typo.host == x","action":"block"}]}"#)
                .unwrap_err()
                .contains("unknown observation field")
        );
        assert!(compile(r#"{"rules":[{"id":"bad","expr":"proto == udp","action":"replace_udp_payload","replacement_hex":"z0"}]}"#)
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
                    {"id":"block_web", "expr":"@restricted && !reverse == true", "action":"block"},
                    {"id":"allow_web", "expr":"@web", "action":"allow"}
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
        let flow_allow = compile(
            r#"{"rules":[{"id":"trusted_carrier","expr":"http2.path == /trusted","action":"allow_flow"}]}"#,
        )
        .unwrap();
        assert_eq!(flow_allow[0].action, Some(FlowAction::AllowFlow));

        let presence = compile(
            r#"{"rules":[{"id":"data","expr":"wireguard.type exists && payload.len >= 32 && dst.port != 53","action":"drop_packet"}]}"#,
        )
        .unwrap();
        assert!(presence[0].condition.references_field("wireguard.type"));
        let quic = compile(
            r#"{"rules":[{"id":"datagram","expr":"fresh.quic.alpn == h3 && quic.datagram_max_size > 0","action":"drop_packet"}]}"#,
        )
        .unwrap();
        assert!(quic[0].condition.references_field("quic.datagram_max_size"));
        let http3 = compile(
            r#"{"rules":[{"id":"auth","expr":"fresh.http3.status == 233 && http3.request_header_name == hysteria-auth","action":"block"}]}"#,
        )
        .unwrap();
        assert!(
            http3[0]
                .condition
                .references_field("http3.request_header_name")
        );
        assert!(
            compile(r#"{"rules":[{"id":"bad","expr":"unknown.field exists","action":"block"}]}"#)
                .unwrap_err()
                .contains("unknown observation field")
        );

        let cycle = compile(
            r#"{"expressions":{"a":"@b","b":"@a"},"rules":[{"id":"loop","expr":"@a","action":"block"}]}"#,
        )
        .unwrap_err();
        assert!(cycle.contains("cyclic expression reference: a -> b -> a"));
        let unknown = compile(r#"{"rules":[{"id":"missing","expr":"@missing","action":"block"}]}"#)
            .unwrap_err();
        assert!(unknown.contains("unknown expression reference @missing"));
    }
}
