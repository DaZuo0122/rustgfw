use rustgfw_core::{
    conditions::{MatchRule, parse_expression},
    inspect::FlowAction,
};
use serde::Deserialize;
use std::{error::Error, fs, path::Path};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleFile {
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

fn decode_hex(value: &str) -> Result<Vec<u8>, String> {
    let value = value.strip_prefix("0x").unwrap_or(value);
    if !value.len().is_multiple_of(2) {
        return Err("replacement_hex must have an even number of digits".into());
    }
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let pair = std::str::from_utf8(pair).unwrap();
            u8::from_str_radix(pair, 16).map_err(|_| format!("invalid replacement_hex byte {pair}"))
        })
        .collect()
}

pub fn compile(source: &str) -> Result<Vec<MatchRule>, String> {
    let file: RuleFile = serde_json::from_str(source).map_err(|error| error.to_string())?;
    file.rules
        .into_iter()
        .map(|spec| {
            let condition = parse_expression(&spec.expr)
                .map_err(|error| format!("rule {:?}: {error}", spec.name))?;
            for field in condition.fields() {
                if !matches!(field, "http.host" | "tls.sni" | "dns.qname") {
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
                        (None, Some(value)) => decode_hex(&value)
                            .map_err(|error| format!("rule {:?}: {error}", spec.name))?,
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
}
