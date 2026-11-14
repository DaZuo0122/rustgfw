//! Static policy intent; kernel routing hooks and handles stay in backends.
use crate::packet::Protocol;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Drop,
    /// A terminal ordered match that still requires userspace inspection.
    Inspect,
    /// Skip this engine's userspace inspection. Other system policies still apply.
    BypassInspection,
}

#[derive(Clone, Debug)]
pub struct Rule {
    pub protocol: Protocol,
    /// Either source or destination port; None matches every port.
    pub port: Option<u16>,
    pub action: Action,
}

/// Preserve first-match semantics. Accept rules remain inspect actions because
/// later application rules and packet validation still have to run.
pub fn compile(rules: &[crate::rules::Rule]) -> Vec<Rule> {
    let mut output = Vec::new();
    for rule in rules {
        for protocol in [Protocol::Tcp, Protocol::Udp] {
            if rule.protocol.is_some_and(|p| p != protocol) {
                continue;
            }
            output.push(Rule {
                protocol,
                port: rule.port,
                action: match rule.verdict {
                    crate::Verdict::Drop | crate::Verdict::DropFlow => Action::Drop,
                    crate::Verdict::Accept => Action::Inspect,
                },
            });
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn acceptance_stays_a_terminal_inspection_match() {
        let rules = compile(&[
            crate::rules::Rule {
                protocol: Some(Protocol::Udp),
                port: Some(53),
                verdict: crate::Verdict::Accept,
            },
            crate::rules::Rule {
                protocol: None,
                port: None,
                verdict: crate::Verdict::Drop,
            },
        ]);
        assert_eq!(rules.len(), 3);
        assert_eq!(rules[0].action, Action::Inspect);
        assert_eq!(rules[0].port, Some(53));
        assert_eq!(rules[1].action, Action::Drop);
        assert_eq!(rules[2].protocol, Protocol::Udp);
    }
}
