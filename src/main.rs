use rustgfw_core::{
    Verdict,
    conditions::MatchRule,
    inspect::{AnalyzerRule, DatagramPort, DatagramRule, InspectLimits, UdpStreamRule},
    packet::Protocol,
    rules::{Rule, RulesLimits},
};
use std::time::Duration;

mod expr_config;

type Error = Box<dyn std::error::Error>;

fn main() -> Result<(), Error> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    match args.first().map(String::as_str) {
        Some("nfqueue") => run_nfqueue(&args[1..]),
        Some("windivert") => run_windivert(&args[1..]),
        _ => Err("usage: rustgfw nfqueue <queue> <accept|drop> [rules...] [nft=input|output|forward] [ctmark=0x80000000] | rustgfw windivert <dll> <network|forward> <accept|drop> [rules...]; shared options: rules-file=path inspect-flows=N transport-flows=N flow-idle-seconds=N reorder-bytes=N http-header-bytes=N tls-buffer-bytes=N dns-message-bytes=N".into()),
    }
}

struct Options {
    default: Verdict,
    rules: Vec<Rule>,
    http_hosts: Vec<String>,
    tls_sni: Vec<String>,
    dns_names: Vec<String>,
    expr_rules: Vec<MatchRule>,
    nft_hook: Option<String>,
    ctmark: Option<u32>,
    inspect_limits: InspectLimits,
    rules_limits: RulesLimits,
    http_header_bytes: usize,
    tls_buffer_bytes: usize,
    dns_message_bytes: usize,
}
impl Options {
    fn parse(default: &str, args: &[String]) -> Result<Self, Error> {
        let default = match default {
            "accept" => Verdict::Accept,
            "drop" => Verdict::Drop,
            _ => return Err("policy must be accept or drop".into()),
        };
        let mut options = Self {
            default,
            rules: Vec::new(),
            http_hosts: Vec::new(),
            tls_sni: Vec::new(),
            dns_names: Vec::new(),
            expr_rules: Vec::new(),
            nft_hook: None,
            ctmark: None,
            inspect_limits: InspectLimits::default(),
            rules_limits: RulesLimits::default(),
            http_header_bytes: 16384,
            tls_buffer_bytes: 131072,
            dns_message_bytes: 65535,
        };
        let mut rule_file_seen = false;
        for arg in args {
            if let Some(host) = arg.strip_prefix("http-host=") {
                options.http_hosts.push(host.to_owned());
            } else if let Some(host) = arg.strip_prefix("tls-sni=") {
                options.tls_sni.push(host.to_owned());
            } else if let Some(name) = arg.strip_prefix("dns-name=") {
                options
                    .dns_names
                    .push(name.trim_end_matches('.').to_ascii_lowercase());
            } else if let Some(path) = arg.strip_prefix("rules-file=") {
                if rule_file_seen {
                    return Err("specify at most one rules file".into());
                }
                options.expr_rules = expr_config::load(std::path::Path::new(path))?;
                rule_file_seen = true;
            } else if let Some(hook) = arg.strip_prefix("nft=") {
                if options.nft_hook.replace(hook.to_owned()).is_some() {
                    return Err("specify at most one nft hook".into());
                }
            } else if let Some(mask) = arg.strip_prefix("ctmark=") {
                let mask = mask
                    .strip_prefix("0x")
                    .ok_or("ctmark must be hexadecimal, for example 0x80000000")?;
                let mask = u32::from_str_radix(mask, 16)?;
                if mask.count_ones() != 1 || options.ctmark.replace(mask).is_some() {
                    return Err("specify one reserved ctmark bit".into());
                }
            } else if let Some(value) = arg.strip_prefix("inspect-flows=") {
                options.inspect_limits.max_flows = value.parse()?;
            } else if let Some(value) = arg.strip_prefix("transport-flows=") {
                options.rules_limits.max_flows = value.parse()?;
            } else if let Some(value) = arg.strip_prefix("flow-idle-seconds=") {
                let seconds: u64 = value.parse()?;
                if seconds == 0 {
                    return Err("flow-idle-seconds must be positive".into());
                }
                let idle = Duration::from_secs(seconds);
                options.inspect_limits.idle = idle;
                options.rules_limits.idle = idle;
            } else if let Some(value) = arg.strip_prefix("reorder-bytes=") {
                options.inspect_limits.reorder_bytes = value.parse()?;
            } else if let Some(value) = arg.strip_prefix("http-header-bytes=") {
                options.http_header_bytes = value.parse()?;
                if options.http_header_bytes == 0 {
                    return Err("http-header-bytes must be positive".into());
                }
            } else if let Some(value) = arg.strip_prefix("tls-buffer-bytes=") {
                options.tls_buffer_bytes = value.parse()?;
                if options.tls_buffer_bytes == 0 {
                    return Err("tls-buffer-bytes must be positive".into());
                }
            } else if let Some(value) = arg.strip_prefix("dns-message-bytes=") {
                options.dns_message_bytes = value.parse()?;
                if options.dns_message_bytes == 0 {
                    return Err("dns-message-bytes must be positive".into());
                }
            } else {
                options.rules.push(parse_rule(arg)?);
            }
        }
        Ok(options)
    }

    fn into_policy(self) -> impl rustgfw_core::Policy {
        use rustgfw_core::{
            dns::{DnsDatagram, DnsUdp},
            inspect::{FlowRule, Inspect},
            rules::Rules,
        };
        let http_header_bytes = self.http_header_bytes;
        let tls_buffer_bytes = self.tls_buffer_bytes;
        let dns_message_bytes = self.dns_message_bytes;
        let dns_names = self.dns_names;
        let field_possible = |field: &str, protocol| {
            !matches!(field, "http.host" | "tls.sni") || protocol == Protocol::Tcp
        };
        let eligible = |rule: &MatchRule, protocol| {
            rule.condition.can_match_protocol(protocol, &field_possible)
        };
        let needs_tcp_field = |field| {
            self.expr_rules
                .iter()
                .any(|rule| eligible(rule, Protocol::Tcp) && rule.condition.references_field(field))
        };
        let needs_http = needs_tcp_field("http.host");
        let needs_tls = needs_tcp_field("tls.sni");
        let needs_dns_tcp = needs_tcp_field("dns.qname");
        let needs_dns_udp = self.expr_rules.iter().any(|rule| {
            eligible(rule, Protocol::Udp) && rule.condition.references_field("dns.qname")
        });
        let tcp_rules: Vec<FlowRule> = self
            .expr_rules
            .iter()
            .filter(|rule| eligible(rule, Protocol::Tcp))
            .cloned()
            .map(MatchRule::into_flow_rule)
            .collect();
        let udp_rules: Vec<FlowRule> = self
            .expr_rules
            .into_iter()
            .filter(|rule| eligible(rule, Protocol::Udp))
            .map(MatchRule::into_flow_rule)
            .collect();
        let analyzers = [
            if self.http_hosts.is_empty() {
                needs_http.then(|| {
                    AnalyzerRule::observing(None, move || {
                        Box::new(rustgfw_core::inspect::HttpHost::with_header_limit(
                            http_header_bytes,
                        ))
                    })
                })
            } else {
                AnalyzerRule::exact("http.host", self.http_hosts, None, move || {
                    Box::new(rustgfw_core::inspect::HttpHost::with_header_limit(
                        http_header_bytes,
                    ))
                })
            },
            if self.tls_sni.is_empty() {
                needs_tls.then(|| {
                    AnalyzerRule::observing(None, move || {
                        Box::new(rustgfw_core::tls::TlsSni::with_buffer_limit(
                            tls_buffer_bytes,
                        ))
                    })
                })
            } else {
                AnalyzerRule::exact("tls.sni", self.tls_sni, None, move || {
                    Box::new(rustgfw_core::tls::TlsSni::with_buffer_limit(
                        tls_buffer_bytes,
                    ))
                })
            },
            if dns_names.is_empty() {
                needs_dns_tcp.then(|| {
                    AnalyzerRule::observing(Some(53), move || {
                        Box::new(rustgfw_core::dns::DnsTcp::with_message_limit(
                            dns_message_bytes,
                        ))
                    })
                })
            } else {
                AnalyzerRule::exact("dns.qname", dns_names.clone(), Some(53), move || {
                    Box::new(rustgfw_core::dns::DnsTcp::with_message_limit(
                        dns_message_bytes,
                    ))
                })
            },
        ]
        .into_iter()
        .flatten()
        .collect();
        let datagrams = DatagramRule::exact(
            "dns.qname",
            dns_names,
            Some(DatagramPort::Destination(53)),
            DnsDatagram,
        )
        .into_iter()
        .collect();
        let udp_analyzers = if needs_dns_udp {
            vec![UdpStreamRule::new(Some(DatagramPort::Either(53)), || {
                Box::new(DnsUdp)
            })]
        } else {
            Vec::new()
        };
        Inspect::with_datagrams(
            Rules::with_limits(self.rules, self.default, self.rules_limits),
            analyzers,
            datagrams,
            self.inspect_limits,
        )
        .with_flow_rules(tcp_rules)
        .with_udp_streams(udp_analyzers, udp_rules)
    }
}

#[cfg(target_os = "linux")]
fn run_nfqueue(args: &[String]) -> Result<(), Error> {
    use rustgfw_core::KernelPolicy;
    use rustgfw_linux::nft::{DynamicOffload, Hook, NftPolicy, Plan};
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };

    if args.len() < 2 {
        return Err("usage: rustgfw nfqueue <queue> <accept|drop> [rules...]".into());
    }
    let number: u16 = args[0].parse()?;
    let options = Options::parse(&args[1], &args[2..])?;
    let hook = options
        .nft_hook
        .as_deref()
        .map(|hook| match hook {
            "input" => Ok(Hook::Input),
            "output" => Ok(Hook::Output),
            "forward" => Ok(Hook::Forward),
            _ => Err("nft hook must be input, output or forward"),
        })
        .transpose()?;
    if options.ctmark.is_some() && hook.is_none() {
        return Err("ctmark requires a managed nft hook".into());
    }
    let dynamic = options
        .ctmark
        .map_or(DynamicOffload::IdSet, DynamicOffload::ConntrackMark);
    let stop = Arc::new(AtomicBool::new(false));
    signal_hook::flag::register(signal_hook::consts::SIGINT, stop.clone())?;
    signal_hook::flag::register(signal_hook::consts::SIGTERM, stop.clone())?;
    let mut backend = rustgfw_linux::NfQueue::open(number)?;
    let mut kernel = NftPolicy::new("/usr/sbin/nft");
    let installed = hook
        .map(|hook| {
            kernel.install(&Plan {
                hook,
                queue: number,
                rules: rustgfw_core::offload::compile(&options.rules),
                dynamic,
                bypass_without_listener: false,
            })
        })
        .transpose()?;
    if let Some(handle) = &installed {
        eprintln!("installed nft table {}", handle.table_name());
        if let Some(mask) = options.ctmark {
            backend.set_mark_offload(mask);
        } else if let Err(error) = backend.set_dynamic_table(handle.table_name()) {
            kernel.revoke(handle)?;
            return Err(error.into());
        }
    }
    let mut engine = rustgfw_core::Engine::new(options.into_policy());
    let mut last_queue_overflow = None::<std::time::Instant>;
    let result = (|| -> std::io::Result<()> {
        while !stop.load(Ordering::Relaxed) {
            match engine.step(&mut backend) {
                Err(e) if e.raw_os_error() == Some(libc::ENOBUFS) => {
                    if last_queue_overflow.is_none_or(|at| at.elapsed().as_secs() >= 1) {
                        eprintln!("NFQUEUE receive buffer overflow; kernel dropped packets");
                        last_queue_overflow = Some(std::time::Instant::now());
                    }
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock
                            | std::io::ErrorKind::TimedOut
                            | std::io::ErrorKind::Interrupted
                    ) => {}
                result => result?,
            }
        }
        Ok(())
    })();
    let worker_result = backend.stop_offload();
    if let Some(handle) = &installed
        && let Err(error) = kernel.revoke(handle)
    {
        return Err(format!(
            "failed to remove nft table {}: {error}; engine result: {result:?}; offload worker result: {worker_result:?}",
            handle.table_name()
        )
        .into());
    }
    worker_result?;
    result?;
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn run_nfqueue(_: &[String]) -> Result<(), Error> {
    Err("NFQUEUE requires Linux".into())
}

#[cfg(target_os = "windows")]
fn run_windivert(args: &[String]) -> Result<(), Error> {
    use rustgfw_windows::{
        Layer, WinDivert, dynamic::FlowBlocker, static_drop_filter, wfp::WfpPolicy,
    };

    if args.len() < 3 {
        return Err(
            "usage: rustgfw windivert <dll> <network|forward> <accept|drop> [rules...]".into(),
        );
    }
    let layer = match args[1].as_str() {
        "network" => Layer::Network,
        "forward" => Layer::Forward,
        _ => return Err("WinDivert layer must be network or forward".into()),
    };
    let options = Options::parse(&args[2], &args[3..])?;
    if options.nft_hook.is_some() {
        return Err("nft= is only available with NFQUEUE".into());
    }
    if options.ctmark.is_some() {
        return Err("ctmark= is only available with NFQUEUE".into());
    }
    // Valid ICMP is always accepted by the transport/DPI policy when the
    // default is Accept. Leave it on the native path: WinDivert cannot
    // reinject some inbound ICMP/ICMPv6 packets. Fragments still reach the
    // engine, where unsupported reassembly is handled consistently.
    let packet_filter = if options.default == Verdict::Accept {
        "(not icmp and not icmpv6) or fragment"
    } else {
        "true"
    };
    let dynamic = if matches!(layer, Layer::Network)
        && (!options.http_hosts.is_empty()
            || !options.tls_sni.is_empty()
            || !options.dns_names.is_empty())
    {
        match FlowBlocker::start(&args[0]) {
            Ok(blocker) => Some(blocker),
            Err(error) => {
                eprintln!("WFP dynamic offload unavailable: {error}; using WinDivert policy");
                None
            }
        }
    } else {
        None
    };
    let mut io = WinDivert::open(&args[0], layer, packet_filter)?;
    if let Some(blocker) = &dynamic {
        io.set_dynamic_offload(blocker.sender());
    }
    if matches!(layer, Layer::Forward)
        && let Some(filter) = static_drop_filter(&options.rules)
    {
        match io.install_drop_filter(&filter) {
            Ok(()) => eprintln!("installed WinDivert static drop filter"),
            Err(error) => {
                eprintln!("WinDivert static offload unavailable: {error}; using packet policy")
            }
        }
    }
    let _wfp = if matches!(layer, Layer::Network)
        && options
            .rules
            .first()
            .is_some_and(|rule| matches!(rule.verdict, Verdict::Drop | Verdict::DropFlow))
    {
        match WfpPolicy::open().and_then(|mut policy| {
            policy
                .install_static(&options.rules)
                .map(|count| (policy, count))
        }) {
            Ok((policy, count)) => {
                eprintln!("installed {count} WFP static filters");
                Some(policy)
            }
            Err(error) => {
                eprintln!("WFP static offload unavailable: {error}; using WinDivert policy");
                None
            }
        }
    } else {
        None
    };
    let mut engine = rustgfw_core::Engine::new(options.into_policy());
    loop {
        engine.step(&mut io)?;
    }
}

#[cfg(not(target_os = "windows"))]
fn run_windivert(_: &[String]) -> Result<(), Error> {
    Err("WinDivert requires Windows".into())
}

fn parse_rule(text: &str) -> Result<Rule, Error> {
    use rustgfw_core::packet::Protocol;
    let fields: Vec<_> = text.split(':').collect();
    if fields.len() != 3 {
        return Err(format!("invalid rule: {text}; expected protocol:port:action").into());
    }
    let protocol = match fields[0] {
        "tcp" => Some(Protocol::Tcp),
        "udp" => Some(Protocol::Udp),
        "any" => None,
        _ => return Err(format!("unknown protocol: {}", fields[0]).into()),
    };
    let port = if fields[1] == "any" {
        None
    } else {
        Some(fields[1].parse()?)
    };
    let verdict = match fields[2] {
        "accept" => Verdict::Accept,
        "drop" => Verdict::Drop,
        _ => return Err(format!("unknown action: {}", fields[2]).into()),
    };
    Ok(Rule {
        protocol,
        port,
        verdict,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustgfw_core::{FlowScope, Packet, Policy};

    #[test]
    fn cli_resource_limits_reach_shared_http_policy() {
        let request = b"GET / HTTP/1.1\r\nHost: blocked.test\r\n\r\n";
        let mut bytes = vec![0; 40 + request.len()];
        let length = bytes.len() as u16;
        bytes[0] = 0x45;
        bytes[2..4].copy_from_slice(&length.to_be_bytes());
        bytes[9] = 6;
        bytes[12..16].copy_from_slice(&[192, 0, 2, 1]);
        bytes[16..20].copy_from_slice(&[198, 51, 100, 2]);
        bytes[20..22].copy_from_slice(&12345u16.to_be_bytes());
        bytes[22..24].copy_from_slice(&80u16.to_be_bytes());
        bytes[32] = 0x50;
        bytes[33] = 0x18;
        bytes[40..].copy_from_slice(request);
        let packet = Packet {
            bytes: &bytes,
            original_len: bytes.len(),
            checksum_ready: true,
            scope: FlowScope::default(),
        };
        for (limit, expected) in [(16, Verdict::Accept), (64, Verdict::DropFlow)] {
            let args = [
                "http-host=blocked.test".to_owned(),
                format!("http-header-bytes={limit}"),
                "inspect-flows=1".to_owned(),
                "transport-flows=0".to_owned(),
                "flow-idle-seconds=60".to_owned(),
                "reorder-bytes=1024".to_owned(),
            ];
            let mut policy = Options::parse("accept", &args).unwrap().into_policy();
            assert_eq!(policy.evaluate(packet), expected);
        }
        let mut options = Options::parse("accept", &[]).unwrap();
        options.expr_rules = expr_config::compile(
            r#"{"rules":[{"name":"web substring","expr":"proto == tcp && http.host contains LOCKED","action":"block"}]}"#,
        )
        .unwrap();
        assert_eq!(options.into_policy().evaluate(packet), Verdict::DropFlow);
        assert!(Options::parse("accept", &["flow-idle-seconds=0".into()]).is_err());
    }
    #[test]
    fn cli_dns_message_budget_reaches_tcp_analyzer() {
        let mut query = vec![0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        query.extend_from_slice(b"\x07example\x03com\x00\x00\x01\x00\x01");
        let mut bytes = vec![0; 42 + query.len()];
        let length = bytes.len() as u16;
        bytes[0] = 0x45;
        bytes[2..4].copy_from_slice(&length.to_be_bytes());
        bytes[9] = 6;
        bytes[12..16].copy_from_slice(&[192, 0, 2, 1]);
        bytes[16..20].copy_from_slice(&[198, 51, 100, 2]);
        bytes[20..22].copy_from_slice(&12345u16.to_be_bytes());
        bytes[22..24].copy_from_slice(&53u16.to_be_bytes());
        bytes[32] = 0x50;
        bytes[33] = 0x18;
        bytes[40..42].copy_from_slice(&(query.len() as u16).to_be_bytes());
        bytes[42..].copy_from_slice(&query);
        let packet = Packet {
            bytes: &bytes,
            original_len: bytes.len(),
            checksum_ready: true,
            scope: FlowScope::default(),
        };
        for (limit, expected) in [(16, Verdict::Accept), (64, Verdict::DropFlow)] {
            let args = [
                "dns-name=example.com".to_owned(),
                format!("dns-message-bytes={limit}"),
            ];
            let mut policy = Options::parse("accept", &args).unwrap().into_policy();
            assert_eq!(policy.evaluate(packet), expected);
        }
        assert!(Options::parse("accept", &["tls-buffer-bytes=0".into()]).is_err());
        assert!(Options::parse("accept", &["dns-message-bytes=0".into()]).is_err());
    }

    #[test]
    fn expression_file_combines_dns_observation_and_packet_action() {
        let path =
            std::path::PathBuf::from(format!("target/expr-rules-{}.json", std::process::id()));
        std::fs::write(
            &path,
            r#"{"expressions":{
                "blocked_dns":"proto == udp && fresh.dns.qname == blocked.test",
                "rewrite_old":"proto == udp && payload == \"old\""
            },"rules":[
                {"name":"blocked DNS","expr":"@blocked_dns","action":"drop_packet"},
                {"name":"rewrite","expr":"@rewrite_old","action":"replace_udp_payload","replacement":"new"},
                {"name":"binary","expr":"proto == udp && payload_hex starts_with 0x00ff","action":"drop_packet"}
            ]}"#,
        )
        .unwrap();
        let options = Options::parse("accept", &[format!("rules-file={}", path.display())]);
        std::fs::remove_file(&path).unwrap();
        let mut policy = options.unwrap().into_policy();

        let query = |name: &str| {
            let mut dns = vec![0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
            for label in name.split('.') {
                dns.push(label.len() as u8);
                dns.extend_from_slice(label.as_bytes());
            }
            dns.extend_from_slice(&[0, 0, 1, 0, 1]);
            dns
        };
        let udp = |payload: &[u8], destination_port: u16| {
            let mut bytes = vec![0; 28];
            let length = (bytes.len() + payload.len()) as u16;
            bytes[0] = 0x45;
            bytes[2..4].copy_from_slice(&length.to_be_bytes());
            bytes[9] = 17;
            bytes[12] = 10;
            bytes[16] = 20;
            bytes[20..22].copy_from_slice(&12345u16.to_be_bytes());
            bytes[22..24].copy_from_slice(&destination_port.to_be_bytes());
            bytes[24..26].copy_from_slice(&(8 + payload.len() as u16).to_be_bytes());
            bytes.extend_from_slice(payload);
            bytes
        };
        let mut decide = |bytes: &[u8]| {
            policy.decide(Packet {
                bytes,
                original_len: bytes.len(),
                checksum_ready: true,
                scope: FlowScope::default(),
            })
        };
        let blocked = udp(&query("blocked.test"), 53);
        assert_eq!(
            decide(&blocked),
            rustgfw_core::Decision::Verdict(Verdict::Drop)
        );
        let allowed = udp(&query("allowed.test"), 53);
        assert_eq!(
            decide(&allowed),
            rustgfw_core::Decision::Verdict(Verdict::Accept)
        );
        let rewritten = udp(b"old", 5353);
        let rustgfw_core::Decision::Replace(output) = decide(&rewritten) else {
            panic!("expected a rewritten UDP packet");
        };
        assert_eq!(
            rustgfw_core::packet::parse(&output).unwrap().payload,
            b"new"
        );
        let binary = udp(&[0, 255, 1], 5353);
        assert_eq!(
            decide(&binary),
            rustgfw_core::Decision::Verdict(Verdict::Drop)
        );
    }

    #[test]
    fn tcp_only_expression_does_not_consume_udp_flow_capacity() {
        let mut options = Options::parse("accept", &[]).unwrap();
        options.inspect_limits.max_flows = 0;
        options.expr_rules = expr_config::compile(
            r#"{"rules":[{"name":"web","expr":"proto == tcp && http.host == blocked.test","action":"block"}]}"#,
        )
        .unwrap();
        let mut policy = options.into_policy();
        let mut bytes = vec![0; 31];
        bytes[0] = 0x45;
        bytes[2..4].copy_from_slice(&31u16.to_be_bytes());
        bytes[9] = 17;
        bytes[12] = 10;
        bytes[16] = 20;
        bytes[20..22].copy_from_slice(&12345u16.to_be_bytes());
        bytes[22..24].copy_from_slice(&9999u16.to_be_bytes());
        bytes[24..26].copy_from_slice(&11u16.to_be_bytes());
        bytes[28..].copy_from_slice(b"udp");
        assert_eq!(
            policy.evaluate(Packet {
                bytes: &bytes,
                original_len: bytes.len(),
                checksum_ready: true,
                scope: FlowScope::default(),
            }),
            Verdict::Accept
        );
    }
}
