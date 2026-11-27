use rustgfw_core::{
    Verdict,
    inspect::{
        AnalyzerRule, BidirectionalAnalyzerRule, DatagramPort, DatagramRule, InspectLimits,
        TcpPacketRule, UdpStreamRule,
    },
    packet::Protocol,
    rule_graph::{RuleGraph, RuleNode},
    rules::{Rule, RulesLimits},
};
use std::time::Duration;

mod decoded_http3;
mod expr_config;

type Error = Box<dyn std::error::Error>;

fn observation_field_possible(field: &str, protocol: Protocol) -> bool {
    if rustgfw_core::wireguard::FIELDS.contains(&field)
        || rustgfw_core::quic::FIELDS.contains(&field)
        || rustgfw_core::dtls::FIELDS.contains(&field)
        || rustgfw_core::udp_shape::FIELDS.contains(&field)
        || rustgfw_core::http3::FIELDS.contains(&field)
    {
        protocol == Protocol::Udp
    } else if rustgfw_core::openvpn::FIELDS.contains(&field) {
        protocol == Protocol::Udp || rustgfw_core::openvpn::TCP_FIELDS.contains(&field)
    } else if rustgfw_core::socks::FIELDS.contains(&field)
        || rustgfw_core::vless::FIELDS.contains(&field)
        || rustgfw_core::http::FIELDS.contains(&field)
        || rustgfw_core::http2::FIELDS.contains(&field)
        || rustgfw_core::mux_cool::FIELDS.contains(&field)
        || rustgfw_core::sing_mux::FIELDS.contains(&field)
        || rustgfw_core::sing_mux_frames::FIELDS.contains(&field)
        || rustgfw_core::fet::FIELDS.contains(&field)
        || rustgfw_core::tcp_rtt::FIELDS.contains(&field)
        || rustgfw_core::tcp_shape::FIELDS.contains(&field)
        || rustgfw_core::tls::FIELDS.contains(&field)
        || rustgfw_core::trojan::FIELDS.contains(&field)
    {
        protocol == Protocol::Tcp
    } else {
        !matches!(field, "ssh.protocol" | "ssh.software" | "ssh.banner")
            || protocol == Protocol::Tcp
    }
}

fn main() -> Result<(), Error> {
    init_logging()?;
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    match args.first().map(String::as_str) {
        Some("nfqueue") => run_nfqueue(&args[1..]),
        Some("windivert") => run_windivert(&args[1..]),
        Some("decoded-http3") => decoded_http3::run(&args[1..]),
        _ => Err("usage: rustgfw nfqueue <queue> <accept|drop> [rules...] [nft=input|output|forward] [ctmark=0x80000000] | rustgfw windivert <dll> <network|forward> <accept|drop> [rules...] | rustgfw decoded-http3 rules-file=path; shared options: inspect-flows=N transport-flows=N flow-idle-seconds=N reorder-bytes=N http-header-bytes=N tls-buffer-bytes=N dns-message-bytes=N ssh-banner-bytes=N".into()),
    }
}

fn init_logging() -> Result<(), Error> {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    match std::env::var("RUSTGFW_LOG_FORMAT").as_deref() {
        Ok("json") => tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_writer(std::io::stderr)
            .json()
            .try_init()
            .map_err(std::io::Error::other)?,
        Ok("text") | Err(_) => tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_writer(std::io::stderr)
            .try_init()
            .map_err(std::io::Error::other)?,
        Ok(other) => {
            return Err(
                format!("unknown RUSTGFW_LOG_FORMAT {other:?}; expected text or json").into(),
            );
        }
    }
    Ok(())
}

struct Options {
    default: Verdict,
    rules: Vec<Rule>,
    http_hosts: Vec<String>,
    tls_sni: Vec<String>,
    dns_names: Vec<String>,
    expr_rules: RuleGraph,
    nft_hook: Option<String>,
    ctmark: Option<u32>,
    inspect_limits: InspectLimits,
    rules_limits: RulesLimits,
    http_header_bytes: usize,
    tls_buffer_bytes: usize,
    dns_message_bytes: usize,
    ssh_banner_bytes: usize,
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
            expr_rules: RuleGraph::default(),
            nft_hook: None,
            ctmark: None,
            inspect_limits: InspectLimits::default(),
            rules_limits: RulesLimits::default(),
            http_header_bytes: 16384,
            tls_buffer_bytes: 131072,
            dns_message_bytes: 65535,
            ssh_banner_bytes: 1024,
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
            } else if let Some(value) = arg.strip_prefix("ssh-banner-bytes=") {
                options.ssh_banner_bytes = value.parse()?;
                if options.ssh_banner_bytes == 0 {
                    return Err("ssh-banner-bytes must be positive".into());
                }
            } else {
                options.rules.push(parse_rule(arg)?);
            }
        }
        Ok(options)
    }

    #[cfg(target_os = "windows")]
    fn needs_wfp_flow_offload(&self) -> bool {
        use rustgfw_core::inspect::FlowAction;

        !self.http_hosts.is_empty()
            || !self.tls_sni.is_empty()
            || !self.dns_names.is_empty()
            || self.expr_rules.iter().any(|rule| match rule.action {
                Some(FlowAction::Block) => {
                    rule.condition
                        .can_match_protocol(Protocol::Tcp, &observation_field_possible)
                        || rule
                            .condition
                            .can_match_protocol(Protocol::Udp, &observation_field_possible)
                }
                Some(FlowAction::DropPacket) => rule
                    .condition
                    .can_match_protocol(Protocol::Tcp, &observation_field_possible),
                _ => false,
            })
    }

    fn into_policy(self) -> rustgfw_core::inspect::Inspect<rustgfw_core::rules::Rules> {
        use rustgfw_core::{
            dns::{DnsDatagram, DnsUdp},
            inspect::Inspect,
            rules::Rules,
        };
        let http_header_bytes = self.http_header_bytes;
        let tls_buffer_bytes = self.tls_buffer_bytes;
        let dns_message_bytes = self.dns_message_bytes;
        let ssh_banner_bytes = self.ssh_banner_bytes;
        let dns_names = self.dns_names;
        let eligible = |rule: &RuleNode, protocol| {
            rule.condition
                .can_match_protocol(protocol, &observation_field_possible)
        };
        let needs_tcp_field = |field| {
            self.expr_rules
                .iter()
                .any(|rule| eligible(rule, Protocol::Tcp) && rule.condition.references_field(field))
        };
        let needs_http = rustgfw_core::http::FIELDS
            .iter()
            .any(|field| needs_tcp_field(field));
        let needs_http2 = rustgfw_core::http2::FIELDS
            .iter()
            .any(|field| needs_tcp_field(field));
        let needs_mux_cool = rustgfw_core::mux_cool::FIELDS
            .iter()
            .any(|field| needs_tcp_field(field));
        let needs_sing_mux = rustgfw_core::sing_mux::FIELDS
            .iter()
            .any(|field| needs_tcp_field(field))
            || rustgfw_core::sing_mux_frames::FIELDS
                .iter()
                .any(|field| needs_tcp_field(field));
        let needs_tls = rustgfw_core::tls::FIELDS
            .iter()
            .any(|field| needs_tcp_field(field));
        let needs_dns_tcp = rustgfw_core::dns::FIELDS
            .iter()
            .any(|field| needs_tcp_field(field));
        let needs_ssh = ["ssh.protocol", "ssh.software", "ssh.banner"]
            .into_iter()
            .any(needs_tcp_field);
        let needs_socks = rustgfw_core::socks::FIELDS
            .iter()
            .any(|field| needs_tcp_field(field));
        let needs_vless = rustgfw_core::vless::FIELDS
            .iter()
            .any(|field| needs_tcp_field(field));
        let needs_fet = rustgfw_core::fet::FIELDS
            .iter()
            .any(|field| needs_tcp_field(field));
        let needs_tcp_shape = rustgfw_core::tcp_shape::FIELDS
            .iter()
            .any(|field| needs_tcp_field(field));
        let needs_tcp_rtt = rustgfw_core::tcp_rtt::FIELDS
            .iter()
            .any(|field| needs_tcp_field(field));
        let needs_trojan = rustgfw_core::trojan::FIELDS
            .iter()
            .any(|field| needs_tcp_field(field));
        let needs_dns_udp = self.expr_rules.iter().any(|rule| {
            eligible(rule, Protocol::Udp)
                && rustgfw_core::dns::FIELDS
                    .iter()
                    .any(|field| rule.condition.references_field(field))
        });
        let needs_wireguard_udp = self.expr_rules.iter().any(|rule| {
            eligible(rule, Protocol::Udp)
                && rustgfw_core::wireguard::FIELDS
                    .iter()
                    .any(|field| rule.condition.references_field(field))
        });
        let needs_openvpn_udp = self.expr_rules.iter().any(|rule| {
            eligible(rule, Protocol::Udp)
                && rustgfw_core::openvpn::FIELDS
                    .iter()
                    .any(|field| rule.condition.references_field(field))
        });
        let needs_quic_client = self.expr_rules.iter().any(|rule| {
            eligible(rule, Protocol::Udp)
                && rustgfw_core::quic::FIELDS.iter().any(|field| {
                    !rustgfw_core::quic::SERVER_FIELDS.contains(field)
                        && rule.condition.references_field(field)
                })
        });
        let needs_quic_server = self.expr_rules.iter().any(|rule| {
            eligible(rule, Protocol::Udp)
                && rustgfw_core::quic::SERVER_FIELDS
                    .iter()
                    .any(|field| rule.condition.references_field(field))
        });
        let needs_dtls_udp = self.expr_rules.iter().any(|rule| {
            eligible(rule, Protocol::Udp)
                && rustgfw_core::dtls::FIELDS
                    .iter()
                    .any(|field| rule.condition.references_field(field))
        });
        let needs_udp_shape = self.expr_rules.iter().any(|rule| {
            eligible(rule, Protocol::Udp)
                && rustgfw_core::udp_shape::FIELDS
                    .iter()
                    .any(|field| rule.condition.references_field(field))
        });
        let needs_openvpn_tcp = self.expr_rules.iter().any(|rule| {
            eligible(rule, Protocol::Tcp)
                && rustgfw_core::openvpn::TCP_FIELDS
                    .iter()
                    .any(|field| rule.condition.references_field(field))
        });
        let analyzers = [
            if self.tls_sni.is_empty() {
                needs_tls.then(|| {
                    AnalyzerRule::observing(None, move || {
                        Box::new(rustgfw_core::tls::TlsHello::with_buffer_limit(
                            tls_buffer_bytes,
                        ))
                    })
                })
            } else {
                AnalyzerRule::exact("tls.sni", self.tls_sni, None, move || {
                    Box::new(rustgfw_core::tls::TlsHello::with_buffer_limit(
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
            needs_ssh.then(|| {
                AnalyzerRule::observing(None, move || {
                    Box::new(rustgfw_core::ssh::SshBanner::with_limit(ssh_banner_bytes))
                })
            }),
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
        let udp_analyzers = [
            needs_dns_udp
                .then(|| UdpStreamRule::new(Some(DatagramPort::Either(53)), || Box::new(DnsUdp))),
            needs_wireguard_udp.then(|| {
                UdpStreamRule::new(None, || {
                    Box::new(rustgfw_core::wireguard::WireGuard::default())
                })
            }),
            needs_openvpn_udp.then(|| {
                UdpStreamRule::new(None, || {
                    Box::new(rustgfw_core::openvpn::OpenVpnUdp::default())
                })
            }),
            needs_quic_client.then(|| {
                UdpStreamRule::new(
                    None,
                    || Box::new(rustgfw_core::quic::QuicInitial::default()),
                )
            }),
            needs_quic_server.then(|| {
                UdpStreamRule::new(None, || {
                    Box::new(rustgfw_core::quic::QuicServerInitial::default())
                })
            }),
            needs_dtls_udp.then(|| {
                UdpStreamRule::new(None, || Box::new(rustgfw_core::dtls::DtlsHello::default()))
            }),
            needs_udp_shape.then(|| {
                UdpStreamRule::new(None, || {
                    Box::new(rustgfw_core::udp_shape::UdpShape::default())
                })
            }),
        ]
        .into_iter()
        .flatten()
        .collect();
        Inspect::with_datagrams(
            Rules::with_limits(self.rules, self.default, self.rules_limits),
            analyzers,
            datagrams,
            self.inspect_limits,
        )
        .with_bidirectional_analyzers(
            [
                if self.http_hosts.is_empty() {
                    needs_http.then(|| {
                        BidirectionalAnalyzerRule::observing(None, move || {
                            Box::new(rustgfw_core::http::HttpConversation::with_header_limit(
                                http_header_bytes,
                            ))
                        })
                    })
                } else {
                    BidirectionalAnalyzerRule::exact(
                        "http.host",
                        self.http_hosts,
                        None,
                        move || {
                            Box::new(rustgfw_core::http::HttpConversation::with_header_limit(
                                http_header_bytes,
                            ))
                        },
                    )
                },
                needs_openvpn_tcp.then(|| {
                    BidirectionalAnalyzerRule::observing(None, || {
                        Box::new(rustgfw_core::openvpn::OpenVpnTcp::default())
                    })
                }),
                needs_http2.then(|| {
                    BidirectionalAnalyzerRule::observing(None, || {
                        Box::<rustgfw_core::http2::Http2Conversation>::default()
                    })
                }),
                needs_mux_cool.then(|| {
                    BidirectionalAnalyzerRule::observing(None, || {
                        Box::<rustgfw_core::mux_cool::MuxCool>::default()
                    })
                }),
                (needs_sing_mux || needs_http2).then(|| {
                    BidirectionalAnalyzerRule::observing(None, || {
                        Box::<rustgfw_core::sing_mux::SingMuxH2>::default()
                    })
                }),
                needs_sing_mux.then(|| {
                    BidirectionalAnalyzerRule::observing(None, || {
                        Box::<rustgfw_core::sing_mux_frames::SingMuxFrames>::default()
                    })
                }),
                needs_socks.then(|| {
                    BidirectionalAnalyzerRule::observing(None, || {
                        Box::new(rustgfw_core::socks::SocksRequest::default())
                    })
                }),
                needs_vless.then(|| {
                    BidirectionalAnalyzerRule::observing(None, || {
                        Box::new(rustgfw_core::vless::VlessRequest::default())
                    })
                }),
                needs_fet.then(|| {
                    BidirectionalAnalyzerRule::observing(None, || {
                        Box::new(rustgfw_core::fet::FullyEncryptedTraffic::default())
                    })
                }),
                needs_trojan.then(|| {
                    BidirectionalAnalyzerRule::observing(None, || {
                        Box::new(rustgfw_core::trojan::TrojanSequence::default())
                    })
                }),
            ]
            .into_iter()
            .flatten()
            .collect(),
        )
        .with_tcp_packet_analyzers(
            [
                needs_tcp_shape.then(|| {
                    TcpPacketRule::new(None, || {
                        Box::new(rustgfw_core::tcp_shape::TcpShape::default())
                    })
                }),
                needs_tcp_rtt.then(|| {
                    TcpPacketRule::new(None, || Box::new(rustgfw_core::tcp_rtt::TcpRtt::default()))
                }),
            ]
            .into_iter()
            .flatten()
            .collect(),
        )
        .with_udp_streams(udp_analyzers, Vec::new())
        .with_rule_graph(self.expr_rules)
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
    let dynamic = if matches!(layer, Layer::Network) && options.needs_wfp_flow_offload() {
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
    fn dependent_rules_remember_prior_udp_packets_and_resolve_priority() {
        let udp = |source_port: u16, payload: &[u8]| {
            let mut bytes = vec![0; 28 + payload.len()];
            let length = bytes.len() as u16;
            bytes[0] = 0x45;
            bytes[2..4].copy_from_slice(&length.to_be_bytes());
            bytes[9] = 17;
            bytes[12..16].copy_from_slice(&[192, 0, 2, 1]);
            bytes[16..20].copy_from_slice(&[198, 51, 100, 2]);
            bytes[20..22].copy_from_slice(&source_port.to_be_bytes());
            bytes[22..24].copy_from_slice(&443u16.to_be_bytes());
            bytes[24..26].copy_from_slice(&(8 + payload.len() as u16).to_be_bytes());
            bytes[28..].copy_from_slice(payload);
            bytes
        };
        let mut options = Options::parse("accept", &[]).unwrap();
        options.expr_rules = expr_config::compile(
            r#"{"rules":[
                {"id":"drop_after_hello","requires":"hello","expr":"payload == world","action":"drop_packet","priority":5},
                {"id":"hello","expr":"payload == hello"},
                {"id":"allow_after_hello","requires":"hello","expr":"payload == world","action":"allow","priority":1}
            ]}"#,
        )
        .unwrap();
        let mut policy = options.into_policy();
        let evaluate = |policy: &mut dyn Policy, bytes: &[u8]| {
            policy.evaluate(Packet {
                bytes,
                original_len: bytes.len(),
                checksum_ready: true,
                scope: FlowScope(7),
                capture_time: None,
            })
        };
        assert_eq!(
            evaluate(&mut policy, &udp(12345, b"hello")),
            Verdict::Accept
        );
        assert_eq!(
            evaluate(&mut policy, &udp(12346, b"world")),
            Verdict::Accept
        );
        assert_eq!(
            evaluate(&mut policy, &udp(12345, b"world")),
            Verdict::Accept
        );

        let mut options = Options::parse("accept", &[]).unwrap();
        options.expr_rules = expr_config::compile(
            r#"{"rules":[
                {"id":"drop_after_hello","requires":"hello","expr":"payload == world","action":"drop_packet"},
                {"id":"hello","expr":"payload == hello"}
            ]}"#,
        )
        .unwrap();
        let mut policy = options.into_policy();
        assert_eq!(
            evaluate(&mut policy, &udp(12345, b"hello")),
            Verdict::Accept
        );
        assert_eq!(
            evaluate(&mut policy, &udp(12346, b"world")),
            Verdict::Accept
        );
        assert_eq!(evaluate(&mut policy, &udp(12345, b"world")), Verdict::Drop);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn expression_only_flow_blocks_enable_wfp_offload() {
        let mut options = Options::parse("accept", &[]).unwrap();
        assert!(!options.needs_wfp_flow_offload());
        options.expr_rules = expr_config::compile(
            r#"{"rules":[{"id":"tls_block","expr":"proto == tcp && tls.sni == blocked.test","action":"block"}]}"#,
        )
        .unwrap();
        assert!(options.needs_wfp_flow_offload());

        options.expr_rules = expr_config::compile(
            r#"{"rules":[{"id":"udp_packet_drop","expr":"proto == udp && dns.qname == blocked.test","action":"drop_packet"}]}"#,
        )
        .unwrap();
        assert!(!options.needs_wfp_flow_offload());

        options.expr_rules = expr_config::compile(
            r#"{"rules":[{"id":"tcp_packet_drop","expr":"proto == tcp && http.host == blocked.test","action":"drop_packet"}]}"#,
        )
        .unwrap();
        assert!(options.needs_wfp_flow_offload());
    }

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
            capture_time: None,
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
            r#"{"rules":[{"id":"web_substring","expr":"proto == tcp && http.host contains LOCKED","action":"block"}]}"#,
        )
        .unwrap();
        assert_eq!(options.into_policy().evaluate(packet), Verdict::DropFlow);
        assert!(Options::parse("accept", &["flow-idle-seconds=0".into()]).is_err());
    }

    #[test]
    fn ssh_expression_inspects_fragmented_banner_on_nonstandard_port() {
        let rules = expr_config::compile(
            r#"{"rules":[{"id":"ssh_software","expr":"proto == tcp && fresh.ssh.software contains openssh","action":"block"}]}"#,
        )
        .unwrap();
        let tcp = |sequence: u32, payload: &[u8]| {
            let mut bytes = vec![0; 40 + payload.len()];
            let length = bytes.len() as u16;
            bytes[0] = 0x45;
            bytes[2..4].copy_from_slice(&length.to_be_bytes());
            bytes[9] = 6;
            bytes[12..16].copy_from_slice(&[192, 0, 2, 1]);
            bytes[16..20].copy_from_slice(&[198, 51, 100, 2]);
            bytes[20..22].copy_from_slice(&12345u16.to_be_bytes());
            bytes[22..24].copy_from_slice(&2222u16.to_be_bytes());
            bytes[24..28].copy_from_slice(&sequence.to_be_bytes());
            bytes[32] = 0x50;
            bytes[33] = 0x18;
            bytes[40..].copy_from_slice(payload);
            bytes
        };
        let first = b"notice\r\nSSH-2.";
        let second = b"0-OpenSSH_9.9 comments\r\n";
        let first_packet = tcp(100, first);
        let second_packet = tcp(100 + first.len() as u32, second);
        for (limit, expected) in [(1024, Verdict::DropFlow), (8, Verdict::Accept)] {
            let mut options =
                Options::parse("accept", &[format!("ssh-banner-bytes={limit}")]).unwrap();
            options.expr_rules = rules.clone();
            let mut policy = options.into_policy();
            let evaluate = |policy: &mut dyn Policy, bytes: &[u8]| {
                policy.evaluate(Packet {
                    bytes,
                    original_len: bytes.len(),
                    checksum_ready: true,
                    scope: FlowScope::default(),
                    capture_time: None,
                })
            };
            assert_eq!(evaluate(&mut policy, &first_packet), Verdict::Accept);
            assert_eq!(evaluate(&mut policy, &second_packet), expected);
        }
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
            capture_time: None,
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
                {"id":"blocked_dns","expr":"@blocked_dns","action":"drop_packet"},
                {"id":"rewrite","expr":"@rewrite_old","action":"replace_udp_payload","replacement":"new"},
                {"id":"binary","expr":"proto == udp && payload_hex starts_with 0x00ff","action":"drop_packet"}
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
                capture_time: None,
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
    fn dns_expression_matches_query_type_and_response_code() {
        let dns = |name: &str, qtype: u16, response: bool, rcode: u8| {
            let mut message = vec![
                0,
                7,
                if response { 0x81 } else { 1 },
                if response { 0x80 | rcode } else { 0 },
                0,
                1,
                0,
                0,
                0,
                0,
                0,
                0,
            ];
            for label in name.split('.') {
                message.push(label.len() as u8);
                message.extend_from_slice(label.as_bytes());
            }
            message.push(0);
            message.extend_from_slice(&qtype.to_be_bytes());
            message.extend_from_slice(&1u16.to_be_bytes());
            message
        };
        let udp = |payload: &[u8], reverse: bool| {
            let mut bytes = vec![0; 28];
            let length = (bytes.len() + payload.len()) as u16;
            bytes[0] = 0x45;
            bytes[2..4].copy_from_slice(&length.to_be_bytes());
            bytes[9] = 17;
            bytes[12] = 10;
            bytes[16] = 20;
            bytes[20..22].copy_from_slice(&12345u16.to_be_bytes());
            bytes[22..24].copy_from_slice(&53u16.to_be_bytes());
            bytes[24..26].copy_from_slice(&(8 + payload.len() as u16).to_be_bytes());
            if reverse {
                bytes.swap(12, 16);
                bytes.swap(20, 22);
                bytes.swap(21, 23);
            }
            bytes.extend_from_slice(payload);
            bytes
        };
        let source = r#"{"rules":[{"id":"aaaa_query","expr":"proto == udp && dns.qname == example.test && dns.qtype == 28 && fresh.dns.qr == query","action":"drop_packet"},{"id":"nxdomain_response","expr":"proto == udp && dns.qname == example.test && fresh.dns.rcode == 3","action":"drop_packet"},{"id":"address_answer","expr":"proto == udp && dns.qname == example.test && fresh.dns.answer_ipv4 in 203.0.113.0/24","action":"drop_packet"}]}"#;
        let mut options = Options::parse("accept", &[]).unwrap();
        options.expr_rules = expr_config::compile(source).unwrap();
        let mut policy = options.into_policy();
        let mut evaluate = |bytes: &[u8]| {
            policy.evaluate(Packet {
                bytes,
                original_len: bytes.len(),
                checksum_ready: true,
                scope: FlowScope::default(),
                capture_time: None,
            })
        };
        assert_eq!(
            evaluate(&udp(&dns("example.test", 1, false, 0), false)),
            Verdict::Accept
        );
        assert_eq!(
            evaluate(&udp(&dns("example.test", 28, false, 0), false)),
            Verdict::Drop
        );
        assert_eq!(
            evaluate(&udp(&dns("example.test", 28, true, 0), true)),
            Verdict::Accept
        );
        let mut answer = dns("example.test", 28, true, 0);
        answer[7] = 1;
        answer.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 203, 0, 113, 7]);
        assert_eq!(evaluate(&udp(&answer, true)), Verdict::Drop);
        assert_eq!(
            evaluate(&udp(&dns("example.test", 28, true, 0), true)),
            Verdict::Accept
        );
        assert_eq!(
            evaluate(&udp(&dns("example.test", 28, true, 3), true)),
            Verdict::Drop
        );
    }

    #[test]
    fn dns_tcp_expression_evaluates_each_message_separately() {
        let query = |name: &str, qtype: u16| {
            let mut message = vec![0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
            for label in name.split('.') {
                message.push(label.len() as u8);
                message.extend_from_slice(label.as_bytes());
            }
            message.push(0);
            message.extend_from_slice(&qtype.to_be_bytes());
            message.extend_from_slice(&1u16.to_be_bytes());
            message
        };
        let first = query("blocked.test", 1);
        let first_qtype_offset = 42 + first.len() - 4;
        let mut payload = Vec::new();
        for message in [first, query("allowed.test", 28)] {
            payload.extend_from_slice(&(message.len() as u16).to_be_bytes());
            payload.extend_from_slice(&message);
        }
        let mut packet = vec![0; 40 + payload.len()];
        let length = packet.len() as u16;
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&length.to_be_bytes());
        packet[9] = 6;
        packet[12] = 10;
        packet[16] = 20;
        packet[20..22].copy_from_slice(&12345u16.to_be_bytes());
        packet[22..24].copy_from_slice(&53u16.to_be_bytes());
        packet[32] = 0x50;
        packet[33] = 0x18;
        packet[40..].copy_from_slice(&payload);
        let source = r#"{"rules":[{"id":"paired_question","expr":"proto == tcp && dns.qname == blocked.test && dns.qtype == 28","action":"block"}]}"#;
        let mut options = Options::parse("accept", &[]).unwrap();
        options.expr_rules = expr_config::compile(source).unwrap();
        let mut policy = options.into_policy();
        assert_eq!(
            policy.evaluate(Packet {
                bytes: &packet,
                original_len: packet.len(),
                checksum_ready: true,
                scope: FlowScope::default(),
                capture_time: None,
            }),
            Verdict::Accept
        );
        packet[first_qtype_offset..first_qtype_offset + 2].copy_from_slice(&28u16.to_be_bytes());
        let mut options = Options::parse("accept", &[]).unwrap();
        options.expr_rules = expr_config::compile(source).unwrap();
        let mut policy = options.into_policy();
        assert_eq!(
            policy.evaluate(Packet {
                bytes: &packet,
                original_len: packet.len(),
                checksum_ready: true,
                scope: FlowScope::default(),
                capture_time: None,
            }),
            Verdict::DropFlow
        );
    }

    #[test]
    fn udp_shape_expression_uses_early_ciphertext_behavior() {
        use rustgfw_core::{FlowScope, Packet, Policy};

        let mut options = Options::parse("accept", &[]).unwrap();
        options.expr_rules = expr_config::compile(
            r#"{"rules":[{"id":"random_fragments","expr":"proto == udp && fresh.udp_shape.fragmented_random_candidate == true && udp_shape.origin_first_varied_lengths == true && udp_shape.origin_first_random_like_packets >= 2 && udp_shape.origin_first_run == 2 && udp_shape.first_entropy_milli >= 4500 && fresh.udp_shape.origin_first_span_us <= 5000","action":"drop_packet"}]}"#,
        )
        .unwrap();
        let mut policy = options.into_policy();
        let payload = (0..700)
            .map(|index| (index * 73 + 151) as u8)
            .collect::<Vec<_>>();
        let mut packet = vec![0; 28 + payload.len()];
        let packet_len = packet.len() as u16;
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&packet_len.to_be_bytes());
        packet[9] = 17;
        packet[12..16].copy_from_slice(&[192, 0, 2, 1]);
        packet[16..20].copy_from_slice(&[198, 51, 100, 2]);
        packet[20..22].copy_from_slice(&12345u16.to_be_bytes());
        packet[22..24].copy_from_slice(&443u16.to_be_bytes());
        packet[24..26].copy_from_slice(&(8 + payload.len() as u16).to_be_bytes());
        packet[28..].copy_from_slice(&payload);
        let mut evaluate = |micros: u64| {
            let mut packet = packet.clone();
            if micros == 103_000 {
                packet.push(0x67);
                let packet_len = packet.len() as u16;
                packet[2..4].copy_from_slice(&packet_len.to_be_bytes());
                packet[24..26].copy_from_slice(&(packet_len - 20).to_be_bytes());
            }
            policy.evaluate(Packet {
                bytes: &packet,
                original_len: packet.len(),
                checksum_ready: true,
                scope: FlowScope::default(),
                capture_time: Some(rustgfw_core::CaptureTime::Kernel(
                    std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_micros(micros),
                )),
            })
        };
        assert_eq!(evaluate(100_000), Verdict::Accept);
        assert_eq!(evaluate(103_000), Verdict::Drop);
    }

    #[test]
    fn udp_short_header_shape_expression_counts_initial_datagrams() {
        use rustgfw_core::{FlowScope, Packet, Policy};

        let mut options = Options::parse("accept", &[]).unwrap();
        options.expr_rules = expr_config::compile(
            r#"{"rules":[{"id":"short_header_shape","expr":"proto == udp && udp_shape.packet_count == 4 && fresh.udp_shape.short_header_fixed_bit_packets >= 4","action":"drop_packet"}]}"#,
        )
        .unwrap();
        let mut policy = options.into_policy();
        let mut packet = vec![0; 28 + 40];
        let packet_len = packet.len() as u16;
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&packet_len.to_be_bytes());
        packet[9] = 17;
        packet[12..16].copy_from_slice(&[192, 0, 2, 1]);
        packet[16..20].copy_from_slice(&[198, 51, 100, 2]);
        packet[20..22].copy_from_slice(&12345u16.to_be_bytes());
        packet[22..24].copy_from_slice(&443u16.to_be_bytes());
        packet[24..26].copy_from_slice(&48u16.to_be_bytes());
        packet[28] = 0x43;
        for expected in [
            Verdict::Accept,
            Verdict::Accept,
            Verdict::Accept,
            Verdict::Drop,
        ] {
            assert_eq!(
                policy.evaluate(Packet {
                    bytes: &packet,
                    original_len: packet.len(),
                    checksum_ready: true,
                    scope: FlowScope::default(),
                    capture_time: None,
                }),
                expected
            );
        }
    }

    #[test]
    fn wireguard_expression_correlates_directions_without_stale_fields() {
        let mut options = Options::parse("accept", &[]).unwrap();
        options.expr_rules = expr_config::compile(
            r#"{"rules":[
                {"id":"stale_sender","expr":"wireguard.sender_index == 99 && wireguard.type == data","action":"block"},
                {"id":"matched_data","expr":"fresh.wireguard.receiver_matched == true && wireguard.type == data","action":"drop_packet"}
            ]}"#,
        )
        .unwrap();
        let mut policy = options.into_policy();
        let udp = |payload: &[u8], reverse: bool| {
            let mut bytes = vec![0; 28 + payload.len()];
            let length = bytes.len() as u16;
            bytes[0] = 0x45;
            bytes[2..4].copy_from_slice(&length.to_be_bytes());
            bytes[9] = 17;
            bytes[12..16].copy_from_slice(&[192, 0, 2, 1]);
            bytes[16..20].copy_from_slice(&[198, 51, 100, 2]);
            bytes[20..22].copy_from_slice(&12345u16.to_be_bytes());
            bytes[22..24].copy_from_slice(&51820u16.to_be_bytes());
            bytes[24..26].copy_from_slice(&(8 + payload.len() as u16).to_be_bytes());
            bytes[28..].copy_from_slice(payload);
            if reverse {
                for offset in 0..4 {
                    bytes.swap(12 + offset, 16 + offset);
                }
                bytes.swap(20, 22);
                bytes.swap(21, 23);
            }
            bytes
        };
        let mut initiation = vec![0; 148];
        initiation[0] = 1;
        initiation[4..8].copy_from_slice(&42u32.to_le_bytes());
        let mut response = vec![0; 92];
        response[0] = 2;
        response[4..8].copy_from_slice(&99u32.to_le_bytes());
        response[8..12].copy_from_slice(&42u32.to_le_bytes());
        let mut data = vec![0; 32];
        data[0] = 4;
        data[4..8].copy_from_slice(&99u32.to_le_bytes());
        let evaluate = |policy: &mut dyn Policy, bytes: &[u8]| {
            policy.evaluate(Packet {
                bytes,
                original_len: bytes.len(),
                checksum_ready: true,
                scope: FlowScope::default(),
                capture_time: None,
            })
        };
        assert_eq!(
            evaluate(&mut policy, &udp(&initiation, false)),
            Verdict::Accept
        );
        assert_eq!(
            evaluate(&mut policy, &udp(&response, true)),
            Verdict::Accept
        );
        assert_eq!(evaluate(&mut policy, &udp(&data, false)), Verdict::Drop);
        data[1] = 1;
        assert_eq!(evaluate(&mut policy, &udp(&data, false)), Verdict::Accept);
        data[1] = 0;
        data[4..8].copy_from_slice(&123u32.to_le_bytes());
        assert_eq!(evaluate(&mut policy, &udp(&data, false)), Verdict::Accept);
    }

    #[test]
    fn openvpn_expression_requires_reverse_reset_and_uses_current_opcode() {
        let mut options = Options::parse("accept", &[]).unwrap();
        options.expr_rules = expr_config::compile(
            r#"{"rules":[
                {"id":"handshake","expr":"openvpn.stage == handshake && openvpn.client_reset == 7 && openvpn.server_reset == 8","action":"drop_packet"},
                {"id":"first_client_data","expr":"fresh.openvpn.opcode == 6 && openvpn.tx_packets == 1 && payload.len >= 6","action":"drop_packet"}
            ]}"#,
        )
        .unwrap();
        let mut policy = options.into_policy();
        let udp = |payload: &[u8], reverse: bool| {
            let mut bytes = vec![0; 28 + payload.len()];
            let length = bytes.len() as u16;
            bytes[0] = 0x45;
            bytes[2..4].copy_from_slice(&length.to_be_bytes());
            bytes[9] = 17;
            bytes[12..16].copy_from_slice(&[192, 0, 2, 1]);
            bytes[16..20].copy_from_slice(&[198, 51, 100, 2]);
            bytes[20..22].copy_from_slice(&12345u16.to_be_bytes());
            bytes[22..24].copy_from_slice(&1194u16.to_be_bytes());
            bytes[24..26].copy_from_slice(&(8 + payload.len() as u16).to_be_bytes());
            bytes[28..].copy_from_slice(payload);
            if reverse {
                for offset in 0..4 {
                    bytes.swap(12 + offset, 16 + offset);
                }
                bytes.swap(20, 22);
                bytes.swap(21, 23);
            }
            bytes
        };
        let evaluate = |policy: &mut dyn Policy, bytes: &[u8]| {
            policy.evaluate(Packet {
                bytes,
                original_len: bytes.len(),
                checksum_ready: true,
                scope: FlowScope::default(),
                capture_time: None,
            })
        };
        let client = [7 << 3, 1, 2, 3, 4, 5, 6, 7, 8];
        let server = [8 << 3, 6, 7, 8, 9, 10, 11, 12, 13];
        let data = [6 << 3, 0, 0, 0, 0, 0];
        assert_eq!(evaluate(&mut policy, &udp(&client, false)), Verdict::Accept);
        assert_eq!(evaluate(&mut policy, &udp(&server, false)), Verdict::Accept);
        assert_eq!(evaluate(&mut policy, &udp(&server, true)), Verdict::Drop);
        assert_eq!(evaluate(&mut policy, &udp(&data, false)), Verdict::Drop);
        assert_eq!(
            evaluate(&mut policy, &udp(&[0xff; 6], true)),
            Verdict::Accept
        );
        assert_eq!(evaluate(&mut policy, &udp(&data, false)), Verdict::Accept);
    }

    #[test]
    fn openvpn_tcp_expression_waits_for_split_reverse_reset() {
        let mut options = Options::parse("accept", &[]).unwrap();
        options.expr_rules = expr_config::compile(
            r#"{"rules":[{"id":"openvpn_tcp","expr":"proto == tcp && openvpn.stage == handshake && openvpn.client_reset == 7 && openvpn.server_reset == 8","action":"block"}]}"#,
        )
        .unwrap();
        let mut policy = options.into_policy();
        let tcp = |sequence: u32, payload: &[u8], reverse: bool| {
            let mut bytes = vec![0; 40 + payload.len()];
            let length = bytes.len() as u16;
            bytes[0] = 0x45;
            bytes[2..4].copy_from_slice(&length.to_be_bytes());
            bytes[9] = 6;
            bytes[12..16].copy_from_slice(&[192, 0, 2, 1]);
            bytes[16..20].copy_from_slice(&[198, 51, 100, 2]);
            bytes[20..22].copy_from_slice(&12345u16.to_be_bytes());
            bytes[22..24].copy_from_slice(&1194u16.to_be_bytes());
            bytes[24..28].copy_from_slice(&sequence.to_be_bytes());
            bytes[32] = 0x50;
            bytes[33] = 0x18;
            bytes[40..].copy_from_slice(payload);
            if reverse {
                for offset in 0..4 {
                    bytes.swap(12 + offset, 16 + offset);
                }
                bytes.swap(20, 22);
                bytes.swap(21, 23);
            }
            bytes
        };
        let evaluate = |policy: &mut dyn Policy, bytes: &[u8]| {
            policy.evaluate(Packet {
                bytes,
                original_len: bytes.len(),
                checksum_ready: true,
                scope: FlowScope::default(),
                capture_time: None,
            })
        };
        let client = [0, 9, 7 << 3, 1, 2, 3, 4, 5, 6, 7, 8];
        let server = [0, 9, 8 << 3, 9, 10, 11, 12, 13, 14, 15, 16];
        assert_eq!(
            evaluate(&mut policy, &tcp(100, &client[..3], false)),
            Verdict::Accept
        );
        assert_eq!(
            evaluate(&mut policy, &tcp(103, &client[3..], false)),
            Verdict::Accept
        );
        assert_eq!(
            evaluate(&mut policy, &tcp(500, &server[..4], true)),
            Verdict::Accept
        );
        assert_eq!(
            evaluate(&mut policy, &tcp(504, &server[4..], true)),
            Verdict::DropFlow
        );
    }

    #[test]
    fn socks_expression_matches_fragmented_proxy_target() {
        let mut options = Options::parse("accept", &[]).unwrap();
        options.expr_rules = expr_config::compile(
            r#"{"expressions":{
                "proxy_target":"socks.target_type == domain && socks.target_host == blocked.test",
                "socks_request":"socks.version == 5 && socks.command == connect && socks.target_port == 443"
            },"rules":[{"id":"proxy_target","expr":"proto == tcp && @proxy_target && @socks_request","action":"block"}]}"#,
        )
        .unwrap();
        let mut policy = options.into_policy();
        let tcp = |sequence: u32, payload: &[u8]| {
            let mut bytes = vec![0; 40 + payload.len()];
            let length = bytes.len() as u16;
            bytes[0] = 0x45;
            bytes[2..4].copy_from_slice(&length.to_be_bytes());
            bytes[9] = 6;
            bytes[12..16].copy_from_slice(&[192, 0, 2, 1]);
            bytes[16..20].copy_from_slice(&[198, 51, 100, 2]);
            bytes[20..22].copy_from_slice(&12345u16.to_be_bytes());
            bytes[22..24].copy_from_slice(&1081u16.to_be_bytes());
            bytes[24..28].copy_from_slice(&sequence.to_be_bytes());
            bytes[32] = 0x50;
            bytes[33] = 0x18;
            bytes[40..].copy_from_slice(payload);
            bytes
        };
        let evaluate = |policy: &mut dyn Policy, bytes: &[u8]| {
            policy.evaluate(Packet {
                bytes,
                original_len: bytes.len(),
                checksum_ready: true,
                scope: FlowScope::default(),
                capture_time: None,
            })
        };
        let greeting = b"\x05\x01\x00";
        let request = b"\x05\x01\x00\x03\x0cblocked.test\x01\xbb";
        assert_eq!(evaluate(&mut policy, &tcp(100, greeting)), Verdict::Accept);
        assert_eq!(
            evaluate(&mut policy, &tcp(103, &request[..7])),
            Verdict::Accept
        );
        assert_eq!(
            evaluate(&mut policy, &tcp(110, &request[7..])),
            Verdict::DropFlow
        );
    }

    #[test]
    fn http2_expression_correlates_interleaved_streams() {
        fn frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
            let mut bytes = vec![0, 0, payload.len() as u8, kind, flags];
            bytes.extend(stream.to_be_bytes());
            bytes.extend(payload);
            bytes
        }
        fn tcp(sequence: u32, payload: &[u8], reverse: bool) -> Vec<u8> {
            let mut bytes = vec![0; 40 + payload.len()];
            let length = bytes.len() as u16;
            bytes[0] = 0x45;
            bytes[2..4].copy_from_slice(&length.to_be_bytes());
            bytes[9] = 6;
            bytes[12..16].copy_from_slice(&[192, 0, 2, 1]);
            bytes[16..20].copy_from_slice(&[198, 51, 100, 2]);
            bytes[20..22].copy_from_slice(&12345u16.to_be_bytes());
            bytes[22..24].copy_from_slice(&80u16.to_be_bytes());
            bytes[24..28].copy_from_slice(&sequence.to_be_bytes());
            bytes[32] = 0x50;
            bytes[33] = 0x18;
            bytes[40..].copy_from_slice(payload);
            if reverse {
                for offset in 0..4 {
                    bytes.swap(12 + offset, 16 + offset);
                }
                bytes.swap(20, 22);
                bytes.swap(21, 23);
            }
            bytes
        }
        let mut options = Options::parse("accept", &[]).unwrap();
        options.expr_rules = expr_config::compile(
            r#"{"rules":[{"id":"h2_stream","expr":"http2.path == /two && fresh.http2.status == 404","action":"block"}]}"#,
        )
        .unwrap();
        let mut policy = options.into_policy();
        let mut client = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
        client.extend(frame(4, 0, 0, &[]));
        for (stream, path) in [(1, b"/one".as_slice()), (3, b"/two".as_slice())] {
            let mut header = vec![0x82, 0x04, path.len() as u8];
            header.extend(path);
            client.extend(frame(1, 4, stream, &header));
        }
        let mut server = frame(4, 0, 0, &[]);
        server.extend(frame(1, 5, 1, &[0x8d]));
        let last = frame(1, 5, 3, &[0x8d]);
        let evaluate = |policy: &mut dyn Policy, bytes: &[u8]| {
            policy.evaluate(Packet {
                bytes,
                original_len: bytes.len(),
                checksum_ready: true,
                scope: FlowScope::default(),
                capture_time: None,
            })
        };
        assert_eq!(
            evaluate(&mut policy, &tcp(100, &client, false)),
            Verdict::Accept
        );
        assert_eq!(
            evaluate(&mut policy, &tcp(500, &server, true)),
            Verdict::Accept
        );
        assert_eq!(
            evaluate(&mut policy, &tcp(500 + server.len() as u32, &last, true)),
            Verdict::DropFlow
        );

        let mut options = Options::parse("accept", &[]).unwrap();
        options.expr_rules = expr_config::compile(
            r#"{"rules":[
                {"id":"error_on_requested_stream","scope":"http2.stream_id","requires":"requested","expr":"fresh.http2.status == 404","action":"block"},
                {"id":"requested","scope":"http2.stream_id","expr":"fresh.http2.path == /one"}
            ]}"#,
        )
        .unwrap();
        let mut policy = options.into_policy();
        let mut server_three = frame(4, 0, 0, &[]);
        server_three.extend(frame(1, 5, 3, &[0x8d]));
        let response_one = frame(1, 5, 1, &[0x8d]);
        assert_eq!(
            evaluate(&mut policy, &tcp(100, &client, false)),
            Verdict::Accept
        );
        assert_eq!(
            evaluate(&mut policy, &tcp(500, &server_three, true)),
            Verdict::Accept
        );
        assert_eq!(
            evaluate(
                &mut policy,
                &tcp(500 + server_three.len() as u32, &response_one, true),
            ),
            Verdict::DropFlow
        );
    }

    #[test]
    fn sing_mux_h2_target_expression_uses_http2_context() {
        fn tcp(sequence: u32, payload: &[u8]) -> Vec<u8> {
            let mut bytes = vec![0; 40 + payload.len()];
            let length = bytes.len() as u16;
            bytes[0] = 0x45;
            bytes[2..4].copy_from_slice(&length.to_be_bytes());
            bytes[9] = 6;
            bytes[12..16].copy_from_slice(&[192, 0, 2, 1]);
            bytes[16..20].copy_from_slice(&[198, 51, 100, 2]);
            bytes[20..22].copy_from_slice(&12345u16.to_be_bytes());
            bytes[22..24].copy_from_slice(&443u16.to_be_bytes());
            bytes[24..28].copy_from_slice(&sequence.to_be_bytes());
            bytes[32] = 0x50;
            bytes[33] = 0x18;
            bytes[40..].copy_from_slice(payload);
            bytes
        }
        let mut options = Options::parse("accept", &[]).unwrap();
        options.expr_rules = expr_config::compile(
            r#"{"rules":[{"id":"mux_h2_target","expr":"sing_mux.protocol == h2mux && fresh.sing_mux.host == example.org && http2.method == CONNECT && http2.authority == localhost","action":"block"}]}"#,
        )
        .unwrap();
        let mut policy = options.into_policy();
        let evaluate = |policy: &mut dyn Policy, bytes: &[u8]| {
            policy.evaluate(Packet {
                bytes,
                original_len: bytes.len(),
                checksum_ready: true,
                scope: FlowScope::default(),
                capture_time: None,
            })
        };
        assert_eq!(evaluate(&mut policy, &tcp(100, &[0, 2])), Verdict::Accept);
        let mut h2 = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
        h2.extend([0, 0, 0, 4, 0, 0, 0, 0, 0]);
        h2.extend([0, 0, 20, 1, 4, 0, 0, 0, 1, 0x02, 7]);
        h2.extend(b"CONNECT");
        h2.extend([0x01, 9]);
        h2.extend(b"localhost");
        assert_eq!(evaluate(&mut policy, &tcp(102, &h2)), Verdict::Accept);
        let mut request = vec![0, 0, 3, 11];
        request.extend(b"example.org");
        request.extend(443u16.to_be_bytes());
        let mut data = vec![0, 0, request.len() as u8, 0, 0, 0, 0, 0, 1];
        data.extend(request);
        assert_eq!(
            evaluate(&mut policy, &tcp(102 + h2.len() as u32, &data)),
            Verdict::DropFlow
        );
    }

    #[test]
    fn sing_mux_smux_rule_matches_the_correct_substream_request() {
        fn tcp(sequence: u32, payload: &[u8]) -> Vec<u8> {
            let mut bytes = vec![0; 40 + payload.len()];
            let length = bytes.len() as u16;
            bytes[0] = 0x45;
            bytes[2..4].copy_from_slice(&length.to_be_bytes());
            bytes[9] = 6;
            bytes[12..16].copy_from_slice(&[192, 0, 2, 1]);
            bytes[16..20].copy_from_slice(&[198, 51, 100, 2]);
            bytes[20..22].copy_from_slice(&12345u16.to_be_bytes());
            bytes[22..24].copy_from_slice(&443u16.to_be_bytes());
            bytes[24..28].copy_from_slice(&sequence.to_be_bytes());
            bytes[32] = 0x50;
            bytes[33] = 0x18;
            bytes[40..].copy_from_slice(payload);
            bytes
        }
        fn smux(command: u8, stream: u32, data: &[u8]) -> Vec<u8> {
            let mut frame = vec![2, command];
            frame.extend((data.len() as u16).to_le_bytes());
            frame.extend(stream.to_le_bytes());
            frame.extend(data);
            frame
        }
        fn request(host: &str) -> Vec<u8> {
            let mut bytes = vec![0, 0, 3, host.len() as u8];
            bytes.extend(host.as_bytes());
            bytes.extend(443u16.to_be_bytes());
            bytes
        }
        let mut options = Options::parse("accept", &[]).unwrap();
        options.expr_rules = expr_config::compile(
            r#"{"rules":[{"id":"mux_target","expr":"sing_mux.protocol == smux && fresh.sing_mux.host == example.org && sing_mux.port == 443","action":"block"}]}"#,
        )
        .unwrap();
        let mut policy = options.into_policy();
        let evaluate = |policy: &mut dyn Policy, bytes: &[u8]| {
            policy.evaluate(Packet {
                bytes,
                original_len: bytes.len(),
                checksum_ready: true,
                scope: FlowScope::default(),
                capture_time: None,
            })
        };
        let mut first = vec![0, 0];
        first.extend(smux(0, 1, &[]));
        first.extend(smux(2, 1, &request("other.test")));
        assert_eq!(evaluate(&mut policy, &tcp(100, &first)), Verdict::Accept);
        let mut second = smux(0, 3, &[]);
        second.extend(smux(2, 3, &request("example.org")));
        assert_eq!(
            evaluate(&mut policy, &tcp(100 + first.len() as u32, &second)),
            Verdict::DropFlow
        );
    }

    #[test]
    fn tls_alpn_expression_enables_inspection_without_sni() {
        let mut options = Options::parse("accept", &[]).unwrap();
        options.expr_rules = expr_config::compile(
            r#"{"rules":[{"id":"http_2_offer","expr":"proto == tcp && fresh.tls.alpn == h2 && tls.ech_extension == false && tls.client_cipher_suite == 0x1301 && tls.client_extension == 0x0010 && tls.client_supported_group == 0x001d && tls.client_signature_algorithm == 0x0804 && tls.client_key_share_group == 0x001d","action":"block"}]}"#,
        )
        .unwrap();
        let mut policy = options.into_policy();
        let mut body = vec![3, 3];
        body.extend([0; 32]);
        body.extend([0, 0, 2, 0x13, 1, 1, 0]);
        let mut extensions = vec![0, 16, 0, 5, 0, 3, 2, b'h', b'2'];
        extensions.extend([0, 10, 0, 4, 0, 2, 0, 29]);
        extensions.extend([0, 13, 0, 4, 0, 2, 8, 4]);
        extensions.extend([0, 51, 0, 7, 0, 5, 0, 29, 0, 1, 1]);
        body.extend((extensions.len() as u16).to_be_bytes());
        body.extend(extensions);
        let mut handshake = vec![1, 0, 0, body.len() as u8];
        handshake.extend(body);
        let mut record = vec![22, 3, 1];
        record.extend((handshake.len() as u16).to_be_bytes());
        record.extend(handshake);
        let mut packet = vec![0; 40 + record.len()];
        let length = packet.len() as u16;
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&length.to_be_bytes());
        packet[9] = 6;
        packet[12..16].copy_from_slice(&[192, 0, 2, 1]);
        packet[16..20].copy_from_slice(&[198, 51, 100, 2]);
        packet[20..22].copy_from_slice(&12345u16.to_be_bytes());
        packet[22..24].copy_from_slice(&443u16.to_be_bytes());
        packet[32] = 0x50;
        packet[33] = 0x18;
        packet[40..].copy_from_slice(&record);
        assert_eq!(
            policy.evaluate(Packet {
                bytes: &packet,
                original_len: packet.len(),
                checksum_ready: true,
                scope: FlowScope::default(),
                capture_time: None,
            }),
            Verdict::DropFlow
        );
    }

    #[test]
    fn tls_expression_combines_client_and_server_hello() {
        let mut options = Options::parse("accept", &[]).unwrap();
        options.expr_rules = expr_config::compile(
            r#"{"rules":[{"id":"selected_tls","expr":"proto == tcp && tls.alpn == h2 && tls.supported_version == 0x0304 && tls.ech_extension == true && fresh.tls.server_version == 0x0304 && tls.server_cipher == 0x1301","action":"block"}]}"#,
        )
        .unwrap();
        let mut policy = options.into_policy();
        let record = |kind: u8, body: Vec<u8>| {
            let mut handshake = vec![kind, 0, 0, body.len() as u8];
            handshake.extend(body);
            let mut record = vec![22, 3, 1];
            record.extend((handshake.len() as u16).to_be_bytes());
            record.extend(handshake);
            record
        };
        let tcp = |sequence: u32, payload: &[u8], reverse: bool| {
            let mut bytes = vec![0; 40 + payload.len()];
            let length = bytes.len() as u16;
            bytes[0] = 0x45;
            bytes[2..4].copy_from_slice(&length.to_be_bytes());
            bytes[9] = 6;
            bytes[12..16].copy_from_slice(&[192, 0, 2, 1]);
            bytes[16..20].copy_from_slice(&[198, 51, 100, 2]);
            bytes[20..22].copy_from_slice(&12345u16.to_be_bytes());
            bytes[22..24].copy_from_slice(&443u16.to_be_bytes());
            bytes[24..28].copy_from_slice(&sequence.to_be_bytes());
            bytes[32] = 0x50;
            bytes[33] = 0x18;
            bytes[40..].copy_from_slice(payload);
            if reverse {
                for offset in 0..4 {
                    bytes.swap(12 + offset, 16 + offset);
                }
                bytes.swap(20, 22);
                bytes.swap(21, 23);
            }
            bytes
        };
        let evaluate = |policy: &mut dyn Policy, bytes: &[u8]| {
            policy.evaluate(Packet {
                bytes,
                original_len: bytes.len(),
                checksum_ready: true,
                scope: FlowScope::default(),
                capture_time: None,
            })
        };
        let mut client = vec![3, 3];
        client.extend([0; 32]);
        client.extend([0, 0, 2, 0x13, 1, 1, 0]);
        client.extend([0, 23, 0, 16, 0, 5, 0, 3, 2, b'h', b'2']);
        client.extend([0, 43, 0, 5, 4, 3, 4, 3, 3]);
        client.extend([0xfe, 0x0d, 0, 1, 0]);
        let mut server = vec![3, 3];
        server.extend([0; 32]);
        server.extend([0, 0x13, 1, 0, 0, 6, 0, 43, 0, 2, 3, 4]);
        let request = tcp(100, &record(1, client), false);
        let response = tcp(500, &record(2, server), true);
        assert_eq!(evaluate(&mut policy, &request), Verdict::Accept);
        assert_eq!(evaluate(&mut policy, &response), Verdict::DropFlow);
    }

    #[test]
    fn http_upgrade_rule_requires_server_selection() {
        let mut options = Options::parse("accept", &[]).unwrap();
        options.expr_rules = expr_config::compile(
            r#"{"rules":[{"id":"websocket_upgrade","expr":"proto == tcp && http.upgrade_offer == websocket && fresh.http.upgrade_selected == websocket && fresh.http.status == 101","action":"block"}]}"#,
        )
        .unwrap();
        let mut policy = options.into_policy();
        let tcp = |sequence: u32, payload: &[u8], reverse: bool| {
            let mut bytes = vec![0; 40 + payload.len()];
            let length = bytes.len() as u16;
            bytes[0] = 0x45;
            bytes[2..4].copy_from_slice(&length.to_be_bytes());
            bytes[9] = 6;
            bytes[12..16].copy_from_slice(&[192, 0, 2, 1]);
            bytes[16..20].copy_from_slice(&[198, 51, 100, 2]);
            bytes[20..22].copy_from_slice(&12345u16.to_be_bytes());
            bytes[22..24].copy_from_slice(&443u16.to_be_bytes());
            bytes[24..28].copy_from_slice(&sequence.to_be_bytes());
            bytes[32] = 0x50;
            bytes[33] = 0x18;
            bytes[40..].copy_from_slice(payload);
            if reverse {
                for offset in 0..4 {
                    bytes.swap(12 + offset, 16 + offset);
                }
                bytes.swap(20, 22);
                bytes.swap(21, 23);
            }
            bytes
        };
        let evaluate = |policy: &mut dyn rustgfw_core::Policy, bytes: &[u8]| {
            policy.evaluate(rustgfw_core::Packet {
                bytes,
                original_len: bytes.len(),
                checksum_ready: true,
                scope: rustgfw_core::FlowScope::default(),
                capture_time: None,
            })
        };
        let request = tcp(
            100,
            b"GET /ws HTTP/1.1\r\nHost: relay.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
            false,
        );
        let response = tcp(
            500,
            b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
            true,
        );
        assert_eq!(evaluate(&mut policy, &request), Verdict::Accept);
        assert_eq!(evaluate(&mut policy, &response), Verdict::DropFlow);
    }

    #[test]
    fn http_expression_combines_request_and_response_fields() {
        let mut options = Options::parse("accept", &[]).unwrap();
        options.expr_rules = expr_config::compile(
            r#"{"rules":[{"id":"failed_request","expr":"proto == tcp && http.method == GET && http.target == /blocked && http.status >= 400","action":"block"}]}"#,
        )
        .unwrap();
        let mut policy = options.into_policy();
        let tcp = |sequence: u32, payload: &[u8], reverse: bool| {
            let mut bytes = vec![0; 40 + payload.len()];
            let length = bytes.len() as u16;
            bytes[0] = 0x45;
            bytes[2..4].copy_from_slice(&length.to_be_bytes());
            bytes[9] = 6;
            bytes[12..16].copy_from_slice(&[192, 0, 2, 1]);
            bytes[16..20].copy_from_slice(&[198, 51, 100, 2]);
            bytes[20..22].copy_from_slice(&12345u16.to_be_bytes());
            bytes[22..24].copy_from_slice(&80u16.to_be_bytes());
            bytes[24..28].copy_from_slice(&sequence.to_be_bytes());
            bytes[32] = 0x50;
            bytes[33] = 0x18;
            bytes[40..].copy_from_slice(payload);
            if reverse {
                for offset in 0..4 {
                    bytes.swap(12 + offset, 16 + offset);
                }
                bytes.swap(20, 22);
                bytes.swap(21, 23);
            }
            bytes
        };
        let evaluate = |policy: &mut dyn Policy, bytes: &[u8]| {
            policy.evaluate(Packet {
                bytes,
                original_len: bytes.len(),
                checksum_ready: true,
                scope: FlowScope::default(),
                capture_time: None,
            })
        };
        let request = tcp(
            100,
            b"GET /blocked HTTP/1.1\r\nHost: example.test\r\n\r\n",
            false,
        );
        let response = tcp(500, b"HTTP/1.1 404 Not Found\r\n\r\n", true);
        assert_eq!(evaluate(&mut policy, &request), Verdict::Accept);
        assert_eq!(evaluate(&mut policy, &response), Verdict::DropFlow);
    }

    #[test]
    fn http_pipelined_responses_use_matching_request_context() {
        let tcp = |sequence: u32, payload: &[u8], reverse: bool| {
            let mut bytes = vec![0; 40 + payload.len()];
            let length = bytes.len() as u16;
            bytes[0] = 0x45;
            bytes[2..4].copy_from_slice(&length.to_be_bytes());
            bytes[9] = 6;
            bytes[12..16].copy_from_slice(&[192, 0, 2, 1]);
            bytes[16..20].copy_from_slice(&[198, 51, 100, 2]);
            bytes[20..22].copy_from_slice(&12345u16.to_be_bytes());
            bytes[22..24].copy_from_slice(&80u16.to_be_bytes());
            bytes[24..28].copy_from_slice(&sequence.to_be_bytes());
            bytes[32] = 0x50;
            bytes[33] = 0x18;
            bytes[40..].copy_from_slice(payload);
            if reverse {
                for offset in 0..4 {
                    bytes.swap(12 + offset, 16 + offset);
                }
                bytes.swap(20, 22);
                bytes.swap(21, 23);
            }
            bytes
        };
        let requests = tcp(
            100,
            b"GET /one HTTP/1.1\r\nHost: one.test\r\n\r\nGET /two HTTP/1.1\r\nHost: two.test\r\n\r\n",
            false,
        );
        let first_response = tcp(
            500,
            b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n",
            true,
        );
        let second_response = tcp(
            500 + (first_response.len() - 40) as u32,
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
            true,
        );
        for (expression, expected_first) in [
            (
                "http.target == /two && fresh.http.status == 404",
                Verdict::Accept,
            ),
            (
                "http.target == /one && fresh.http.status == 404",
                Verdict::DropFlow,
            ),
            (
                "fresh.http.target == /one && fresh.http.status == 404",
                Verdict::Accept,
            ),
        ] {
            let source = format!(
                r#"{{"rules":[{{"id":"paired","expr":"{expression}","action":"block"}}]}}"#
            );
            let mut options = Options::parse("accept", &[]).unwrap();
            options.expr_rules = expr_config::compile(&source).unwrap();
            let mut policy = options.into_policy();
            let mut evaluate = |bytes: &[u8]| {
                policy.evaluate(Packet {
                    bytes,
                    original_len: bytes.len(),
                    checksum_ready: true,
                    scope: FlowScope::default(),
                    capture_time: None,
                })
            };
            assert_eq!(evaluate(&requests), Verdict::Accept, "{expression}");
            assert_eq!(evaluate(&first_response), expected_first, "{expression}");
            if expected_first == Verdict::Accept {
                assert_eq!(evaluate(&second_response), Verdict::Accept, "{expression}");
            }
        }
    }

    #[test]
    fn http_expression_keeps_pipelined_request_fields_together() {
        let mut options = Options::parse("accept", &[]).unwrap();
        options.expr_rules = expr_config::compile(
            r#"{"rules":[{"id":"post_target","expr":"proto == tcp && http.method == POST && http.host == blocked.test","action":"block"}]}"#,
        )
        .unwrap();
        let mut policy = options.into_policy();
        let tcp = |sequence: u32, payload: &[u8]| {
            let mut bytes = vec![0; 40 + payload.len()];
            let length = bytes.len() as u16;
            bytes[0] = 0x45;
            bytes[2..4].copy_from_slice(&length.to_be_bytes());
            bytes[9] = 6;
            bytes[12..16].copy_from_slice(&[192, 0, 2, 1]);
            bytes[16..20].copy_from_slice(&[198, 51, 100, 2]);
            bytes[20..22].copy_from_slice(&12345u16.to_be_bytes());
            bytes[22..24].copy_from_slice(&80u16.to_be_bytes());
            bytes[24..28].copy_from_slice(&sequence.to_be_bytes());
            bytes[32] = 0x50;
            bytes[33] = 0x18;
            bytes[40..].copy_from_slice(payload);
            bytes
        };
        let mut evaluate = |sequence, payload: &[u8]| {
            let bytes = tcp(sequence, payload);
            policy.evaluate(Packet {
                bytes: &bytes,
                original_len: bytes.len(),
                checksum_ready: true,
                scope: FlowScope::default(),
                capture_time: None,
            })
        };
        let first_two = b"POST /one HTTP/1.1\r\nHost: allowed.test\r\nContent-Length: 0\r\n\r\nGET /two HTTP/1.1\r\nHost: blocked.test\r\n\r\n";
        assert_eq!(evaluate(100, first_two), Verdict::Accept);
        assert_eq!(
            evaluate(
                100 + first_two.len() as u32,
                b"POST /three HTTP/1.1\r\nHost: blocked.test\r\nContent-Length: 0\r\n\r\n",
            ),
            Verdict::DropFlow
        );
    }

    #[test]
    fn vless_expression_matches_fragmented_raw_request() {
        let mut options = Options::parse("accept", &[]).unwrap();
        options.expr_rules = expr_config::compile(
            r#"{"rules":[{"id":"raw_vless_target","expr":"proto == tcp && vless.candidate == true && vless.command == tcp && vless.target_host == blocked.test && vless.target_port == 443","action":"block"}]}"#,
        )
        .unwrap();
        let mut policy = options.into_policy();
        let tcp = |sequence: u32, payload: &[u8]| {
            let mut bytes = vec![0; 40 + payload.len()];
            let length = bytes.len() as u16;
            bytes[0] = 0x45;
            bytes[2..4].copy_from_slice(&length.to_be_bytes());
            bytes[9] = 6;
            bytes[12..16].copy_from_slice(&[192, 0, 2, 1]);
            bytes[16..20].copy_from_slice(&[198, 51, 100, 2]);
            bytes[20..22].copy_from_slice(&12345u16.to_be_bytes());
            bytes[22..24].copy_from_slice(&443u16.to_be_bytes());
            bytes[24..28].copy_from_slice(&sequence.to_be_bytes());
            bytes[32] = 0x50;
            bytes[33] = 0x18;
            bytes[40..].copy_from_slice(payload);
            bytes
        };
        let mut request = vec![0];
        request.extend([0x42; 16]);
        request.extend([0, 1, 1, 187, 2, 12]);
        request.extend(b"blocked.test");
        let split = 20;
        let first = tcp(100, &request[..split]);
        let second = tcp(100 + split as u32, &request[split..]);
        let evaluate = |policy: &mut dyn rustgfw_core::Policy, bytes: &[u8]| {
            policy.evaluate(rustgfw_core::Packet {
                bytes,
                original_len: bytes.len(),
                checksum_ready: true,
                scope: rustgfw_core::FlowScope::default(),
                capture_time: None,
            })
        };
        assert_eq!(evaluate(&mut policy, &first), Verdict::Accept);
        assert_eq!(evaluate(&mut policy, &second), Verdict::DropFlow);
    }

    #[test]
    fn decoded_stream_reuses_vless_analyzer_and_expression() {
        use rustgfw_core::{FlowScope, inspect::DecodedStream};

        let mut options = Options::parse("accept", &[]).unwrap();
        options.expr_rules = expr_config::compile(
            r#"{"rules":[{"id":"inner_vless_target","expr":"proto == tcp && vless.candidate == true && vless.target_host == blocked.test","action":"block"}]}"#,
        )
        .unwrap();
        let mut policy = options.into_policy();
        let mut request = vec![0];
        request.extend([0x42; 16]);
        request.extend([0, 1, 1, 187, 2, 12]);
        request.extend(b"blocked.test");
        let origin = "192.0.2.1:12345".parse().unwrap();
        let target = "198.51.100.2:443".parse().unwrap();
        let mut feed = |bytes: &[u8]| {
            policy.feed_decoded(DecodedStream {
                scope: FlowScope(7),
                stream_id: 19,
                origin,
                target,
                reverse: false,
                bytes,
            })
        };
        assert_eq!(feed(&request[..20]), Verdict::Accept);
        assert_eq!(feed(&request[20..]), Verdict::DropFlow);
    }

    #[test]
    fn tcp_shape_expression_uses_raw_packets_and_ignores_retransmission() {
        let mut options = Options::parse("accept", &[]).unwrap();
        options.expr_rules = expr_config::compile(
            r#"{"rules":[{"id":"early_burst","expr":"proto == tcp && tcp_shape.first_random_like == true && fet.candidate == true && tcp_shape.packet_count == 3 && tcp_shape.handshake_rtt_us == 10000 && tcp_shape.size_trigram == \"1,-2,-2\" && fresh.tcp_shape.timed_bursts == \"100,-500\" && tcp_shape.first_reply_delay_us >= 30000 && fresh.tcp_shape.last_gap_us >= 10000","action":"block"}]}"#,
        )
        .unwrap();
        let mut policy = options.into_policy();
        let tcp = |sequence: u32, payload: &[u8], reverse: bool, flags: u8| {
            let mut bytes = vec![0; 40 + payload.len()];
            let length = bytes.len() as u16;
            bytes[0] = 0x45;
            bytes[2..4].copy_from_slice(&length.to_be_bytes());
            bytes[9] = 6;
            bytes[12..16].copy_from_slice(&[192, 0, 2, 1]);
            bytes[16..20].copy_from_slice(&[198, 51, 100, 2]);
            bytes[20..22].copy_from_slice(&12345u16.to_be_bytes());
            bytes[22..24].copy_from_slice(&443u16.to_be_bytes());
            bytes[24..28].copy_from_slice(&sequence.to_be_bytes());
            let acknowledgment = if flags & 0x10 == 0 {
                0u32
            } else if reverse {
                100
            } else {
                500
            };
            bytes[28..32].copy_from_slice(&acknowledgment.to_be_bytes());
            bytes[32] = 0x50;
            bytes[33] = flags;
            bytes[40..].copy_from_slice(payload);
            if reverse {
                for offset in 0..4 {
                    bytes.swap(12 + offset, 16 + offset);
                }
                bytes.swap(20, 22);
                bytes.swap(21, 23);
            }
            bytes
        };
        let evaluate = |policy: &mut dyn rustgfw_core::Policy, bytes: &[u8], micros: u64| {
            policy.evaluate(rustgfw_core::Packet {
                bytes,
                original_len: bytes.len(),
                checksum_ready: true,
                scope: rustgfw_core::FlowScope::default(),
                capture_time: Some(rustgfw_core::CaptureTime::Kernel(
                    std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_micros(micros),
                )),
            })
        };
        let random = (0..100)
            .map(|index| (index * 73 + 151) as u8)
            .collect::<Vec<_>>();
        assert_eq!(
            evaluate(&mut policy, &tcp(99, &[], false, 0x02), 80_000),
            Verdict::Accept
        );
        assert_eq!(
            evaluate(&mut policy, &tcp(499, &[], true, 0x12), 85_000),
            Verdict::Accept
        );
        assert_eq!(
            evaluate(&mut policy, &tcp(100, &[], false, 0x10), 90_000),
            Verdict::Accept
        );
        let first = tcp(100, &random, false, 0x18);
        assert_eq!(evaluate(&mut policy, &first, 100_000), Verdict::Accept);
        assert_eq!(evaluate(&mut policy, &first, 105_000), Verdict::Accept);
        assert_eq!(
            evaluate(&mut policy, &tcp(500, &[0; 200], true, 0x18), 130_000),
            Verdict::Accept
        );
        assert_eq!(
            evaluate(&mut policy, &tcp(700, &[0; 300], true, 0x18), 145_000),
            Verdict::DropFlow
        );
    }

    #[test]
    fn tcp_rtt_expression_uses_ack_and_three_response_rounds() {
        let mut options = Options::parse("accept", &[]).unwrap();
        options.expr_rules = expr_config::compile(
            r#"{"rules":[{"id":"rtt_gap","expr":"proto == tcp && fresh.tcp_rtt.diff_us >= 40000 && tcp_rtt.completed_pairs == 3 && tcp_rtt.transport_samples == 3","action":"block"}]}"#,
        )
        .unwrap();
        let mut policy = options.into_policy();
        let tcp = |sequence: u32, acknowledgment: u32, payload: &[u8], reverse: bool| {
            let mut bytes = vec![0; 40 + payload.len()];
            let length = bytes.len() as u16;
            bytes[0] = 0x45;
            bytes[2..4].copy_from_slice(&length.to_be_bytes());
            bytes[9] = 6;
            bytes[12..16].copy_from_slice(&[192, 0, 2, 1]);
            bytes[16..20].copy_from_slice(&[198, 51, 100, 2]);
            bytes[20..22].copy_from_slice(&12345u16.to_be_bytes());
            bytes[22..24].copy_from_slice(&443u16.to_be_bytes());
            bytes[24..28].copy_from_slice(&sequence.to_be_bytes());
            bytes[28..32].copy_from_slice(&acknowledgment.to_be_bytes());
            bytes[32] = 0x50;
            bytes[33] = if payload.is_empty() { 0x10 } else { 0x18 };
            bytes[40..].copy_from_slice(payload);
            if reverse {
                for offset in 0..4 {
                    bytes.swap(12 + offset, 16 + offset);
                }
                bytes.swap(20, 22);
                bytes.swap(21, 23);
            }
            bytes
        };
        let evaluate = |policy: &mut dyn rustgfw_core::Policy, bytes: &[u8], micros: u64| {
            policy.evaluate(rustgfw_core::Packet {
                bytes,
                original_len: bytes.len(),
                checksum_ready: true,
                scope: rustgfw_core::FlowScope::default(),
                capture_time: Some(rustgfw_core::CaptureTime::Kernel(
                    std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_micros(micros),
                )),
            })
        };
        for index in 0..3u32 {
            let base = u64::from(index) * 100_000;
            let request_sequence = 100 + index * 40;
            let response_sequence = 500 + index * 40;
            assert_eq!(
                evaluate(
                    &mut policy,
                    &tcp(request_sequence, 500, &[1; 40], false),
                    base
                ),
                Verdict::Accept
            );
            assert_eq!(
                evaluate(
                    &mut policy,
                    &tcp(response_sequence, request_sequence + 40, &[], true),
                    base + 10_000,
                ),
                Verdict::Accept
            );
            assert_eq!(
                evaluate(
                    &mut policy,
                    &tcp(response_sequence, request_sequence + 40, &[2; 40], true),
                    base + 50_000,
                ),
                if index == 2 {
                    Verdict::DropFlow
                } else {
                    Verdict::Accept
                }
            );
        }
    }

    #[test]
    fn fet_observations_combine_with_sample_length_and_port() {
        let expression = r#"{"rules":[{"id":"candidate","expr":"proto == tcp && fet.candidate == true && fet.sample_len >= 32 && dst.port == 443","action":"block"}]}"#;
        let tcp = |payload: &[u8]| {
            let mut bytes = vec![0; 40 + payload.len()];
            let length = bytes.len() as u16;
            bytes[0] = 0x45;
            bytes[2..4].copy_from_slice(&length.to_be_bytes());
            bytes[9] = 6;
            bytes[12..16].copy_from_slice(&[192, 0, 2, 1]);
            bytes[16..20].copy_from_slice(&[198, 51, 100, 2]);
            bytes[20..22].copy_from_slice(&12345u16.to_be_bytes());
            bytes[22..24].copy_from_slice(&443u16.to_be_bytes());
            bytes[32] = 0x50;
            bytes[33] = 0x18;
            bytes[40..].copy_from_slice(payload);
            bytes
        };
        let evaluate = |payload: &[u8]| {
            let mut options = Options::parse("accept", &[]).unwrap();
            options.expr_rules = expr_config::compile(expression).unwrap();
            let mut policy = options.into_policy();
            let packet = tcp(payload);
            policy.evaluate(Packet {
                bytes: &packet,
                original_len: packet.len(),
                checksum_ready: true,
                scope: FlowScope::default(),
                capture_time: None,
            })
        };
        assert_eq!(evaluate(&[0x0f; 64]), Verdict::DropFlow);
        assert_eq!(evaluate(b"GET / HTTP/1.1\r\n\r\n"), Verdict::Accept);
        assert_eq!(evaluate(&[0x0f; 8]), Verdict::Accept);
    }

    #[test]
    fn trojan_sequence_combines_with_fet_expression() {
        let mut options = Options::parse("accept", &[]).unwrap();
        options.expr_rules = expr_config::compile(
            r#"{"expressions":{
                "tls_like":"fet.tls_http_prefix == true",
                "lengths":"fresh.trojan.candidate == true && trojan.seq1 >= 200"
            },"rules":[{"id":"length_candidate","expr":"proto == tcp && dst.port == 443 && @tls_like && @lengths","action":"block"}]}"#,
        )
        .unwrap();
        let mut policy = options.into_policy();
        let tcp = |sequence: u32, payload: &[u8], reverse: bool| {
            let mut bytes = vec![0; 40 + payload.len()];
            let length = bytes.len() as u16;
            bytes[0] = 0x45;
            bytes[2..4].copy_from_slice(&length.to_be_bytes());
            bytes[9] = 6;
            bytes[12..16].copy_from_slice(&[192, 0, 2, 1]);
            bytes[16..20].copy_from_slice(&[198, 51, 100, 2]);
            bytes[20..22].copy_from_slice(&12345u16.to_be_bytes());
            bytes[22..24].copy_from_slice(&443u16.to_be_bytes());
            bytes[24..28].copy_from_slice(&sequence.to_be_bytes());
            bytes[32] = 0x50;
            bytes[33] = 0x18;
            bytes[40..].copy_from_slice(payload);
            if reverse {
                for offset in 0..4 {
                    bytes.swap(12 + offset, 16 + offset);
                }
                bytes.swap(20, 22);
                bytes.swap(21, 23);
            }
            bytes
        };
        let mut evaluate = |sequence, payload: &[u8], reverse| {
            let bytes = tcp(sequence, payload, reverse);
            policy.evaluate(Packet {
                bytes: &bytes,
                original_len: bytes.len(),
                checksum_ready: true,
                scope: FlowScope::default(),
                capture_time: None,
            })
        };
        let mut ccs = vec![20, 3, 3, 0, 1, 1];
        ccs.resize(200, 0);
        assert_eq!(evaluate(100, b"\x16\x03\x03", false), Verdict::Accept);
        assert_eq!(evaluate(103, &ccs, false), Verdict::Accept);
        assert_eq!(evaluate(500, &[0; 100], true), Verdict::Accept);
        assert_eq!(evaluate(303, &[0; 100], false), Verdict::Accept);
        assert_eq!(evaluate(600, &[0; 100], true), Verdict::Accept);
        assert_eq!(evaluate(403, b"x", false), Verdict::DropFlow);
    }

    #[test]
    fn dtls_expression_reassembles_real_client_hello() {
        use rustgfw_core::{FlowScope, Packet, Policy};

        let mut options = Options::parse("accept", &[]).unwrap();
        options.expr_rules = expr_config::compile(
            r#"{"rules":[{"id":"dtls_sni","expr":"proto == udp && fresh.dtls.sni == dtls.example && dtls.alpn == h2 && dtls.client_session_id_len == 0 && dtls.client_compression_methods == 0x00","action":"drop_packet"}]}"#,
        )
        .unwrap();
        let mut policy = options.into_policy();
        let udp = |payload: &[u8]| {
            let mut bytes = vec![0; 28 + payload.len()];
            let length = bytes.len() as u16;
            bytes[0] = 0x45;
            bytes[2..4].copy_from_slice(&length.to_be_bytes());
            bytes[9] = 17;
            bytes[12..16].copy_from_slice(&[192, 0, 2, 1]);
            bytes[16..20].copy_from_slice(&[198, 51, 100, 2]);
            bytes[20..22].copy_from_slice(&12345u16.to_be_bytes());
            bytes[22..24].copy_from_slice(&443u16.to_be_bytes());
            bytes[24..26].copy_from_slice(&(8 + payload.len() as u16).to_be_bytes());
            bytes[28..].copy_from_slice(payload);
            bytes
        };
        let evaluate = |policy: &mut dyn Policy, bytes: &[u8]| {
            policy.evaluate(Packet {
                bytes,
                original_len: bytes.len(),
                checksum_ready: true,
                scope: FlowScope::default(),
                capture_time: None,
            })
        };
        let first = udp(include_bytes!(
            "../tests/fixtures/dtls-openssl12-client-0.bin"
        ));
        let second = udp(include_bytes!(
            "../tests/fixtures/dtls-openssl12-client-1.bin"
        ));
        assert_eq!(evaluate(&mut policy, &first), Verdict::Accept);
        assert_eq!(evaluate(&mut policy, &second), Verdict::Drop);
        assert_eq!(evaluate(&mut policy, &udp(b"later")), Verdict::Accept);
    }

    #[test]
    #[ignore = "requires the read-only OpenGFW QUIC capture fixture"]
    fn quic_expression_drops_only_the_initial_with_matching_sni() {
        let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("references/opengfw/analyzer/udp/testdata/quic-ngtcp2-1.11-0.bin");
        let payload = std::fs::read(fixture).unwrap();
        let mut options = Options::parse("accept", &[]).unwrap();
        options.expr_rules = expr_config::compile(
            r#"{"rules":[{"id":"quic_sni","expr":"proto == udp && fresh.quic.sni == ngtcp2.sniff.test && quic.transport_parameter_id == 0xf && quic.disable_active_migration exists","action":"drop_packet"}]}"#,
        )
        .unwrap();
        let mut policy = options.into_policy();
        let udp = |payload: &[u8]| {
            let mut bytes = vec![0; 28 + payload.len()];
            let length = bytes.len() as u16;
            bytes[0] = 0x45;
            bytes[2..4].copy_from_slice(&length.to_be_bytes());
            bytes[9] = 17;
            bytes[12..16].copy_from_slice(&[192, 0, 2, 1]);
            bytes[16..20].copy_from_slice(&[198, 51, 100, 2]);
            bytes[20..22].copy_from_slice(&12345u16.to_be_bytes());
            bytes[22..24].copy_from_slice(&443u16.to_be_bytes());
            bytes[24..26].copy_from_slice(&(8 + payload.len() as u16).to_be_bytes());
            bytes[28..].copy_from_slice(payload);
            bytes
        };
        let evaluate = |policy: &mut dyn Policy, bytes: &[u8]| {
            policy.evaluate(Packet {
                bytes,
                original_len: bytes.len(),
                checksum_ready: true,
                scope: FlowScope::default(),
                capture_time: None,
            })
        };
        assert_eq!(evaluate(&mut policy, &udp(&payload)), Verdict::Drop);
        assert_eq!(evaluate(&mut policy, &udp(b"later")), Verdict::Accept);
    }

    #[test]
    fn tcp_only_expression_does_not_consume_udp_flow_capacity() {
        let mut options = Options::parse("accept", &[]).unwrap();
        options.inspect_limits.max_flows = 0;
        options.expr_rules = expr_config::compile(
            r#"{"rules":[{"id":"web","expr":"proto == tcp && http.host == blocked.test","action":"block"}]}"#,
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
                capture_time: None,
            }),
            Verdict::Accept
        );
    }
}
