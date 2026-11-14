use rustgfw_core::{Verdict, inspect::AnalyzerRule, rules::Rule};

type Error = Box<dyn std::error::Error>;

fn main() -> Result<(), Error> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    match args.first().map(String::as_str) {
        Some("nfqueue") => run_nfqueue(&args[1..]),
        Some("windivert") => run_windivert(&args[1..]),
        _ => Err("usage: rustgfw nfqueue <queue> <accept|drop> [rules...] [nft=input|output|forward] | rustgfw windivert <dll> <network|forward> <accept|drop> [rules...]".into()),
    }
}

struct Options {
    default: Verdict,
    rules: Vec<Rule>,
    http_hosts: Vec<String>,
    tls_sni: Vec<String>,
    dns_names: Vec<String>,
    nft_hook: Option<String>,
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
            nft_hook: None,
        };
        for arg in args {
            if let Some(host) = arg.strip_prefix("http-host=") {
                options.http_hosts.push(host.to_owned());
            } else if let Some(host) = arg.strip_prefix("tls-sni=") {
                options.tls_sni.push(host.to_owned());
            } else if let Some(name) = arg.strip_prefix("dns-name=") {
                options
                    .dns_names
                    .push(name.trim_end_matches('.').to_ascii_lowercase());
            } else if let Some(hook) = arg.strip_prefix("nft=") {
                if options.nft_hook.replace(hook.to_owned()).is_some() {
                    return Err("specify at most one nft hook".into());
                }
            } else {
                options.rules.push(parse_rule(arg)?);
            }
        }
        Ok(options)
    }

    fn into_policy(self) -> impl rustgfw_core::Policy {
        use rustgfw_core::{dns::DnsPolicy, inspect::Inspect, rules::Rules};
        let analyzers = vec![
            AnalyzerRule {
                hosts: self.http_hosts,
                port: None,
                factory: || Box::<rustgfw_core::inspect::HttpHost>::default(),
            },
            AnalyzerRule {
                hosts: self.tls_sni,
                port: None,
                factory: || Box::<rustgfw_core::tls::TlsSni>::default(),
            },
            AnalyzerRule {
                hosts: self.dns_names.clone(),
                port: Some(53),
                factory: || Box::<rustgfw_core::dns::DnsTcp>::default(),
            },
        ];
        DnsPolicy::new(
            Inspect::with_analyzers(Rules::new(self.rules, self.default), analyzers),
            self.dns_names,
        )
    }
}

#[cfg(target_os = "linux")]
fn run_nfqueue(args: &[String]) -> Result<(), Error> {
    use rustgfw_core::KernelPolicy;
    use rustgfw_linux::nft::{Hook, NftPolicy, Plan};
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
                bypass_without_listener: false,
            })
        })
        .transpose()?;
    if let Some(handle) = &installed {
        eprintln!("installed nft table {}", handle.table_name());
        if let Err(error) = backend.set_dynamic_table(handle.table_name()) {
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
    if let Some(handle) = &installed
        && let Err(error) = kernel.revoke(handle)
    {
        return Err(format!(
            "failed to remove nft table {}: {error}; engine result: {result:?}",
            handle.table_name()
        )
        .into());
    }
    result?;
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn run_nfqueue(_: &[String]) -> Result<(), Error> {
    Err("NFQUEUE requires Linux".into())
}

#[cfg(target_os = "windows")]
fn run_windivert(args: &[String]) -> Result<(), Error> {
    use rustgfw_windows::{Layer, WinDivert, static_drop_filter, wfp::WfpPolicy};

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
    // Valid ICMP is always accepted by the transport/DPI policy when the
    // default is Accept. Leave it on the native path: WinDivert cannot
    // reinject some inbound ICMP/ICMPv6 packets. Fragments still reach the
    // engine, where unsupported reassembly is handled consistently.
    let packet_filter = if options.default == Verdict::Accept {
        "(not icmp and not icmpv6) or fragment"
    } else {
        "true"
    };
    let mut io = WinDivert::open(&args[0], layer, packet_filter)?;
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
