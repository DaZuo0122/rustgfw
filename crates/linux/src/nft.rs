//! Owned nftables table with an ordered static fast path and NFQUEUE fallback.
use rustgfw_core::{
    KernelPolicy,
    offload::{Action, Rule},
    packet::Protocol,
};
use std::{
    io::{self, Write},
    path::PathBuf,
    process::{Command, Stdio},
    sync::atomic::{AtomicU64, Ordering},
};

#[derive(Clone, Copy)]
pub enum Hook {
    Input,
    Output,
    Forward,
}
impl Hook {
    fn name(self) -> &'static str {
        match self {
            Self::Input => "input",
            Self::Output => "output",
            Self::Forward => "forward",
        }
    }
}
pub struct Plan {
    pub hook: Hook,
    pub queue: u16,
    pub rules: Vec<Rule>,
    /// No queue listener: bypass or drop. Independent of queue overflow policy.
    pub bypass_without_listener: bool,
}
pub struct Handle {
    table: String,
}
impl Handle {
    pub fn table_name(&self) -> &str {
        &self.table
    }
}

pub struct NftPolicy {
    executable: PathBuf,
}
impl NftPolicy {
    pub fn new(executable: impl Into<PathBuf>) -> Self {
        Self {
            executable: executable.into(),
        }
    }
    fn execute(&self, script: &str) -> io::Result<()> {
        let mut child = Command::new(&self.executable)
            .args(["-f", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()?;
        let write = child.stdin.take().unwrap().write_all(script.as_bytes());
        let output = child.wait_with_output()?;
        if !output.status.success() {
            return Err(io::Error::other(
                String::from_utf8_lossy(&output.stderr).into_owned(),
            ));
        }
        write
    }
    /// Replace only this table's contents in one nft transaction.
    pub fn replace(&mut self, handle: &Handle, plan: &Plan) -> io::Result<()> {
        self.execute(&format!(
            "delete table inet {}\n{}",
            handle.table,
            render(&handle.table, plan)
        ))
    }
    /// Conntrack ID identifies both directions of one connection.
    pub fn block_tcp_flow(&self, table: &str, conntrack_id: u32) -> io::Result<()> {
        self.execute(&format!(
            "add element inet {table} blocked_ct {{ {conntrack_id} timeout 120s }}\n"
        ))
    }
    pub fn unblock_tcp_flow(&self, table: &str, conntrack_id: u32) -> io::Result<()> {
        self.execute(&format!(
            "destroy element inet {table} blocked_ct {{ {conntrack_id} }}\n"
        ))
    }
}
impl KernelPolicy for NftPolicy {
    type Rule = Plan;
    type Handle = Handle;
    fn install(&mut self, plan: &Plan) -> io::Result<Handle> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let table = format!(
            "rustgfw_{}_{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        );
        self.execute(&render(&table, plan))?;
        Ok(Handle { table })
    }
    fn revoke(&mut self, handle: &Handle) -> io::Result<()> {
        self.execute(&format!("delete table inet {}\n", handle.table))
    }
}

fn render(table: &str, plan: &Plan) -> String {
    // 'create' refuses a preexisting table, rather than taking ownership of it.
    let mut out = format!(
        "create table inet {table}\nadd chain inet {table} inspect {{ type filter hook {} priority 0; policy accept; }}\n",
        plan.hook.name()
    );
    out.push_str(&format!(
        "add set inet {table} blocked_ct {{ typeof ct id; flags timeout; }}\n"
    ));
    out.push_str(&format!(
        "add rule inet {table} inspect ct event set destroy\n"
    ));
    out.push_str(&format!(
        "add rule inet {table} inspect meta l4proto tcp ct id @blocked_ct tcp flags & rst == rst counter queue num {}\n", plan.queue
    ));
    out.push_str(&format!(
        "add rule inet {table} inspect meta l4proto tcp ct id @blocked_ct counter drop\n"
    ));
    for rule in &plan.rules {
        let protocol = match rule.protocol {
            Protocol::Tcp => "tcp",
            Protocol::Udp => "udp",
        };
        let action = match rule.action {
            Action::Drop => "drop".to_owned(),
            Action::BypassInspection => "accept".to_owned(),
            Action::Inspect => format!(
                "queue num {}{}",
                plan.queue,
                if plan.bypass_without_listener {
                    " bypass"
                } else {
                    ""
                }
            ),
        };
        if let Some(port) = rule.port {
            for direction in ["sport", "dport"] {
                out.push_str(&format!(
                    "add rule inet {table} inspect {protocol} {direction} {port} counter {action}\n"
                ));
            }
        } else {
            out.push_str(&format!(
                "add rule inet {table} inspect meta l4proto {protocol} counter {action}\n"
            ));
        }
    }
    let bypass = if plan.bypass_without_listener {
        " bypass"
    } else {
        ""
    };
    out.push_str(&format!(
        "add rule inet {table} inspect counter queue num {}{bypass}\n",
        plan.queue
    ));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{net::UdpSocket, time::Duration};
    #[test]
    fn ordered_rules_and_queue_semantics() {
        let p = Plan {
            hook: Hook::Forward,
            queue: 12,
            bypass_without_listener: false,
            rules: vec![Rule {
                protocol: Protocol::Udp,
                port: Some(53),
                action: Action::Drop,
            }],
        };
        let text = render("test", &p);
        assert!(text.find("udp dport 53").unwrap() < text.rfind("queue num 12").unwrap());
        assert!(!text.contains("bypass"));
        assert!(text.starts_with("create table inet test\n"));
    }
    #[test]
    #[ignore = "run in an isolated network namespace with nft and loopback up"]
    fn kernel_install_replace_revoke() -> io::Result<()> {
        let receiver = UdpSocket::bind("127.0.0.1:0")?;
        receiver.set_read_timeout(Some(Duration::from_millis(150)))?;
        let sender = UdpSocket::bind("127.0.0.1:0")?;
        let addr = receiver.local_addr()?;
        let mut backend = NftPolicy::new("/usr/sbin/nft");
        let mut plan = Plan {
            hook: Hook::Output,
            queue: 100,
            bypass_without_listener: true,
            rules: vec![Rule {
                protocol: Protocol::Udp,
                port: Some(addr.port()),
                action: Action::Drop,
            }],
        };
        let handle = backend.install(&plan)?;
        let result = (|| {
            // Local OUTPUT drop may surface EPERM to sendto, unlike forwarding.
            let _ = sender.send_to(b"drop", addr);
            let mut buf = [0; 16];
            assert!(matches!(
                receiver.recv(&mut buf).unwrap_err().kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            ));
            plan.rules[0].action = Action::BypassInspection;
            backend.replace(&handle, &plan)?;
            sender.send_to(b"accept", addr)?;
            assert_eq!(receiver.recv(&mut buf)?, 6);
            Ok::<_, io::Error>(())
        })();
        backend.revoke(&handle)?;
        result?;
        sender.send_to(b"revoked", addr)?;
        assert_eq!(receiver.recv(&mut [0; 16])?, 7);
        Ok(())
    }
    #[test]
    #[ignore = "run in an isolated network namespace with nft"]
    fn repeated_dynamic_block_is_idempotent() -> io::Result<()> {
        let mut backend = NftPolicy::new("/usr/sbin/nft");
        let plan = Plan {
            hook: Hook::Output,
            queue: 100,
            rules: vec![],
            bypass_without_listener: false,
        };
        let handle = backend.install(&plan)?;
        let result = (|| {
            backend.block_tcp_flow(handle.table_name(), 12345)?;
            backend.block_tcp_flow(handle.table_name(), 12345)
        })();
        backend.revoke(&handle)?;
        result
    }
}
