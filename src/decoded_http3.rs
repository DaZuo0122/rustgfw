//! Line-delimited decoded QUIC stream input for rule validation and adapters.
use super::{Error, Options};
use rustgfw_core::{FlowScope, Verdict, inspect::DecodedStream};
use serde::{Deserialize, Serialize};
use std::{
    io::{self, BufRead, Write},
    net::SocketAddr,
};

#[derive(Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
enum Input {
    Data {
        scope: ScopeInput,
        stream_id: u64,
        origin: SocketAddr,
        target: SocketAddr,
        reverse: bool,
        bytes: Vec<u8>,
    },
    CloseStream {
        scope: ScopeInput,
        stream_id: u64,
    },
    CloseConnection {
        scope: ScopeInput,
    },
}

#[derive(Deserialize)]
#[serde(untagged)]
enum ScopeInput {
    Number(u64),
    Text(String),
}

impl ScopeInput {
    fn parse(self) -> Result<u128, Error> {
        match self {
            Self::Number(value) => Ok(u128::from(value)),
            Self::Text(value) => Ok(value.parse()?),
        }
    }
}

#[derive(Serialize)]
struct Output {
    scope: String,
    stream_id: u64,
    verdict: &'static str,
}

pub(super) fn run(args: &[String]) -> Result<(), Error> {
    let options = Options::parse("accept", args)?;
    if options.expr_rules.is_empty() {
        return Err("decoded-http3 requires rules-file with expression rules".into());
    }
    if !options.rules.is_empty()
        || !options.http_hosts.is_empty()
        || !options.tls_sni.is_empty()
        || !options.dns_names.is_empty()
        || options.nft_hook.is_some()
        || options.ctmark.is_some()
    {
        return Err("decoded-http3 accepts expression rules and inspection limits only".into());
    }
    let mut policy = options.into_policy();
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut output = stdout.lock();
    for (index, line) in stdin.lock().lines().enumerate() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let input: Input = serde_json::from_str(&line)
            .map_err(|error| format!("input line {}: {error}", index + 1))?;
        match input {
            Input::Data {
                scope,
                stream_id,
                origin,
                target,
                reverse,
                bytes,
            } => {
                let scope = scope.parse()?;
                for result in policy.feed_http3(DecodedStream {
                    scope: FlowScope(scope),
                    stream_id,
                    origin,
                    target,
                    reverse,
                    bytes: &bytes,
                }) {
                    let verdict = match result.verdict {
                        Verdict::Accept => "accept",
                        Verdict::Drop | Verdict::DropFlow => "drop_flow",
                    };
                    serde_json::to_writer(
                        &mut output,
                        &Output {
                            scope: scope.to_string(),
                            stream_id: result.stream_id,
                            verdict,
                        },
                    )?;
                    writeln!(output)?;
                }
                output.flush()?;
            }
            Input::CloseStream { scope, stream_id } => {
                policy.close_http3_stream(FlowScope(scope.parse()?), stream_id);
            }
            Input::CloseConnection { scope } => {
                policy.close_http3_connection(FlowScope(scope.parse()?));
            }
        }
    }
    Ok(())
}
