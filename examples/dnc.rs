//! dnc — DNS netcat
//!
//! A netcat-style client for the DNS Message Broker.
//!
//! Send mode (default):
//!   echo "hello" | dnc general
//!   echo "hello" | dnc -s alice general
//!
//! Listen mode:
//!   dnc -l general
//!   dnc -l -1 general          # receive one message and exit
//!
//! Examples:
//!   # pipe a file
//!   cat secret.txt | dnc -s bob inbox
//!
//!   # interactive listen
//!   dnc -l inbox
//!
//!   # one-shot receive
//!   dnc -l -1 inbox

use std::io::{self, BufRead, Read};
use std::net::SocketAddr;

use clap::Parser;
use dns_message_broker::encoding::{base32_encode, decode_envelope};
use hickory_proto::op::{Message, MessageType, Query};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData, RecordType};
use tokio::net::UdpSocket;

/// Try to read the first nameserver from /etc/resolv.conf.
/// Falls back to 1.1.1.1:53 if it can't be determined.
fn system_resolver() -> SocketAddr {
    if let Ok(contents) = std::fs::read_to_string("/etc/resolv.conf") {
        for line in contents.lines() {
            let line = line.trim();
            if let Some(addr_str) = line.strip_prefix("nameserver") {
                let addr_str = addr_str.trim();
                if let Ok(ip) = addr_str.parse::<std::net::IpAddr>() {
                    return SocketAddr::new(ip, 53);
                }
            }
        }
    }
    "1.1.1.1:53".parse().unwrap()
}

#[derive(Parser)]
#[command(
    name = "dnc",
    about = "DNS netcat — send and receive via DNS Message Broker",
    after_help = "Examples:\n  echo 'hello' | dnc general\n  dnc -l general\n  dnc -l -1 general\n\nBy default, queries go through your system resolver (or 1.1.1.1).\nUse -b to target a broker directly for local testing."
)]
struct Cli {
    /// Listen mode (receive messages)
    #[arg(short = 'l', long)]
    listen: bool,

    /// Receive one message and exit (listen mode only)
    #[arg(short = '1', long)]
    once: bool,

    /// Sender ID (send mode, default: "anon")
    #[arg(short = 's', long, default_value = "anon")]
    sender: String,

    /// DNS resolver or broker address (default: system resolver)
    #[arg(short = 'b', long)]
    broker: Option<SocketAddr>,

    /// Controlled domain
    #[arg(short = 'd', long, default_value = "broker.example.com")]
    domain: String,

    /// Channel name
    channel: String,
}

fn nonce() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("{:016x}", t & 0xFFFF_FFFF_FFFF_FFFF)
}

fn query_id() -> u16 {
    use std::time::{SystemTime, UNIX_EPOCH};
    (SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .subsec_nanos()
        & 0xFFFF) as u16
}

fn build_send_name(payload: &[u8], sender: &str, channel: &str, domain: &str) -> String {
    let encoded = base32_encode(payload);
    let labels: Vec<&str> = encoded.as_bytes().chunks(63)
        .map(|c| std::str::from_utf8(c).unwrap())
        .collect();
    let mut parts = vec![nonce().as_str().to_string()];
    parts.extend(labels.iter().map(|s| s.to_string()));
    parts.push(sender.to_string());
    parts.push(channel.to_string());
    parts.push(domain.to_string());
    format!("{}.", parts.join("."))
}

async fn dns_send(
    socket: &UdpSocket,
    broker: SocketAddr,
    payload: &[u8],
    sender: &str,
    channel: &str,
    domain: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let name_str = build_send_name(payload, sender, channel, domain);
    let name = Name::from_ascii(&name_str)?;

    let mut msg = Message::new();
    msg.set_id(query_id());
    msg.set_message_type(MessageType::Query);
    msg.set_recursion_desired(true);
    msg.add_query(Query::query(name, RecordType::A));

    socket.send_to(&msg.to_vec()?, broker).await?;

    let mut buf = [0u8; 512];
    let (len, _) = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        socket.recv_from(&mut buf),
    ).await??;

    let resp = Message::from_vec(&buf[..len])?;
    for ans in resp.answers() {
        if let RData::A(A(ip)) = ans.data() {
            // 1.2.3.4 = ack, 1.2.3.5 = too large, 1.2.3.6 = full
            if ip.octets() == [1, 2, 3, 5] {
                eprintln!("dnc: payload too large");
            } else if ip.octets() == [1, 2, 3, 6] {
                eprintln!("dnc: channel full");
            }
        }
    }
    Ok(())
}

async fn dns_recv(
    socket: &UdpSocket,
    broker: SocketAddr,
    channel: &str,
    domain: &str,
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    let name_str = format!("{}.{}.{}.", nonce(), channel, domain);
    let name = Name::from_ascii(&name_str)?;

    let mut msg = Message::new();
    msg.set_id(query_id());
    msg.set_message_type(MessageType::Query);
    msg.set_recursion_desired(true);
    msg.add_query(Query::query(name, RecordType::TXT));

    socket.send_to(&msg.to_vec()?, broker).await?;

    let mut buf = [0u8; 512];
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        socket.recv_from(&mut buf),
    ).await;

    let (len, _) = match result {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => return Err(e.into()),
        Err(_) => return Ok(None), // timeout = treat as no message
    };

    let resp = Message::from_vec(&buf[..len])?;
    if resp.answers().is_empty() {
        return Ok(None);
    }

    for ans in resp.answers() {
        if let RData::TXT(ref txt) = ans.data() {
            let envelope_str: String = txt.iter()
                .map(|b| String::from_utf8_lossy(b).to_string())
                .collect::<Vec<_>>()
                .join("");
            if let Ok(parts) = decode_envelope(&envelope_str) {
                let text = String::from_utf8_lossy(&parts.payload);
                return Ok(Some(text.into_owned()));
            }
        }
    }
    Ok(None)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let resolver = cli.broker.unwrap_or_else(system_resolver);
    let bind_addr = if resolver.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" };
    let socket = UdpSocket::bind(bind_addr).await?;

    eprintln!("dnc: using resolver {}", resolver);

    if cli.listen {
        // Listen mode — poll with exponential backoff
        let min_interval = std::time::Duration::from_millis(50);
        let max_interval = std::time::Duration::from_secs(1);
        let mut interval = min_interval;

        loop {
            match dns_recv(&socket, resolver, &cli.channel, &cli.domain).await {
                Ok(Some(text)) => {
                    println!("{}", text);
                    interval = min_interval;
                    if cli.once {
                        break;
                    }
                }
                Ok(None) => {
                    interval = (interval * 2).min(max_interval);
                }
                Err(e) => {
                    eprintln!("dnc: {}", e);
                    interval = (interval * 2).min(max_interval);
                }
            }
            tokio::time::sleep(interval).await;
        }
    } else {
        // Send mode — read stdin, send each line (or all of stdin if piped)
        let stdin = io::stdin();
        if atty::is(atty::Stream::Stdin) {
            // Interactive: read lines
            eprintln!("dnc: reading from stdin (Ctrl+D to finish)");
            for line in stdin.lock().lines() {
                let line = line?;
                if line.is_empty() { continue; }
                dns_send(&socket, resolver, line.as_bytes(), &cli.sender, &cli.channel, &cli.domain).await?;
            }
        } else {
            // Piped: read all at once
            let mut data = Vec::new();
            stdin.lock().read_to_end(&mut data)?;
            // Strip trailing newline if present
            if data.last() == Some(&b'\n') { data.pop(); }
            if !data.is_empty() {
                dns_send(&socket, resolver, &data, &cli.sender, &cli.channel, &cli.domain).await?;
            }
        }
    }

    Ok(())
}
