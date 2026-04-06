//! dnc — DNS netcat
//!
//! A netcat-style client for the DNS Message Broker.
//!
//! Send mode (default):
//!   echo "hello" | dnc general
//!   echo "hello" | dnc -s alice general
//!   cat bigfile.txt | dnc -s bob inbox    # auto-chunks large inputs
//!
//! Listen mode:
//!   dnc -l general
//!   dnc -l -1 general          # receive one stream and exit
//!
//! Examples:
//!   # pipe a file (auto-chunked, reassembled on receive)
//!   cat secret.txt | dnc -s bob inbox
//!
//!   # interactive listen
//!   dnc -l inbox
//!
//!   # one-shot receive
//!   dnc -l -1 inbox

use std::io::{self, BufRead, Read, Write};
use std::net::SocketAddr;

use clap::Parser;
use dns_message_broker::encoding::{base32_encode, decode_envelope, EnvelopeParts};
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
    after_help = "Examples:\n  echo 'hello' | dnc general\n  cat file.txt | dnc -s bob inbox\n  dnc -l general\n  dnc -l -1 general\n\nLarge inputs are automatically chunked into a stream of DNS messages\nand reassembled on the receiving end.\n\nBy default, queries go through your system resolver (or 1.1.1.1).\nUse -b to target a broker directly for local testing."
)]
struct Cli {
    /// Listen mode (receive messages)
    #[arg(short = 'l', long)]
    listen: bool,

    /// Receive one complete stream and exit (listen mode only)
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

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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
    let labels: Vec<&str> = encoded
        .as_bytes()
        .chunks(63)
        .map(|c| std::str::from_utf8(c).unwrap())
        .collect();
    let mut parts = vec![nonce().as_str().to_string()];
    parts.extend(labels.iter().map(|s| s.to_string()));
    parts.push(sender.to_string());
    parts.push(channel.to_string());
    parts.push(domain.to_string());
    format!("{}.", parts.join("."))
}

/// Max raw payload bytes that fit in a single DNS query name.
fn max_payload_size(sender: &str, channel: &str, domain: &str) -> usize {
    let nonce_len = 16;
    let fixed = nonce_len + sender.len() + channel.len() + domain.len() + 5;
    if fixed >= 253 {
        return 0;
    }
    let remaining = 253 - fixed;
    let base32_chars = ((remaining + 1) * 63) / 64;
    (base32_chars * 5) / 8
}

// ---------------------------------------------------------------------------
// Stream framing
// ---------------------------------------------------------------------------
// Header: [seq_hi, seq_lo, flags, reserved] = 4 bytes
// Flags: 0x00 = DATA, 0x01 = EOF (may still contain payload data)

const STREAM_HEADER_SIZE: usize = 4;
const FLAG_DATA: u8 = 0x00;
const FLAG_EOF: u8 = 0x01;

fn encode_stream_frame(seq: u16, eof: bool, data: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(STREAM_HEADER_SIZE + data.len());
    buf.push((seq >> 8) as u8);
    buf.push((seq & 0xFF) as u8);
    buf.push(if eof { FLAG_EOF } else { FLAG_DATA });
    buf.push(0x00); // reserved
    buf.extend_from_slice(data);
    buf
}

struct StreamFrame {
    seq: u16,
    eof: bool,
    data: Vec<u8>,
}

fn decode_stream_frame(payload: &[u8]) -> Option<StreamFrame> {
    if payload.len() < STREAM_HEADER_SIZE {
        return None;
    }
    let seq = ((payload[0] as u16) << 8) | (payload[1] as u16);
    let eof = payload[2] == FLAG_EOF;
    let data = payload[STREAM_HEADER_SIZE..].to_vec();
    Some(StreamFrame { seq, eof, data })
}

// ---------------------------------------------------------------------------
// DNS send/recv primitives
// ---------------------------------------------------------------------------

async fn dns_send_raw(
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
    )
    .await??;

    let resp = Message::from_vec(&buf[..len])?;
    for ans in resp.answers() {
        if let RData::A(A(ip)) = ans.data() {
            if ip.octets() == [1, 2, 3, 5] {
                return Err("payload too large for broker".into());
            } else if ip.octets() == [1, 2, 3, 6] {
                return Err("channel full".into());
            }
        }
    }
    Ok(())
}

async fn dns_recv_raw(
    socket: &UdpSocket,
    broker: SocketAddr,
    channel: &str,
    domain: &str,
) -> Result<Option<EnvelopeParts>, Box<dyn std::error::Error>> {
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
    )
    .await;

    let (len, _) = match result {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => return Err(e.into()),
        Err(_) => return Ok(None),
    };

    let resp = Message::from_vec(&buf[..len])?;
    if resp.answers().is_empty() {
        return Ok(None);
    }

    for ans in resp.answers() {
        if let RData::TXT(ref txt) = ans.data() {
            let envelope_str: String = txt
                .iter()
                .map(|b| String::from_utf8_lossy(b).to_string())
                .collect::<Vec<_>>()
                .join("");
            if let Ok(parts) = decode_envelope(&envelope_str) {
                return Ok(Some(parts));
            }
        }
    }
    Ok(None)
}

// ---------------------------------------------------------------------------
// Stream send: chunk data and send as a sequence of framed messages
// ---------------------------------------------------------------------------

async fn stream_send(
    socket: &UdpSocket,
    broker: SocketAddr,
    data: &[u8],
    sender: &str,
    channel: &str,
    domain: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let max_raw = max_payload_size(sender, channel, domain);
    if max_raw <= STREAM_HEADER_SIZE {
        return Err("DNS name overhead too large for any payload".into());
    }
    let max_data_per_frame = max_raw - STREAM_HEADER_SIZE;

    if data.is_empty() {
        // Just send EOF with no data
        let frame = encode_stream_frame(0, true, &[]);
        return dns_send_raw(socket, broker, &frame, sender, channel, domain).await;
    }

    let chunks: Vec<&[u8]> = data.chunks(max_data_per_frame).collect();
    let total = chunks.len();

    if total > 65535 {
        return Err(format!(
            "input too large: would need {} frames (max 65535)",
            total
        )
        .into());
    }

    if total > 1 {
        eprintln!(
            "dnc: streaming {} bytes in {} frames ({} bytes/frame)",
            data.len(),
            total,
            max_data_per_frame
        );
    }

    for (i, chunk) in chunks.iter().enumerate() {
        let seq = i as u16;
        let is_last = i == total - 1;
        let frame = encode_stream_frame(seq, is_last, chunk);
        dns_send_raw(socket, broker, &frame, sender, channel, domain).await?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Stream receive: collect framed messages and reassemble in order
// ---------------------------------------------------------------------------

/// Receive a complete stream (all frames until EOF), output data to stdout.
/// Returns true if a stream was received, false if channel was empty.
async fn stream_recv(
    socket: &UdpSocket,
    broker: SocketAddr,
    channel: &str,
    domain: &str,
) -> Result<bool, Box<dyn std::error::Error>> {
    let min_interval = std::time::Duration::from_millis(50);
    let max_interval = std::time::Duration::from_millis(500);
    let mut interval = min_interval;

    let mut next_expected: u16 = 0;
    let mut buffer: std::collections::BTreeMap<u16, (bool, Vec<u8>)> = std::collections::BTreeMap::new();
    let mut got_first = false;
    let mut eof_seq: Option<u16> = None;
    let stdout = io::stdout();
    let mut out = stdout.lock();

    loop {
        match dns_recv_raw(socket, broker, channel, domain).await? {
            Some(envelope) => {
                interval = min_interval;

                // Try to decode as stream frame
                if let Some(frame) = decode_stream_frame(&envelope.payload) {
                    got_first = true;
                    if frame.eof {
                        eof_seq = Some(frame.seq);
                    }
                    buffer.insert(frame.seq, (frame.eof, frame.data));

                    // Flush contiguous frames from next_expected
                    while let Some((is_eof, data)) = buffer.remove(&next_expected) {
                        if !data.is_empty() {
                            out.write_all(&data)?;
                        }
                        if is_eof {
                            // EOF frame — we're done
                            out.flush()?;
                            return Ok(true);
                        }
                        next_expected = next_expected.wrapping_add(1);
                    }
                } else {
                    // Legacy message (no stream header) — output as-is
                    out.write_all(&envelope.payload)?;
                    out.write_all(b"\n")?;
                    out.flush()?;
                    return Ok(true);
                }
            }
            None => {
                if !got_first {
                    return Ok(false);
                }
                // We've started receiving but channel is empty — back off and retry
                interval = (interval * 2).min(max_interval);
            }
        }

        // Check if we've received everything
        if let Some(eof) = eof_seq {
            if next_expected > eof {
                out.flush()?;
                return Ok(true);
            }
        }

        if !got_first {
            return Ok(false);
        }

        tokio::time::sleep(interval).await;
    }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let resolver = cli.broker.unwrap_or_else(system_resolver);
    let bind_addr = if resolver.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" };
    let socket = UdpSocket::bind(bind_addr).await?;

    eprintln!("dnc: using resolver {}", resolver);

    if cli.listen {
        let min_interval = std::time::Duration::from_millis(50);
        let max_interval = std::time::Duration::from_secs(1);
        let mut interval = min_interval;

        loop {
            match stream_recv(&socket, resolver, &cli.channel, &cli.domain).await {
                Ok(true) => {
                    interval = min_interval;
                    if cli.once {
                        break;
                    }
                }
                Ok(false) => {
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
        let stdin = io::stdin();
        if atty::is(atty::Stream::Stdin) {
            // Interactive: each line is its own stream
            eprintln!("dnc: reading from stdin (Ctrl+D to finish)");
            for line in stdin.lock().lines() {
                let line = line?;
                if line.is_empty() {
                    continue;
                }
                stream_send(
                    &socket,
                    resolver,
                    line.as_bytes(),
                    &cli.sender,
                    &cli.channel,
                    &cli.domain,
                )
                .await?;
            }
        } else {
            // Piped: read all stdin as one stream
            let mut data = Vec::new();
            stdin.lock().read_to_end(&mut data)?;
            if data.last() == Some(&b'\n') {
                data.pop();
            }
            if !data.is_empty() {
                stream_send(
                    &socket,
                    resolver,
                    &data,
                    &cli.sender,
                    &cli.channel,
                    &cli.domain,
                )
                .await?;
            }
        }
    }

    Ok(())
}
