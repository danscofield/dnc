//! dchat — DNS chat
//!
//! A dumb IRC-like chat over the DNS Message Broker.
//! Everyone joins a "room" (channel) and their nickname is the sender ID.
//!
//! Usage:
//!   dchat -n alice -r lobby                     # join room "lobby" as "alice"
//!   dchat -n bob -r lobby -b 127.0.0.1:5353     # direct to local broker
//!
//! Features a split-screen TUI: scrolling chat on top, fixed input line at bottom.

use std::io::{self, Write};
use std::net::SocketAddr;

use clap::Parser;
use crossterm::{
    cursor, execute,
    event::{self, Event, KeyCode, KeyModifiers},
    terminal::{self, ClearType},
};
use dns_message_broker::encoding::{base32_encode, decode_envelope, EnvelopeParts};
use hickory_proto::op::{Message, MessageType, Query};
use hickory_proto::rr::{Name, RData, RecordType};
use tokio::net::UdpSocket;

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
#[command(name = "dchat", about = "DNS chat — IRC-like rooms over DNS Message Broker")]
struct Cli {
    /// Your nickname
    #[arg(short = 'n', long)]
    nick: String,

    /// Room (channel) to join
    #[arg(short = 'r', long, default_value = "lobby")]
    room: String,

    /// DNS resolver or broker address (default: system resolver)
    #[arg(short = 'b', long)]
    broker: Option<SocketAddr>,

    /// Controlled domain
    #[arg(short = 'd', long, default_value = "broker.example.com")]
    domain: String,
}

// ---------------------------------------------------------------------------
// DNS helpers
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
    let mut parts = vec![nonce()];
    parts.extend(labels.iter().map(|s| s.to_string()));
    parts.push(sender.to_string());
    parts.push(channel.to_string());
    parts.push(domain.to_string());
    format!("{}.", parts.join("."))
}

async fn dns_send(
    socket: &UdpSocket,
    broker: SocketAddr,
    text: &str,
    sender: &str,
    channel: &str,
    domain: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let name_str = build_send_name(text.as_bytes(), sender, channel, domain);
    let name = Name::from_ascii(&name_str)?;

    let mut msg = Message::new();
    msg.set_id(query_id());
    msg.set_message_type(MessageType::Query);
    msg.set_recursion_desired(true);
    msg.add_query(Query::query(name, RecordType::A));

    socket.send_to(&msg.to_vec()?, broker).await?;
    let mut buf = [0u8; 512];
    let _ = tokio::time::timeout(std::time::Duration::from_secs(3), socket.recv_from(&mut buf)).await;
    Ok(())
}

async fn dns_recv(
    socket: &UdpSocket,
    broker: SocketAddr,
    channel: &str,
    domain: &str,
    cursor: u64,
) -> Result<(Vec<EnvelopeParts>, u64), Box<dyn std::error::Error>> {
    let name_str = format!("{}-c{}.{}.{}.", nonce(), cursor, channel, domain);
    let name = Name::from_ascii(&name_str)?;

    let mut msg = Message::new();
    msg.set_id(query_id());
    msg.set_message_type(MessageType::Query);
    msg.set_recursion_desired(true);
    msg.add_query(Query::query(name, RecordType::TXT));

    socket.send_to(&msg.to_vec()?, broker).await?;

    let mut buf = [0u8; 512];
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        socket.recv_from(&mut buf),
    ).await;

    let (len, _) = match result {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => return Err(e.into()),
        Err(_) => return Ok((vec![], cursor)),
    };

    let resp = Message::from_vec(&buf[..len])?;
    if resp.answers().is_empty() {
        return Ok((vec![], cursor));
    }

    let mut new_cursor = cursor;
    let mut envelopes = Vec::new();

    for ans in resp.answers() {
        if let RData::TXT(ref txt) = ans.data() {
            let envelope_str: String = txt
                .iter()
                .map(|b| String::from_utf8_lossy(b).to_string())
                .collect::<Vec<_>>()
                .join("");
            if let Ok(parts) = decode_envelope(&envelope_str) {
                if parts.sequence >= new_cursor {
                    new_cursor = parts.sequence + 1;
                }
                envelopes.push(parts);
            }
        }
    }
    Ok((envelopes, new_cursor))
}

// ---------------------------------------------------------------------------
// TUI
// ---------------------------------------------------------------------------

struct Tui {
    chat_lines: Vec<String>,
    input_buf: String,
    room: String,
    width: u16,
    height: u16,
}

impl Tui {
    fn new(nick: &str, room: &str) -> Self {
        let (w, h) = terminal::size().unwrap_or((80, 24));
        Self {
            chat_lines: vec![format!("  joined #{room} as {nick}")],
            input_buf: String::new(),
            room: room.to_string(),
            width: w,
            height: h,
        }
    }

    fn add_message(&mut self, sender: &str, text: &str) {
        self.chat_lines.push(format!("<{sender}> {text}"));
    }

    fn add_system(&mut self, text: &str) {
        self.chat_lines.push(format!("  {text}"));
    }

    fn redraw(&self, stdout: &mut io::Stdout) {
        let w = self.width as usize;
        let h = self.height;
        if h < 4 { return; }

        // Layout: row 0..h-3 = chat, row h-2 = separator, row h-1 = input
        let chat_rows = (h - 2) as usize;

        // Collect visible lines (word-wrap long lines)
        let mut visible: Vec<&str> = Vec::new();
        for line in &self.chat_lines {
            if line.len() <= w {
                visible.push(line);
            } else {
                // Simple char-boundary chunking
                let mut start = 0;
                while start < line.len() {
                    let end = (start + w).min(line.len());
                    visible.push(&line[start..end]);
                    start = end;
                }
            }
        }

        // Take the last chat_rows lines
        let skip = visible.len().saturating_sub(chat_rows);
        let shown = &visible[skip..];

        // Draw chat area
        let _ = execute!(stdout, cursor::MoveTo(0, 0));
        for (i, line) in shown.iter().enumerate() {
            let _ = execute!(stdout, cursor::MoveTo(0, i as u16));
            let _ = execute!(stdout, terminal::Clear(ClearType::CurrentLine));
            let _ = write!(stdout, "{line}");
        }
        // Clear remaining chat rows
        for i in shown.len()..chat_rows {
            let _ = execute!(stdout, cursor::MoveTo(0, i as u16));
            let _ = execute!(stdout, terminal::Clear(ClearType::CurrentLine));
        }

        // Separator
        let sep_row = h - 2;
        let _ = execute!(stdout, cursor::MoveTo(0, sep_row));
        let _ = execute!(stdout, terminal::Clear(ClearType::CurrentLine));
        let title = format!(" #{} ", self.room);
        let dashes = w.saturating_sub(title.len());
        let left = dashes / 2;
        let right = dashes - left;
        let _ = write!(stdout, "{}{}{}", "─".repeat(left), title, "─".repeat(right));

        // Input line
        let input_row = h - 1;
        let _ = execute!(stdout, cursor::MoveTo(0, input_row));
        let _ = execute!(stdout, terminal::Clear(ClearType::CurrentLine));
        let prompt = format!("> {}", self.input_buf);
        let _ = write!(stdout, "{prompt}");

        // Position cursor at end of input
        let cx = (2 + self.input_buf.len()).min(w) as u16;
        let _ = execute!(stdout, cursor::MoveTo(cx, input_row));

        let _ = stdout.flush();
    }

    fn resize(&mut self, w: u16, h: u16) {
        self.width = w;
        self.height = h;
    }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let broker = cli.broker.unwrap_or_else(system_resolver);
    let bind_addr = if broker.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" };

    let send_sock = UdpSocket::bind(bind_addr).await?;
    let recv_sock = UdpSocket::bind(bind_addr).await?;

    let nick = cli.nick;
    let room = cli.room;
    let domain = cli.domain;

    // Enter raw mode for TUI
    terminal::enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, terminal::EnterAlternateScreen, cursor::Show)?;

    let mut tui = Tui::new(&nick, &room);
    tui.redraw(&mut stdout);

    let poll_interval = std::time::Duration::from_secs(3);
    let mut cursor: u64 = 0;
    let mut last_poll = tokio::time::Instant::now();

    loop {
        // Check for keyboard input (non-blocking, 50ms timeout)
        let has_event = tokio::task::block_in_place(|| {
            event::poll(std::time::Duration::from_millis(50)).unwrap_or(false)
        });

        if has_event {
            let evt = tokio::task::block_in_place(|| event::read());
            match evt {
                Ok(Event::Key(key)) => {
                    match key.code {
                        KeyCode::Enter => {
                            let text = tui.input_buf.clone();
                            tui.input_buf.clear();
                            if !text.is_empty() {
                                tui.add_message(&nick, &text);
                                tui.redraw(&mut stdout);
                                if let Err(e) = dns_send(&send_sock, broker, &text, &nick, &room, &domain).await {
                                    tui.add_system(&format!("send error: {e}"));
                                }
                                tui.redraw(&mut stdout);
                            }
                        }
                        KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                            break;
                        }
                        KeyCode::Char(c) => {
                            tui.input_buf.push(c);
                            tui.redraw(&mut stdout);
                        }
                        KeyCode::Backspace => {
                            tui.input_buf.pop();
                            tui.redraw(&mut stdout);
                        }
                        KeyCode::Esc => break,
                        _ => {}
                    }
                }
                Ok(Event::Resize(w, h)) => {
                    tui.resize(w, h);
                    tui.redraw(&mut stdout);
                }
                _ => {}
            }
        }

        // Poll for messages on interval
        if last_poll.elapsed() >= poll_interval {
            last_poll = tokio::time::Instant::now();
            match dns_recv(&recv_sock, broker, &room, &domain, cursor).await {
                Ok((envelopes, new_cursor)) => {
                    cursor = new_cursor;
                    let mut got_new = false;
                    for envelope in &envelopes {
                        let sender = &envelope.sender_id;
                        if sender != &nick {
                            let text = String::from_utf8_lossy(&envelope.payload);
                            tui.add_message(sender, &text);
                            got_new = true;
                        }
                    }
                    if got_new {
                        tui.redraw(&mut stdout);
                    }
                }
                Err(_) => {}
            }
        }
    }

    // Restore terminal
    execute!(stdout, terminal::LeaveAlternateScreen)?;
    terminal::disable_raw_mode()?;
    println!("dchat: bye!");

    Ok(())
}
