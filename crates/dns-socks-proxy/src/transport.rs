// Transport backend: DNS and direct store transports.

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use async_trait::async_trait;
use hickory_proto::op::{Message, Query};
use hickory_proto::rr::{Name, RData, RecordType};
use rand::Rng;
use thiserror::Error;
use tokio::net::UdpSocket;
use tracing::{debug, warn};

/// Errors that can occur during transport operations.
#[derive(Debug, Error)]
pub enum TransportError {
    #[error("DNS query timed out after {0} retries")]
    Timeout(usize),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("DNS protocol error: {0}")]
    DnsProtocol(String),

    #[error("Envelope decode error: {0}")]
    EnvelopeDecode(String),

    #[error("Base32 decode error: {0}")]
    Base32Decode(String),

    #[error("Channel full after retries")]
    ChannelFull,

    #[error("Socket bind error: {0}")]
    SocketBind(String),

    #[error("Store error: {0}")]
    StoreError(String),

    #[error("Unrecognized status IP: {0}")]
    UnrecognizedStatusIp(Ipv4Addr),
}

/// Well-known broker response IPs.
const ACK_IP: Ipv4Addr = Ipv4Addr::new(1, 2, 3, 4);
const CHANNEL_FULL_IP: Ipv4Addr = Ipv4Addr::new(1, 2, 3, 6);

/// Maximum DNS label length.
const MAX_LABEL_LEN: usize = 63;

/// Default DNS query timeout per attempt.
const DEFAULT_QUERY_TIMEOUT: Duration = Duration::from_secs(2);

/// Default max retries for DNS queries.
const DEFAULT_MAX_RETRIES: usize = 3;

/// Default backoff duration when channel is full.
const DEFAULT_CHANNEL_FULL_BACKOFF: Duration = Duration::from_millis(500);

/// Maximum channel-full retries before giving up.
const MAX_CHANNEL_FULL_RETRIES: usize = 5;

/// Maximum value representable in 24 bits.
const MAX_DEPTH_24BIT: usize = 0x00FF_FFFF;

/// Status IP sentinel: first octet for status responses.
const STATUS_OCTET: u8 = 128;

/// No-data IP returned when a channel's queue is empty.
const NO_DATA_IP: Ipv4Addr = Ipv4Addr::new(0, 0, 0, 0);

/// Encode a queue depth into a status IP address.
/// First octet = 128, remaining 24 bits = depth (clamped to 0x00FF_FFFF).
pub fn encode_status_ip(depth: usize) -> Ipv4Addr {
    let clamped = depth.min(MAX_DEPTH_24BIT) as u32;
    Ipv4Addr::new(
        STATUS_OCTET,
        ((clamped >> 16) & 0xFF) as u8,
        ((clamped >> 8) & 0xFF) as u8,
        (clamped & 0xFF) as u8,
    )
}

/// Decode a status IP response into a queue depth.
/// Returns `Ok(0)` for `0.0.0.0`, `Ok(depth)` for `128.x.x.x`,
/// `Err` for any other IP.
pub fn decode_status_ip(ip: Ipv4Addr) -> Result<usize, TransportError> {
    if ip == NO_DATA_IP {
        return Ok(0);
    }
    let octets = ip.octets();
    if octets[0] == STATUS_OCTET {
        let depth = ((octets[1] as usize) << 16)
            | ((octets[2] as usize) << 8)
            | (octets[3] as usize);
        return Ok(depth);
    }
    Err(TransportError::UnrecognizedStatusIp(ip))
}

/// UDP receive buffer size — large enough for EDNS0 responses.
const UDP_BUF_SIZE: usize = 4096;

/// EDNS0 advertised UDP buffer size.
const EDNS_UDP_SIZE: u16 = 1232;

/// Trait abstracting Broker communication.
#[async_trait]
pub trait TransportBackend: Send + Sync {
    /// Send a frame to the specified channel.
    async fn send_frame(
        &self,
        channel: &str,
        sender_id: &str,
        frame_bytes: &[u8],
    ) -> Result<(), TransportError>;

    /// Receive the next frame(s) from the specified channel.
    /// Returns `(frames, max_store_seq)` where `max_store_seq` is the highest
    /// store sequence number seen across all returned envelopes (used for
    /// cursor-based replay advancement). Returns `None` if no frames.
    /// When `cursor` is `Some`, the query nonce includes a cursor suffix for
    /// cursor-based replay advancement.
    async fn recv_frames(&self, channel: &str, cursor: Option<u64>) -> Result<(Vec<Vec<u8>>, Option<u64>), TransportError>;

    /// Convenience: receive a single frame (pops the first from a batch).
    async fn recv_frame(&self, channel: &str, cursor: Option<u64>) -> Result<Option<Vec<u8>>, TransportError> {
        let (mut frames, _seq) = self.recv_frames(channel, cursor).await?;
        Ok(if frames.is_empty() { None } else { Some(frames.remove(0)) })
    }

    /// Query the queue depth for a channel.
    async fn query_status(&self, channel: &str) -> Result<usize, TransportError>;

    /// Receive a manifest of available sequence IDs and payload lengths.
    /// Default: not supported, return empty.
    async fn recv_manifest(&self, _channel: &str) -> Result<Vec<(u64, usize)>, TransportError> {
        Ok(vec![])
    }

    /// Receive specific frames by sequence ID (selective fetch).
    /// Default: fall back to recv_frames.
    async fn recv_fetch(&self, channel: &str, _seq_ids: &[u64]) -> Result<(Vec<Vec<u8>>, Option<u64>), TransportError> {
        self.recv_frames(channel, None).await
    }
}

/// DNS-based transport: sends/receives via DNS A/TXT queries.
pub struct DnsTransport {
    resolver_addr: SocketAddr,
    controlled_domain: String,
    socket: UdpSocket,
    query_timeout: Duration,
    max_retries: usize,
    channel_full_backoff: Duration,
    query_interval: Duration,
    last_query: tokio::sync::Mutex<tokio::time::Instant>,
    use_edns: bool,
}

impl DnsTransport {
    /// Create a new DnsTransport, binding a UDP socket to an ephemeral port.
    pub async fn new(
        resolver_addr: SocketAddr,
        controlled_domain: String,
    ) -> Result<Self, TransportError> {
        let bind_addr: SocketAddr = if resolver_addr.is_ipv6() {
            "[::]:0".parse().unwrap()
        } else {
            "0.0.0.0:0".parse().unwrap()
        };
        let socket = UdpSocket::bind(bind_addr)
            .await
            .map_err(|e| TransportError::SocketBind(e.to_string()))?;
        Ok(Self {
            resolver_addr,
            controlled_domain,
            socket,
            query_timeout: DEFAULT_QUERY_TIMEOUT,
            max_retries: DEFAULT_MAX_RETRIES,
            channel_full_backoff: DEFAULT_CHANNEL_FULL_BACKOFF,
            query_interval: Duration::ZERO,
            last_query: tokio::sync::Mutex::new(tokio::time::Instant::now()),
            use_edns: true,
        })
    }

    /// Set the query timeout per attempt.
    pub fn with_query_timeout(mut self, timeout: Duration) -> Self {
        self.query_timeout = timeout;
        self
    }

    /// Set the channel-full backoff duration.
    pub fn with_channel_full_backoff(mut self, backoff: Duration) -> Self {
        self.channel_full_backoff = backoff;
        self
    }

    /// Set the minimum interval between DNS queries (rate limiting).
    pub fn with_query_interval(mut self, interval: Duration) -> Self {
        self.query_interval = interval;
        self
    }

    /// Set whether to include EDNS0 OPT records on TXT queries.
    pub fn with_edns(mut self, use_edns: bool) -> Self {
        self.use_edns = use_edns;
        self
    }

    /// Throttle: wait until at least `query_interval` has passed since the last query.
    async fn throttle(&self) {
        if self.query_interval.is_zero() {
            return;
        }
        let mut last = self.last_query.lock().await;
        let elapsed = last.elapsed();
        if elapsed < self.query_interval {
            tokio::time::sleep(self.query_interval - elapsed).await;
        }
        *last = tokio::time::Instant::now();
    }

    /// Generate a random 4-char lowercase alphanumeric nonce.
    fn generate_nonce() -> String {
        let mut rng = rand::thread_rng();
        (0..4)
            .map(|_| {
                let idx = rng.gen_range(0..36);
                if idx < 10 {
                    (b'0' + idx) as char
                } else {
                    (b'a' + idx - 10) as char
                }
            })
            .collect()
    }

    /// Generate a nonce with an optional cursor suffix.
    ///
    /// - `Some(c)` → `<8-char-random>-c<cursor_base10>` (e.g., `aB3kQ12x-c42`)
    /// - `None`    → `<4-char-random>` (existing behavior)
    ///
    /// The result is guaranteed to fit within the 63-byte DNS label limit.
    pub fn generate_nonce_with_cursor(cursor: Option<u64>) -> String {
        match cursor {
            None => Self::generate_nonce(),
            Some(c) => {
                let mut rng = rand::thread_rng();
                let random_part: String = (0..8)
                    .map(|_| {
                        let idx = rng.gen_range(0..62);
                        if idx < 10 {
                            (b'0' + idx) as char
                        } else if idx < 36 {
                            (b'a' + idx - 10) as char
                        } else {
                            (b'A' + idx - 36) as char
                        }
                    })
                    .collect();
                let nonce = format!("{}-c{}", random_part, c);
                // Ensure the nonce fits within the 63-byte DNS label limit.
                // 8 (random) + 2 ("-c") + up to 20 digits (u64 max) = 30 max, well within 63.
                debug_assert!(nonce.len() <= MAX_LABEL_LEN);
                nonce
            }
        }
    }

    /// Split a base32-encoded string into DNS labels of at most MAX_LABEL_LEN chars.
    fn split_into_labels(encoded: &str) -> Vec<&str> {
        if encoded.is_empty() {
            return vec![];
        }
        encoded
            .as_bytes()
            .chunks(MAX_LABEL_LEN)
            .map(|chunk| std::str::from_utf8(chunk).unwrap())
            .collect()
    }

    /// Build a DNS query message for the given name and record type.
    pub fn build_dns_query(name: &Name, record_type: RecordType, use_edns: bool) -> Result<Vec<u8>, TransportError> {
        let mut message = Message::new();
        let id: u16 = rand::thread_rng().gen();
        message.set_id(id);
        message.set_recursion_desired(true);
        let query = Query::query(name.clone(), record_type);
        message.add_query(query);

        // Add EDNS0 OPT record for TXT queries to enable larger responses.
        if record_type == RecordType::TXT && use_edns {
            use hickory_proto::op::Edns;
            let mut edns = Edns::new();
            edns.set_max_payload(EDNS_UDP_SIZE);
            edns.set_version(0);
            message.set_edns(edns);
        }

        message
            .to_vec()
            .map_err(|e| TransportError::DnsProtocol(format!("failed to serialize DNS query: {e}")))
    }

    /// Send a DNS query and wait for a response, with timeout and retries.
    async fn send_dns_query(&self, query_bytes: &[u8]) -> Result<Vec<u8>, TransportError> {
        for attempt in 0..self.max_retries {
            self.throttle().await;
            self.socket.send_to(query_bytes, self.resolver_addr).await?;

            let mut buf = vec![0u8; UDP_BUF_SIZE];
            match tokio::time::timeout(self.query_timeout, self.socket.recv_from(&mut buf)).await {
                Ok(Ok((len, _addr))) => {
                    buf.truncate(len);
                    return Ok(buf);
                }
                Ok(Err(e)) => {
                    warn!(attempt, "UDP recv error: {e}");
                    // Fall through to retry
                }
                Err(_) => {
                    debug!(attempt, "DNS query timed out");
                    // Fall through to retry
                }
            }
        }
        Err(TransportError::Timeout(self.max_retries))
    }

    /// Build the send query name: `<nonce>.<payload_labels>.<sender_id>.<channel>.<domain>`
    fn build_send_query_name(
        &self,
        channel: &str,
        sender_id: &str,
        encoded_payload: &str,
    ) -> Result<Name, TransportError> {
        let nonce = Self::generate_nonce();
        let payload_labels = Self::split_into_labels(encoded_payload);

        // Build the full name: nonce.payload_labels.sender_id.channel.domain
        let mut parts = vec![nonce.as_str()];
        parts.extend(payload_labels);
        parts.push(sender_id);
        parts.push(channel);

        let prefix = parts.join(".");
        let full_name = format!("{}.{}.", prefix, self.controlled_domain);

        Name::from_ascii(&full_name)
            .map_err(|e| TransportError::DnsProtocol(format!("invalid DNS name: {e}")))
    }

    /// Build the status query name: `<nonce>.status.<channel>.<domain>`
    fn build_status_query_name(&self, channel: &str) -> Result<Name, TransportError> {
        let nonce = Self::generate_nonce();
        let full_name = format!("{}.status.{}.{}.", nonce, channel, self.controlled_domain);

        Name::from_ascii(&full_name)
            .map_err(|e| TransportError::DnsProtocol(format!("invalid DNS name: {e}")))
    }

    /// Build the manifest query name: `m<nonce>.<channel>.<domain>`
    fn build_manifest_query_name(&self, channel: &str) -> Result<Name, TransportError> {
        let nonce = format!("m{}", Self::generate_nonce());
        let full_name = format!("{}.{}.{}.", nonce, channel, self.controlled_domain);

        Name::from_ascii(&full_name)
            .map_err(|e| TransportError::DnsProtocol(format!("invalid DNS name: {e}")))
    }

    /// Build the fetch query name: `f<nonce>.<seq1>-<seq2>-<seq3>.<channel>.<domain>`
    ///
    /// Sequence IDs are dash-separated decimal numbers in a single label.
    /// Must fit within the 63-char DNS label limit.
    fn build_fetch_query_name(&self, channel: &str, seq_ids: &[u64]) -> Result<Name, TransportError> {
        let nonce = format!("f{}", Self::generate_nonce());
        let seq_label: String = seq_ids
            .iter()
            .map(|id| id.to_string())
            .collect::<Vec<_>>()
            .join("-");

        if seq_label.len() > MAX_LABEL_LEN {
            return Err(TransportError::DnsProtocol(format!(
                "sequence IDs label exceeds {MAX_LABEL_LEN}-char DNS label limit: {} chars",
                seq_label.len()
            )));
        }

        let full_name = format!("{}.{}.{}.{}.", nonce, seq_label, channel, self.controlled_domain);

        Name::from_ascii(&full_name)
            .map_err(|e| TransportError::DnsProtocol(format!("invalid DNS name: {e}")))
    }

    /// Build the receive query name: `<nonce>.<channel>.<domain>`
    ///
    /// When `cursor` is `Some`, the nonce includes a `-c<cursor>` suffix for
    /// cursor-based replay advancement.
    fn build_recv_query_name(&self, channel: &str, cursor: Option<u64>) -> Result<Name, TransportError> {
        let nonce = Self::generate_nonce_with_cursor(cursor);
        let full_name = format!("{}.{}.{}.", nonce, channel, self.controlled_domain);

        Name::from_ascii(&full_name)
            .map_err(|e| TransportError::DnsProtocol(format!("invalid DNS name: {e}")))
    }

    /// Parse an A record response and extract the IP address.
    fn parse_a_response(response_bytes: &[u8]) -> Result<Ipv4Addr, TransportError> {
        let message = Message::from_vec(response_bytes)
            .map_err(|e| TransportError::DnsProtocol(format!("failed to parse DNS response: {e}")))?;

        if message.answers().is_empty() {
            let rcode = message.response_code();
            return Err(TransportError::DnsProtocol(format!(
                "no A record in response (rcode={rcode})"
            )));
        }

        for answer in message.answers() {
            if let Some(RData::A(a)) = answer.data().into() {
                return Ok(a.0);
            }
        }

        Err(TransportError::DnsProtocol(
            "no A record in response".to_string(),
        ))
    }

    /// Parse a TXT record response and extract all text records.
    fn parse_txt_responses(response_bytes: &[u8]) -> Result<Vec<String>, TransportError> {
        let message = Message::from_vec(response_bytes)
            .map_err(|e| TransportError::DnsProtocol(format!("failed to parse DNS response: {e}")))?;

        if message.answers().is_empty() {
            return Ok(vec![]);
        }

        let mut results = Vec::new();
        for answer in message.answers() {
            if let Some(RData::TXT(txt)) = answer.data().into() {
                let text: String = txt
                    .iter()
                    .map(|b| String::from_utf8_lossy(b).to_string())
                    .collect::<Vec<_>>()
                    .join("");
                results.push(text);
            }
        }
        Ok(results)
    }

    /// Send a manifest TXT query and parse the response into (seq_id, payload_len) pairs.
    ///
    /// The manifest response contains comma-separated `seq_id,payload_len` entries
    /// packed into TXT records.
    pub async fn recv_manifest(&self, channel: &str) -> Result<Vec<(u64, usize)>, TransportError> {
        let query_name = self.build_manifest_query_name(channel)?;
        let query_bytes = Self::build_dns_query(&query_name, RecordType::TXT, self.use_edns)?;
        let response_bytes = self.send_dns_query(&query_bytes).await?;

        let txt_records = Self::parse_txt_responses(&response_bytes)?;
        if txt_records.is_empty() {
            return Ok(vec![]);
        }

        let mut entries = Vec::new();
        for record in &txt_records {
            // Each record contains comma-separated values: seq1,len1,seq2,len2,...
            let tokens: Vec<&str> = record.split(',').collect();
            // Process pairs of tokens
            let mut i = 0;
            while i + 1 < tokens.len() {
                if let (Ok(seq_id), Ok(payload_len)) = (
                    tokens[i].trim().parse::<u64>(),
                    tokens[i + 1].trim().parse::<usize>(),
                ) {
                    entries.push((seq_id, payload_len));
                }
                i += 2;
            }
        }
        Ok(entries)
    }

    /// Send a selective fetch TXT query for specific sequence IDs and decode the envelopes.
    ///
    /// Returns `(frames, max_seq)` like `recv_frames`.
    pub async fn recv_fetch(&self, channel: &str, seq_ids: &[u64]) -> Result<(Vec<Vec<u8>>, Option<u64>), TransportError> {
        let query_name = self.build_fetch_query_name(channel, seq_ids)?;
        let query_bytes = Self::build_dns_query(&query_name, RecordType::TXT, self.use_edns)?;
        let response_bytes = self.send_dns_query(&query_bytes).await?;

        let envelopes = Self::parse_txt_responses(&response_bytes)?;
        if envelopes.is_empty() {
            return Ok((vec![], None));
        }

        let mut frames = Vec::with_capacity(envelopes.len());
        let mut max_seq: Option<u64> = None;
        for envelope_str in envelopes {
            match dns_message_broker::encoding::decode_envelope(&envelope_str) {
                Ok(parts) => {
                    max_seq = Some(max_seq.map_or(parts.sequence, |m: u64| m.max(parts.sequence)));
                    frames.push(parts.payload);
                }
                Err(e) => {
                    debug!("failed to decode envelope in fetch response: {e}");
                }
            }
        }
        Ok((frames, max_seq))
    }
}

#[async_trait]
impl TransportBackend for DnsTransport {
    async fn send_frame(
        &self,
        channel: &str,
        sender_id: &str,
        frame_bytes: &[u8],
    ) -> Result<(), TransportError> {
        let encoded = dns_message_broker::encoding::base32_encode(frame_bytes);
        let query_name = self.build_send_query_name(channel, sender_id, &encoded)?;
        debug!(name_len = query_name.to_string().len(), channel, "send_frame query");
        let query_bytes = Self::build_dns_query(&query_name, RecordType::A, self.use_edns)?;

        for _retry in 0..MAX_CHANNEL_FULL_RETRIES {
            let response_bytes = self.send_dns_query(&query_bytes).await?;
            let ip = match Self::parse_a_response(&response_bytes) {
                Ok(ip) => ip,
                Err(e) => {
                    debug!("send_frame: no A record in response, retrying: {e}");
                    tokio::time::sleep(self.channel_full_backoff).await;
                    continue;
                }
            };

            if ip == ACK_IP {
                return Ok(());
            } else if ip == CHANNEL_FULL_IP {
                debug!("channel full, backing off");
                tokio::time::sleep(self.channel_full_backoff).await;
                continue;
            } else {
                // Treat unknown IPs as transient — log and retry.
                debug!("send_frame: unexpected response IP {ip}, retrying");
                tokio::time::sleep(self.channel_full_backoff).await;
                continue;
            }
        }

        Err(TransportError::ChannelFull)
    }

    async fn recv_frames(&self, channel: &str, cursor: Option<u64>) -> Result<(Vec<Vec<u8>>, Option<u64>), TransportError> {
        let query_name = self.build_recv_query_name(channel, cursor)?;
        let query_bytes = Self::build_dns_query(&query_name, RecordType::TXT, self.use_edns)?;
        let response_bytes = self.send_dns_query(&query_bytes).await?;

        let envelopes = Self::parse_txt_responses(&response_bytes)?;
        if envelopes.is_empty() {
            return Ok((vec![], None));
        }

        let mut frames = Vec::with_capacity(envelopes.len());
        let mut max_seq: Option<u64> = None;
        for envelope_str in envelopes {
            match dns_message_broker::encoding::decode_envelope(&envelope_str) {
                Ok(parts) => {
                    max_seq = Some(max_seq.map_or(parts.sequence, |m: u64| m.max(parts.sequence)));
                    frames.push(parts.payload);
                }
                Err(e) => {
                    debug!("failed to decode envelope in batch: {e}");
                }
            }
        }
        Ok((frames, max_seq))
    }

    async fn query_status(&self, channel: &str) -> Result<usize, TransportError> {
        let query_name = self.build_status_query_name(channel)?;
        let query_bytes = Self::build_dns_query(&query_name, RecordType::A, self.use_edns)?;
        let response_bytes = self.send_dns_query(&query_bytes).await?;
        let ip = Self::parse_a_response(&response_bytes)?;
        decode_status_ip(ip)
    }

    async fn recv_manifest(&self, channel: &str) -> Result<Vec<(u64, usize)>, TransportError> {
        // Delegate to the inherent method on DnsTransport
        DnsTransport::recv_manifest(self, channel).await
    }

    async fn recv_fetch(&self, channel: &str, seq_ids: &[u64]) -> Result<(Vec<Vec<u8>>, Option<u64>), TransportError> {
        // Delegate to the inherent method on DnsTransport
        DnsTransport::recv_fetch(self, channel, seq_ids).await
    }
}


// ---------------------------------------------------------------------------
// Parallel data retrieval
// ---------------------------------------------------------------------------

/// Fire `count` parallel TXT recv queries on separate ephemeral UDP sockets.
/// Returns all successfully received frame payloads, flattened.
/// Each query uses a unique nonce. Failed/timed-out queries are logged and skipped.
pub async fn recv_frames_parallel(
    resolver_addr: SocketAddr,
    controlled_domain: &str,
    channel: &str,
    count: usize,
    query_timeout: Duration,
    use_edns: bool,
    cursor: Option<u64>,
) -> (Vec<Vec<u8>>, Option<u64>) {
    if count == 0 {
        return (vec![], None);
    }

    let mut join_set = tokio::task::JoinSet::new();

    for _ in 0..count {
        let resolver = resolver_addr;
        let domain = controlled_domain.to_string();
        let chan = channel.to_string();
        let timeout = query_timeout;

        join_set.spawn(async move {
            recv_single_parallel_query(resolver, &domain, &chan, timeout, use_edns, cursor).await
        });
    }

    let mut all_frames = Vec::new();
    let mut max_seq: Option<u64> = None;
    while let Some(result) = join_set.join_next().await {
        match result {
            Ok(Ok((frames, seq))) => {
                all_frames.extend(frames);
                if let Some(s) = seq {
                    max_seq = Some(max_seq.map_or(s, |m: u64| m.max(s)));
                }
            }
            Ok(Err(e)) => {
                debug!("parallel recv query failed: {e}");
            }
            Err(e) => {
                warn!("parallel recv task panicked: {e}");
            }
        }
    }

    (all_frames, max_seq)
}

/// Execute a single parallel TXT recv query on its own ephemeral UDP socket.
async fn recv_single_parallel_query(
    resolver_addr: SocketAddr,
    controlled_domain: &str,
    channel: &str,
    query_timeout: Duration,
    use_edns: bool,
    cursor: Option<u64>,
) -> Result<(Vec<Vec<u8>>, Option<u64>), TransportError> {
    // 1. Bind an ephemeral UDP socket
    let bind_addr: SocketAddr = if resolver_addr.is_ipv6() {
        "[::]:0".parse().unwrap()
    } else {
        "0.0.0.0:0".parse().unwrap()
    };
    let socket = UdpSocket::bind(bind_addr)
        .await
        .map_err(|e| TransportError::SocketBind(format!("parallel socket bind: {e}")))?;

    // 2. Generate a unique nonce (with optional cursor suffix)
    let nonce = DnsTransport::generate_nonce_with_cursor(cursor);

    // 3. Build the TXT query name: <nonce>.<channel>.<domain>
    let full_name = format!("{}.{}.{}.", nonce, channel, controlled_domain);
    let query_name = Name::from_ascii(&full_name)
        .map_err(|e| TransportError::DnsProtocol(format!("invalid DNS name: {e}")))?;

    // 4. Build and send the DNS query
    let query_bytes = DnsTransport::build_dns_query(&query_name, RecordType::TXT, use_edns)?;
    socket.send_to(&query_bytes, resolver_addr).await?;

    // 5. Wait for response with timeout
    let mut buf = vec![0u8; UDP_BUF_SIZE];
    let response_bytes = match tokio::time::timeout(query_timeout, socket.recv_from(&mut buf)).await
    {
        Ok(Ok((len, _addr))) => {
            buf.truncate(len);
            buf
        }
        Ok(Err(e)) => return Err(TransportError::Io(e)),
        Err(_) => return Err(TransportError::Timeout(1)),
    };
    // Socket is dropped here (closed after use)

    // 6. Parse TXT records and decode envelopes
    let envelopes = DnsTransport::parse_txt_responses(&response_bytes)?;
    if envelopes.is_empty() {
        return Ok((vec![], None));
    }

    // 7. Return the frame payloads and max store sequence
    let mut frames = Vec::with_capacity(envelopes.len());
    let mut max_seq: Option<u64> = None;
    for envelope_str in envelopes {
        match dns_message_broker::encoding::decode_envelope(&envelope_str) {
            Ok(parts) => {
                max_seq = Some(max_seq.map_or(parts.sequence, |m: u64| m.max(parts.sequence)));
                frames.push(parts.payload);
            }
            Err(e) => {
                debug!("parallel recv: failed to decode envelope: {e}");
            }
        }
    }
    Ok((frames, max_seq))
}

// ---------------------------------------------------------------------------
// Payload budget calculation
// ---------------------------------------------------------------------------

/// Frame header size in bytes (1 + 8 + 4 + 1 + 1 = 15).
const FRAME_HEADER: usize = 15;

/// ChaCha20-Poly1305 authentication tag size for DATA frames.
const ENCRYPTION_TAG: usize = 16;

/// Maximum DNS name length in presentation (text) format.
const MAX_DNS_NAME_LEN: usize = 253;

/// Compute the effective DATA payload budget (in plaintext bytes) for a DNS
/// tunnel frame.
///
/// The DNS query name has the form:
/// `<nonce>.<payload_labels>.<sender_id>.<channel>.<domain>`
///
/// Fixed overhead = nonce + sender_id + channel + domain + 4 dot separators.
/// The remaining characters are available for base32-encoded payload labels,
/// which are split into chunks of at most 63 characters (each extra chunk adds
/// one dot separator).
///
/// The result is clamped to 0 if the overhead exceeds the budget.
pub fn compute_payload_budget(
    domain_len: usize,
    sender_id_len: usize,
    channel_len: usize,
    nonce_len: usize,
) -> usize {
    // Fixed parts: nonce.sender_id.channel.domain (4 dots between them)
    let fixed = nonce_len + sender_id_len + channel_len + domain_len + 4;
    if fixed >= MAX_DNS_NAME_LEN {
        return 0;
    }
    let remaining = MAX_DNS_NAME_LEN - fixed;

    // Payload labels are split into chunks of at most 63 chars.
    // For N payload chars we need ceil(N/63) - 1 extra dots.
    // Solve: N + max(0, ceil(N/63) - 1) <= remaining
    // Approximate: N <= (remaining + 1) * 63 / 64
    let payload_chars = ((remaining + 1) * 63) / 64;

    // Convert base32 chars to raw bytes: each char encodes 5 bits.
    let raw_bytes = (payload_chars * 5) / 8;

    // Subtract frame header and encryption tag.
    raw_bytes.saturating_sub(FRAME_HEADER + ENCRYPTION_TAG)
}

// ---------------------------------------------------------------------------
// DirectTransport – bypasses DNS, calls ChannelStore directly (embedded mode)
// ---------------------------------------------------------------------------

use dns_message_broker::server::SharedStore;

/// Direct ChannelStore transport: bypasses DNS, calls store directly.
/// Used in embedded mode where the Exit Node runs the Broker in-process.
pub struct DirectTransport {
    store: SharedStore,
    sender_id: String,
}

impl DirectTransport {
    /// Create a new `DirectTransport` wrapping a shared `ChannelStore`.
    pub fn new(store: SharedStore, sender_id: String) -> Self {
        Self { store, sender_id }
    }
}

#[async_trait]
impl TransportBackend for DirectTransport {
    async fn send_frame(
        &self,
        channel: &str,
        _sender_id: &str,
        frame_bytes: &[u8],
    ) -> Result<(), TransportError> {
        let mut store = self.store.write().await;
        store
            .push(channel, &self.sender_id, frame_bytes.to_vec())
            .map_err(|e| match e {
                dns_message_broker::error::StoreError::ChannelFull(_) => TransportError::ChannelFull,
                other => TransportError::StoreError(other.to_string()),
            })?;
        Ok(())
    }

    async fn recv_frames(&self, channel: &str, cursor: Option<u64>) -> Result<(Vec<Vec<u8>>, Option<u64>), TransportError> {
        let mut store = self.store.write().await;
        let msgs = store.peek_many(channel, 10, cursor);
        let max_seq = msgs.last().map(|m| m.sequence);
        Ok((msgs.into_iter().map(|msg| msg.payload).collect(), max_seq))
    }

    async fn query_status(&self, channel: &str) -> Result<usize, TransportError> {
        let store = self.store.read().await;
        Ok(store.queue_depth(channel))
    }
}


// ---------------------------------------------------------------------------
// Adaptive exponential backoff
// ---------------------------------------------------------------------------

/// Adaptive exponential backoff for poll intervals.
///
/// Starts at `min`, doubles on each `increase()` call (clamped to `max`),
/// and resets to `min` on `reset()`.
#[derive(Debug, Clone)]
pub struct AdaptiveBackoff {
    current: Duration,
    min: Duration,
    max: Duration,
}

impl AdaptiveBackoff {
    /// Create a new `AdaptiveBackoff` starting at `min`.
    /// If `max < min`, `max` is clamped to `min`.
    pub fn new(min: Duration, max: Duration) -> Self {
        let max = if max < min { min } else { max };
        Self {
            current: min,
            min,
            max,
        }
    }

    /// Double the current interval, clamped to `max`.
    pub fn increase(&mut self) {
        self.current = (self.current * 2).min(self.max);
    }

    /// Reset the interval to `min`.
    pub fn reset(&mut self) {
        self.current = self.min;
    }

    /// Return the current interval.
    pub fn current(&self) -> Duration {
        self.current
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_budget_typical_values() {
        // domain="t.co" (4), sender_id="client1" (7), channel="u-abcd1234" (10), nonce=4
        let budget = compute_payload_budget(4, 7, 10, 4);
        // fixed = 4 + 7 + 10 + 4 + 4 = 29
        // remaining = 253 - 29 = 224
        // payload_chars = (225 * 63) / 64 = 14175 / 64 = 221
        // raw_bytes = (221 * 5) / 8 = 1105 / 8 = 138
        // budget = 138 - 15 - 16 = 107
        assert_eq!(budget, 107);
    }

    #[test]
    fn payload_budget_longer_domain() {
        // domain="example.com" (11), sender_id="client1" (7), channel="u-abcd1234" (10), nonce=4
        let budget = compute_payload_budget(11, 7, 10, 4);
        // fixed = 11 + 7 + 10 + 4 + 4 = 36
        // remaining = 253 - 36 = 217
        // payload_chars = (218 * 63) / 64 = 13734 / 64 = 214
        // raw_bytes = (214 * 5) / 8 = 1070 / 8 = 133
        // budget = 133 - 15 - 16 = 102
        assert_eq!(budget, 102);
    }

    #[test]
    fn payload_budget_zero_when_overhead_exceeds_limit() {
        // Huge domain that exceeds 253
        let budget = compute_payload_budget(250, 10, 10, 4);
        assert_eq!(budget, 0);
    }

    #[test]
    fn payload_budget_zero_when_exactly_at_limit() {
        // fixed = 253 exactly → remaining = 0
        let budget = compute_payload_budget(240, 5, 4, 0);
        // fixed = 240 + 5 + 4 + 0 + 4 = 253
        assert_eq!(budget, 0);
    }

    #[test]
    fn payload_budget_clamps_small_remaining() {
        // Very little remaining space → raw_bytes < 31 → clamps to 0
        // fixed = 4 + 4 + 4 + 4 + 4 = 20, remaining = 233 → not small enough
        // Let's use a case where remaining is tiny
        let budget = compute_payload_budget(200, 20, 20, 4);
        // fixed = 200 + 20 + 20 + 4 + 4 = 248
        // remaining = 253 - 248 = 5
        // payload_chars = (6 * 63) / 64 = 378 / 64 = 5
        // raw_bytes = (5 * 5) / 8 = 25 / 8 = 3
        // budget = 3.saturating_sub(31) = 0
        assert_eq!(budget, 0);
    }

    #[test]
    fn payload_budget_non_negative_always() {
        // Exhaustive check for a range of inputs
        for domain in 0..100 {
            for sender in 0..20 {
                let budget = compute_payload_budget(domain, sender, 10, 4);
                // Should never panic or underflow
                let _ = budget;
            }
        }
    }
}
