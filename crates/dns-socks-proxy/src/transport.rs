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
    /// Returns an empty vec if the channel is empty.
    async fn recv_frames(&self, channel: &str) -> Result<Vec<Vec<u8>>, TransportError>;

    /// Convenience: receive a single frame (pops the first from a batch).
    async fn recv_frame(&self, channel: &str) -> Result<Option<Vec<u8>>, TransportError> {
        let mut frames = self.recv_frames(channel).await?;
        Ok(if frames.is_empty() { None } else { Some(frames.remove(0)) })
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
    fn build_dns_query(name: &Name, record_type: RecordType) -> Result<Vec<u8>, TransportError> {
        let mut message = Message::new();
        let id: u16 = rand::thread_rng().gen();
        message.set_id(id);
        message.set_recursion_desired(true);
        let query = Query::query(name.clone(), record_type);
        message.add_query(query);

        // Add EDNS0 OPT record for TXT queries to enable larger responses.
        if record_type == RecordType::TXT {
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

    /// Build the receive query name: `<nonce>.<channel>.<domain>`
    fn build_recv_query_name(&self, channel: &str) -> Result<Name, TransportError> {
        let nonce = Self::generate_nonce();
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
        let query_bytes = Self::build_dns_query(&query_name, RecordType::A)?;

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

    async fn recv_frames(&self, channel: &str) -> Result<Vec<Vec<u8>>, TransportError> {
        let query_name = self.build_recv_query_name(channel)?;
        let query_bytes = Self::build_dns_query(&query_name, RecordType::TXT)?;
        let response_bytes = self.send_dns_query(&query_bytes).await?;

        let envelopes = Self::parse_txt_responses(&response_bytes)?;
        if envelopes.is_empty() {
            return Ok(vec![]);
        }

        let mut frames = Vec::with_capacity(envelopes.len());
        for envelope_str in envelopes {
            match dns_message_broker::encoding::decode_envelope(&envelope_str) {
                Ok(parts) => frames.push(parts.payload),
                Err(e) => {
                    debug!("failed to decode envelope in batch: {e}");
                }
            }
        }
        Ok(frames)
    }
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

    async fn recv_frames(&self, channel: &str) -> Result<Vec<Vec<u8>>, TransportError> {
        let mut store = self.store.write().await;
        // DirectTransport pops multiple messages at once for consistency.
        let msgs = store.pop_many(channel, 10);
        Ok(msgs.into_iter().map(|msg| msg.payload).collect())
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
