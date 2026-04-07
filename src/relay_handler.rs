//! Relay handler module.
//!
//! Routes incoming DNS queries to the RelayStore and produces responses.
//! Simplified version of `handler.rs` — no FIFO queues, no replay buffers,
//! no cursor tracking, no adaptive sizing.

use std::net::Ipv4Addr;

use hickory_proto::op::ResponseCode;
use hickory_proto::rr::{Name, RecordType};

use crate::dns::{a_record, build_response, txt_record, DnsMessage};
use crate::encoding::{decode_send_query, encode_envelope_parts};
use crate::relay_store::RelayStore;
use crate::store::Clock;

/// Maximum value representable in 24 bits for status IP encoding.
const MAX_DEPTH_24BIT: usize = 0x00FF_FFFF;

/// First octet sentinel for status response IPs.
const STATUS_OCTET: u8 = 128;

/// No-data IP returned when a channel has zero slots.
const NO_DATA_IP: Ipv4Addr = Ipv4Addr::new(0, 0, 0, 0);

/// Configuration for the relay handler.
#[derive(Debug, Clone)]
pub struct RelayConfig {
    /// The controlled domain (e.g., "relay.example.com").
    pub controlled_domain: String,
    /// IP returned on successful write (ACK).
    pub ack_ip: Ipv4Addr,
    /// IP returned when payload is too large.
    pub error_payload_too_large_ip: Ipv4Addr,
    /// IP returned when channel is full (unused in relay, but kept for compatibility).
    pub error_channel_full_ip: Ipv4Addr,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            controlled_domain: String::new(),
            ack_ip: Ipv4Addr::new(1, 2, 3, 4),
            error_payload_too_large_ip: Ipv4Addr::new(1, 2, 3, 5),
            error_channel_full_ip: Ipv4Addr::new(1, 2, 3, 6),
        }
    }
}

/// Encode a slot count into a status IP address.
/// First octet = 128, remaining 24 bits = count (clamped to 0x00FF_FFFF).
/// For count 0, returns 0.0.0.0.
fn encode_status_ip(count: usize) -> Ipv4Addr {
    if count == 0 {
        return NO_DATA_IP;
    }
    let clamped = count.min(MAX_DEPTH_24BIT) as u32;
    Ipv4Addr::new(
        STATUS_OCTET,
        ((clamped >> 16) & 0xFF) as u8,
        ((clamped >> 8) & 0xFF) as u8,
        (clamped & 0xFF) as u8,
    )
}

/// Check whether the query name is under the controlled domain.
///
/// The query name labels (excluding root) must end with the controlled domain labels,
/// and there must be at least one additional label (a subdomain).
fn is_under_controlled_domain(query_labels: &[String], controlled_domain: &str) -> bool {
    let domain_labels: Vec<&str> = controlled_domain.split('.').filter(|s| !s.is_empty()).collect();

    if query_labels.len() <= domain_labels.len() {
        return false;
    }

    let query_suffix = &query_labels[query_labels.len() - domain_labels.len()..];
    for (ql, dl) in query_suffix.iter().zip(domain_labels.iter()) {
        if !ql.eq_ignore_ascii_case(dl) {
            return false;
        }
    }

    true
}

/// Extract the remaining labels from a query name after stripping the controlled domain suffix.
fn extract_remaining_labels<'a>(
    query_labels: &'a [String],
    controlled_domain: &str,
) -> Vec<&'a str> {
    let domain_labels: Vec<&str> = controlled_domain
        .split('.')
        .filter(|s| !s.is_empty())
        .collect();
    let remaining_count = query_labels.len().saturating_sub(domain_labels.len());
    query_labels[..remaining_count]
        .iter()
        .map(|s| s.as_str())
        .collect()
}

/// Detect whether the remaining labels represent a status query.
///
/// Status query format: `<nonce>.status.<channel>.<controlled_domain>`
/// After stripping the controlled domain, remaining labels are: `[nonce, status, channel]`
fn is_status_query(remaining_labels: &[&str]) -> bool {
    remaining_labels.len() >= 3 && remaining_labels[1].eq_ignore_ascii_case("status")
}

/// Route a DNS query to the RelayStore and produce a response.
///
/// Routing logic:
/// 1. Check if query name is under the controlled domain → REFUSED if not
/// 2. A/AAAA queries → check for status query first, then handle send
/// 3. TXT queries → receive handler (read from RelayStore)
/// 4. Other query types → REFUSED
pub fn handle_relay_query(
    query: &DnsMessage,
    config: &RelayConfig,
    store: &RelayStore<impl Clock>,
) -> Vec<u8> {
    // Check if query is under controlled domain
    if !is_under_controlled_domain(&query.query_name_labels, &config.controlled_domain) {
        return build_response(
            query.query_id,
            &query.query_name,
            query.query_type,
            ResponseCode::Refused,
            vec![],
        )
        .unwrap_or_default();
    }

    match query.query_type {
        RecordType::A | RecordType::AAAA => {
            let remaining = extract_remaining_labels(
                &query.query_name_labels,
                &config.controlled_domain,
            );
            if is_status_query(&remaining) {
                handle_relay_status(query, config, store)
            } else {
                handle_relay_send(query, config, store)
            }
        }
        RecordType::TXT => handle_relay_receive(query, config, store),
        _ => {
            // Unsupported query type → REFUSED
            build_response(
                query.query_id,
                &query.query_name,
                query.query_type,
                ResponseCode::Refused,
                vec![],
            )
            .unwrap_or_default()
        }
    }
}

/// Handle a status query: look up slot count, encode as A record with TTL 0.
fn handle_relay_status(
    query: &DnsMessage,
    config: &RelayConfig,
    store: &RelayStore<impl Clock>,
) -> Vec<u8> {
    let remaining = extract_remaining_labels(
        &query.query_name_labels,
        &config.controlled_domain,
    );

    // remaining should be [nonce, "status", channel]
    let channel = if remaining.len() >= 3 {
        remaining[2]
    } else {
        ""
    };

    let count = store.slot_count(channel);
    let ip = encode_status_ip(count);
    let record = a_record(&query.query_name, ip);

    build_response(
        query.query_id,
        &query.query_name,
        query.query_type,
        ResponseCode::NoError,
        vec![record],
    )
    .unwrap_or_default()
}

/// Handle a send operation (A/AAAA query).
///
/// Decodes the send query, writes to the RelayStore, returns ACK IP.
/// Uses the sender_id from the query directly — single-slot-per-sender
/// semantics mean each write overwrites the previous slot for the same sender.
fn handle_relay_send(
    query: &DnsMessage,
    config: &RelayConfig,
    store: &RelayStore<impl Clock>,
) -> Vec<u8> {
    let labels: Vec<&str> = query.query_name_labels.iter().map(|s| s.as_str()).collect();

    let controlled_name = match Name::from_ascii(&config.controlled_domain) {
        Ok(n) => n,
        Err(_) => {
            return build_response(
                query.query_id,
                &query.query_name,
                query.query_type,
                ResponseCode::NXDomain,
                vec![],
            )
            .unwrap_or_default();
        }
    };

    let (sender_id, channel, payload) = match decode_send_query(&labels, &controlled_name) {
        Ok(result) => result,
        Err(_) => {
            return build_response(
                query.query_id,
                &query.query_name,
                query.query_type,
                ResponseCode::NXDomain,
                vec![],
            )
            .unwrap_or_default();
        }
    };

    // RelayStore write is infallible — always returns ACK.
    // Single-slot-per-sender: overwrites previous slot for same (channel, sender_id).
    store.write(&channel, &sender_id, payload);

    let record = a_record(&query.query_name, config.ack_ip);
    build_response(
        query.query_id,
        &query.query_name,
        query.query_type,
        ResponseCode::NoError,
        vec![record],
    )
    .unwrap_or_default()
}

/// DNS response overhead: header (12) + question section (~query name + 4).
/// We estimate conservatively; the exact size depends on the query name length.
const DNS_RESPONSE_OVERHEAD: usize = 80;

/// Per-TXT-record wire overhead: name pointer (2) + type (2) + class (2) +
/// TTL (4) + rdlength (2) + TXT length byte (1) = 13 bytes.
const TXT_RECORD_OVERHEAD: usize = 13;

/// Compute the EDNS0-aware response budget.
fn compute_budget(edns_udp_size: u16) -> usize {
    let max_response: usize = if edns_udp_size >= 512 {
        edns_udp_size as usize
    } else {
        1232
    };
    max_response.saturating_sub(DNS_RESPONSE_OVERHEAD)
}

/// Handle a receive operation (TXT query).
///
/// Routes to manifest, fetch, or legacy mode based on the nonce prefix:
/// - `m` prefix → manifest mode (compact seq_id,payload_len list)
/// - `f` prefix → fetch mode (selective envelope retrieval)
/// - no prefix → legacy mode (all envelopes, budget-limited)
///
/// Limits the total response size to fit within the client's advertised UDP payload
/// budget (EDNS0) or 512 bytes (no EDNS0) to avoid truncation by resolvers.
fn handle_relay_receive(
    query: &DnsMessage,
    config: &RelayConfig,
    store: &RelayStore<impl Clock>,
) -> Vec<u8> {
    let labels = &query.query_name_labels;

    let domain_labels: Vec<&str> = config
        .controlled_domain
        .split('.')
        .filter(|s| !s.is_empty())
        .collect();

    // Receive query structure: <nonce>.<channel>.<controlled_domain>
    // Or for fetch: <f_nonce>.<seq_ids>.<channel>.<controlled_domain>
    let remaining_count = labels.len().saturating_sub(domain_labels.len());
    if remaining_count < 2 {
        // Need at least nonce + channel
        return build_response(
            query.query_id,
            &query.query_name,
            query.query_type,
            ResponseCode::NXDomain,
            vec![],
        )
        .unwrap_or_default();
    }

    let remaining = &labels[..remaining_count];
    let nonce_label = &remaining[0];

    // Detect mode from nonce prefix.
    // Manifest: m<nonce>.<channel>.<domain> — needs >= 2 remaining labels (same as legacy)
    // Fetch: f<nonce>.<seq_ids>.<channel>.<domain> — needs >= 3 remaining labels
    // If not enough labels for the detected mode, fall through to legacy.
    if nonce_label.starts_with('m') && remaining.len() >= 2 {
        return handle_relay_receive_manifest(query, remaining, store);
    }
    if nonce_label.starts_with('f') && remaining.len() >= 3 {
        return handle_relay_receive_fetch(query, remaining, store);
    }

    // Legacy mode — existing behavior unchanged
    handle_relay_receive_legacy(query, remaining, store)
}

/// Manifest mode: return compact `seq_id,payload_len` entries for all non-expired slots.
///
/// Query structure: `m<nonce>.<channel>.<controlled_domain>`
/// remaining = [m<nonce>, channel]
fn handle_relay_receive_manifest(
    query: &DnsMessage,
    remaining: &[String],
    store: &RelayStore<impl Clock>,
) -> Vec<u8> {
    // Channel is remaining[1] (same position as legacy)
    if remaining.len() < 2 {
        return build_response(
            query.query_id,
            &query.query_name,
            query.query_type,
            ResponseCode::NXDomain,
            vec![],
        )
        .unwrap_or_default();
    }

    let channel = &remaining[1];
    let mut slots = store.read_and_advance(channel, None);

    if slots.is_empty() {
        return build_response(
            query.query_id,
            &query.query_name,
            query.query_type,
            ResponseCode::NoError,
            vec![],
        )
        .unwrap_or_default();
    }

    // Sort by sequence descending for consistency with legacy mode
    slots.sort_by(|a, b| b.sequence.cmp(&a.sequence));

    // Build compact manifest entries: "seq_id,payload_len"
    let entries: Vec<String> = slots
        .iter()
        .map(|slot| format!("{},{}", slot.sequence, slot.payload.len()))
        .collect();

    // Pack entries into TXT records, each up to 255 chars, respecting budget
    let mut budget = compute_budget(query.edns_udp_size);
    let mut records = Vec::new();
    let mut current_txt = String::new();

    for entry in &entries {
        // Check if adding this entry to the current TXT string would exceed 255 chars
        let needed = if current_txt.is_empty() {
            entry.len()
        } else {
            1 + entry.len() // comma separator + entry
        };

        if !current_txt.is_empty() && current_txt.len() + needed > 255 {
            // Flush current TXT record
            let record_size = TXT_RECORD_OVERHEAD + current_txt.len();
            if record_size > budget && !records.is_empty() {
                break;
            }
            budget = budget.saturating_sub(record_size);
            records.push(txt_record(&query.query_name, &current_txt));
            current_txt = String::new();
        }

        if current_txt.is_empty() {
            current_txt.push_str(entry);
        } else {
            current_txt.push(',');
            current_txt.push_str(entry);
        }
    }

    // Flush remaining content
    if !current_txt.is_empty() {
        let record_size = TXT_RECORD_OVERHEAD + current_txt.len();
        if record_size <= budget || records.is_empty() {
            records.push(txt_record(&query.query_name, &current_txt));
        }
    }

    build_response(
        query.query_id,
        &query.query_name,
        query.query_type,
        ResponseCode::NoError,
        records,
    )
    .unwrap_or_default()
}

/// Fetch mode: return full envelopes for specific requested sequence IDs.
///
/// Query structure: `f<nonce>.<seq1>-<seq2>-<seq3>.<channel>.<controlled_domain>`
/// remaining = [f<nonce>, seq_ids_label, channel]
fn handle_relay_receive_fetch(
    query: &DnsMessage,
    remaining: &[String],
    store: &RelayStore<impl Clock>,
) -> Vec<u8> {
    // Need at least 3 remaining labels: nonce, seq_ids, channel
    if remaining.len() < 3 {
        return build_response(
            query.query_id,
            &query.query_name,
            query.query_type,
            ResponseCode::NXDomain,
            vec![],
        )
        .unwrap_or_default();
    }

    let seq_ids_label = &remaining[1];
    let channel = &remaining[2];

    // Parse dash-separated decimal sequence IDs
    let seq_ids: Vec<u64> = seq_ids_label
        .split('-')
        .filter_map(|s| s.parse::<u64>().ok())
        .collect();

    if seq_ids.is_empty() {
        return build_response(
            query.query_id,
            &query.query_name,
            query.query_type,
            ResponseCode::NoError,
            vec![],
        )
        .unwrap_or_default();
    }

    let mut slots = store.read_sequences(channel, &seq_ids);

    if slots.is_empty() {
        return build_response(
            query.query_id,
            &query.query_name,
            query.query_type,
            ResponseCode::NoError,
            vec![],
        )
        .unwrap_or_default();
    }

    // Sort by sequence descending like legacy mode
    slots.sort_by(|a, b| b.sequence.cmp(&a.sequence));

    // Use same budget logic as legacy mode
    let mut budget = compute_budget(query.edns_udp_size);

    let mut records = Vec::new();
    for slot in &slots {
        let envelope = encode_envelope_parts(
            &slot.sender_id,
            slot.sequence,
            slot.timestamp,
            &slot.payload,
        );
        let record_size = TXT_RECORD_OVERHEAD + envelope.len();
        if record_size > budget && !records.is_empty() {
            break;
        }
        budget = budget.saturating_sub(record_size);
        records.push(txt_record(&query.query_name, &envelope));
    }

    build_response(
        query.query_id,
        &query.query_name,
        query.query_type,
        ResponseCode::NoError,
        records,
    )
    .unwrap_or_default()
}

/// Legacy mode: existing behavior — return all envelopes, budget-limited.
///
/// Query structure: `<nonce>.<channel>.<controlled_domain>`
/// remaining = [nonce, channel]
fn handle_relay_receive_legacy(
    query: &DnsMessage,
    remaining: &[String],
    store: &RelayStore<impl Clock>,
) -> Vec<u8> {
    // Parse cursor from nonce: `-c<N>` suffix signals the client has
    // received all slots with sequence < N. The relay prunes those slots.
    let nonce_label = &remaining[0];
    let _cursor: Option<u64> = nonce_label.rfind("-c").and_then(|pos| {
        nonce_label[pos + 2..].parse::<u64>().ok()
    });

    // Strip nonce (leftmost label)
    let after_nonce = &remaining[1..];

    if after_nonce.is_empty() {
        return build_response(
            query.query_id,
            &query.query_name,
            query.query_type,
            ResponseCode::NXDomain,
            vec![],
        )
        .unwrap_or_default();
    }

    let channel = &after_nonce[0];

    let mut slots = store.read_and_advance(channel, None);
    if slots.is_empty() {
        return build_response(
            query.query_id,
            &query.query_name,
            query.query_type,
            ResponseCode::NoError,
            vec![],
        )
        .unwrap_or_default();
    }

    // Sort by sequence descending — newest first. Under the response size
    // budget we may not be able to return all slots, and smoltcp needs the
    // most recent retransmits (highest sequence) to fill gaps and make
    // progress. Returning oldest-first would starve retransmits.
    slots.sort_by(|a, b| b.sequence.cmp(&a.sequence));

    // Budget: the relay is authoritative and the client always sends EDNS0
    // with a 1232-byte buffer. Even if the recursive resolver strips the OPT
    // record, we can safely assume 1232 as the floor — responses larger than
    // 512 bytes may be retried over TCP by the resolver, and modern resolvers
    // handle up to 1232 without issues.
    let mut budget = compute_budget(query.edns_udp_size);

    let mut records = Vec::new();
    for slot in &slots {
        let envelope = encode_envelope_parts(
            &slot.sender_id,
            slot.sequence,
            slot.timestamp,
            &slot.payload,
        );
        let record_size = TXT_RECORD_OVERHEAD + envelope.len();
        if record_size > budget && !records.is_empty() {
            // Adding this record would exceed the budget; stop here.
            break;
        }
        budget = budget.saturating_sub(record_size);
        records.push(txt_record(&query.query_name, &envelope));
    }

    build_response(
        query.query_id,
        &query.query_name,
        query.query_type,
        ResponseCode::NoError,
        records,
    )
    .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::relay_store::RelayStore;
    use crate::store::test_support::MockClock;
    use hickory_proto::op::Message;
    use hickory_proto::rr::RecordType;
    use std::time::Duration;

    fn test_relay_config() -> RelayConfig {
        RelayConfig {
            controlled_domain: "relay.example.com".to_string(),
            ..Default::default()
        }
    }

    fn make_relay_store() -> RelayStore<MockClock> {
        let clock = MockClock::new();
        RelayStore::new(Duration::from_secs(600), clock)
    }

    fn make_dns_message(name: &str, qtype: RecordType) -> DnsMessage {
        let query_name = Name::from_ascii(name).unwrap();
        let query_name_labels: Vec<String> = query_name
            .iter()
            .map(|l| String::from_utf8_lossy(l).to_string())
            .collect();
        DnsMessage {
            query_id: 0x1234,
            query_name,
            query_type: qtype,
            query_name_labels,
            edns_udp_size: 0,
        }
    }

    fn parse_response(bytes: &[u8]) -> Message {
        Message::from_vec(bytes).unwrap()
    }

    // --- Domain validation tests ---

    #[test]
    fn test_query_outside_controlled_domain_returns_refused() {
        let config = test_relay_config();
        let store = make_relay_store();

        let query = make_dns_message("nonce.something.other.com.", RecordType::A);
        let response = parse_response(&handle_relay_query(&query, &config, &store));
        assert_eq!(response.response_code(), ResponseCode::Refused);
    }

    #[test]
    fn test_unsupported_query_type_returns_refused() {
        let config = test_relay_config();
        let store = make_relay_store();

        let query = make_dns_message("nonce.inbox.relay.example.com.", RecordType::MX);
        let response = parse_response(&handle_relay_query(&query, &config, &store));
        assert_eq!(response.response_code(), ResponseCode::Refused);
    }

    // --- Send (A query) tests ---

    #[test]
    fn test_send_returns_ack_ip() {
        let config = test_relay_config();
        let store = make_relay_store();

        // nonce.payload.sender.channel.relay.example.com
        // payload "hi" base32 = "nbsq"
        let query = make_dns_message(
            "nonce123.nbsq.alice.inbox.relay.example.com.",
            RecordType::A,
        );
        let response = parse_response(&handle_relay_query(&query, &config, &store));
        assert_eq!(response.response_code(), ResponseCode::NoError);
        assert_eq!(response.answers().len(), 1);

        let ans = &response.answers()[0];
        assert_eq!(ans.ttl(), 0);
        match ans.data() {
            hickory_proto::rr::RData::A(a) => {
                assert_eq!(a.0, Ipv4Addr::new(1, 2, 3, 4));
            }
            other => panic!("expected A record, got {:?}", other),
        }
    }

    #[test]
    fn test_send_bad_structure_returns_nxdomain() {
        let config = test_relay_config();
        let store = make_relay_store();

        // Too few labels for a valid send query
        let query = make_dns_message("nonce.relay.example.com.", RecordType::A);
        let response = parse_response(&handle_relay_query(&query, &config, &store));
        assert_eq!(response.response_code(), ResponseCode::NXDomain);
    }

    // --- Receive (TXT query) tests ---

    #[test]
    fn test_receive_empty_channel_returns_noerror_no_answers() {
        let config = test_relay_config();
        let store = make_relay_store();

        let query = make_dns_message("nonce.inbox.relay.example.com.", RecordType::TXT);
        let response = parse_response(&handle_relay_query(&query, &config, &store));
        assert_eq!(response.response_code(), ResponseCode::NoError);
        assert!(response.answers().is_empty());
    }

    #[test]
    fn test_send_then_receive_roundtrip() {
        let config = test_relay_config();
        let store = make_relay_store();

        // Send: nonce.payload.sender.channel.relay.example.com
        // payload "hi" base32 = "nbsq"
        let send_query = make_dns_message(
            "nonce1.nbsq.alice.inbox.relay.example.com.",
            RecordType::A,
        );
        let send_resp = parse_response(&handle_relay_query(&send_query, &config, &store));
        assert_eq!(send_resp.response_code(), ResponseCode::NoError);

        // Receive
        let recv_query = make_dns_message("nonce2.inbox.relay.example.com.", RecordType::TXT);
        let recv_resp = parse_response(&handle_relay_query(&recv_query, &config, &store));
        assert_eq!(recv_resp.response_code(), ResponseCode::NoError);
        assert_eq!(recv_resp.answers().len(), 1);

        // Verify envelope format
        let ans = &recv_resp.answers()[0];
        assert_eq!(ans.ttl(), 0);
    }

    // --- Cursor suffix ignored ---

    #[test]
    fn test_cursor_suffix_in_nonce_is_ignored() {
        let config = test_relay_config();
        let store = make_relay_store();

        // Write data
        store.write("inbox", "alice", b"hello".to_vec());

        // Query with cursor suffix
        let query_with_cursor = make_dns_message(
            "nonce-c42.inbox.relay.example.com.",
            RecordType::TXT,
        );
        let resp_with = parse_response(&handle_relay_query(&query_with_cursor, &config, &store));

        // Query without cursor suffix
        let query_without = make_dns_message(
            "nonce.inbox.relay.example.com.",
            RecordType::TXT,
        );
        let resp_without = parse_response(&handle_relay_query(&query_without, &config, &store));

        assert_eq!(resp_with.answers().len(), resp_without.answers().len());
        assert_eq!(resp_with.answers().len(), 1);
    }

    // --- Status query tests ---

    #[test]
    fn test_status_empty_channel_returns_no_data_ip() {
        let config = test_relay_config();
        let store = make_relay_store();

        let query = make_dns_message(
            "nonce.status.inbox.relay.example.com.",
            RecordType::A,
        );
        let response = parse_response(&handle_relay_query(&query, &config, &store));
        assert_eq!(response.response_code(), ResponseCode::NoError);
        assert_eq!(response.answers().len(), 1);

        match response.answers()[0].data() {
            hickory_proto::rr::RData::A(a) => {
                assert_eq!(a.0, Ipv4Addr::new(0, 0, 0, 0));
            }
            other => panic!("expected A record, got {:?}", other),
        }
    }

    #[test]
    fn test_status_with_slots_returns_count() {
        let config = test_relay_config();
        let store = make_relay_store();

        store.write("inbox", "alice", b"a".to_vec());
        store.write("inbox", "bob", b"b".to_vec());

        let query = make_dns_message(
            "nonce.status.inbox.relay.example.com.",
            RecordType::A,
        );
        let response = parse_response(&handle_relay_query(&query, &config, &store));
        assert_eq!(response.answers().len(), 1);

        match response.answers()[0].data() {
            hickory_proto::rr::RData::A(a) => {
                // 2 slots → 128.0.0.2
                assert_eq!(a.0, Ipv4Addr::new(128, 0, 0, 2));
            }
            other => panic!("expected A record, got {:?}", other),
        }
    }

    // --- TTL tests ---

    #[test]
    fn test_all_response_records_have_ttl_zero() {
        let config = test_relay_config();
        let store = make_relay_store();

        store.write("inbox", "alice", b"data".to_vec());
        store.write("inbox", "bob", b"data2".to_vec());

        let query = make_dns_message("nonce.inbox.relay.example.com.", RecordType::TXT);
        let response = parse_response(&handle_relay_query(&query, &config, &store));

        for ans in response.answers() {
            assert_eq!(ans.ttl(), 0, "All response records must have TTL 0");
        }
    }

    // --- AA flag ---

    #[test]
    fn test_response_has_aa_flag() {
        let config = test_relay_config();
        let store = make_relay_store();

        let query = make_dns_message("nonce.inbox.relay.example.com.", RecordType::TXT);
        let response = parse_response(&handle_relay_query(&query, &config, &store));
        assert!(response.authoritative());
    }

    // --- Bug condition exploration: Response Budget Crowds Out Needed Retransmits ---
    // **Validates: Requirements 1.1, 1.2, 1.3**
    //
    // This test populates 20 slots in a relay channel and asserts that ALL 20
    // sequence IDs are retrievable by the client. On unfixed code, only ~7
    // highest-sequence envelopes fit in the 1232-byte EDNS0 budget, so
    // lower-sequence retransmits are unreachable — proving the bug exists.

    /// Helper: build a DnsMessage with a specific edns_udp_size.
    fn make_dns_message_edns(name: &str, qtype: RecordType, edns_udp_size: u16) -> DnsMessage {
        let query_name = Name::from_ascii(name).unwrap();
        let query_name_labels: Vec<String> = query_name
            .iter()
            .map(|l| String::from_utf8_lossy(l).to_string())
            .collect();
        DnsMessage {
            query_id: 0x1234,
            query_name,
            query_type: qtype,
            query_name_labels,
            edns_udp_size,
        }
    }

    /// Extract sequence IDs from TXT envelope records in a DNS response.
    /// Envelope format: `sender_id|seq|timestamp|base32_payload`
    fn extract_sequence_ids(response: &Message) -> std::collections::BTreeSet<u64> {
        let mut seqs = std::collections::BTreeSet::new();
        for ans in response.answers() {
            if let Some(hickory_proto::rr::RData::TXT(txt)) = ans.data().into() {
                let text: String = txt
                    .iter()
                    .map(|b| String::from_utf8_lossy(b).to_string())
                    .collect();
                // Parse envelope: sender_id|seq|timestamp|base32_payload
                let parts: Vec<&str> = text.splitn(4, '|').collect();
                if parts.len() == 4 {
                    if let Ok(seq) = parts[1].parse::<u64>() {
                        seqs.insert(seq);
                    }
                }
            }
        }
        seqs
    }

    // =========================================================================
    // Preservation Property Tests (Task 2)
    // **Validates: Requirements 3.1, 3.2, 3.3, 3.4, 3.5, 3.6**
    //
    // These property-based tests capture the baseline behavior of the UNFIXED
    // code. They MUST continue to pass after the selective-fetch fix is
    // implemented, ensuring no regressions in legacy query paths, send path,
    // status path, empty channels, TTL, and AA flag.
    // =========================================================================

    use proptest::prelude::*;

    /// Strategy: generate a sender ID from a small set.
    fn sender_id_strategy() -> impl Strategy<Value = String> {
        prop_oneof![
            Just("alice".to_string()),
            Just("bob".to_string()),
            Just("charlie".to_string()),
        ]
    }

    /// Strategy: generate a single slot entry (sender_id, payload).
    fn slot_entry_strategy() -> impl Strategy<Value = (String, Vec<u8>)> {
        (sender_id_strategy(), prop::collection::vec(any::<u8>(), 1..=100))
    }

    /// Strategy: generate a channel state with 1-6 slots.
    fn channel_state_strategy() -> impl Strategy<Value = Vec<(String, Vec<u8>)>> {
        prop::collection::vec(slot_entry_strategy(), 1..=6)
    }

    /// Helper: extract envelope text strings from a TXT DNS response.
    fn extract_envelope_texts(response: &Message) -> Vec<String> {
        let mut envelopes = Vec::new();
        for ans in response.answers() {
            if let Some(hickory_proto::rr::RData::TXT(txt)) = ans.data().into() {
                let text: String = txt
                    .iter()
                    .map(|b| String::from_utf8_lossy(b).to_string())
                    .collect();
                envelopes.push(text);
            }
        }
        envelopes
    }

    proptest! {
        /// **Validates: Requirements 3.4, 3.5, 3.6**
        ///
        /// Property 2a: Legacy TXT query preservation.
        /// For random channel states (1-6 slots), a legacy TXT query (unprefixed
        /// nonce) returns all non-expired slots sorted by sequence descending,
        /// with correct envelope format and NoError rcode.
        #[test]
        fn preservation_legacy_txt_query_returns_correct_envelopes(
            slots in channel_state_strategy(),
        ) {
            let config = test_relay_config();
            let store = make_relay_store();

            // Populate the store
            let mut expected_seqs = Vec::new();
            for (sender_id, payload) in &slots {
                let seq = store.write("inbox", sender_id, payload.clone());
                expected_seqs.push(seq);
            }

            // Issue a legacy TXT query (unprefixed nonce)
            let query = make_dns_message("nonce42.inbox.relay.example.com.", RecordType::TXT);
            let response_bytes = handle_relay_query(&query, &config, &store);
            let response = parse_response(&response_bytes);

            // NoError rcode
            prop_assert_eq!(
                response.response_code(),
                ResponseCode::NoError,
                "Legacy TXT query must return NoError"
            );

            // Extract returned sequence IDs
            let returned_seqs = extract_sequence_ids(&response);

            // All slots should be returned (1-6 slots fit in budget)
            let expected_set: std::collections::BTreeSet<u64> = expected_seqs.iter().copied().collect();
            prop_assert_eq!(
                &returned_seqs,
                &expected_set,
                "Legacy TXT query should return all {} slots. Got {:?}, expected {:?}",
                slots.len(),
                returned_seqs,
                expected_set
            );

            // Verify envelopes are sorted by sequence descending
            let envelopes = extract_envelope_texts(&response);
            let mut prev_seq: Option<u64> = None;
            for env in &envelopes {
                let parts: Vec<&str> = env.splitn(4, '|').collect();
                prop_assert_eq!(parts.len(), 4, "Envelope must have 4 pipe-delimited fields");
                let seq: u64 = parts[1].parse().unwrap();
                if let Some(p) = prev_seq {
                    prop_assert!(
                        seq < p,
                        "Envelopes must be sorted by sequence descending: {} should be < {}",
                        seq,
                        p
                    );
                }
                prev_seq = Some(seq);
            }

            // Verify all returned sequences exist in the store
            for seq in &returned_seqs {
                prop_assert!(
                    expected_set.contains(seq),
                    "Returned sequence {} not in store",
                    seq
                );
            }

            // Verify envelope format: sender_id|seq|timestamp|base32_payload
            for env in &envelopes {
                let parts: Vec<&str> = env.splitn(4, '|').collect();
                prop_assert_eq!(parts.len(), 4, "Envelope format must be sender_id|seq|timestamp|base32_payload");
                prop_assert!(parts[1].parse::<u64>().is_ok(), "seq must be a valid u64");
                prop_assert!(parts[2].parse::<u64>().is_ok(), "timestamp must be a valid u64");
                // base32 payload should be non-empty (payloads are 1-100 bytes)
                prop_assert!(!parts[3].is_empty(), "base32 payload must be non-empty");
            }
        }

        /// **Validates: Requirements 3.1**
        ///
        /// Property 2b: Send path preservation.
        /// For all A queries with valid send structure, response IP is ACK (1.2.3.4).
        #[test]
        fn preservation_send_path_returns_ack_ip(
            // Limit payload to 39 bytes so base32 encoding fits in a single
            // 63-char DNS label (ceil(39*8/5) = 63).
            payload in prop::collection::vec(any::<u8>(), 1..=39),
            sender in sender_id_strategy(),
        ) {
            let config = test_relay_config();
            let store = make_relay_store();

            // Encode payload as base32 for the DNS query name
            let encoded_payload = crate::encoding::base32_encode(&payload);

            // Build send query: nonce.payload.sender.channel.relay.example.com
            let query_name = format!(
                "nonce99.{}.{}.inbox.relay.example.com.",
                encoded_payload, sender
            );
            let query = make_dns_message(&query_name, RecordType::A);
            let response_bytes = handle_relay_query(&query, &config, &store);
            let response = parse_response(&response_bytes);

            prop_assert_eq!(
                response.response_code(),
                ResponseCode::NoError,
                "Send query must return NoError"
            );
            prop_assert_eq!(
                response.answers().len(),
                1,
                "Send query must return exactly 1 answer"
            );

            match response.answers()[0].data() {
                hickory_proto::rr::RData::A(a) => {
                    prop_assert_eq!(
                        a.0,
                        Ipv4Addr::new(1, 2, 3, 4),
                        "Send query must return ACK IP 1.2.3.4"
                    );
                }
                other => prop_assert!(false, "Expected A record, got {:?}", other),
            }
        }

        /// **Validates: Requirements 3.2**
        ///
        /// Property 2c: Status path preservation.
        /// For all status queries, response IP encodes slot_count correctly.
        #[test]
        fn preservation_status_query_encodes_slot_count(
            slots in channel_state_strategy(),
        ) {
            let config = test_relay_config();
            let store = make_relay_store();

            // Populate the store
            for (sender_id, payload) in &slots {
                store.write("inbox", sender_id, payload.clone());
            }

            let expected_count = store.slot_count("inbox");

            // Issue status query
            let query = make_dns_message(
                "nonce.status.inbox.relay.example.com.",
                RecordType::A,
            );
            let response_bytes = handle_relay_query(&query, &config, &store);
            let response = parse_response(&response_bytes);

            prop_assert_eq!(
                response.response_code(),
                ResponseCode::NoError,
                "Status query must return NoError"
            );
            prop_assert_eq!(
                response.answers().len(),
                1,
                "Status query must return exactly 1 answer"
            );

            match response.answers()[0].data() {
                hickory_proto::rr::RData::A(a) => {
                    let expected_ip = encode_status_ip(expected_count);
                    prop_assert_eq!(
                        a.0,
                        expected_ip,
                        "Status IP must encode slot count {}. Expected {:?}, got {:?}",
                        expected_count,
                        expected_ip,
                        a.0
                    );
                }
                other => prop_assert!(false, "Expected A record, got {:?}", other),
            }
        }

        /// **Validates: Requirements 3.3**
        ///
        /// Property 2d: Empty channel preservation.
        /// For all TXT queries on empty channels, response has zero answers and NoError rcode.
        #[test]
        fn preservation_empty_channel_txt_returns_noerror_no_answers(
            nonce in "[a-z0-9]{4,12}",
            channel in prop_oneof![
                Just("inbox".to_string()),
                Just("outbox".to_string()),
                Just("data".to_string()),
            ],
        ) {
            let config = test_relay_config();
            let store = make_relay_store();

            // Do NOT write anything — channel is empty
            let query_name = format!("{}.{}.relay.example.com.", nonce, channel);
            let query = make_dns_message(&query_name, RecordType::TXT);
            let response_bytes = handle_relay_query(&query, &config, &store);
            let response = parse_response(&response_bytes);

            prop_assert_eq!(
                response.response_code(),
                ResponseCode::NoError,
                "Empty channel TXT query must return NoError"
            );
            prop_assert!(
                response.answers().is_empty(),
                "Empty channel TXT query must return zero answers, got {}",
                response.answers().len()
            );
        }

        /// **Validates: Requirements 3.4, 3.6**
        ///
        /// Property 2e: TTL 0 and AA flag preservation.
        /// For all responses (TXT, A send, A status), every record has TTL 0
        /// and the response has the AA (Authoritative Answer) flag set.
        #[test]
        fn preservation_ttl_zero_and_aa_flag(
            slots in channel_state_strategy(),
        ) {
            let config = test_relay_config();
            let store = make_relay_store();

            // Populate the store
            for (sender_id, payload) in &slots {
                store.write("inbox", sender_id, payload.clone());
            }

            // Test TXT query response
            let txt_query = make_dns_message("nonce.inbox.relay.example.com.", RecordType::TXT);
            let txt_resp = parse_response(&handle_relay_query(&txt_query, &config, &store));
            prop_assert!(txt_resp.authoritative(), "TXT response must have AA flag");
            for ans in txt_resp.answers() {
                prop_assert_eq!(ans.ttl(), 0, "TXT response records must have TTL 0");
            }

            // Test status query response
            let status_query = make_dns_message(
                "nonce.status.inbox.relay.example.com.",
                RecordType::A,
            );
            let status_resp = parse_response(&handle_relay_query(&status_query, &config, &store));
            prop_assert!(status_resp.authoritative(), "Status response must have AA flag");
            for ans in status_resp.answers() {
                prop_assert_eq!(ans.ttl(), 0, "Status response records must have TTL 0");
            }

            // Test empty channel TXT query response
            let empty_query = make_dns_message("nonce.emptych.relay.example.com.", RecordType::TXT);
            let empty_resp = parse_response(&handle_relay_query(&empty_query, &config, &store));
            prop_assert!(empty_resp.authoritative(), "Empty channel response must have AA flag");
        }
    }

    #[test]
    fn test_bug_condition_response_budget_crowds_out_retransmits() {
        // **Validates: Requirements 2.1, 2.2, 2.3**
        //
        // Bug Condition: channel has more non-expired slots than fit in one
        // DNS response (~7 records at 1232-byte EDNS0 budget), and the client
        // needs lower-sequence packets that are crowded out by higher-sequence ones.
        //
        // Expected Behavior: Client can discover ALL available sequence IDs
        // via a compact manifest query, then selectively fetch all sequences
        // in batches. After manifest+fetch, all 20 sequences are retrievable.
        //
        // On UNFIXED code: No manifest or fetch mode exists. Test FAILS.
        // On FIXED code: Manifest returns all 20 seq IDs compactly, fetch
        // retrieves all envelopes in batches. Test PASSES.

        let config = test_relay_config();
        let store = make_relay_store();

        // Populate 20 slots in channel "inbox" from sender "server1" (seq 1-20).
        // Each payload is a small 72-byte packet (simulating encrypted IP packet).
        let expected_seqs: std::collections::BTreeSet<u64> = (1..=20).collect();
        for i in 0..20 {
            let payload = vec![i as u8; 72]; // 72-byte payload per slot
            store.write("inbox", "server1", payload);
        }

        // Verify all 20 slots are in the store.
        assert_eq!(store.slot_count("inbox"), 20);

        // --- Phase 1: Manifest query ---
        // Issue a manifest TXT query (m-prefixed nonce) with EDNS0 1232.
        let manifest_query = make_dns_message_edns(
            "mnonce1.inbox.relay.example.com.",
            RecordType::TXT,
            1232,
        );
        let manifest_bytes = handle_relay_query(&manifest_query, &config, &store);
        let manifest_response = parse_response(&manifest_bytes);

        assert_eq!(manifest_response.response_code(), ResponseCode::NoError);

        // Parse manifest response: TXT records with comma-separated "seq_id,payload_len" entries.
        let mut manifest_seqs: std::collections::BTreeSet<u64> = std::collections::BTreeSet::new();
        for ans in manifest_response.answers() {
            if let Some(hickory_proto::rr::RData::TXT(txt)) = ans.data().into() {
                let text: String = txt
                    .iter()
                    .map(|b| String::from_utf8_lossy(b).to_string())
                    .collect();
                // Each TXT record contains comma-separated "seq_id,payload_len" pairs.
                // The pairs themselves are comma-separated, so the format is:
                // "seq1,len1,seq2,len2,..." — parse pairs by taking every two values.
                let parts: Vec<&str> = text.split(',').collect();
                // Each entry is two consecutive values: seq_id, payload_len
                for chunk in parts.chunks(2) {
                    if chunk.len() == 2 {
                        if let Ok(seq) = chunk[0].parse::<u64>() {
                            manifest_seqs.insert(seq);
                        }
                    }
                }
            }
        }

        // Assert the manifest contains all 20 sequence IDs.
        assert_eq!(
            manifest_seqs, expected_seqs,
            "Manifest must list all 20 sequence IDs. Got {:?}, expected {:?}. \
             Missing: {:?}",
            manifest_seqs,
            expected_seqs,
            expected_seqs.difference(&manifest_seqs).collect::<Vec<_>>()
        );

        // --- Phase 2: Fetch queries in batches ---
        // The fetch response is budget-limited to ~7 envelopes per query,
        // so we need multiple fetch queries to retrieve all 20 sequences.
        let all_seq_ids: Vec<u64> = manifest_seqs.iter().copied().collect();
        let mut retrieved_seqs: std::collections::BTreeSet<u64> = std::collections::BTreeSet::new();

        // Fetch in batches — each batch requests a subset of sequence IDs.
        // Use batches of 7 to stay within the response budget.
        for batch in all_seq_ids.chunks(7) {
            let seq_label = batch
                .iter()
                .map(|s| s.to_string())
                .collect::<Vec<_>>()
                .join("-");
            let fetch_name = format!(
                "fnonce2.{}.inbox.relay.example.com.",
                seq_label
            );
            let fetch_query = make_dns_message_edns(
                &fetch_name,
                RecordType::TXT,
                1232,
            );
            let fetch_bytes = handle_relay_query(&fetch_query, &config, &store);
            let fetch_response = parse_response(&fetch_bytes);

            assert_eq!(fetch_response.response_code(), ResponseCode::NoError);

            // Extract sequence IDs from the returned envelopes.
            let batch_seqs = extract_sequence_ids(&fetch_response);
            retrieved_seqs.extend(batch_seqs);
        }

        // Assert ALL 20 sequences were retrieved via manifest+fetch.
        assert_eq!(
            retrieved_seqs, expected_seqs,
            "All 20 sequences must be retrievable via manifest+fetch. \
             Got {} of 20: {:?}. Missing: {:?}.",
            retrieved_seqs.len(),
            retrieved_seqs,
            expected_seqs.difference(&retrieved_seqs).collect::<Vec<_>>()
        );
    }
}
