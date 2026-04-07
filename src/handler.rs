//! Query router and handler module.
//!
//! Routes incoming DNS queries to send/receive handlers and produces responses.

use hickory_proto::op::ResponseCode;
use hickory_proto::rr::Record;
use hickory_proto::rr::{Name, RecordType};

use std::net::Ipv4Addr;

use crate::config::Config;
use crate::dns::{a_record, build_response, DnsMessage};
use crate::store::{ChannelStore, Clock};

/// Maximum value representable in 24 bits for status IP encoding.
const MAX_DEPTH_24BIT: usize = 0x00FF_FFFF;

/// First octet sentinel for status response IPs.
const STATUS_OCTET: u8 = 128;

/// No-data IP returned when a channel's queue is empty or doesn't exist.
const NO_DATA_IP: Ipv4Addr = Ipv4Addr::new(0, 0, 0, 0);

/// Encode a queue depth into a status IP address.
/// First octet = 128, remaining 24 bits = depth (clamped to 0x00FF_FFFF).
/// For depth 0, returns 0.0.0.0.
fn encode_status_ip(depth: usize) -> Ipv4Addr {
    if depth == 0 {
        return NO_DATA_IP;
    }
    let clamped = depth.min(MAX_DEPTH_24BIT) as u32;
    Ipv4Addr::new(
        STATUS_OCTET,
        ((clamped >> 16) & 0xFF) as u8,
        ((clamped >> 8) & 0xFF) as u8,
        (clamped & 0xFF) as u8,
    )
}

/// Check whether the query name is under the controlled domain.
///
/// The query name labels (excluding root) must end with the controlled domain labels.
/// For example, if controlled_domain is "broker.example.com", then
/// "nonce.payload.sender.channel.broker.example.com" is under it, but
/// "nonce.payload.sender.channel.other.com" is not.
fn is_under_controlled_domain(query_labels: &[String], controlled_domain: &str) -> bool {
    // Split controlled domain into labels
    let domain_labels: Vec<&str> = controlled_domain.split('.').filter(|s| !s.is_empty()).collect();

    if query_labels.len() <= domain_labels.len() {
        return false;
    }

    // Compare the rightmost labels of the query name with the controlled domain labels
    let query_suffix = &query_labels[query_labels.len() - domain_labels.len()..];
    for (ql, dl) in query_suffix.iter().zip(domain_labels.iter()) {
        if !ql.eq_ignore_ascii_case(dl) {
            return false;
        }
    }

    true
}

/// Detect whether the remaining labels (after stripping the controlled domain)
/// represent a status query.
///
/// Status query format: `<nonce>.status.<channel>.<controlled_domain>`
/// After stripping the controlled domain, remaining labels are: `[nonce, status, channel]`
/// We check that there are at least 3 labels and that the second label (index 1) is "status".
fn is_status_query(remaining_labels: &[&str]) -> bool {
    remaining_labels.len() >= 3
        && remaining_labels[1].eq_ignore_ascii_case("status")
}

/// Handle a status query: look up queue depth, encode as A record with TTL 0.
///
/// Takes an immutable reference to the store (read-only operation).
/// For empty or non-existent channels, returns A record with `0.0.0.0`.
///
/// This function is public so that `server.rs` can call it directly
/// when holding a read lock (status queries don't need a write lock).
pub fn handle_status<C: Clock>(
    query: &DnsMessage,
    config: &Config,
    store: &ChannelStore<C>,
) -> Vec<u8> {
    let labels = &query.query_name_labels;

    // Split controlled domain into labels to determine how many to strip
    let domain_labels: Vec<&str> = config
        .controlled_domain
        .split('.')
        .filter(|s| !s.is_empty())
        .collect();

    let remaining_count = labels.len().saturating_sub(domain_labels.len());
    let remaining: Vec<&str> = labels[..remaining_count].iter().map(|s| s.as_str()).collect();

    // remaining should be [nonce, "status", channel]
    // Channel is at index 2
    let channel = if remaining.len() >= 3 {
        remaining[2]
    } else {
        // Malformed — treat as empty channel
        ""
    };

    let depth = store.queue_depth(channel);
    let ip = encode_status_ip(depth);
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

/// Extract the remaining labels from a query name after stripping the controlled domain suffix.
///
/// Returns the labels before the controlled domain as `&str` slices.
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

/// Check whether a parsed DNS query is a status query.
///
/// This is a public helper intended to be called from `server.rs` BEFORE
/// acquiring the store lock, so the server can choose a read lock for status
/// queries and a write lock for send/receive queries.
///
/// Returns `true` if the query is an A/AAAA query under the controlled domain
/// whose remaining labels match the status query pattern
/// (`<nonce>.status.<channel>`).
pub fn is_status_query_packet(query: &DnsMessage, config: &Config) -> bool {
    match query.query_type {
        RecordType::A | RecordType::AAAA => {
            if !is_under_controlled_domain(&query.query_name_labels, &config.controlled_domain) {
                return false;
            }
            let remaining = extract_remaining_labels(
                &query.query_name_labels,
                &config.controlled_domain,
            );
            is_status_query(&remaining)
        }
        _ => false,
    }
}

/// Route an incoming DNS query to the appropriate handler and produce a response.
///
/// Routing logic:
/// 1. Check if query name is under the controlled domain → REFUSED if not
/// 2. A/AAAA queries → check for status query first; if yes, route to `handle_status`; otherwise route to `handle_send`
/// 3. TXT queries → receive handler
/// 4. Other query types → REFUSED
pub fn handle_query<C: Clock>(
    query: &DnsMessage,
    config: &Config,
    store: &mut ChannelStore<C>,
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
                // Status queries only need immutable access
                handle_status(query, config, &*store)
            } else {
                handle_send(query, config, store)
            }
        }
        RecordType::TXT => {
            handle_receive(query, config, store)
        }
        _ => {
            // Unsupported query type under controlled domain → REFUSED
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

/// Handle a send operation (A/AAAA query).
///
/// Strips nonce, decodes the send query, stores the message, and returns
/// an A record response with ack_ip or error IP.
///
/// Stub implementation — will be fully implemented in task 8.2.
fn handle_send<C: Clock>(
    query: &DnsMessage,
    config: &Config,
    store: &mut ChannelStore<C>,
) -> Vec<u8> {
    use crate::dns::a_record;
    use crate::encoding::decode_send_query;

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

    match store.push(&channel, &sender_id, payload) {
        Ok(_seq) => {
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
        Err(crate::error::StoreError::ChannelFull(_)) => {
            let record = a_record(&query.query_name, config.error_channel_full_ip);
            build_response(
                query.query_id,
                &query.query_name,
                query.query_type,
                ResponseCode::NoError,
                vec![record],
            )
            .unwrap_or_default()
        }
        Err(crate::error::StoreError::PayloadTooLarge { .. }) => {
            let record = a_record(&query.query_name, config.error_payload_too_large_ip);
            build_response(
                query.query_id,
                &query.query_name,
                query.query_type,
                ResponseCode::NoError,
                vec![record],
            )
            .unwrap_or_default()
        }
    }
}

/// Handle a receive operation (TXT query).
///
/// Strips nonce, identifies the channel, pops the oldest message, and returns
/// a TXT record with the envelope or NOERROR with zero answers.
///
/// Stub implementation — will be fully implemented in task 8.3.
fn handle_receive<C: Clock>(
    query: &DnsMessage,
    config: &Config,
    store: &mut ChannelStore<C>,
) -> Vec<u8> {
    use crate::dns::txt_record;
    use crate::encoding::encode_envelope;

    let labels = &query.query_name_labels;

    // Split controlled domain into labels to determine how many to strip
    let domain_labels: Vec<&str> = config
        .controlled_domain
        .split('.')
        .filter(|s| !s.is_empty())
        .collect();

    // Receive query structure: <nonce>.<channel>.<controlled_domain>
    // After stripping domain labels from the right and nonce from the left,
    // we should have exactly 1 label: the channel name.
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

    // The channel is the remaining label(s) — for receive, it should be exactly 1 label.
    // Pop mode: if the nonce starts with 'p', use destructive pop_many instead of peek_many.
    // This allows simple consumers (like dnc) to get consume-once semantics.
    let channel = &after_nonce[0];
    let nonce_label = &remaining[0];
    let use_pop = nonce_label.starts_with('P');

    // Parse cursor from nonce: look for -c<number> suffix (only for peek mode)
    let cursor: Option<u64> = if !use_pop {
        nonce_label.rfind("-c").and_then(|pos| {
            nonce_label[pos + 2..].parse::<u64>().ok()
        })
    } else {
        None
    };

    // Determine how many messages to return.
    //
    // Priority:
    // 1. Config override (`max_response_messages`): fixed value, no adaptive update
    // 2. EDNS0 present (>= 1232) in peek mode: adaptive AIMD via store
    // 3. EDNS0 present in pop mode: use EDNS0-based formula (no adaptive state touch)
    // 4. No EDNS0 (< 1232): always 1
    let max_messages = if query.edns_udp_size < 1232 {
        // No EDNS0 — always 1 message
        1
    } else if let Some(n) = config.max_response_messages {
        // Config override — fixed value, skip adaptive state
        n
    } else if use_pop {
        // Pop mode with EDNS0 — use existing formula, don't touch adaptive state
        ((query.edns_udp_size as usize).saturating_sub(100) / 250).max(1).min(2)
    } else {
        // Peek mode with EDNS0 — adaptive AIMD
        store.update_adaptive_state(channel, cursor)
    };

    let messages = if use_pop {
        store.pop_many(channel, max_messages)
    } else {
        store.peek_many(channel, max_messages, cursor)
    };
    if messages.is_empty() {
        // No messages — NOERROR with zero answers
        return build_response(
            query.query_id,
            &query.query_name,
            query.query_type,
            ResponseCode::NoError,
            vec![],
        )
        .unwrap_or_default();
    }

    let records: Vec<Record> = messages
        .iter()
        .map(|msg| {
            let envelope = encode_envelope(msg);
            txt_record(&query.query_name, &envelope)
        })
        .collect();

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
    use crate::config::parse_config;
    use crate::store::test_support::MockClock;
    use crate::store::ChannelStore;
    use hickory_proto::op::Message;
    use hickory_proto::rr::RecordType;
    use proptest::prelude::*;
    use std::time::Duration;

    fn test_config() -> Config {
        parse_config(r#"controlled_domain = "broker.example.com""#).unwrap()
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

    #[test]
    fn test_query_outside_controlled_domain_returns_refused() {
        let config = test_config();
        let clock = MockClock::new();
        let mut store = ChannelStore::new(100, Duration::from_secs(3600), Duration::from_secs(600), clock, 32);

        let query = make_dns_message("nonce.something.other.com.", RecordType::A);
        let response_bytes = handle_query(&query, &config, &mut store);
        let response = parse_response(&response_bytes);

        assert_eq!(response.response_code(), ResponseCode::Refused);
    }

    #[test]
    fn test_query_under_controlled_domain_a_record_routes_to_send() {
        let config = test_config();
        let clock = MockClock::new();
        let mut store = ChannelStore::new(100, Duration::from_secs(3600), Duration::from_secs(600), clock, 32);

        // nonce.payload.sender.channel.broker.example.com
        // payload "me" base32 = "nvsq"
        let query = make_dns_message(
            "abc12345.nvsq.alice.inbox.broker.example.com.",
            RecordType::A,
        );
        let response_bytes = handle_query(&query, &config, &mut store);
        let response = parse_response(&response_bytes);

        // Should get NOERROR with an A record (ack_ip)
        assert_eq!(response.response_code(), ResponseCode::NoError);
        assert_eq!(response.answers().len(), 1);
    }

    #[test]
    fn test_query_under_controlled_domain_txt_routes_to_receive() {
        let config = test_config();
        let clock = MockClock::new();
        let mut store = ChannelStore::new(100, Duration::from_secs(3600), Duration::from_secs(600), clock, 32);

        // TXT query for receive: nonce.channel.broker.example.com
        let query = make_dns_message(
            "abc12345.inbox.broker.example.com.",
            RecordType::TXT,
        );
        let response_bytes = handle_query(&query, &config, &mut store);
        let response = parse_response(&response_bytes);

        // Empty channel → NOERROR with zero answers
        assert_eq!(response.response_code(), ResponseCode::NoError);
        assert!(response.answers().is_empty());
    }

    #[test]
    fn test_unsupported_query_type_returns_refused() {
        let config = test_config();
        let clock = MockClock::new();
        let mut store = ChannelStore::new(100, Duration::from_secs(3600), Duration::from_secs(600), clock, 32);

        let query = make_dns_message(
            "abc12345.inbox.broker.example.com.",
            RecordType::MX,
        );
        let response_bytes = handle_query(&query, &config, &mut store);
        let response = parse_response(&response_bytes);

        assert_eq!(response.response_code(), ResponseCode::Refused);
    }

    #[test]
    fn test_send_then_receive_roundtrip() {
        let config = test_config();
        let clock = MockClock::new();
        let mut store = ChannelStore::new(100, Duration::from_secs(3600), Duration::from_secs(600), clock, 32);

        // Send: nonce.payload.sender.channel.broker.example.com
        // payload "hi" base32 = "nbsq"
        let send_query = make_dns_message(
            "nonce123.nbsq.alice.inbox.broker.example.com.",
            RecordType::A,
        );
        let send_response_bytes = handle_query(&send_query, &config, &mut store);
        let send_response = parse_response(&send_response_bytes);
        assert_eq!(send_response.response_code(), ResponseCode::NoError);
        assert_eq!(send_response.answers().len(), 1);

        // Receive: nonce.channel.broker.example.com
        let recv_query = make_dns_message(
            "nonce456.inbox.broker.example.com.",
            RecordType::TXT,
        );
        let recv_response_bytes = handle_query(&recv_query, &config, &mut store);
        let recv_response = parse_response(&recv_response_bytes);
        assert_eq!(recv_response.response_code(), ResponseCode::NoError);
        assert_eq!(recv_response.answers().len(), 1);
    }

    #[test]
    fn test_is_under_controlled_domain_true() {
        let labels = vec![
            "nonce".to_string(),
            "payload".to_string(),
            "sender".to_string(),
            "channel".to_string(),
            "broker".to_string(),
            "example".to_string(),
            "com".to_string(),
        ];
        assert!(is_under_controlled_domain(&labels, "broker.example.com"));
    }

    #[test]
    fn test_is_under_controlled_domain_false() {
        let labels = vec![
            "nonce".to_string(),
            "payload".to_string(),
            "other".to_string(),
            "domain".to_string(),
            "com".to_string(),
        ];
        assert!(!is_under_controlled_domain(&labels, "broker.example.com"));
    }

    #[test]
    fn test_is_under_controlled_domain_exact_match_not_subdomain() {
        // Query name is exactly the controlled domain (no subdomain labels) → false
        let labels = vec![
            "broker".to_string(),
            "example".to_string(),
            "com".to_string(),
        ];
        assert!(!is_under_controlled_domain(&labels, "broker.example.com"));
    }

    #[test]
    fn test_send_bad_structure_returns_nxdomain() {
        let config = test_config();
        let clock = MockClock::new();
        let mut store = ChannelStore::new(100, Duration::from_secs(3600), Duration::from_secs(600), clock, 32);

        // Too few labels for a valid send query (only nonce + domain)
        let query = make_dns_message(
            "nonce.broker.example.com.",
            RecordType::A,
        );
        let response_bytes = handle_query(&query, &config, &mut store);
        let response = parse_response(&response_bytes);

        assert_eq!(response.response_code(), ResponseCode::NXDomain);
    }

    #[test]
    fn test_receive_bad_structure_returns_nxdomain() {
        let config = test_config();
        let clock = MockClock::new();
        let mut store = ChannelStore::new(100, Duration::from_secs(3600), Duration::from_secs(600), clock, 32);

        // Only domain labels, no nonce or channel
        let query = make_dns_message(
            "broker.example.com.",
            RecordType::TXT,
        );
        let response_bytes = handle_query(&query, &config, &mut store);
        let response = parse_response(&response_bytes);

        // Not under controlled domain (exact match, no subdomain) → REFUSED
        assert_eq!(response.response_code(), ResponseCode::Refused);
    }

    #[test]
    fn test_response_has_aa_flag() {
        let config = test_config();
        let clock = MockClock::new();
        let mut store = ChannelStore::new(100, Duration::from_secs(3600), Duration::from_secs(600), clock, 32);

        let query = make_dns_message(
            "abc12345.inbox.broker.example.com.",
            RecordType::TXT,
        );
        let response_bytes = handle_query(&query, &config, &mut store);
        let response = parse_response(&response_bytes);

        assert!(response.authoritative());
    }

    // --- encode_status_ip tests ---

    #[test]
    fn test_encode_status_ip_zero_returns_no_data() {
        assert_eq!(encode_status_ip(0), Ipv4Addr::new(0, 0, 0, 0));
    }

    #[test]
    fn test_encode_status_ip_one() {
        assert_eq!(encode_status_ip(1), Ipv4Addr::new(128, 0, 0, 1));
    }

    #[test]
    fn test_encode_status_ip_max_24bit() {
        assert_eq!(encode_status_ip(0x00FF_FFFF), Ipv4Addr::new(128, 255, 255, 255));
    }

    #[test]
    fn test_encode_status_ip_clamped() {
        // Values above 24-bit max should clamp to 128.255.255.255
        assert_eq!(encode_status_ip(0x0100_0000), Ipv4Addr::new(128, 255, 255, 255));
        assert_eq!(encode_status_ip(usize::MAX), Ipv4Addr::new(128, 255, 255, 255));
    }

    #[test]
    fn test_encode_status_ip_mid_value() {
        // depth = 256 = 0x000100 → 128.0.1.0
        assert_eq!(encode_status_ip(256), Ipv4Addr::new(128, 0, 1, 0));
    }

    // --- is_status_query tests ---

    #[test]
    fn test_is_status_query_valid() {
        let labels = vec!["a7k2", "status", "d-aBcD1234"];
        assert!(is_status_query(&labels));
    }

    #[test]
    fn test_is_status_query_case_insensitive() {
        let labels = vec!["nonce", "STATUS", "channel"];
        assert!(is_status_query(&labels));
        let labels = vec!["nonce", "Status", "channel"];
        assert!(is_status_query(&labels));
    }

    #[test]
    fn test_is_status_query_too_few_labels() {
        let labels = vec!["nonce", "status"];
        assert!(!is_status_query(&labels));
        let labels: Vec<&str> = vec![];
        assert!(!is_status_query(&labels));
    }

    #[test]
    fn test_is_status_query_wrong_position() {
        // "status" at index 0 instead of index 1
        let labels = vec!["status", "nonce", "channel"];
        assert!(!is_status_query(&labels));
    }

    #[test]
    fn test_is_status_query_no_status_label() {
        let labels = vec!["nonce", "payload", "sender", "channel"];
        assert!(!is_status_query(&labels));
    }

    // --- handle_status tests ---

    #[test]
    fn test_handle_status_empty_channel_returns_no_data_ip() {
        let config = test_config();
        let clock = MockClock::new();
        let store = ChannelStore::new(100, Duration::from_secs(3600), Duration::from_secs(600), clock, 32);

        let query = make_dns_message(
            "a7k2.status.inbox.broker.example.com.",
            RecordType::A,
        );
        let response_bytes = handle_status(&query, &config, &store);
        let response = parse_response(&response_bytes);

        assert_eq!(response.response_code(), ResponseCode::NoError);
        assert_eq!(response.answers().len(), 1);
        let ans = &response.answers()[0];
        assert_eq!(ans.ttl(), 0);
        match ans.data() {
            hickory_proto::rr::RData::A(a) => assert_eq!(a.0, Ipv4Addr::new(0, 0, 0, 0)),
            other => panic!("expected A record, got {:?}", other),
        }
    }

    #[test]
    fn test_handle_status_nonexistent_channel_returns_no_data_ip() {
        let config = test_config();
        let clock = MockClock::new();
        let store = ChannelStore::new(100, Duration::from_secs(3600), Duration::from_secs(600), clock, 32);

        let query = make_dns_message(
            "a7k2.status.nonexistent.broker.example.com.",
            RecordType::A,
        );
        let response_bytes = handle_status(&query, &config, &store);
        let response = parse_response(&response_bytes);

        assert_eq!(response.response_code(), ResponseCode::NoError);
        assert_eq!(response.answers().len(), 1);
        let ans = &response.answers()[0];
        assert_eq!(ans.ttl(), 0);
        match ans.data() {
            hickory_proto::rr::RData::A(a) => assert_eq!(a.0, Ipv4Addr::new(0, 0, 0, 0)),
            other => panic!("expected A record, got {:?}", other),
        }
    }

    #[test]
    fn test_handle_status_with_messages_returns_depth() {
        let config = test_config();
        let clock = MockClock::new();
        let mut store = ChannelStore::new(100, Duration::from_secs(3600), Duration::from_secs(600), clock, 32);

        // Push 3 messages to the "inbox" channel
        store.push("inbox", "alice", b"msg1".to_vec()).unwrap();
        store.push("inbox", "bob", b"msg2".to_vec()).unwrap();
        store.push("inbox", "alice", b"msg3".to_vec()).unwrap();

        let query = make_dns_message(
            "a7k2.status.inbox.broker.example.com.",
            RecordType::A,
        );
        let response_bytes = handle_status(&query, &config, &store);
        let response = parse_response(&response_bytes);

        assert_eq!(response.response_code(), ResponseCode::NoError);
        assert_eq!(response.answers().len(), 1);
        let ans = &response.answers()[0];
        assert_eq!(ans.ttl(), 0);
        match ans.data() {
            hickory_proto::rr::RData::A(a) => {
                // depth 3 → 128.0.0.3
                assert_eq!(a.0, Ipv4Addr::new(128, 0, 0, 3));
            }
            other => panic!("expected A record, got {:?}", other),
        }
    }

    #[test]
    fn test_handle_status_is_read_only() {
        let config = test_config();
        let clock = MockClock::new();
        let mut store = ChannelStore::new(100, Duration::from_secs(3600), Duration::from_secs(600), clock, 32);

        store.push("inbox", "alice", b"msg1".to_vec()).unwrap();
        store.push("inbox", "bob", b"msg2".to_vec()).unwrap();

        assert_eq!(store.queue_depth("inbox"), 2);

        let query = make_dns_message(
            "a7k2.status.inbox.broker.example.com.",
            RecordType::A,
        );
        // Call handle_status — should not modify the store
        let _ = handle_status(&query, &config, &store);

        // Queue depth should be unchanged
        assert_eq!(store.queue_depth("inbox"), 2);
    }

    #[test]
    fn test_handle_status_ttl_is_zero() {
        let config = test_config();
        let clock = MockClock::new();
        let mut store = ChannelStore::new(100, Duration::from_secs(3600), Duration::from_secs(600), clock, 32);

        store.push("inbox", "alice", b"msg".to_vec()).unwrap();

        let query = make_dns_message(
            "nonce.status.inbox.broker.example.com.",
            RecordType::A,
        );
        let response_bytes = handle_status(&query, &config, &store);
        let response = parse_response(&response_bytes);

        for ans in response.answers() {
            assert_eq!(ans.ttl(), 0, "Status response TTL must be 0");
        }
    }

    // =========================================================================
    // Bug Condition Exploration: Adaptive Response Sizing (Task 1)
    // =========================================================================

    /// Helper: create a TXT recv query with EDNS0 and a cursor-bearing nonce.
    /// Format: `<nonce>-c<cursor>.<channel>.<controlled_domain>`
    fn make_edns_recv_query(channel: &str, nonce: &str, cursor: u64, edns_udp_size: u16) -> DnsMessage {
        let name_str = format!("{}-c{}.{}.broker.example.com.", nonce, cursor, channel);
        let query_name = Name::from_ascii(&name_str).unwrap();
        let query_name_labels: Vec<String> = query_name
            .iter()
            .map(|l| String::from_utf8_lossy(l).to_string())
            .collect();
        DnsMessage {
            query_id: 0xABCD,
            query_name,
            query_type: RecordType::TXT,
            query_name_labels,
            edns_udp_size,
        }
    }

    // **Validates: Requirements 1.1, 1.2, 1.3, 2.1, 2.2, 2.3**
    //
    // Bug Condition Exploration: Static max_messages Ignores Cursor Advancement
    //
    // For any EDNS0-bearing TXT recv query (edns_udp_size ≥ 1232) in peek
    // mode, when the cursor advances between polls (indicating the client
    // received the previous response), the broker should increase
    // max_messages (additive increase). On unfixed code, max_messages is
    // always 2 regardless of cursor advancement history.
    //
    // Steps:
    //   1. Push many messages to a channel (enough to fill any batch size)
    //   2. Send an initial EDNS0 TXT recv query with cursor=0 (first poll)
    //   3. Record the number of TXT records returned (the initial batch)
    //   4. Send subsequent queries with advancing cursors (simulating
    //      successful receipt of previous batches)
    //   5. After several cursor advances, assert that the response TXT
    //      record count has increased beyond the initial value
    //
    // On UNFIXED code this test is EXPECTED TO FAIL — the response always
    // contains at most 2 TXT records because max_messages is statically
    // computed as min(((edns_udp_size - 100) / 250), 2).
    proptest! {
        #[test]
        fn bug_condition_static_max_messages_ignores_cursor_advancement(
            edns_size in 1232u16..=4096,
            num_advances in 3usize..=6,
        ) {
            let config = test_config();
            let clock = MockClock::new();
            let mut store = ChannelStore::new(
                200,
                Duration::from_secs(3600),
                Duration::from_secs(600),
                clock,
                32,
            );

            let channel = "adaptive-ch";

            // Step 1: Push enough messages so the channel always has data
            // to return (more than the max ceiling of 8).
            for i in 0..50 {
                store.push(channel, "sender", vec![i as u8; 10]).unwrap();
            }

            // Step 2: Initial poll with cursor=0 — establishes baseline
            let initial_query = make_edns_recv_query(channel, "n0", 0, edns_size);
            let initial_response_bytes = handle_query(&initial_query, &config, &mut store);
            let initial_response = parse_response(&initial_response_bytes);
            let initial_count = initial_response.answers().len();

            // The initial count should be the conservative starting value (2)
            prop_assert!(
                initial_count > 0,
                "Initial poll should return at least 1 message, got 0"
            );

            // Step 3: Send queries with advancing cursors.
            // Each advance simulates the client confirming receipt of the
            // previous batch. The cursor value is the sequence number of
            // the last message received + 1.
            let mut cursor: u64 = initial_count as u64;
            let mut max_seen_count = initial_count;

            for advance_idx in 0..num_advances {
                // Push more messages to ensure the channel never runs dry
                for j in 0..10 {
                    let _ = store.push(
                        channel,
                        "sender",
                        vec![(advance_idx * 10 + j) as u8; 10],
                    );
                }

                let nonce = format!("n{}", advance_idx + 1);
                let query = make_edns_recv_query(channel, &nonce, cursor, edns_size);
                let response_bytes = handle_query(&query, &config, &mut store);
                let response = parse_response(&response_bytes);
                let count = response.answers().len();

                if count > max_seen_count {
                    max_seen_count = count;
                }

                // Advance cursor by the number of messages received
                if count > 0 {
                    cursor += count as u64;
                }
            }

            // Step 4: After multiple cursor advances, max_messages should
            // have increased beyond the initial conservative value.
            // With AIMD additive increase of +1 per advance, after 3+
            // advances we expect max_messages >= initial + 1 = 3.
            //
            // On UNFIXED code: max_seen_count == 2 (always static)
            // On FIXED code: max_seen_count >= initial_count + 1 (adaptive)
            prop_assert!(
                max_seen_count > initial_count,
                "After {} cursor advances, max TXT record count should have \
                 increased beyond initial value of {}, but the maximum observed \
                 was {} — max_messages is static and ignores cursor advancement. \
                 EDNS0 UDP size: {}, cursor reached: {}",
                num_advances,
                initial_count,
                max_seen_count,
                edns_size,
                cursor
            );
        }
    }

    // =========================================================================
    // Preservation Property Tests: Adaptive Response Sizing (Task 2)
    // =========================================================================
    //
    // These tests capture the CURRENT correct behavior of the handler on
    // UNFIXED code for inputs that are NOT affected by the adaptive sizing
    // bug. They must all PASS on the current unfixed code. After the fix
    // is applied, they verify no regressions were introduced.

    /// Helper: create a TXT recv query WITHOUT EDNS0 (edns_udp_size = 0).
    /// Format: `<nonce>.<channel>.<controlled_domain>`
    fn make_non_edns_recv_query(channel: &str, nonce: &str) -> DnsMessage {
        let name_str = format!("{}.{}.broker.example.com.", nonce, channel);
        let query_name = Name::from_ascii(&name_str).unwrap();
        let query_name_labels: Vec<String> = query_name
            .iter()
            .map(|l| String::from_utf8_lossy(l).to_string())
            .collect();
        DnsMessage {
            query_id: 0xBEEF,
            query_name,
            query_type: RecordType::TXT,
            query_name_labels,
            edns_udp_size: 0,
        }
    }

    /// Helper: create a TXT recv query with a specific edns_udp_size (no cursor).
    /// Format: `<nonce>.<channel>.<controlled_domain>`
    fn make_recv_query_with_edns(channel: &str, nonce: &str, edns_udp_size: u16) -> DnsMessage {
        let name_str = format!("{}.{}.broker.example.com.", nonce, channel);
        let query_name = Name::from_ascii(&name_str).unwrap();
        let query_name_labels: Vec<String> = query_name
            .iter()
            .map(|l| String::from_utf8_lossy(l).to_string())
            .collect();
        DnsMessage {
            query_id: 0xCAFE,
            query_name,
            query_type: RecordType::TXT,
            query_name_labels,
            edns_udp_size,
        }
    }

    /// Helper: create a pop-mode TXT recv query (nonce starts with 'P').
    /// Format: `P<nonce>.<channel>.<controlled_domain>`
    fn make_pop_recv_query(channel: &str, nonce_suffix: &str, edns_udp_size: u16) -> DnsMessage {
        let nonce = format!("P{}", nonce_suffix);
        let name_str = format!("{}.{}.broker.example.com.", nonce, channel);
        let query_name = Name::from_ascii(&name_str).unwrap();
        let query_name_labels: Vec<String> = query_name
            .iter()
            .map(|l| String::from_utf8_lossy(l).to_string())
            .collect();
        DnsMessage {
            query_id: 0xFACE,
            query_name,
            query_type: RecordType::TXT,
            query_name_labels,
            edns_udp_size,
        }
    }

    // **Validates: Requirements 3.1**
    //
    // Preservation: Non-EDNS0 queries always return at most 1 TXT record.
    //
    // For all TXT recv queries with edns_udp_size < 1232, the response
    // contains at most 1 TXT record regardless of channel state. This
    // captures the existing single-message behavior for non-EDNS0 clients.
    proptest! {
        #[test]
        fn preservation_non_edns0_returns_at_most_one_txt(
            msg_count in 1usize..=10,
            edns_size in 0u16..1232,
        ) {
            let config = test_config();
            let clock = MockClock::new();
            let mut store = ChannelStore::new(
                100,
                Duration::from_secs(3600),
                Duration::from_secs(600),
                clock,
                32,
            );

            let channel = "noedns";

            // Push multiple messages so the channel has plenty of data
            for i in 0..msg_count {
                store.push(channel, "sender", vec![i as u8; 10]).unwrap();
            }

            // Query with edns_udp_size < 1232 (non-EDNS0)
            let query = make_recv_query_with_edns(channel, "nonce1", edns_size);
            let response_bytes = handle_query(&query, &config, &mut store);
            let response = parse_response(&response_bytes);

            prop_assert_eq!(
                response.response_code(),
                ResponseCode::NoError,
                "Non-EDNS0 recv query should return NOERROR"
            );
            prop_assert!(
                response.answers().len() <= 1,
                "Non-EDNS0 recv query (edns_udp_size={}) should return at most 1 TXT record, \
                 but got {} — non-EDNS0 single-message behavior violated",
                edns_size,
                response.answers().len()
            );
        }
    }

    // **Validates: Requirements 3.2**
    //
    // Preservation: Pop-mode queries consume messages destructively via pop_many.
    //
    // For all TXT recv queries with nonce starting with 'P', messages are
    // consumed destructively. After a pop-mode query, the popped messages
    // are gone from the channel and cannot be retrieved again.
    proptest! {
        #[test]
        fn preservation_pop_mode_consumes_destructively(
            msg_count in 1usize..=8,
            edns_size in 1232u16..=4096,
        ) {
            let config = test_config();
            let clock = MockClock::new();
            let mut store = ChannelStore::new(
                100,
                Duration::from_secs(3600),
                Duration::from_secs(600),
                clock,
                32,
            );

            let channel = "popch";

            // Push messages
            for i in 0..msg_count {
                store.push(channel, "sender", vec![i as u8; 10]).unwrap();
            }

            // Pop-mode query (nonce starts with 'P')
            let query = make_pop_recv_query(channel, "nonce1", edns_size);
            let response_bytes = handle_query(&query, &config, &mut store);
            let response = parse_response(&response_bytes);

            let first_count = response.answers().len();
            prop_assert!(
                first_count > 0,
                "Pop-mode query on non-empty channel should return at least 1 message"
            );

            // Second pop-mode query — should get remaining messages (or none if all consumed)
            let query2 = make_pop_recv_query(channel, "nonce2", edns_size);
            let response_bytes2 = handle_query(&query2, &config, &mut store);
            let response2 = parse_response(&response_bytes2);
            let second_count = response2.answers().len();

            // Total consumed across both pops should equal msg_count
            // (pop is destructive — messages don't come back)
            let total = first_count + second_count;
            prop_assert!(
                total <= msg_count,
                "Pop mode should consume messages destructively: \
                 first pop got {}, second got {}, total {} but only {} pushed",
                first_count, second_count, total, msg_count
            );

            // If we keep popping, eventually the channel is empty
            let mut remaining = msg_count - total;
            while remaining > 0 {
                let q = make_pop_recv_query(channel, "drain", edns_size);
                let rb = handle_query(&q, &config, &mut store);
                let r = parse_response(&rb);
                let c = r.answers().len();
                if c == 0 { break; }
                remaining = remaining.saturating_sub(c);
            }

            // Final pop should return empty
            let final_query = make_pop_recv_query(channel, "final", edns_size);
            let final_bytes = handle_query(&final_query, &config, &mut store);
            let final_response = parse_response(&final_bytes);
            prop_assert_eq!(
                final_response.answers().len(),
                0,
                "After consuming all messages via pop mode, channel should be empty"
            );
        }
    }

    // **Validates: Requirements 3.4**
    //
    // Preservation: Empty/nonexistent channels return NOERROR with zero answers.
    //
    // For all TXT recv queries on empty or nonexistent channels, the response
    // is NOERROR with zero answers, regardless of EDNS0 size or nonce format.
    proptest! {
        #[test]
        fn preservation_empty_channel_returns_noerror_zero_answers(
            edns_size in 0u16..=4096,
            use_pop in proptest::bool::ANY,
        ) {
            let config = test_config();
            let clock = MockClock::new();
            let mut store = ChannelStore::new(
                100,
                Duration::from_secs(3600),
                Duration::from_secs(600),
                clock,
                32,
            );

            let channel = "emptych";

            // Query on a channel that was never created (nonexistent)
            let query = if use_pop {
                make_pop_recv_query(channel, "nonce1", edns_size)
            } else {
                make_recv_query_with_edns(channel, "nonce1", edns_size)
            };
            let response_bytes = handle_query(&query, &config, &mut store);
            let response = parse_response(&response_bytes);

            prop_assert_eq!(
                response.response_code(),
                ResponseCode::NoError,
                "Empty/nonexistent channel should return NOERROR"
            );
            prop_assert_eq!(
                response.answers().len(),
                0,
                "Empty/nonexistent channel should return zero answers, \
                 but got {} (edns_size={}, pop_mode={})",
                response.answers().len(),
                edns_size,
                use_pop
            );
        }
    }

    // **Validates: Requirements 3.3, 3.5**
    //
    // Preservation: Store operations produce identical results for non-EDNS0 inputs.
    //
    // For all push/pop/pop_many/peek_many/queue_depth/sweep_expired operations,
    // behavior is identical regardless of whether adaptive sizing exists.
    // This test exercises the store operations through the handler to verify
    // that the full send→receive roundtrip works correctly for non-EDNS0 queries.
    proptest! {
        #[test]
        fn preservation_store_operations_roundtrip_non_edns0(
            msg_count in 1usize..=5,
        ) {
            let config = test_config();
            let clock = MockClock::new();
            let mut store = ChannelStore::new(
                100,
                Duration::from_secs(3600),
                Duration::from_secs(600),
                clock,
                32,
            );

            let channel = "storech";

            // Push messages via send handler (A query)
            for i in 0..msg_count {
                // payload "hi" base32 = "nbsq"
                let send_query = make_dns_message(
                    &format!("nonce{}.nbsq.sender{}.{}.broker.example.com.", i, i, channel),
                    RecordType::A,
                );
                let send_bytes = handle_query(&send_query, &config, &mut store);
                let send_resp = parse_response(&send_bytes);
                prop_assert_eq!(
                    send_resp.response_code(),
                    ResponseCode::NoError,
                    "Send should succeed for message {}", i
                );
            }

            // Receive messages one at a time via non-EDNS0 TXT queries
            let mut received = 0;
            for i in 0..msg_count {
                let recv_query = make_non_edns_recv_query(channel, &format!("recv{}", i));
                let recv_bytes = handle_query(&recv_query, &config, &mut store);
                let recv_resp = parse_response(&recv_bytes);
                prop_assert_eq!(
                    recv_resp.response_code(),
                    ResponseCode::NoError,
                    "Receive should return NOERROR"
                );
                // Non-EDNS0 returns at most 1
                prop_assert!(
                    recv_resp.answers().len() <= 1,
                    "Non-EDNS0 should return at most 1 TXT record"
                );
                received += recv_resp.answers().len();
            }

            prop_assert!(
                received > 0,
                "Should have received at least some messages via non-EDNS0 queries"
            );
        }
    }
}
