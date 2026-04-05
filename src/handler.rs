//! Query router and handler module.
//!
//! Routes incoming DNS queries to send/receive handlers and produces responses.

use hickory_proto::op::ResponseCode;
use hickory_proto::rr::Record;
use hickory_proto::rr::{Name, RecordType};

use crate::config::Config;
use crate::dns::{build_response, DnsMessage};
use crate::store::{ChannelStore, Clock};

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

/// Route an incoming DNS query to the appropriate handler and produce a response.
///
/// Routing logic:
/// 1. Check if query name is under the controlled domain → REFUSED if not
/// 2. A/AAAA queries → send handler
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
            handle_send(query, config, store)
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

    // The channel is the remaining label(s) — for receive, it should be exactly 1 label
    let channel = &after_nonce[0];

    // Determine how many messages to pop based on EDNS0 buffer size.
    // Each TXT record envelope is roughly 200-300 bytes in the wire response.
    // With EDNS0, we can fit multiple records. Without EDNS0, stick to 1.
    let max_messages = if query.edns_udp_size >= 1232 {
        // Conservative: ~250 bytes per TXT record in wire format
        ((query.edns_udp_size as usize).saturating_sub(100) / 250).max(1)
    } else {
        1
    };

    let messages = store.pop_many(channel, max_messages);
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
        let mut store = ChannelStore::new(100, Duration::from_secs(3600), Duration::from_secs(600), clock);

        let query = make_dns_message("nonce.something.other.com.", RecordType::A);
        let response_bytes = handle_query(&query, &config, &mut store);
        let response = parse_response(&response_bytes);

        assert_eq!(response.response_code(), ResponseCode::Refused);
    }

    #[test]
    fn test_query_under_controlled_domain_a_record_routes_to_send() {
        let config = test_config();
        let clock = MockClock::new();
        let mut store = ChannelStore::new(100, Duration::from_secs(3600), Duration::from_secs(600), clock);

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
        let mut store = ChannelStore::new(100, Duration::from_secs(3600), Duration::from_secs(600), clock);

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
        let mut store = ChannelStore::new(100, Duration::from_secs(3600), Duration::from_secs(600), clock);

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
        let mut store = ChannelStore::new(100, Duration::from_secs(3600), Duration::from_secs(600), clock);

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
        let mut store = ChannelStore::new(100, Duration::from_secs(3600), Duration::from_secs(600), clock);

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
        let mut store = ChannelStore::new(100, Duration::from_secs(3600), Duration::from_secs(600), clock);

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
        let mut store = ChannelStore::new(100, Duration::from_secs(3600), Duration::from_secs(600), clock);

        let query = make_dns_message(
            "abc12345.inbox.broker.example.com.",
            RecordType::TXT,
        );
        let response_bytes = handle_query(&query, &config, &mut store);
        let response = parse_response(&response_bytes);

        assert!(response.authoritative());
    }
}
