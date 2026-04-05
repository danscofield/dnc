//! DNS protocol layer module.
//!
//! Handles parsing raw DNS queries and building DNS response packets.

use std::net::Ipv4Addr;

use hickory_proto::op::{Message, MessageType, Query, ResponseCode};
use hickory_proto::rr::rdata::{A, TXT};
use hickory_proto::rr::{Name, RData, Record, RecordType};

use crate::error::DnsError;

/// Parsed DNS query information needed by the handler.
#[derive(Debug, Clone)]
pub struct DnsMessage {
    /// The query transaction ID.
    pub query_id: u16,
    /// The domain name being queried.
    pub query_name: Name,
    /// The record type being queried (A, AAAA, TXT, etc.).
    pub query_type: RecordType,
    /// The query name labels as strings for easy processing.
    pub query_name_labels: Vec<String>,
    /// EDNS0 UDP buffer size advertised by the client (0 if no EDNS0).
    pub edns_udp_size: u16,
}

/// Parse raw UDP bytes into a DNS message.
pub fn parse_dns_query(bytes: &[u8]) -> Result<DnsMessage, DnsError> {
    let message = Message::from_vec(bytes)
        .map_err(|e| DnsError::MalformedPacket(e.to_string()))?;

    let query = message
        .queries()
        .first()
        .ok_or_else(|| DnsError::MalformedPacket("no question section in query".into()))?;

    let query_name = query.name().clone();
    let query_type = query.query_type();

    let query_name_labels = query_name
        .iter()
        .map(|label| String::from_utf8_lossy(label).to_string())
        .collect();

    // Extract EDNS0 UDP buffer size from OPT record if present.
    let edns_udp_size = if let Some(edns) = message.extensions() {
        edns.max_payload()
    } else {
        0
    };

    Ok(DnsMessage {
        query_id: message.id(),
        query_name,
        query_type,
        query_name_labels,
        edns_udp_size,
    })
}

/// Build a DNS response with the given rcode and answer records.
///
/// Sets the AA (Authoritative Answer) flag and serializes to wire format bytes.
/// All answer records should have TTL 0 (callers use `a_record` / `txt_record` helpers).
pub fn build_response(
    query_id: u16,
    query_name: &Name,
    query_type: RecordType,
    rcode: ResponseCode,
    answers: Vec<Record>,
) -> Result<Vec<u8>, DnsError> {
    let mut message = Message::new();
    message.set_id(query_id);
    message.set_message_type(MessageType::Response);
    message.set_authoritative(true);
    message.set_response_code(rcode);

    // Echo back the question section
    let query = Query::query(query_name.clone(), query_type);
    message.add_query(query);

    for record in answers {
        message.add_answer(record);
    }

    message
        .to_vec()
        .map_err(|e| DnsError::ResponseBuildError(e.to_string()))
}

/// Create an A record with TTL 0.
pub fn a_record(name: &Name, ip: Ipv4Addr) -> Record {
    Record::from_rdata(name.clone(), 0, RData::A(A(ip)))
}

/// Create a TXT record with TTL 0.
pub fn txt_record(name: &Name, text: &str) -> Record {
    Record::from_rdata(
        name.clone(),
        0,
        RData::TXT(TXT::new(vec![text.to_string()])),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_response_noerror_no_answers() {
        let name = Name::from_ascii("test.broker.example.com.").unwrap();
        let bytes = build_response(
            0x1234,
            &name,
            RecordType::TXT,
            ResponseCode::NoError,
            vec![],
        )
        .unwrap();

        let msg = Message::from_vec(&bytes).unwrap();
        assert_eq!(msg.id(), 0x1234);
        assert_eq!(msg.message_type(), MessageType::Response);
        assert!(msg.authoritative());
        assert_eq!(msg.response_code(), ResponseCode::NoError);
        assert!(msg.answers().is_empty());
    }

    #[test]
    fn test_build_response_with_a_record() {
        let name = Name::from_ascii("test.broker.example.com.").unwrap();
        let ip = Ipv4Addr::new(1, 2, 3, 4);
        let record = a_record(&name, ip);

        let bytes = build_response(
            0xABCD,
            &name,
            RecordType::A,
            ResponseCode::NoError,
            vec![record],
        )
        .unwrap();

        let msg = Message::from_vec(&bytes).unwrap();
        assert_eq!(msg.id(), 0xABCD);
        assert!(msg.authoritative());
        assert_eq!(msg.answers().len(), 1);

        let ans = &msg.answers()[0];
        assert_eq!(ans.ttl(), 0);
        assert_eq!(ans.record_type(), RecordType::A);
        match ans.data() {
            RData::A(a) => assert_eq!(a.0, ip),
            other => panic!("expected A record, got {:?}", other),
        }
    }

    #[test]
    fn test_build_response_with_txt_record() {
        let name = Name::from_ascii("inbox.broker.example.com.").unwrap();
        let text = "alice|42|1718000000|nbswy3dp";
        let record = txt_record(&name, text);

        let bytes = build_response(
            0x5678,
            &name,
            RecordType::TXT,
            ResponseCode::NoError,
            vec![record],
        )
        .unwrap();

        let msg = Message::from_vec(&bytes).unwrap();
        assert_eq!(msg.answers().len(), 1);

        let ans = &msg.answers()[0];
        assert_eq!(ans.ttl(), 0);
        assert_eq!(ans.record_type(), RecordType::TXT);
        match ans.data() {
            RData::TXT(txt) => {
                let data: Vec<String> = txt
                    .iter()
                    .map(|b| String::from_utf8_lossy(b).to_string())
                    .collect();
                assert_eq!(data, vec![text]);
            }
            other => panic!("expected TXT record, got {:?}", other),
        }
    }

    #[test]
    fn test_build_response_refused() {
        let name = Name::from_ascii("other.example.org.").unwrap();
        let bytes = build_response(
            0x0001,
            &name,
            RecordType::A,
            ResponseCode::Refused,
            vec![],
        )
        .unwrap();

        let msg = Message::from_vec(&bytes).unwrap();
        assert_eq!(msg.response_code(), ResponseCode::Refused);
        assert!(msg.authoritative());
        assert!(msg.answers().is_empty());
    }

    #[test]
    fn test_build_response_formerr() {
        let name = Name::from_ascii("bad.example.com.").unwrap();
        let bytes = build_response(
            0x0002,
            &name,
            RecordType::A,
            ResponseCode::FormErr,
            vec![],
        )
        .unwrap();

        let msg = Message::from_vec(&bytes).unwrap();
        assert_eq!(msg.response_code(), ResponseCode::FormErr);
    }

    #[test]
    fn test_build_response_nxdomain() {
        let name = Name::from_ascii("unknown.broker.example.com.").unwrap();
        let bytes = build_response(
            0x0003,
            &name,
            RecordType::A,
            ResponseCode::NXDomain,
            vec![],
        )
        .unwrap();

        let msg = Message::from_vec(&bytes).unwrap();
        assert_eq!(msg.response_code(), ResponseCode::NXDomain);
    }

    #[test]
    fn test_a_record_ttl_zero() {
        let name = Name::from_ascii("test.example.com.").unwrap();
        let record = a_record(&name, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(record.ttl(), 0);
        assert_eq!(record.name(), &name);
    }

    #[test]
    fn test_txt_record_ttl_zero() {
        let name = Name::from_ascii("test.example.com.").unwrap();
        let record = txt_record(&name, "hello world");
        assert_eq!(record.ttl(), 0);
        assert_eq!(record.name(), &name);
    }

    #[test]
    fn test_build_response_echoes_query_section() {
        let name = Name::from_ascii("test.broker.example.com.").unwrap();
        let bytes = build_response(
            0x9999,
            &name,
            RecordType::TXT,
            ResponseCode::NoError,
            vec![],
        )
        .unwrap();

        let msg = Message::from_vec(&bytes).unwrap();
        assert_eq!(msg.queries().len(), 1);
        assert_eq!(msg.queries()[0].name(), &name);
        assert_eq!(msg.queries()[0].query_type(), RecordType::TXT);
    }
}
