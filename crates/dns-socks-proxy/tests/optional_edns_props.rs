// Property-based tests for optional EDNS0 behavior in build_dns_query.
//
// [Feature: optional-edns, Property 1: EDNS0 OPT record presence is determined by record type and use_edns flag]
// **Validates: Requirements 3.2, 3.3, 4.1, 4.2**

use dns_socks_proxy::transport::DnsTransport;
use hickory_proto::op::Message;
use hickory_proto::rr::{Name, RecordType};
use proptest::prelude::*;

/// Strategy for generating a valid DNS label (1-10 alphanumeric chars).
fn dns_label_strategy() -> impl Strategy<Value = String> {
    prop::string::string_regex("[a-z0-9]{1,10}").unwrap()
}

/// Strategy for generating a valid DNS name with 1-3 labels.
fn dns_name_strategy() -> impl Strategy<Value = Name> {
    prop::collection::vec(dns_label_strategy(), 1..=3).prop_map(|labels| {
        let joined = labels.join(".");
        Name::from_ascii(&format!("{}.", joined)).unwrap()
    })
}

/// Strategy for generating either A or TXT record type.
fn record_type_strategy() -> impl Strategy<Value = RecordType> {
    prop_oneof![Just(RecordType::A), Just(RecordType::TXT)]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// Property 1: EDNS0 OPT record presence is determined by record type and use_edns flag.
    ///
    /// For any valid DNS name, record type in {A, TXT}, and boolean use_edns:
    /// - OPT record is present ⟺ record_type == TXT && use_edns == true
    /// - When present, max_payload == 1232
    #[test]
    fn edns0_opt_record_presence(
        name in dns_name_strategy(),
        record_type in record_type_strategy(),
        use_edns in any::<bool>(),
    ) {
        let query_bytes = DnsTransport::build_dns_query(&name, record_type, use_edns)
            .expect("build_dns_query should succeed for valid inputs");

        let parsed = Message::from_vec(&query_bytes)
            .expect("query bytes should parse back into a valid Message");

        let expect_opt = record_type == RecordType::TXT && use_edns;

        if expect_opt {
            let edns = parsed.extensions().as_ref().expect("OPT record should be present when TXT + use_edns");
            prop_assert_eq!(
                edns.max_payload(),
                1232,
                "max_payload must be 1232 when OPT is present"
            );
        } else {
            prop_assert!(
                parsed.extensions().is_none(),
                "OPT record should be absent when record_type={:?} and use_edns={}",
                record_type,
                use_edns,
            );
        }
    }
}
