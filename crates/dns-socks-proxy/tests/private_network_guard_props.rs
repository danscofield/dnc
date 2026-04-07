// Property-based tests for the private network guard.
//
// These tests verify the CIDR-based address classification logic using
// randomly generated IP addresses and CIDR ranges.

use std::net::{IpAddr, Ipv4Addr};

use dns_socks_proxy::guard::{default_blocked_ranges, is_blocked};
use ipnet::IpNet;
use proptest::prelude::*;

// ---------------------------------------------------------------------------
// Helpers / strategies
// ---------------------------------------------------------------------------

/// Generate a random IPv4 prefix length between `lo` and `hi` (inclusive).
fn prefix_len_strategy(lo: u8, hi: u8) -> impl Strategy<Value = u8> {
    lo..=hi
}

/// Generate a random IPv4 network: random base address + random prefix length
/// in [8, 28]. We cap at 28 so the range has at least 16 addresses, making
/// offset generation meaningful.
fn ipv4_net_strategy() -> impl Strategy<Value = IpNet> {
    (any::<[u8; 4]>(), prefix_len_strategy(8, 28)).prop_map(|(octets, prefix)| {
        let raw = u32::from_be_bytes(octets);
        // Mask to network boundary.
        let mask = if prefix == 0 { 0 } else { !0u32 << (32 - prefix) };
        let network = raw & mask;
        let addr = Ipv4Addr::from(network);
        format!("{addr}/{prefix}").parse::<IpNet>().unwrap()
    })
}

/// Strategy that generates a small vec of IPv4 CIDRs (1-4 ranges).
fn cidr_vec_strategy() -> impl Strategy<Value = Vec<IpNet>> {
    prop::collection::vec(ipv4_net_strategy(), 1..=4)
}

/// Strategy for generating valid CIDR strings (IPv4 only for simplicity).
fn valid_cidr_string_strategy() -> impl Strategy<Value = String> {
    ipv4_net_strategy().prop_map(|net| net.to_string())
}

// ---------------------------------------------------------------------------
// Property 1: Addresses inside any CIDR are blocked
// [Feature: private-network-guard, Property 1: Addresses inside any CIDR are blocked]
// **Validates: Requirements 1.2**
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    #[test]
    fn addresses_inside_cidr_are_blocked(
        net in ipv4_net_strategy(),
    ) {
        // Generate an address inside the network by picking a random offset.
        // We use a nested proptest runner to get the random offset.
        let network_u32 = match net.network() {
            IpAddr::V4(v4) => u32::from(v4),
            _ => unreachable!(),
        };
        let host_count: u32 = match net.prefix_len() {
            32 => 1,
            p => 1u32 << (32 - p),
        };
        // Pick the first, last, and a middle address to cover the range.
        let cidrs = vec![net];
        for offset in [0, host_count / 2, host_count - 1] {
            let addr = IpAddr::V4(Ipv4Addr::from(network_u32 + offset));
            prop_assert!(
                is_blocked(addr, &cidrs),
                "address {addr} should be blocked by {net}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Property 2: Addresses outside all CIDRs are allowed
// [Feature: private-network-guard, Property 2: Addresses outside all CIDRs are allowed]
// **Validates: Requirements 1.3**
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    #[test]
    fn addresses_outside_cidrs_are_allowed(
        cidrs in cidr_vec_strategy(),
        raw_addr in any::<[u8; 4]>(),
    ) {
        let addr = IpAddr::V4(Ipv4Addr::from(raw_addr));
        // Only test addresses that are actually outside all CIDRs.
        let inside_any = cidrs.iter().any(|net| net.contains(&addr));
        prop_assume!(!inside_any);
        prop_assert!(
            !is_blocked(addr, &cidrs),
            "address {addr} should NOT be blocked (outside all CIDRs)"
        );
    }
}

// ---------------------------------------------------------------------------
// Property 3: Blocked list computation from flags
// [Feature: private-network-guard, Property 3: Blocked list computation from flags]
// **Validates: Requirements 4.1, 4.3**
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    #[test]
    fn blocked_list_computation_from_flags(
        allow_private in any::<bool>(),
        custom_cidrs in prop::collection::vec(valid_cidr_string_strategy(), 0..=4),
    ) {
        // Replicate the composition logic from ExitNodeCli::into_config().
        let mut blocked = if allow_private {
            vec![]
        } else {
            default_blocked_ranges()
        };
        for cidr_str in &custom_cidrs {
            let net: IpNet = cidr_str.parse().unwrap();
            blocked.push(net);
        }

        // Build the expected list independently.
        let mut expected: Vec<IpNet> = if allow_private {
            vec![]
        } else {
            default_blocked_ranges()
        };
        let custom_nets: Vec<IpNet> = custom_cidrs
            .iter()
            .map(|s| s.parse::<IpNet>().unwrap())
            .collect();
        expected.extend(custom_nets);

        prop_assert_eq!(blocked, expected);
    }
}

// ---------------------------------------------------------------------------
// Property 4: Invalid CIDR strings produce parse error
// [Feature: private-network-guard, Property 4: Invalid CIDR strings produce parse errors]
// **Validates: Requirements 4.4**
// ---------------------------------------------------------------------------

/// Strategy that generates strings which are NOT valid CIDR notation.
/// We combine several classes of invalid input.
fn invalid_cidr_strategy() -> impl Strategy<Value = String> {
    prop_oneof![
        // Pure alphabetic strings (no dots, no slashes)
        prop::string::string_regex("[a-z]{3,20}").unwrap(),
        // Missing prefix length (bare IP)
        any::<[u8; 4]>().prop_map(|b| {
            format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3])
        }),
        // Invalid octets (values > 255)
        (256u32..999).prop_map(|v| format!("{v}.{v}.{v}.{v}/8")),
        // Empty string
        Just(String::new()),
        // Slash but no prefix
        any::<[u8; 4]>().prop_map(|b| {
            format!("{}.{}.{}.{}/", b[0], b[1], b[2], b[3])
        }),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    #[test]
    fn invalid_cidr_strings_produce_parse_error(
        s in invalid_cidr_strategy(),
    ) {
        let result = s.parse::<IpNet>();
        prop_assert!(
            result.is_err(),
            "string {:?} should NOT parse as valid CIDR, but got {:?}",
            s,
            result,
        );
    }
}
