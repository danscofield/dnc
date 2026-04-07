use std::net::IpAddr;
use ipnet::IpNet;

/// Returns the default set of blocked CIDR ranges.
pub fn default_blocked_ranges() -> Vec<IpNet> {
    [
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",   // RFC 1918
        "127.0.0.0/8", "::1/128",                            // Loopback
        "169.254.0.0/16", "fe80::/10",                       // Link-local
        "fc00::/7",                                           // Unique local
        "0.0.0.0/8", "::/128",                               // Unspecified
        "169.254.169.254/32",                                 // EC2 IMDS IPv4
        "fd00:ec2::254/128",                                  // EC2 IMDS IPv6
    ]
    .iter()
    .map(|s| s.parse().expect("hardcoded CIDR is valid"))
    .collect()
}

/// Returns true if `addr` falls within any of the provided CIDR ranges.
pub fn is_blocked(addr: IpAddr, blocked: &[IpNet]) -> bool {
    blocked.iter().any(|net| net.contains(&addr))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_blocked_ranges_returns_12_entries() {
        assert_eq!(default_blocked_ranges().len(), 12);
    }

    #[test]
    fn is_blocked_true_for_each_default_range() {
        let ranges = default_blocked_ranges();
        // One representative address per CIDR range (12 total)
        let test_cases: Vec<(&str, &str)> = vec![
            ("10.0.0.1",        "10.0.0.0/8"),
            ("172.16.5.1",      "172.16.0.0/12"),
            ("192.168.1.1",     "192.168.0.0/16"),
            ("127.0.0.1",       "127.0.0.0/8"),
            ("::1",             "::1/128"),
            ("169.254.1.1",     "169.254.0.0/16"),
            ("fe80::1",         "fe80::/10"),
            ("fc00::1",         "fc00::/7"),
            ("0.0.0.1",         "0.0.0.0/8"),
            ("::",              "::/128"),
            ("fd00:ec2::254",   "fd00:ec2::254/128"),
            ("169.254.169.254", "169.254.169.254/32 (EC2 IMDS IPv4)"),
        ];
        assert_eq!(test_cases.len(), 12);
        for (addr_str, range_label) in &test_cases {
            let addr: IpAddr = addr_str.parse().unwrap();
            assert!(is_blocked(addr, &ranges), "{addr} should be blocked by {range_label}");
        }
    }

    #[test]
    fn is_blocked_false_for_public_address() {
        let ranges = default_blocked_ranges();
        let addr: IpAddr = "8.8.8.8".parse().unwrap();
        assert!(!is_blocked(addr, &ranges));
    }
}
