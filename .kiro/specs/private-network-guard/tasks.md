# Implementation Plan: Private Network Guard

## Overview

Add a CIDR-based address guard to the exit node that blocks outbound TCP connections to private, loopback, link-local, and other sensitive network ranges. Implementation adds a `guard` module with a pure `is_blocked` function, extends CLI/config with two new flags, and inserts the guard check in `handle_syn` between `resolve_target` and `TcpStream::connect`.

## Tasks

- [x] 1. Create `guard.rs` module with core guard logic
  - [x] 1.1 Add `ipnet = "2"` to `[dependencies]` in `crates/dns-socks-proxy/Cargo.toml`
    - _Requirements: 1.1_
  - [x] 1.2 Create `crates/dns-socks-proxy/src/guard.rs` with `default_blocked_ranges()` and `is_blocked()` functions
    - Implement `default_blocked_ranges() -> Vec<IpNet>` returning all 12 hardcoded CIDR ranges (RFC 1918, loopback, link-local, unique local, unspecified, EC2 IMDS)
    - Implement `is_blocked(addr: IpAddr, blocked: &[IpNet]) -> bool` using `blocked.iter().any(|net| net.contains(&addr))`
    - _Requirements: 1.1, 1.2, 1.3, 3.1_
  - [x] 1.3 Add `pub mod guard;` to `crates/dns-socks-proxy/src/lib.rs`
    - _Requirements: 1.1_
  - [x] 1.4 Write inline unit tests in `guard.rs` (`#[cfg(test)]` module)
    - Test `is_blocked` returns true for one address in each of the 12 default ranges
    - Test `is_blocked` returns false for a public address (e.g., `8.8.8.8`) against defaults
    - Test `default_blocked_ranges()` returns exactly 12 entries
    - _Requirements: 1.2, 1.3, 3.1_

- [x] 2. Extend CLI and config with guard flags
  - [x] 2.1 Add `ConfigError::InvalidCidr { value: String, source: ipnet::AddrParseError }` variant to `ConfigError` in `crates/dns-socks-proxy/src/config.rs`
    - _Requirements: 4.4_
  - [x] 2.2 Add `allow_private_networks: bool` and `disallow_networks: Vec<String>` CLI fields to `ExitNodeCli`
    - `--allow-private-networks` as a boolean flag
    - `--disallow-network <CIDR>` as a repeatable string argument
    - _Requirements: 3.2, 4.1_
  - [x] 2.3 Add `blocked_networks: Vec<IpNet>` field to `ExitNodeConfig`
    - _Requirements: 1.1, 4.1, 4.3_
  - [x] 2.4 Update `ExitNodeCli::into_config()` to compute `blocked_networks` from flags
    - If `allow_private_networks` is false, start with `default_blocked_ranges()`; otherwise start with empty vec and log info
    - Parse each `disallow_networks` entry as `IpNet`, return `ConfigError::InvalidCidr` on failure
    - Append parsed custom ranges to the blocked list
    - _Requirements: 3.2, 3.3, 4.1, 4.2, 4.3, 4.4_
  - [x] 2.5 Update `base_exit_cli()` test helper in `config.rs` to include the new fields with default values
    - _Requirements: 3.2, 4.1_
  - [x] 2.6 Write inline unit tests in `config.rs` for the new config logic
    - Test default config (no flags) produces `blocked_networks` equal to `default_blocked_ranges()`
    - Test `allow_private_networks = true` produces empty default list
    - Test `disallow_networks = ["203.0.113.0/24"]` adds the range
    - Test invalid CIDR string `"not-a-cidr"` produces `ConfigError::InvalidCidr`
    - Test both flags together: only custom ranges present
    - _Requirements: 3.1, 3.2, 3.3, 4.1, 4.3, 4.4_

- [x] 3. Checkpoint
  - Ensure all tests pass, ask the user if questions arise.

- [x] 4. Insert guard check in `handle_syn`
  - [x] 4.1 Add `use dns_socks_proxy::guard::is_blocked;` import in `crates/dns-socks-proxy/src/bin/exit_node.rs`
    - _Requirements: 2.1_
  - [x] 4.2 Insert the guard check between `resolve_target` and `TcpStream::connect` in `handle_syn`
    - After `resolve_target` returns `target_socket_addr`, call `is_blocked(target_socket_addr.ip(), &config.blocked_networks)`
    - If blocked: log warning with session ID and address, call `send_rst`, return `Ok(())`
    - If not blocked: proceed to `TcpStream::connect` as normal
    - _Requirements: 2.1, 2.2, 2.3_
  - [x] 4.3 Wrap `config.blocked_networks` in `Arc` alongside the existing `shared_config` so it is available in spawned `handle_syn` tasks
    - Since `ExitNodeConfig` is already wrapped in `Arc<ExitNodeConfig>`, the `blocked_networks` field is accessible through it — verify no additional wrapping is needed
    - _Requirements: 2.1_

- [x] 5. Property-based tests
  - [x] 5.1 Create `crates/dns-socks-proxy/tests/private_network_guard_props.rs`
    - Add `use dns_socks_proxy::guard::{is_blocked, default_blocked_ranges};` and `use proptest::prelude::*;` imports
    - _Requirements: 1.2, 1.3_
  - [x] 5.2 Property 1: Addresses inside any CIDR are blocked
    - Generate random `IpNet` ranges and construct addresses within those ranges (network address + offset within range)
    - Assert `is_blocked(addr, &cidrs)` returns `true`
    - **Property 1: Addresses inside any CIDR are blocked**
    - **Validates: Requirements 1.2**
  - [x] 5.3 Property 2: Addresses outside all CIDRs are allowed
    - Generate random `IpNet` ranges and random `IpAddr` values, filter to those outside all ranges
    - Assert `is_blocked(addr, &cidrs)` returns `false`
    - **Property 2: Addresses outside all CIDRs are allowed**
    - **Validates: Requirements 1.3**
  - [x] 5.4 Property 3: Blocked list computation from flags
    - Generate random `bool` for `allow_private_networks` and random valid CIDR strings for `disallow_networks`
    - Compute blocked list and assert it equals defaults (when not allowed) plus custom, or only custom (when allowed)
    - **Property 3: Blocked list computation from flags**
    - **Validates: Requirements 4.1, 4.3**
  - [x] 5.5 Property 4: Invalid CIDR strings produce parse errors
    - Generate random strings that are not valid CIDR notation
    - Assert that parsing them as `IpNet` fails
    - **Property 4: Invalid CIDR strings produce parse errors**
    - **Validates: Requirements 4.4**

- [x] 6. Final checkpoint
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- Each task references specific requirements for traceability
- Property tests validate universal correctness properties from the design document
- The `ipnet` crate handles all CIDR parsing and containment logic
