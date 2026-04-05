# Implementation Plan: DNS Message Broker

## Overview

Incremental implementation of the DNS Message Broker daemon in Rust. Each task builds on the previous, starting with core data types and encoding, then storage, query handling, DNS wire format, and finally the daemon event loop. Property-based tests use `proptest` with 100 iterations per property.

## Tasks

- [x] 1. Set up project structure and dependencies
  - Initialize a Rust binary crate with `cargo init`
  - Add dependencies: `hickory-dns` (or `trust-dns`), `tokio`, `data-encoding` (base32), `toml`, `serde`, `proptest` (dev), `clap`, `tracing`, `tracing-subscriber`
  - Create module files: `config.rs`, `encoding.rs`, `store.rs`, `handler.rs`, `dns.rs`, `server.rs`
  - Define shared error types (`ConfigError`, `DecodeError`, `StoreError`, `DnsError`)
  - _Requirements: 6.1, 7.1_

- [ ] 2. Implement base32 and envelope encoding (`encoding` module)
  - [x] 2.1 Implement `base32_encode` and `base32_decode` (RFC 4648, lowercase, no padding)
    - Use `data-encoding` crate or hand-roll per spec
    - _Requirements: 5.2_

  - [ ]* 2.2 Write property test: base32 round-trip
    - **Property 1: Base32 round-trip**
    - For any byte sequence, `base32_decode(base32_encode(input)) == input`
    - **Validates: Requirements 5.2**

  - [x] 2.3 Implement `encode_envelope` and `decode_envelope`
    - Pipe-delimited format: `<sender_id>|<sequence>|<timestamp>|<base32_payload>`
    - _Requirements: 3.2, 5.3_

  - [ ]* 2.4 Write property test: envelope encoding round-trip
    - **Property 2: Envelope encoding round-trip**
    - For any valid StoredMessage, `decode_envelope(encode_envelope(msg))` produces equivalent components
    - **Validates: Requirements 5.3**

  - [ ]* 2.5 Write property test: envelope contains all required fields
    - **Property 16: Envelope contains all required fields**
    - For any StoredMessage, the encoded envelope contains sender_id, sequence, timestamp, and base32 payload as pipe-delimited fields
    - **Validates: Requirements 3.2**

  - [x] 2.6 Implement `decode_send_query` to extract sender_id, channel, and payload from query labels
    - Strip nonce (leftmost label), identify channel and sender_id by position relative to controlled domain, concatenate remaining labels as base32 payload
    - _Requirements: 5.1, 5.4, 9.4, 9.7_

  - [ ]* 2.7 Write unit tests for `decode_send_query`
    - Test known query names with expected extracted components
    - Test nonce stripping, multi-label payloads, edge cases
    - _Requirements: 5.1, 5.4, 9.4_

- [ ] 3. Implement configuration (`config` module)
  - [x] 3.1 Define `Config` struct with serde derives and implement `parse_config` / `print_config`
    - All fields from design: listen_addr, listen_port, controlled_domain, channel_inactivity_timeout, max_messages_per_channel, message_ttl, expiry_interval, log_level, ack_ip, error IPs
    - Document and apply default values for all optional fields
    - Validate required field `controlled_domain`
    - _Requirements: 7.1, 7.2, 7.3, 7.4, 7.5, 7.6_

  - [ ]* 3.2 Write property test: configuration round-trip
    - **Property 3: Configuration round-trip**
    - For any valid Config, `parse_config(print_config(config))` produces an equivalent Config
    - **Validates: Requirements 7.7**

  - [ ]* 3.3 Write property test: default configuration values
    - **Property 12: Default configuration values**
    - For any TOML string specifying only `controlled_domain`, parsing produces a Config with all defaults matching documented values
    - **Validates: Requirements 7.3**

  - [ ]* 3.4 Write unit tests for config parsing
    - Test valid TOML with all fields, minimal TOML, invalid TOML, missing required field
    - _Requirements: 7.3, 7.4_

- [x] 4. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 5. Implement channel store (`store` module)
  - [x] 5.1 Define `ChannelStore`, `Channel`, and `StoredMessage` structs
    - Implement `ChannelStore::new`, `push`, `pop`, `sweep_expired`
    - `push`: auto-create channel, assign monotonic sequence number and timestamp, enforce max messages per channel, compute expiry
    - `pop`: return oldest message from channel, remove it (FIFO)
    - `sweep_expired`: remove messages past expiry, remove channels past inactivity timeout
    - Introduce a `Clock` trait for injectable time (real clock + mock clock for tests)
    - _Requirements: 2.1, 2.5, 3.1, 3.4, 4.1, 4.2, 4.3, 8.1, 8.2_

  - [ ]* 5.2 Write property test: monotonically increasing sequence numbers
    - **Property 8: Monotonically increasing sequence numbers**
    - For any sequence of N successful pushes, assigned sequence numbers are strictly increasing
    - **Validates: Requirements 2.5**

  - [ ]* 5.3 Write property test: FIFO pop semantics
    - **Property 9: FIFO pop semantics**
    - For any channel with N messages, successive pops return messages in insertion order, and each popped message is not returned again
    - **Validates: Requirements 3.1, 3.4**

  - [ ]* 5.4 Write property test: channel full enforcement
    - **Property 11: Channel full enforcement**
    - For any channel at max capacity, an additional push fails with the correct error and channel contents are unchanged
    - **Validates: Requirements 4.3, 4.4**

  - [ ]* 5.5 Write property test: expiry sweep removes expired messages
    - **Property 14: Expiry sweep removes expired messages**
    - Using mock clock, after advancing past expiry times, sweep removes expired messages and preserves non-expired ones
    - **Validates: Requirements 8.1, 8.2**

  - [ ]* 5.6 Write property test: inactivity timeout removes channels
    - **Property 15: Inactivity timeout removes channels**
    - Using mock clock, after advancing past inactivity timeout with no activity, sweep removes the channel
    - **Validates: Requirements 4.2**

  - [ ]* 5.7 Write unit tests for channel store
    - Test auto-creation of channels, empty channel pop returns None, push/pop basic flow
    - _Requirements: 4.1, 3.3_

- [x] 6. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 7. Implement DNS layer (`dns` module)
  - [x] 7.1 Implement `parse_dns_query` to decode raw UDP bytes into a `DnsMessage` struct
    - Use `hickory-dns` (or `trust-dns`) for parsing RFC 1035 messages
    - Return `DnsError` for malformed packets
    - _Requirements: 1.4, 1.5_

  - [x] 7.2 Implement `build_response` to construct DNS response bytes
    - Support A records (for send ack/errors), TXT records (for receive), and error rcodes (REFUSED, FORMERR, NXDOMAIN, NOERROR)
    - Set TTL to 0 on all answer records
    - Set AA flag for responses to queries under controlled domain
    - _Requirements: 1.2, 3.5, 9.1_

  - [ ]* 7.3 Write property test: TTL zero on all responses
    - **Property 10: TTL zero on all responses**
    - For any DNS response with answer records, every record's TTL is 0
    - **Validates: Requirements 3.5, 9.1**

  - [ ]* 7.4 Write unit tests for DNS parsing and response building
    - Test malformed packet → FORMERR, known good packet parses correctly, response wire format
    - _Requirements: 1.4, 1.5_

- [ ] 8. Implement query router and handlers (`handler` module)
  - [x] 8.1 Implement `handle_query` routing logic
    - Check if query name is under controlled domain → REFUSED if not
    - Route A/AAAA queries to send handler, TXT queries to receive handler
    - Return FORMERR for malformed queries
    - Return NXDOMAIN for unparseable query structure
    - _Requirements: 1.2, 1.3, 1.5, 5.5_

  - [x] 8.2 Implement send handler
    - Strip nonce, call `decode_send_query`, store message via `ChannelStore::push`
    - Return A record with ack_ip on success, error IPs on failure (payload too large, channel full)
    - _Requirements: 2.1, 2.2, 2.3, 2.4, 4.4_

  - [x] 8.3 Implement receive handler
    - Strip nonce, identify channel, call `ChannelStore::pop`
    - If message available: encode envelope, return TXT record with TTL 0
    - If no message: return NOERROR with zero answers
    - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5_

  - [ ]* 8.4 Write property test: authoritative answer for controlled domain
    - **Property 5: Authoritative answer for controlled domain**
    - For any query under the controlled domain, the response has the AA flag set
    - **Validates: Requirements 1.2**

  - [ ]* 8.5 Write property test: REFUSED for queries outside controlled domain
    - **Property 6: REFUSED for queries outside controlled domain**
    - For any query not under the controlled domain, the response has rcode REFUSED
    - **Validates: Requirements 1.3**

  - [ ]* 8.6 Write property test: send stores message and returns acknowledgment
    - **Property 7: Send stores message and returns acknowledgment**
    - For any valid send query (within budget, channel not full), the message is stored and response contains ack_ip
    - **Validates: Requirements 2.1, 2.3**

  - [ ]* 8.7 Write property test: nonce label invariants
    - **Property 13: Nonce label invariants**
    - For any generated nonce label, it is at least 8 chars and entirely alphanumeric
    - **Validates: Requirements 9.2, 9.3**

  - [ ]* 8.8 Write unit tests for handler error cases
    - Test outside domain → REFUSED, malformed → FORMERR, bad structure → NXDOMAIN, oversized payload → error IP, full channel → error IP, empty channel → NOERROR with zero answers
    - _Requirements: 1.3, 1.5, 2.4, 4.4, 3.3, 5.5_

- [x] 9. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 10. Implement full message round-trip property test
  - [ ]* 10.1 Write property test: full message round-trip
    - **Property 4: Full message round-trip**
    - For any valid payload, sender_id, and channel within budget: encode as send query → parse and store → pop → encode envelope → decode envelope → payload matches original
    - **Validates: Requirements 5.6**

- [ ] 11. Implement daemon and server loop (`server` module + `main`)
  - [x] 11.1 Implement async UDP server loop
    - Bind to configured address/port using `tokio::net::UdpSocket`
    - Receive UDP packets, call `parse_dns_query`, route through `handle_query`, send response
    - Wrap `ChannelStore` in `Arc<RwLock<...>>` for shared access
    - _Requirements: 1.1, 6.2_

  - [x] 11.2 Implement expiry sweeper task
    - Spawn a tokio task that calls `sweep_expired` at the configured interval
    - _Requirements: 8.3_

  - [x] 11.3 Implement graceful shutdown
    - Handle SIGTERM/SIGINT via `tokio::signal`
    - Stop accepting new packets, finish in-flight query, exit within 5 seconds
    - _Requirements: 6.3_

  - [x] 11.4 Implement CLI entry point (`main.rs`)
    - Parse config file path from CLI args using `clap`
    - Load and parse config, set up logging with `tracing`, call `run`
    - Log error and exit non-zero on config/bind failures
    - _Requirements: 6.1, 6.4, 6.5, 7.4_

- [x] 12. Final checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- Each task references specific requirements for traceability
- Property-based tests use `proptest` with 100 iterations per property
- Time-dependent tests (Properties 14, 15) use a `Clock` trait with mock injection
- Checkpoints ensure incremental validation throughout implementation
