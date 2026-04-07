# Implementation Plan: Broker Relay Mode

## Overview

Implement the `dnsrelay` and `dnssocksrelay` binaries with a `RelayStore` data structure, relay handler, relay transport, and CLI configuration. Tasks follow a bottom-up build order: data structures first, then handler, then transport, then binaries, then wiring.

## Tasks

- [x] 1. Implement RelayStore data structure
  - [x] 1.1 Create `src/relay_store.rs` with `PacketSlot`, `RelayChannel`, and `RelayStore<C: Clock>` structs
    - Implement `RelayStore::new(message_ttl, clock)` constructor
    - Implement `write(&self, channel, sender_id, payload) -> u64` with per-channel locking and `AtomicU64` sequence counter
    - Implement `read(&self, channel) -> Vec<PacketSlot>` returning owned clones of non-expired slots
    - Implement `slot_count(&self, channel) -> usize` returning count of non-expired slots
    - Implement `sweep_expired(&self)` removing expired slots and empty channels
    - Use `RwLock<HashMap<String, Arc<RwLock<RelayChannel>>>>` for per-channel locking
    - All methods take `&self` (internal mutability via locks and atomics)
    - Define `pub type SharedRelayStore = Arc<RelayStore<RealClock>>`
    - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 2.1, 2.2, 2.3, 2.4, 2.5, 3.1, 3.2, 3.3, 4.1, 4.2_

  - [ ]* 1.2 Write property test: write-read round-trip (Property 1)
    - **Property 1: Write-read round-trip**
    - For any valid (channel, sender_id, payload), writing then reading returns a result containing the written payload with matching sender_id and valid sequence number
    - **Validates: Requirements 1.7, 15.1, 1.2, 1.3**

  - [ ]* 1.3 Write property test: single-slot invariant under overwrites (Property 2)
    - **Property 2: Single-slot invariant under overwrites**
    - For any channel and sender_id, writing N times results in `slot_count` equal to 1 and read returns only the most recent payload
    - **Validates: Requirements 1.8, 15.2, 1.1, 1.2**

  - [ ]* 1.4 Write property test: slot count equals distinct sender count (Property 3)
    - **Property 3: Slot count equals distinct sender count**
    - For any channel with K distinct sender_ids, `slot_count` equals K and read returns exactly K results
    - **Validates: Requirements 15.3, 2.1, 4.1**

  - [ ]* 1.5 Write property test: non-destructive read (Property 4)
    - **Property 4: Non-destructive read**
    - Calling read twice without intervening writes returns the same set of payloads, sender_ids, and sequence numbers
    - **Validates: Requirements 2.2, 15.5**

  - [ ]* 1.6 Write property test: monotonic sequence numbers (Property 5)
    - **Property 5: Monotonic sequence numbers**
    - For any sequence of N writes (N >= 2), each returned sequence number is strictly greater than the previous
    - **Validates: Requirements 1.6, 15.6, 1.4**

  - [ ]* 1.7 Write property test: expiry removes stale slots (Property 6)
    - **Property 6: Expiry removes stale slots**
    - After `sweep_expired` with time beyond TTL, expired slots no longer appear in read results and slot_count decreases
    - **Validates: Requirements 3.1, 15.4**

- [x] 2. Modify `src/lib.rs` to add relay modules
  - Add `pub mod relay_store;` and `pub mod relay_handler;` to `src/lib.rs`
  - _Requirements: 14.3, 14.4_

- [x] 3. Add `encode_envelope_parts` helper to `src/encoding.rs`
  - [x] 3.1 Add standalone `encode_envelope_parts(sender_id: &str, sequence: u64, timestamp: u64, payload: &[u8]) -> String` function
    - Produces the same `sender_id|sequence|timestamp|base32_payload` format as `encode_envelope`
    - Avoids coupling relay handler to `StoredMessage` type
    - _Requirements: 7.1, 14.4_

- [x] 4. Implement relay handler
  - [x] 4.1 Create `src/relay_handler.rs` with `handle_relay_query` function
    - Define `RelayConfig` struct with `controlled_domain`, `ack_ip`, `error_payload_too_large_ip`, `error_channel_full_ip` fields
    - Route A/AAAA queries to send handler (decode via `encoding::decode_send_query`, write to RelayStore)
    - Route TXT queries to receive handler (read from RelayStore, encode via `encode_envelope_parts`, return TXT records)
    - Route status queries to slot_count (encode as status IP)
    - Return REFUSED for queries outside controlled domain or unsupported record types
    - Ignore cursor suffixes in TXT query nonces
    - Set TTL 0 on all response records
    - _Requirements: 5.3, 5.4, 6.1, 6.2, 6.3, 6.4, 6.5, 7.1, 7.2, 7.3, 7.4_

  - [ ]* 4.2 Write property test: relay handler rejects invalid queries (Property 7)
    - **Property 7: Relay handler rejects invalid queries**
    - For any DNS query outside the controlled domain or with unsupported record type, the handler returns REFUSED
    - **Validates: Requirements 5.3, 5.4**

  - [ ]* 4.3 Write property test: relay handler send-receive round-trip (Property 8)
    - **Property 8: Relay handler send-receive round-trip**
    - For any valid A query that writes a payload, a subsequent TXT query on the same channel returns the payload in standard envelope format
    - **Validates: Requirements 6.1, 6.2**

  - [ ]* 4.4 Write property test: cursor suffix is ignored (Property 9)
    - **Property 9: Cursor suffix is ignored by relay handler**
    - A TXT query with cursor suffix returns the same results as one without
    - **Validates: Requirements 6.5**

- [x] 5. Checkpoint — Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 6. Implement RelayTransport
  - [x] 6.1 Create `crates/dns-socks-proxy/src/relay_transport.rs` with `RelayTransport` struct
    - Implement `TransportBackend` trait for `RelayTransport`
    - `send_frame` writes to RelayStore via `store.write()`
    - `recv_frames` reads from RelayStore via `store.read()`, with per-channel deduplication using `HashMap<String, u64>` tracking last-seen sequence numbers
    - `query_status` returns `store.slot_count()`
    - Ignore `cursor` parameter (relay channels don't use cursors)
    - _Requirements: 8.6, 14.1_

  - [x] 6.2 Add `pub mod relay_transport;` to `crates/dns-socks-proxy/src/lib.rs`
    - _Requirements: 14.1_

- [x] 7. Add CLI configuration structs
  - [x] 7.1 Add `RelayCliArgs` and `RelayConfig` to `crates/dns-socks-proxy/src/config.rs`
    - `--domain`, `--listen` (default `0.0.0.0:53`), `--node-id`, `--psk`/`--psk-file`
    - `--message-ttl-secs` (default 600), `--expiry-interval-secs` (default 30)
    - `--connect-timeout-ms` (default 10000), `--poll-active-ms` (default 50), `--poll-idle-ms` (default 500)
    - `--smol-rto-ms`, `--smol-window-segments`, `--smol-mss`
    - `--allow-private-networks`, `--disallow-network`
    - Implement `into_config()` with validation
    - _Requirements: 11.1, 11.2, 11.3, 11.4, 11.5, 11.6_

  - [x] 7.2 Add `RelaySocksCliArgs` and `RelaySocksConfig` to `crates/dns-socks-proxy/src/config.rs`
    - `--domain`, `--resolver`, `--client-id`, `--exit-node-id`, `--psk`/`--psk-file`
    - `--listen-addr` (default `127.0.0.1`), `--listen-port` (default 1080)
    - `--connect-timeout-ms` (default 30000), `--poll-active-ms`, `--poll-idle-ms`, `--backoff-max-ms`
    - `--smol-rto-ms`, `--smol-window-segments`, `--smol-mss`
    - `--no-edns`, `--query-interval-ms`, `--max-concurrent-sessions`, `--queue-timeout-ms`
    - Implement `into_config()` with validation
    - _Requirements: 12.1, 12.2, 12.3, 12.4_

- [x] 8. Implement dnsrelay binary
  - [x] 8.1 Create `crates/dns-socks-proxy/src/bin/dnsrelay.rs`
    - Parse CLI via `RelayCliArgs`
    - Create `SharedRelayStore` with configured TTL
    - Bind UDP socket on configured listen address
    - Implement DNS listener loop: parse queries via `dns::parse_dns_query`, route via `handle_relay_query`, send responses
    - Spawn expiry sweeper task calling `store.sweep_expired()` at configured interval
    - Spawn control channel poller task reading `ctl-<node_id>` from RelayStore, verifying MAC, decoding Init messages
    - For each Init: spawn session task that performs X25519 key exchange, TCP connect (with private network guard), creates smoltcp interface, writes InitAck to `ctl-<session_id>`, runs `run_session_poll_loop` with `RelayTransport`, sends Teardown on cleanup
    - Handle graceful shutdown via SIGINT/SIGTERM
    - _Requirements: 5.1, 5.2, 8.1, 8.2, 8.3, 8.4, 8.5, 8.6, 8.7, 8.8, 8.9, 9.1, 9.2, 14.1, 14.2, 14.3, 14.7_

- [x] 9. Implement dnssocksrelay binary
  - [x] 9.1 Create `crates/dns-socks-proxy/src/bin/dnssocksrelay.rs`
    - Parse CLI via `RelaySocksCliArgs`
    - Listen for SOCKS5 connections on configured address/port
    - Implement concurrency limiter with semaphore (reuse pattern from `smol_client.rs`)
    - Per-session: SOCKS5 handshake, generate `SessionId`, compute `sender_id = "<client_id>-<session_id>"`
    - Send Init to `ctl-<exit_node_id>` via `DnsTransport`
    - Poll `ctl-<session_id>` via `DnsTransport` for InitAck (with configurable timeout)
    - Derive session key, compute payload budget/MTU/MSS, create smoltcp interface
    - Run `run_session_poll_loop` with `DnsTransport` for data channels
    - Send Teardown on cleanup, close SOCKS5 connection
    - No shared control channel poller or ControlDispatcher needed
    - _Requirements: 10.1, 10.2, 10.3, 10.4, 10.5, 10.6, 10.7, 10.8, 10.9, 10.10, 10.11, 14.1, 14.2, 14.5, 14.6_

- [x] 10. Update Cargo.toml and verify build
  - [x] 10.1 Add `[[bin]]` entries to `crates/dns-socks-proxy/Cargo.toml`
    - Add `dnsrelay` binary entry pointing to `src/bin/dnsrelay.rs`
    - Add `dnssocksrelay` binary entry pointing to `src/bin/dnssocksrelay.rs`
    - _Requirements: 13.1, 13.2, 13.3, 13.4_

- [x] 11. Final checkpoint — Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.
  - Verify that existing tests for traditional broker, socks-client, exit-node, smol-client, and smol-exit still pass unchanged.
  - _Requirements: 13.1, 13.2, 13.3, 13.4_

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- Each task references specific requirements for traceability
- Checkpoints ensure incremental validation
- Property tests validate universal correctness properties from the design document
- The traditional broker and all existing binaries remain completely unchanged (Requirement 13)
