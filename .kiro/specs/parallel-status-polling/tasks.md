# Implementation Plan: Parallel Status Polling

## Overview

Bottom-up implementation of the two-phase poll cycle: status query → parallel data retrieval. We start with pure encoding functions, add broker-side queue inspection and routing, extend the transport trait, build the adaptive backoff and parallel fetch logic, add configuration, and finally wire everything into the socks-client and exit-node poll loops.

## Tasks

- [x] 1. Implement Status IP encoding and decoding
  - [x] 1.1 Add `encode_status_ip` and `decode_status_ip` functions in `crates/dns-socks-proxy/src/transport.rs`
    - `encode_status_ip(depth: usize) -> Ipv4Addr`: first octet `128`, lower 24 bits = depth clamped to `0x00FF_FFFF`
    - `decode_status_ip(ip: Ipv4Addr) -> Result<usize, TransportError>`: returns `Ok(0)` for `0.0.0.0`, `Ok(depth)` for `128.x.x.x`, `Err` otherwise
    - _Requirements: 2.1, 2.2, 2.4, 2.5, 2.6_

  - [ ]* 1.2 Write property test for Status IP round-trip (Property 1)
    - **Property 1: Status IP encoding round-trip**
    - For all `depth` in `0..=16_777_215`, `decode_status_ip(encode_status_ip(depth)) == Ok(depth)`
    - **Validates: Requirements 2.1, 2.2, 2.3**

  - [ ]* 1.3 Write property test for non-status IP rejection (Property 2)
    - **Property 2: Non-status IPs are rejected by the decoder**
    - For all `Ipv4Addr` where octet 0 ≠ 128 and addr ≠ `0.0.0.0`, `decode_status_ip` returns `Err`
    - **Validates: Requirements 2.6**

  - [ ]* 1.4 Write unit tests for encoding edge cases
    - `encode_status_ip(0)` → `128.0.0.0`
    - `encode_status_ip(1)` → `128.0.0.1`
    - `encode_status_ip(16_777_215)` → `128.255.255.255`
    - `encode_status_ip(16_777_216)` → `128.255.255.255` (clamped)
    - `decode_status_ip(0.0.0.0)` → `Ok(0)`
    - `decode_status_ip(1.2.3.4)` → `Err` (existing ACK IP)
    - _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5, 2.6_

- [x] 2. Implement `ChannelStore::queue_depth` on the Broker
  - [x] 2.1 Add `queue_depth(&self, channel: &str) -> usize` method to `ChannelStore<C>` in `src/store.rs`
    - Takes `&self` (not `&mut self`) — read-only, no write lock needed
    - Returns `messages.len()` for existing channels, `0` for non-existent channels
    - _Requirements: 7.1, 7.2, 7.3_

  - [ ]* 2.2 Write unit tests for `queue_depth`
    - Non-existent channel returns 0
    - Channel with N pushed messages returns N
    - After pop, depth decreases
    - _Requirements: 7.1, 7.2_

- [x] 3. Implement Broker status query routing and handler
  - [x] 3.1 Add `is_status_query` detection and `handle_status` function in `src/handler.rs`
    - Detect `status` label in position immediately before the channel label in the remaining labels after stripping the controlled domain
    - `handle_status` takes `&ChannelStore<C>` (immutable), calls `queue_depth`, encodes result via `encode_status_ip` (imported from `dns-socks-proxy` or re-implemented inline), returns A record with TTL 0
    - For empty/non-existent channels, return A record with `0.0.0.0`
    - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 6.1, 6.3_

  - [x] 3.2 Update `handle_query` router in `src/handler.rs` to route status queries
    - For A/AAAA queries: check if it's a status query first; if yes, route to `handle_status`; otherwise route to existing `handle_send`
    - Non-status A queries must continue to work unchanged
    - _Requirements: 6.1, 6.2_

  - [x] 3.3 Update `process_packet` in `src/server.rs` to use read lock for status queries
    - Status queries only need `store.read().await` instead of `store.write().await`
    - Send/receive queries continue using write lock
    - _Requirements: 1.5, 7.3_

  - [ ]* 3.4 Write property test for status query routing (Property 3)
    - **Property 3: Status query routing — status label routes to status handler**
    - For all valid channel names and nonces, an A query `<nonce>.status.<channel>.<domain>` routes to status handler
    - **Validates: Requirements 1.1, 6.1**

  - [ ]* 3.5 Write property test for non-status A queries (Property 4)
    - **Property 4: Non-status A queries still route to send handler**
    - For all valid A queries without `status` label, the send handler is invoked
    - **Validates: Requirements 6.2**

  - [ ]* 3.6 Write property test for correct queue depth in status response (Property 5)
    - **Property 5: Status query returns correct queue depth**
    - Push N messages, issue status query, verify encoded depth == N
    - **Validates: Requirements 1.2, 7.1**

  - [ ]* 3.7 Write property test for read-only status queries (Property 6)
    - **Property 6: Status queries are read-only**
    - Push N messages, issue status query, verify queue_depth unchanged
    - **Validates: Requirements 1.5**

  - [ ]* 3.8 Write property test for TTL zero (Property 7)
    - **Property 7: Status response TTL is always zero**
    - For all status queries, verify TTL == 0 in the A record response
    - **Validates: Requirements 1.6**

  - [ ]* 3.9 Write unit tests for status handler edge cases
    - Status query for empty channel returns `0.0.0.0`
    - Status query for non-existent channel returns `0.0.0.0`
    - Status query outside controlled domain returns REFUSED
    - _Requirements: 1.3, 6.3_

- [x] 4. Checkpoint — Ensure all broker-side tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 5. Extend `TransportBackend` trait with `query_status`
  - [x] 5.1 Add `query_status(&self, channel: &str) -> Result<usize, TransportError>` to the `TransportBackend` trait in `crates/dns-socks-proxy/src/transport.rs`
    - _Requirements: 8.1, 8.4_

  - [x] 5.2 Implement `query_status` for `DnsTransport`
    - Build DNS name `<nonce>.status.<channel>.<domain>`, send A query, parse A record, call `decode_status_ip`
    - Add `build_status_query_name` helper method
    - _Requirements: 3.1, 8.2_

  - [x] 5.3 Implement `query_status` for `DirectTransport`
    - Call `store.read().await.queue_depth(channel)` directly
    - _Requirements: 8.3_

  - [ ]* 5.4 Write property test for status query name format (Property 8)
    - **Property 8: Status query name format**
    - For all channel names and domains, the constructed name matches `<4-char-nonce>.status.<channel>.<domain>`
    - **Validates: Requirements 3.1**

  - [ ]* 5.5 Write property test for DirectTransport query_status (Property 14)
    - **Property 14: DirectTransport query_status matches store queue_depth**
    - For all channel states, `DirectTransport::query_status(channel)` == `store.queue_depth(channel)`
    - **Validates: Requirements 8.3**

- [x] 6. Implement `AdaptiveBackoff` struct
  - [x] 6.1 Add `AdaptiveBackoff` struct in `crates/dns-socks-proxy/src/transport.rs` (or a new `backoff.rs` module)
    - Fields: `current: Duration`, `min: Duration`, `max: Duration`
    - Methods: `new(min, max)`, `increase()` (double, clamp to max), `reset()` (set to min), `current()` (return current)
    - Clamp `max` to `min` if `max < min`
    - _Requirements: 5.1, 5.2, 5.3, 5.5_

  - [ ]* 6.2 Write property test for exponential backoff (Property 12)
    - **Property 12: Exponential backoff doubles on idle and clamps to max**
    - For all K consecutive idle cycles, interval == `min(poll_active × 2^K, backoff_max)`
    - **Validates: Requirements 5.1, 5.2, 5.5**

  - [ ]* 6.3 Write property test for backoff reset (Property 13)
    - **Property 13: Backoff resets to poll_active on data detection**
    - For all backoff states, after reset, interval == min
    - **Validates: Requirements 5.3**

  - [ ]* 6.4 Write unit tests for AdaptiveBackoff
    - `new(50ms, 500ms)` starts at 50ms
    - After 1 idle → 100ms, 2 → 200ms, 3 → 400ms, 4 → 500ms (clamped)
    - Reset returns to 50ms
    - `new(100ms, 50ms)` clamps max to 100ms
    - _Requirements: 5.1, 5.2, 5.3, 5.5_

- [x] 7. Add configuration parameters
  - [x] 7.1 Add `--max-parallel-queries` and `--backoff-max-ms` CLI args to `SocksClientCli` and `ExitNodeCli` in `crates/dns-socks-proxy/src/config.rs`
    - `max_parallel_queries: usize` (default 8)
    - `backoff_max_ms: Option<u64>` (defaults to `poll_idle_ms`)
    - Add corresponding fields to `SocksClientConfig` and `ExitNodeConfig`
    - Clamp `max_parallel_queries` to minimum 1
    - _Requirements: 10.1, 10.2, 10.3_

  - [ ]* 7.2 Write unit tests for new config fields
    - Default values: `max_parallel_queries` = 8, `backoff_max` = `poll_idle`
    - Custom values propagate correctly
    - `max_parallel_queries = 0` is clamped to 1
    - _Requirements: 10.1, 10.2, 10.3_

- [x] 8. Implement parallel data retrieval function
  - [x] 8.1 Add `recv_frames_parallel` function in `crates/dns-socks-proxy/src/transport.rs`
    - Accepts `resolver_addr`, `controlled_domain`, `channel`, `count`, `query_timeout`
    - Binds `count` ephemeral UDP sockets, sends TXT queries with unique nonces concurrently via `tokio::spawn` / `join_all`
    - Collects results, skips failed/timed-out queries, flattens frame batches
    - Closes sockets after use
    - _Requirements: 4.1, 4.2, 4.3, 4.4, 4.5, 4.6, 4.7, 9.1, 9.2, 9.3_

  - [ ]* 8.2 Write property test for parallel query count (Property 9)
    - **Property 9: Parallel query count equals min(depth, max_parallel)**
    - For all (depth, max_parallel) pairs, computed count == `min(depth, max_parallel)`
    - **Validates: Requirements 3.4, 4.1, 4.7, 10.3**

  - [ ]* 8.3 Write property test for unique nonces (Property 10)
    - **Property 10: Parallel queries use unique nonces**
    - For all N ≥ 2 parallel queries, every nonce is distinct
    - **Validates: Requirements 4.2**

  - [ ]* 8.4 Write property test for partial failure (Property 11)
    - **Property 11: Partial parallel query failure preserves successful results**
    - For all success/failure masks, returned frames == exactly the successful frames
    - **Validates: Requirements 4.6**

- [x] 9. Checkpoint — Ensure all transport and backoff tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 10. Update socks-client downstream task to use status + parallel polling
  - [x] 10.1 Refactor `downstream_task` in `crates/dns-socks-proxy/src/bin/socks_client.rs`
    - Replace the existing `idle_count`-based adaptive polling with `AdaptiveBackoff`
    - At the start of each poll cycle: call `transport.query_status(downstream_channel)`
    - If depth == 0: call `backoff.increase()`, sleep `backoff.current()`, continue
    - If depth > 0: call `backoff.reset()`, fire `min(depth, max_parallel_queries)` parallel data queries via `recv_frames_parallel`
    - On status query failure: fall back to single `recv_frames` call
    - After processing frames, immediately re-poll status (no sleep) if data was received
    - Feed all received frames into the existing decryption/reassembly/ACK pipeline
    - _Requirements: 3.2, 3.3, 3.4, 3.5, 4.5, 5.1, 5.2, 5.3, 5.4_

- [x] 11. Update exit-node upstream task to use status + parallel polling
  - [x] 11.1 Refactor `upstream_task` in `crates/dns-socks-proxy/src/bin/exit_node.rs`
    - Same pattern as socks-client downstream: `AdaptiveBackoff` + status query + parallel fetch
    - Replace `idle_count`-based polling with `AdaptiveBackoff`
    - Call `transport.query_status(upstream_channel)` at the start of each cycle
    - Fire parallel data queries when depth > 0
    - Fall back to single `recv_frames` on status query failure
    - _Requirements: 3.2, 3.3, 3.4, 3.5, 4.5, 5.1, 5.2, 5.3, 5.4_

  - [x] 11.2 Update exit-node control channel polling to use `AdaptiveBackoff`
    - Replace the `idle_count`-based polling in the main control loop with `AdaptiveBackoff`
    - _Requirements: 5.1, 5.2, 5.3_

- [x] 12. Final checkpoint — Ensure all tests pass and integration is complete
  - Run `cargo test --workspace` to verify all unit and property tests pass
  - Verify no regressions in existing send/receive handler tests
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- Each task references specific requirements for traceability
- Checkpoints ensure incremental validation
- Property tests validate universal correctness properties from the design document
- The status IP encoding functions live in `dns-socks-proxy` but the broker handler needs to produce the same encoding — either import from `dns-socks-proxy` (since the broker crate is already a dependency) or implement a minimal inline version in the broker's handler
- The `process_packet` change (task 3.3) requires distinguishing status queries before acquiring the lock, which may require parsing the query first with a read lock, then upgrading to write only for send/receive
