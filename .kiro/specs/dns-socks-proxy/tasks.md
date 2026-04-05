# Implementation Plan: DNS SOCKS Proxy

## Overview

Incremental implementation of the `socks-client` and `exit-node` binaries as new crates in the workspace. Tasks build bottom-up: shared library modules first (frame, crypto, reliability, transport), then the two binaries that wire everything together. The existing `dns-message-broker` crate is used as a path dependency for encoding utilities and ChannelStore access.

## Tasks

- [x] 1. Set up workspace structure and shared crate
  - [x] 1.1 Convert the repository to a Cargo workspace
    - Add a top-level `[workspace]` to `Cargo.toml` with members: the existing broker crate (move to `crates/dns-message-broker` or use `.` as a member) and a new `crates/dns-socks-proxy` shared library crate
    - Create `crates/dns-socks-proxy/Cargo.toml` with dependencies: `dns-message-broker` (path), `tokio`, `clap`, `x25519-dalek`, `chacha20poly1305`, `hkdf`, `sha2`, `hmac`, `rand`, `tracing`, `tracing-subscriber`, `thiserror`, `async-trait`, `data-encoding`
    - Add `proptest` as a dev-dependency
    - Create `crates/dns-socks-proxy/src/lib.rs` declaring modules: `frame`, `crypto`, `reliability`, `transport`, `session`, `socks`, `config`
    - _Requirements: 5.6, 13.7_

  - [x] 1.2 Create binary crate stubs for `socks-client` and `exit-node`
    - Add `[[bin]]` entries in `crates/dns-socks-proxy/Cargo.toml` for `socks-client` (src/bin/socks_client.rs) and `exit-node` (src/bin/exit_node.rs)
    - Create minimal `main()` stubs that parse CLI args and print a placeholder message
    - _Requirements: 7.1, 8.1_

- [x] 2. Implement frame protocol module
  - [x] 2.1 Implement `frame` module: types, encoder, and decoder
    - Define `FrameType` enum (`Data=0x01`, `Ack=0x02`, `Syn=0x03`, `SynAck=0x04`, `Fin=0x05`, `Rst=0x06`)
    - Define `FrameFlags(u8)`, `SessionId([u8; 8])`, and `Frame` struct
    - Implement `encode_frame(frame: &Frame) -> Vec<u8>` per the 15-byte header wire format
    - Implement `decode_frame(data: &[u8]) -> Result<Frame, FrameError>` with validation for minimum length and valid FrameType
    - Implement `SessionId::generate()` using `rand` (8 random alphanumeric chars)
    - Implement `SessionId::as_str()` returning the ASCII string
    - _Requirements: 3.1, 3.2, 3.3, 3.6, 3.7, 11.1, 11.2, 11.4, 2.1, 9.2_

  - [x] 2.2 Implement SYN frame target address encoding/decoding
    - Implement `encode_syn_payload(target: &ConnectRequest, pubkey: &[u8; 32]) -> Vec<u8>` encoding addr_type + address + port + x25519 pubkey
    - Implement `decode_syn_payload(data: &[u8]) -> Result<(TargetAddr, u16, [u8; 32]), FrameError>` parsing the SYN payload
    - Handle IPv4 (`0x01`), domain (`0x03` with length prefix), IPv6 (`0x04`) address types
    - _Requirements: 3.5, 12.2_

  - [ ]* 2.3 Write property test for frame encoding round-trip
    - **Property 5: Frame encoding round-trip**
    - **Validates: Requirements 3.8, 11.3**

  - [ ]* 2.4 Write property test for SYN frame target address round-trip
    - **Property 6: SYN frame target address round-trip**
    - **Validates: Requirements 3.5**

  - [ ]* 2.5 Write property test for Session_ID format and uniqueness
    - **Property 3: Session_ID format and uniqueness**
    - **Validates: Requirements 2.1, 9.2**

- [x] 3. Implement crypto module
  - [x] 3.1 Implement `crypto` module: PSK, key exchange, encryption, and HMAC
    - Define `Psk` struct with `from_bytes(bytes: Vec<u8>) -> Result<Self, CryptoError>` enforcing ≥32 byte minimum
    - Implement `Psk::from_file(path: &Path)` reading raw bytes from a file
    - Define `SessionKey` struct with `data_key: [u8; 32]` and `control_key: [u8; 32]`
    - Define `Direction` enum (`Upstream`, `Downstream`)
    - Implement `generate_keypair() -> (EphemeralSecret, PublicKey)` using `x25519_dalek`
    - Implement `derive_session_key(shared_secret: &[u8], psk: &Psk) -> SessionKey` using HKDF-SHA256 with info `"dns-socks-v1"`, extracting 64 bytes (first 32 = data_key, next 32 = control_key)
    - Implement `encrypt_data(key, seq, direction, plaintext) -> Vec<u8>` using ChaCha20-Poly1305 with nonce = `[direction_byte, 0, 0, 0, seq_be(4), 0, 0, 0, 0]`
    - Implement `decrypt_data(key, seq, direction, ciphertext) -> Result<Vec<u8>, CryptoError>`
    - Implement `compute_control_mac(psk, frame_bytes) -> [u8; 16]` using HMAC-SHA256 truncated to 16 bytes
    - Implement `verify_control_mac(psk, frame_bytes, mac) -> bool` with constant-time comparison
    - _Requirements: 12.1, 12.2, 12.3, 12.4, 12.5, 12.6, 12.7, 12.8, 12.9, 12.10, 12.11_

  - [ ]* 3.2 Write property test for PSK minimum length enforcement
    - **Property 21: PSK minimum length enforcement**
    - **Validates: Requirements 12.11**

  - [ ]* 3.3 Write property test for key derivation determinism
    - **Property 18: Key derivation determinism**
    - **Validates: Requirements 12.4**

  - [ ]* 3.4 Write property test for encryption round-trip
    - **Property 19: Encryption round-trip**
    - **Validates: Requirements 12.5**

  - [ ]* 3.5 Write property test for HMAC compute/verify round-trip
    - **Property 20: HMAC compute/verify round-trip**
    - **Validates: Requirements 12.9**

- [x] 4. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 5. Implement reliability module
  - [x] 5.1 Implement `RetransmitBuffer`
    - Define `RetransmitBuffer` with `BTreeMap<u32, RetransmitEntry>`, configurable `window_size`, `max_retransmits`, and `rto`
    - Implement `insert(seq, frame)` to queue a frame for retransmission tracking
    - Implement `acknowledge(ack_seq) -> usize` to remove all entries with seq ≤ ack_seq (cumulative ACK)
    - Implement `get_retransmittable(now) -> Vec<&Frame>` returning frames past RTO
    - Implement `is_window_full() -> bool` checking unacknowledged count ≥ window_size
    - Implement `has_exceeded_max_retransmits() -> Option<u32>` returning the seq of the first frame exceeding the limit
    - _Requirements: 4.4, 4.5, 4.7, 4.8_

  - [x] 5.2 Implement `ReassemblyBuffer`
    - Define `ReassemblyBuffer` with `BTreeMap<u32, Vec<u8>>`, `next_expected: u32`, configurable `max_buffer_size`
    - Implement `insert(seq, payload) -> bool` returning false for duplicates (already buffered or already drained)
    - Implement `drain_contiguous() -> Vec<u8>` draining payloads from `next_expected` onward, updating `next_expected`
    - Implement `ack_seq() -> u32` returning the highest contiguous seq received (next_expected - 1, or 0 if none)
    - Implement `is_overflowed() -> bool` checking buffer size > max_buffer_size
    - _Requirements: 4.2, 4.3, 4.6, 6.3, 6.4, 6.5_

  - [ ]* 5.3 Write property test for reassembly buffer delivers in order
    - **Property 8: Reassembly buffer delivers in order**
    - **Validates: Requirements 4.2**

  - [ ]* 5.4 Write property test for ACK sequence equals highest contiguous
    - **Property 9: ACK sequence equals highest contiguous**
    - **Validates: Requirements 4.3**

  - [ ]* 5.5 Write property test for retransmission triggers past RTO
    - **Property 10: Retransmission triggers past RTO**
    - **Validates: Requirements 4.4**

  - [ ]* 5.6 Write property test for duplicate frame detection
    - **Property 11: Duplicate frame detection**
    - **Validates: Requirements 4.6**

  - [ ]* 5.7 Write property test for window full enforcement
    - **Property 12: Window full enforcement**
    - **Validates: Requirements 4.7**

  - [ ]* 5.8 Write property test for reassembly buffer overflow detection
    - **Property 15: Reassembly buffer overflow detection**
    - **Validates: Requirements 6.4**

  - [ ]* 5.9 Write property test for monotonically increasing sequence numbers
    - **Property 7: Monotonically increasing sequence numbers**
    - **Validates: Requirements 4.1**

  - [ ]* 5.10 Write property test for fragmentation and reassembly round-trip
    - **Property 14: Fragmentation and reassembly round-trip**
    - **Validates: Requirements 6.1, 6.2**

- [x] 6. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 7. Implement transport backend module
  - [x] 7.1 Define `TransportBackend` trait and implement `DnsTransport`
    - Define the `TransportBackend` async trait with `send_frame(channel, sender_id, frame_bytes)` and `recv_frame(channel) -> Option<Vec<u8>>`
    - Implement `DnsTransport` struct holding `resolver_addr: SocketAddr`, `controlled_domain: String`, `socket: UdpSocket`
    - `send_frame`: encode frame_bytes as base32, build DNS A query name (`<nonce>.<payload_labels>.<sender_id>.<channel>.<domain>`), send UDP, check response for ack/error IPs
    - `recv_frame`: build DNS TXT query name (`<nonce>.<channel>.<domain>`), send UDP, parse TXT response, decode envelope, return payload bytes
    - Handle DNS query timeout with up to 3 retries
    - Handle channel-full error IP with configurable backoff
    - _Requirements: 5.1, 5.2, 5.3, 5.4, 5.6, 10.1, 10.2_

  - [x] 7.2 Implement `DirectTransport` for embedded mode
    - Implement `DirectTransport` struct holding `store: SharedStore` and `sender_id: String`
    - `send_frame`: acquire write lock, call `store.push(channel, sender_id, frame_bytes)`
    - `recv_frame`: acquire write lock, call `store.pop(channel)`, return payload bytes
    - _Requirements: 13.3, 13.7_

  - [ ]* 7.3 Write property test for transport backend equivalence
    - **Property 22: Transport backend equivalence**
    - **Validates: Requirements 13.6**

  - [x] 7.4 Implement payload budget calculation utility
    - Implement `compute_payload_budget(domain_len, sender_id_len, channel_len, nonce_len) -> usize` computing effective DATA payload budget: `floor((253 - overhead) * 5 / 8) - 15 (header) - 16 (encryption tag)`
    - Ensure result is non-negative (clamp to 0)
    - _Requirements: 5.7, 12.8_

  - [ ]* 7.5 Write property test for payload budget computation
    - **Property 13: Payload budget computation**
    - **Validates: Requirements 5.7**

  - [ ]* 7.6 Write property test for channel naming convention and DNS label fit
    - **Property 16: Channel naming convention and DNS label fit**
    - **Validates: Requirements 9.1, 9.3**

- [x] 8. Implement SOCKS5 listener module
  - [x] 8.1 Implement `socks` module: handshake and CONNECT parsing
    - Define `TargetAddr` enum (Ipv4, Ipv6, Domain) and `ConnectRequest` struct
    - Implement `socks5_handshake(stream) -> Result<ConnectRequest, SocksError>`:
      - Read version byte, verify `0x05`
      - Read method count and methods, select NO AUTH (`0x00`) or reject with `0xFF`
      - Read CONNECT request: verify command `0x01`, parse address type + address + port
      - For non-CONNECT commands, reply `0x07` and return error
    - Implement `socks5_reply(stream, reply_code, bind_addr)` sending the SOCKS5 reply
    - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7_

  - [ ]* 8.2 Write property test for SOCKS5 CONNECT request round-trip
    - **Property 1: SOCKS5 CONNECT request round-trip**
    - **Validates: Requirements 1.3**

  - [ ]* 8.3 Write property test for non-CONNECT commands rejected
    - **Property 2: Non-CONNECT commands rejected**
    - **Validates: Requirements 1.4**

- [x] 9. Implement session manager module
  - [x] 9.1 Implement `session` module: SessionManager and Session lifecycle
    - Define `SessionState` enum (`SynSent`, `Established`, `FinSent`, `Closed`)
    - Define `Session` struct with id, state, target, channel names, tx_seq, rx_next, session_key, retransmit_buf, reassembly_buf
    - Implement `SessionManager` with `HashMap<SessionId, Session>`, `max_sessions: usize` (default 64)
    - Implement `create_session(target) -> Result<&mut Session, SessionError>` generating SessionId, initializing channels (`u-<id>`, `d-<id>`), setting state to `SynSent`
    - Implement `get_session(id)`, `remove_session(id)`, `active_count()`
    - _Requirements: 2.1, 2.6, 2.7, 2.8, 2.9, 2.10, 9.1_

  - [ ]* 9.2 Write property test for session cleanup releases resources
    - **Property 4: Session cleanup releases resources**
    - **Validates: Requirements 2.10**

  - [ ]* 9.3 Write property test for session isolation
    - **Property 17: Session isolation**
    - **Validates: Requirements 10.4**

- [x] 10. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 11. Implement configuration for both binaries
  - [x] 11.1 Implement `config` module: CLI parsing for socks-client and exit-node
    - Define `SocksClientConfig` struct with all fields from design (listen_addr, listen_port, controlled_domain, resolver_addr, client_id, psk, rto, max_retransmits, window_size, poll_active, poll_idle) with documented defaults
    - Define `ExitNodeConfig` struct with all fields (controlled_domain, resolver_addr, node_id, psk, mode, broker_config_path, rto, max_retransmits, window_size, poll_active, poll_idle, connect_timeout) with documented defaults
    - Define `DeploymentMode` enum (`Standalone`, `Embedded`)
    - Use `clap` derive macros for CLI argument parsing
    - Validate PSK length at parse time (reject < 32 bytes)
    - Validate that `--broker-config` is provided when mode is `embedded`
    - Validate that `--resolver` is provided when mode is `standalone`
    - _Requirements: 7.1, 7.2, 7.3, 7.4, 7.5, 8.1, 8.2, 8.3, 12.1, 12.11, 13.1, 13.5_

- [x] 12. Implement socks-client binary
  - [x] 12.1 Implement socks-client main loop and session orchestration
    - Parse CLI args into `SocksClientConfig`
    - Bind TCP listener on configured address/port
    - Initialize `DnsTransport` with resolver address and controlled domain
    - Initialize `SessionManager`
    - For each incoming TCP connection, spawn an async task:
      - Perform SOCKS5 handshake
      - Create session in SessionManager
      - Generate X25519 keypair, build SYN frame with target + pubkey + HMAC, send on control channel
      - Poll control channel for SYN-ACK, extract Exit Node pubkey, derive SessionKey
      - Send SOCKS5 success reply
      - Spawn upstream task: read TCP → fragment → encrypt → send DATA frames
      - Spawn downstream task: poll downstream channel → decrypt → reassemble → write TCP
      - Spawn retransmit timer task: check RetransmitBuffer, retransmit past-RTO frames
      - Handle FIN/RST for session teardown
    - Implement adaptive polling: short interval (poll_active) when data flowing, back off to poll_idle when idle
    - Handle session setup timeout (no SYN-ACK within connect_timeout) → SOCKS5 error reply
    - _Requirements: 1.1, 1.6, 1.7, 2.2, 2.3, 2.4, 2.6, 2.7, 2.8, 2.9, 4.1, 4.4, 4.7, 4.8, 5.1, 5.2, 5.5, 5.7, 6.1, 10.3, 10.4, 10.5, 12.2, 12.5_

  - [x] 12.2 Implement graceful error handling in socks-client
    - DNS query timeout → retry up to 3 times
    - Channel-full error → back off and retry
    - Local TCP socket close → send FIN, clean up session
    - Unrecoverable session error → send RST, clean up, continue accepting new connections
    - Max retransmissions exceeded → send RST, close session
    - Reassembly buffer overflow → send RST, close session
    - _Requirements: 10.1, 10.2, 10.3, 10.4, 10.5_

- [x] 13. Implement exit-node binary
  - [x] 13.1 Implement exit-node main loop and session handling
    - Parse CLI args into `ExitNodeConfig`
    - Based on mode:
      - Standalone: initialize `DnsTransport` with resolver address
      - Embedded: load Broker TOML config, create `ChannelStore` in-process, wrap in `SharedStore`, start Broker DNS server loop and expiry sweeper sharing the same store, initialize `DirectTransport`
    - Poll control channel (`ctl-<node_id>`) for incoming SYN frames
    - On SYN received:
      - Decode target address and SOCKS Client X25519 pubkey from SYN payload
      - Verify HMAC on SYN frame
      - Generate X25519 keypair, compute shared secret, derive SessionKey
      - Attempt TCP connection to target host within connect_timeout
      - On success: send SYN-ACK with Exit Node pubkey + HMAC on control channel, create session
      - On failure: send RST with error reason on control channel
    - For each established session:
      - Spawn upstream task: poll upstream channel → decrypt → reassemble → write to target TCP socket
      - Spawn downstream task: read target TCP → fragment → encrypt → send DATA frames on downstream channel
      - Spawn retransmit timer task
      - Handle FIN/RST for session teardown
    - Implement adaptive polling strategy
    - _Requirements: 2.3, 2.4, 2.5, 2.6, 2.7, 2.8, 4.1, 4.4, 5.3, 5.4, 5.5, 6.2, 8.4, 12.3, 12.4, 12.6, 12.9, 12.10, 13.1, 13.2, 13.3, 13.4, 13.5_

  - [x] 13.2 Implement embedded mode: Broker in-process with DNS server
    - Load Broker config from `--broker-config` TOML file
    - Create `ChannelStore` with Broker config parameters
    - Start Broker's `run_server_loop` in a spawned task sharing the `SharedStore`
    - Start Broker's `spawn_expiry_sweeper` task sharing the same store
    - Use `DirectTransport` wrapping the shared store for Exit Node's own frame operations
    - _Requirements: 13.3, 13.4, 13.5, 13.8_

  - [x] 13.3 Implement graceful shutdown for exit-node
    - Handle SIGTERM/SIGINT signals
    - Send FIN frames for all active sessions
    - Shut down within 10 seconds
    - Log session lifecycle events at info level, frame activity at debug level
    - _Requirements: 8.5, 8.6_

- [x] 14. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 15. Integration wiring and final validation
  - [x] 15.1 Wire end-to-end: socks-client ↔ Broker ↔ exit-node
    - Verify that the socks-client can send a SYN through DnsTransport, the exit-node receives it, completes the handshake, and bidirectional DATA frames flow correctly
    - Ensure channel naming convention is consistent between both binaries
    - Verify encryption/decryption works end-to-end (same PSK, derived keys match)
    - Verify FIN/RST teardown works from both sides
    - _Requirements: 2.2, 2.3, 2.4, 2.6, 2.7, 5.1, 5.3, 9.1, 9.4, 12.2, 12.3_

  - [ ]* 15.2 Write integration tests for end-to-end tunnel flow
    - Test: SYN → SYN-ACK → DATA exchange → FIN using DirectTransport (in-process, no real DNS)
    - Test: Multiple concurrent sessions through the same Broker store
    - Test: Session abort via RST
    - _Requirements: 2.9, 10.4_

- [x] 16. Final checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- Each task references specific requirements for traceability
- Checkpoints ensure incremental validation
- Property tests validate universal correctness properties from the design document (22 properties total)
- Unit tests validate specific examples and edge cases
- The `dns-message-broker` crate is used as a path dependency — no modifications to the Broker
- All property-based tests use `proptest` with 100 iterations minimum
