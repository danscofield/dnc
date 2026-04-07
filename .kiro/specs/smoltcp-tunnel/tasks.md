# Implementation Plan: smoltcp Tunnel

## Overview

Introduce two new binaries (`smol_client` and `smol_exit`) that replace the hand-rolled TCP reliability layer with smoltcp, a userspace TCP/IP stack. The DNS channel is treated as a lossy datagram link carrying encrypted IP packets between two smoltcp instances. Existing broker, DNS transport, crypto, SOCKS5, guard, and config modules are reused unchanged.

## Tasks

- [x] 1. Add smoltcp dependency and create new module files
  - [x] 1.1 Add `smoltcp = { version = "0.12", features = ["medium-ip", "socket-tcp"], default-features = false }` to `[dependencies]` in `crates/dns-socks-proxy/Cargo.toml`
    - _Requirements: 1.1, 1.2_
  - [x] 1.2 Create `crates/dns-socks-proxy/src/smol_device.rs` with an empty `VirtualDevice` struct and add `pub mod smol_device;` to `lib.rs`
    - _Requirements: 2.1_
  - [x] 1.3 Create `crates/dns-socks-proxy/src/smol_frame.rs` with message type constants (`SMOL_MSG_INIT`, `SMOL_MSG_INIT_ACK`, `SMOL_MSG_TEARDOWN`) and add `pub mod smol_frame;` to `lib.rs`
    - _Requirements: 7.1, 7.2_
  - [x] 1.4 Create `crates/dns-socks-proxy/src/smol_poll.rs` with a placeholder `SmolPollConfig` struct and add `pub mod smol_poll;` to `lib.rs`
    - _Requirements: 9.1_
  - [x] 1.5 Verify existing `socks-client` and `exit-node` binaries still compile with `cargo build --release -p dns-socks-proxy`
    - _Requirements: 1.3, 10.6_

- [x] 2. Implement VirtualDevice
  - [x] 2.1 Implement `VirtualDevice` struct with `rx_queue: VecDeque<Vec<u8>>`, `tx_queue: VecDeque<Vec<u8>>`, and `mtu: usize` fields
    - Implement `new(mtu)`, `inject_rx(packet)`, `drain_tx() -> Vec<Vec<u8>>` methods
    - _Requirements: 2.1, 2.2, 2.3_
  - [x] 2.2 Implement `VirtualRxToken` and `VirtualTxToken` structs that implement smoltcp's `RxToken` and `TxToken` traits
    - `VirtualRxToken` wraps a `Vec<u8>` and passes it to the consume closure
    - `VirtualTxToken` holds a mutable reference to `tx_queue` and pushes the produced buffer
    - _Requirements: 2.1_
  - [x] 2.3 Implement `smoltcp::phy::Device` trait for `VirtualDevice`
    - `capabilities()` returns `Medium::Ip` and `max_transmission_unit = self.mtu`
    - `receive()` pops from `rx_queue`, returns `(RxToken, TxToken)` pair
    - `transmit()` returns a `TxToken` that pushes to `tx_queue`
    - _Requirements: 2.1, 2.2, 2.3, 2.4_
  - [ ]* 2.4 Write property test: VirtualDevice TX preserves packets
    - **Property 1: VirtualDevice TX preserves packets**
    - **Validates: Requirements 2.2**
  - [ ]* 2.5 Write property test: VirtualDevice RX preserves packets
    - **Property 2: VirtualDevice RX preserves packets**
    - **Validates: Requirements 2.3**

- [x] 3. Implement session initiation messages (smol_frame.rs)
  - [x] 3.1 Define `SmolFrameError` enum with variants for too-short, invalid message type, invalid address type, decode failures
    - _Requirements: 7.1, 7.2_
  - [x] 3.2 Implement `encode_init_message` / `decode_init_message` for Init messages
    - Layout: `msg_type(1) | session_id(8) | addr_type(1) | address(var) | port(2) | pubkey(32) | client_id_len(1) | client_id(var)`
    - Reuse `TargetAddr` enum from `socks.rs` for address encoding (IPv4/IPv6/Domain)
    - _Requirements: 7.1, 7.5_
  - [x] 3.3 Implement `encode_init_ack_message` / `decode_init_ack_message` for InitAck messages
    - Layout: `msg_type(1) | session_id(8) | pubkey(32)`
    - _Requirements: 7.2, 7.5_
  - [x] 3.4 Implement `encode_teardown_message` / `decode_teardown_message` for Teardown messages
    - Layout: `msg_type(1) | session_id(8)`
    - _Requirements: 12.5_
  - [x] 3.5 Implement `encrypt_ip_packet` and `decrypt_ip_packet` functions
    - Wire format: `session_id(8) | seq(4, BE) | ChaCha20-Poly1305 ciphertext(IP packet + 16-byte tag)`
    - Reuse existing `encrypt_data` / `decrypt_data` from `crypto.rs` for the encryption, prepend/strip the 12-byte header
    - _Requirements: 8.1, 8.2, 8.4, 8.5_
  - [ ]* 3.6 Write property test: Session message encode/decode round trip
    - **Property 6: Session message encode/decode round trip**
    - **Validates: Requirements 7.1, 7.2**
  - [ ]* 3.7 Write property test: IP packet encryption round trip
    - **Property 7: IP packet encryption round trip**
    - **Validates: Requirements 8.1, 8.2, 8.5**
  - [ ]* 3.8 Write property test: Tampered ciphertext is rejected
    - **Property 8: Tampered ciphertext is rejected**
    - **Validates: Requirements 8.3**
  - [ ]* 3.9 Write property test: Direction and sequence number produce distinct ciphertexts
    - **Property 9: Direction and sequence number produce distinct ciphertexts**
    - **Validates: Requirements 8.4**

- [x] 4. Checkpoint
  - Ensure all tests pass, ask the user if questions arise.

- [x] 5. Implement configuration extensions
  - [x] 5.1 Add `SmolTuningConfig` struct to `crates/dns-socks-proxy/src/config.rs`
    - Fields: `initial_rto: Duration` (default 3000ms), `window_segments: usize` (default 4), `mss: Option<usize>` (default None = auto)
    - _Requirements: 4.1, 4.2, 4.3_
  - [x] 5.2 Add `SmolClientCli` struct with clap derive in `config.rs`
    - Reuse all existing `SocksClientCli` fields (listen addr/port, domain, resolver, client_id, exit_node_id, psk, poll intervals, concurrency, etc.)
    - Add `--smol-rto-ms` (default 3000), `--smol-window-segments` (default 4), `--smol-mss` (optional) flags
    - _Requirements: 4.4, 10.5_
  - [x] 5.3 Add `SmolClientConfig` struct and `SmolClientCli::into_config()` method
    - Include all fields from `SocksClientConfig` plus `smol_tuning: SmolTuningConfig`
    - _Requirements: 4.4, 5.1, 10.5_
  - [x] 5.4 Add `SmolExitCli` struct with clap derive in `config.rs`
    - Reuse all existing `ExitNodeCli` fields (domain, resolver, node_id, psk, mode, broker_config, poll intervals, guard flags, etc.)
    - Add `--smol-rto-ms`, `--smol-window-segments`, `--smol-mss` flags
    - _Requirements: 4.4, 10.5_
  - [x] 5.5 Add `SmolExitConfig` struct and `SmolExitCli::into_config()` method
    - Include all fields from `ExitNodeConfig` plus `smol_tuning: SmolTuningConfig`
    - _Requirements: 4.4, 6.11, 10.5_
  - [ ]* 5.6 Write property test: CLI tuning flags override defaults
    - **Property 5: CLI tuning flags override defaults**
    - **Validates: Requirements 4.4**

- [x] 6. Implement MTU calculation and smoltcp Interface setup helpers
  - [x] 6.1 Add `compute_mtu(dns_payload_budget: usize) -> usize` function to `smol_device.rs`
    - `mtu = dns_payload_budget - 12 (session_id + seq header) - 16 (Poly1305 tag)`
    - Clamp to 0 if budget is too small
    - _Requirements: 2.4, 3.2_
  - [x] 6.2 Add `create_smol_interface` helper function in `smol_poll.rs`
    - Configure `Interface` with `Medium::Ip`, add IP address from `192.168.69.0/24`, add default route through peer IP
    - _Requirements: 3.1, 3.3_
  - [x] 6.3 Add `create_tcp_socket` helper function in `smol_poll.rs`
    - Create TCP socket with `rx_buf = mss * window_segments`, `tx_buf = mss * window_segments`
    - Set timeout (120s) and keep-alive (30s)
    - _Requirements: 4.1, 4.2, 4.3_
  - [ ]* 6.4 Write property test: MTU and MSS are consistent with DNS payload budget
    - **Property 3: MTU and MSS are consistent with DNS payload budget**
    - **Validates: Requirements 2.4, 3.2**
  - [ ]* 6.5 Write property test: TCP buffer sizes are bounded by window configuration
    - **Property 4: TCP buffer sizes are bounded by window configuration**
    - **Validates: Requirements 4.2, 4.3**

- [x] 7. Implement the poll loop (`smol_poll.rs`)
  - [x] 7.1 Define `SmolPollConfig` struct with fields: `poll_active`, `poll_idle`, `backoff_max`, `query_interval`, `no_edns`
    - _Requirements: 9.4_
  - [x] 7.2 Define `PollDirection` enum (`Client` / `Exit`) for encrypt/decrypt direction selection
    - _Requirements: 8.4_
  - [x] 7.3 Implement `run_session_poll_loop` async function
    - Each iteration: (1) poll broker for inbound encrypted packets, (2) decrypt and inject into VirtualDevice RX, (3) call `Interface::poll`, (4) drain VirtualDevice TX, (5) encrypt and send via transport, (6) transfer data between smoltcp TCP socket and local stream, (7) sleep for `min(adaptive_interval, poll_delay_hint)`
    - Use `AdaptiveBackoff` for timing (reuse existing)
    - Respect `Interface::poll_delay` hint as upper bound on next poll interval
    - _Requirements: 9.1, 9.2, 9.3, 9.4, 9.5_

- [x] 8. Checkpoint
  - Ensure all tests pass, ask the user if questions arise.

- [x] 9. Implement smol_client binary
  - [x] 9.1 Create `crates/dns-socks-proxy/src/bin/smol_client.rs` with `main()` function
    - Parse `SmolClientCli`, initialize tracing, bind SOCKS5 TCP listener
    - Create concurrency semaphore (reuse `acquire_permit` pattern from `socks_client.rs`)
    - Create `ControlDispatcher` and spawn control channel poller (reuse pattern from `socks_client.rs`)
    - _Requirements: 5.1, 10.1, 10.2, 11.1, 11.2, 11.3_
  - [x] 9.2 Add `[[bin]] name = "smol-client" path = "src/bin/smol_client.rs"` to `crates/dns-socks-proxy/Cargo.toml`
    - _Requirements: 5.1_
  - [x] 9.3 Implement `handle_smol_connection` function for per-session logic
    - SOCKS5 handshake (reuse `socks::socks5_handshake`)
    - Generate X25519 keypair, send Init message on control channel (with HMAC-SHA256 MAC)
    - Wait for InitAck via `ControlDispatcher` with configurable timeout (default 30s)
    - Derive `SessionKey` using existing `crypto::derive_session_key`
    - Send SOCKS5 success reply
    - _Requirements: 5.2, 5.3, 7.1, 7.3, 7.5, 7.6, 10.1, 10.3_
  - [x] 9.4 Implement per-session smoltcp setup in `handle_smol_connection`
    - Compute MTU from payload budget, create `VirtualDevice`
    - Create smoltcp `Interface` (client IP `192.168.69.1`, gateway `192.168.69.2`)
    - Create TCP socket with tuned buffers, add to interface socket set
    - Call `socket.connect()` to `192.168.69.2:4321`
    - _Requirements: 5.4, 5.5, 5.6, 3.1, 3.3_
  - [x] 9.5 Wire `handle_smol_connection` to call `run_session_poll_loop` with `PollDirection::Client`
    - Split SOCKS5 TCP stream, pass read/write halves to poll loop
    - On poll loop exit: send Teardown on control channel, clean up session resources, release semaphore permit
    - _Requirements: 5.7, 5.8, 5.9, 5.10, 9.1, 11.4, 12.1, 12.3, 12.5_

- [x] 10. Implement smol_exit binary
  - [x] 10.1 Create `crates/dns-socks-proxy/src/bin/smol_exit.rs` with `main()` function
    - Parse `SmolExitCli`, initialize tracing, initialize transport (standalone or embedded, reuse existing pattern from `exit_node.rs`)
    - Poll control channel for Init messages with adaptive backoff
    - Set up graceful shutdown signal handling (reuse pattern from `exit_node.rs`)
    - _Requirements: 6.1, 6.11, 10.2_
  - [x] 10.2 Add `[[bin]] name = "smol-exit" path = "src/bin/smol_exit.rs"` to `crates/dns-socks-proxy/Cargo.toml`
    - _Requirements: 6.1_
  - [x] 10.3 Implement `handle_init` function for per-session logic
    - Decode Init message, verify HMAC-SHA256 MAC
    - Generate X25519 keypair, derive `SessionKey`
    - Resolve target address, check private network guard (reuse `guard::is_blocked`)
    - TCP connect to real target with timeout
    - Send InitAck on client's control channel (with MAC)
    - _Requirements: 6.2, 6.3, 7.2, 7.4, 7.5, 10.3, 10.4_
  - [x] 10.4 Implement per-session smoltcp setup in `handle_init`
    - Compute MTU, create `VirtualDevice`
    - Create smoltcp `Interface` (exit IP `192.168.69.2`, gateway `192.168.69.1`)
    - Create TCP listener socket, bind to `192.168.69.2:4321`
    - _Requirements: 6.4, 6.5, 6.6, 3.1, 3.3_
  - [x] 10.5 Wire `handle_init` to call `run_session_poll_loop` with `PollDirection::Exit`
    - Split real `TcpStream`, pass read/write halves to poll loop
    - On poll loop exit: send Teardown on control channel, close real TCP, clean up session
    - _Requirements: 6.7, 6.8, 6.9, 6.10, 9.1, 12.2, 12.3, 12.4, 12.5_

- [x] 11. Checkpoint
  - Ensure all tests pass, ask the user if questions arise.

- [x] 12. Update Makefile and verify full build
  - [x] 12.1 Add `SMOL_CLIENT` and `SMOL_EXIT` variables to `Makefile`
    - Add `cp` commands for both new binaries in the `COPY_BINS` macro
    - Add `TOUCH_SOURCES` entries for the new binary source files
    - _Requirements: 1.3, 10.6_
  - [x] 12.2 Verify all four binaries compile: `cargo build --release -p dns-socks-proxy`
    - Confirm `socks-client`, `exit-node`, `smol-client`, `smol-exit` all produce binaries
    - _Requirements: 1.3, 10.6_

- [x] 13. Final checkpoint
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- Each task references specific requirements for traceability
- Property tests validate universal correctness properties from the design document
- The existing `socks-client` and `exit-node` binaries remain fully functional and unmodified
- smoltcp handles TCP retransmission, congestion control, and FIN/RST internally — no hand-rolled reliability code needed
