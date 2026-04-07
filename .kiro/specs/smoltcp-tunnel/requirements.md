# Requirements Document

## Introduction

This feature introduces two new binaries (`smol_client` and `smol_exit`) that replace the hand-rolled TCP reliability layer (sliding window, retransmit buffer, reassembly buffer, SYN/ACK/FIN state machine) with smoltcp, a userspace TCP/IP stack. The existing broker, DNS transport, encryption (ChaCha20-Poly1305, X25519), and SOCKS5 handshake code are reused unchanged. smoltcp operates entirely in userspace with no root or TUN device required — the DNS channel is treated as a lossy datagram link that carries raw IP packets between the two smoltcp instances.

## Glossary

- **Smol_Client**: The new SOCKS5 proxy client binary (`smol_client.rs`) that uses smoltcp for TCP reliability instead of the hand-rolled sliding window protocol.
- **Smol_Exit**: The new exit node binary (`smol_exit.rs`) that uses smoltcp for TCP reliability instead of the hand-rolled sliding window protocol.
- **Virtual_Interface**: A smoltcp `Interface` backed by a virtual device that bridges packet I/O to the DNS transport layer rather than a real network device.
- **Virtual_Device**: A smoltcp device implementation that queues outbound IP packets for encryption and DNS transmission, and accepts inbound IP packets from DNS reception and decryption.
- **Broker**: The existing DNS message broker that provides store-and-forward relay via DNS A (send) and TXT (receive) queries.
- **DNS_Transport**: The existing `TransportBackend` trait and its implementations (`DnsTransport`, `DirectTransport`) used to send and receive data through the broker.
- **Session_Key**: The ChaCha20-Poly1305 symmetric key derived from X25519 key exchange and PSK via HKDF-SHA256.
- **MSS**: Maximum Segment Size — the largest amount of TCP payload data smoltcp will place in a single TCP segment.
- **RTO**: Retransmission Timeout — the time smoltcp waits before retransmitting an unacknowledged TCP segment.
- **IP_Packet**: A raw IPv4 packet produced or consumed by smoltcp's `Interface::poll` method.

## Requirements

### Requirement 1: smoltcp Dependency Integration

**User Story:** As a developer, I want smoltcp added as a dependency to the dns-socks-proxy crate, so that the new binaries can use its userspace TCP/IP stack.

#### Acceptance Criteria

1. THE Smol_Client SHALL link against smoltcp with the `medium-ip` and `socket-tcp` features enabled.
2. THE Smol_Exit SHALL link against smoltcp with the `medium-ip` and `socket-tcp` features enabled.
3. THE existing `socks-client` and `exit-node` binaries SHALL remain compilable and unchanged after the smoltcp dependency is added.

### Requirement 2: Virtual Device for DNS-backed Packet I/O

**User Story:** As a developer, I want a virtual smoltcp device that bridges IP packet I/O to the DNS transport layer, so that smoltcp can send and receive packets over the DNS tunnel without a real network interface.

#### Acceptance Criteria

1. THE Virtual_Device SHALL implement the smoltcp `Device` trait using `Medium::Ip` (no Ethernet framing).
2. WHEN smoltcp calls `transmit` on the Virtual_Device, THE Virtual_Device SHALL enqueue the IP_Packet into an outbound buffer for later encryption and DNS transmission.
3. WHEN an encrypted IP_Packet is received from the DNS_Transport and decrypted, THE Virtual_Device SHALL enqueue the IP_Packet into an inbound buffer for smoltcp to consume via `receive`.
4. THE Virtual_Device SHALL report an MTU consistent with the DNS payload budget (frame header + encryption overhead subtracted from the maximum DNS-encodable payload size).

### Requirement 3: Virtual Interface Configuration

**User Story:** As a developer, I want the smoltcp Interface configured with parameters appropriate for the DNS tunnel's high-latency, low-bandwidth, lossy characteristics, so that TCP performs reasonably over DNS.

#### Acceptance Criteria

1. THE Virtual_Interface SHALL be configured with an IP address from a link-local or private range (e.g., 192.168.69.0/24) that does not conflict with real network interfaces.
2. THE Virtual_Interface SHALL use an MSS no larger than the DNS payload budget minus IP and TCP header overhead (targeting approximately 100 bytes of TCP payload).
3. WHEN the Smol_Client or Smol_Exit initializes the Virtual_Interface, THE Virtual_Interface SHALL be configured with a default gateway route so that smoltcp routes all outbound packets through the Virtual_Device.

### Requirement 4: smoltcp Tuning for DNS Link Characteristics

**User Story:** As a developer, I want smoltcp's TCP parameters tuned for the DNS tunnel's multi-second RTT and high loss rate, so that the connection remains stable and does not collapse under aggressive retransmission.

#### Acceptance Criteria

1. THE Virtual_Interface SHALL be configured with an initial RTO of at least 3 seconds to account for multi-second DNS round-trip times.
2. THE Virtual_Interface SHALL use a TCP receive window size no larger than 4 × MSS to limit in-flight data on the slow DNS link.
3. THE Virtual_Interface SHALL use a TCP send buffer size no larger than 4 × MSS to limit in-flight data on the slow DNS link.
4. WHEN the user provides `--smol-rto-ms`, `--smol-window-segments`, or `--smol-mss` CLI flags, THE Smol_Client or Smol_Exit SHALL override the corresponding default tuning parameter with the user-provided value.

### Requirement 5: Smol Client Binary — SOCKS5 Proxy with smoltcp

**User Story:** As a user, I want a new `smol_client` binary that accepts SOCKS5 connections and tunnels TCP traffic through smoltcp over DNS, so that I can use a standards-compliant TCP stack instead of the hand-rolled reliability layer.

#### Acceptance Criteria

1. THE Smol_Client SHALL listen on a configurable local address and port (defaulting to `127.0.0.1:1080`) for incoming SOCKS5 connections.
2. WHEN a SOCKS5 CONNECT request is received, THE Smol_Client SHALL perform the SOCKS5 handshake using the existing `socks::handshake` function.
3. WHEN a SOCKS5 CONNECT request is accepted, THE Smol_Client SHALL perform X25519 key exchange with the Smol_Exit using the existing crypto module and the shared PSK.
4. WHEN a session is established, THE Smol_Client SHALL create a smoltcp TCP socket, bind it to the Virtual_Interface, and connect it to the Smol_Exit's virtual IP address and a designated port.
5. WHEN application data arrives on the SOCKS5 connection, THE Smol_Client SHALL write the data into the smoltcp TCP socket's send buffer.
6. WHEN smoltcp produces outbound IP_Packets via `Interface::poll`, THE Smol_Client SHALL encrypt each IP_Packet using the Session_Key and send it to the upstream broker channel via DNS_Transport.
7. WHEN encrypted IP_Packets arrive from the downstream broker channel, THE Smol_Client SHALL decrypt each IP_Packet and inject it into the Virtual_Device's inbound buffer for smoltcp to process.
8. WHEN the smoltcp TCP socket receives data, THE Smol_Client SHALL forward the data to the SOCKS5 client connection.
9. WHEN the SOCKS5 client closes the connection, THE Smol_Client SHALL close the smoltcp TCP socket, allowing smoltcp to perform a graceful TCP FIN exchange.
10. IF the smoltcp TCP socket enters a closed or reset state, THEN THE Smol_Client SHALL close the SOCKS5 client connection and clean up session resources.

### Requirement 6: Smol Exit Binary — Exit Node with smoltcp

**User Story:** As a user, I want a new `smol_exit` binary that receives tunneled traffic via smoltcp over DNS and forwards it to real TCP targets, so that the exit node uses a standards-compliant TCP stack.

#### Acceptance Criteria

1. THE Smol_Exit SHALL poll the control channel (`ctl-<node_id>`) for incoming session initiation messages.
2. WHEN a session initiation message containing a target address, port, and X25519 public key is received, THE Smol_Exit SHALL perform X25519 key exchange using the existing crypto module and the shared PSK.
3. WHEN a session is established, THE Smol_Exit SHALL open a real `TcpStream` connection to the target address and port (subject to the existing private network guard).
4. WHEN a session is established, THE Smol_Exit SHALL create a smoltcp TCP listener socket on the Virtual_Interface and accept the incoming connection from the Smol_Client's smoltcp instance.
5. WHEN encrypted IP_Packets arrive from the upstream broker channel, THE Smol_Exit SHALL decrypt each IP_Packet and inject it into the Virtual_Device's inbound buffer for smoltcp to process.
6. WHEN smoltcp produces outbound IP_Packets via `Interface::poll`, THE Smol_Exit SHALL encrypt each IP_Packet using the Session_Key and send it to the downstream broker channel via DNS_Transport.
7. WHEN the smoltcp TCP socket receives data, THE Smol_Exit SHALL forward the data to the real TcpStream connected to the target.
8. WHEN data arrives from the real TcpStream, THE Smol_Exit SHALL write the data into the smoltcp TCP socket's send buffer.
9. WHEN the real TcpStream closes (EOF), THE Smol_Exit SHALL close the smoltcp TCP socket, allowing smoltcp to perform a graceful TCP FIN exchange.
10. IF the smoltcp TCP socket enters a closed or reset state, THEN THE Smol_Exit SHALL close the real TcpStream and clean up session resources.
11. THE Smol_Exit SHALL support both `standalone` mode (DNS_Transport to a separate broker) and `embedded` mode (DirectTransport with an in-process broker).

### Requirement 7: Session Initiation Protocol (Lightweight Handshake)

**User Story:** As a developer, I want a lightweight session initiation protocol for the smoltcp binaries that reuses the existing crypto handshake but does not use the old SYN/SYN-ACK/FIN/RST frame types, so that session setup is clean and separate from smoltcp's own TCP state machine.

#### Acceptance Criteria

1. THE Smol_Client SHALL send a session initiation message on the control channel containing the target address, target port, X25519 public key, client ID, and session ID.
2. THE Smol_Exit SHALL respond with a session acceptance message on the control channel containing the Smol_Exit's X25519 public key and the session ID.
3. WHEN the Smol_Client receives the session acceptance message, THE Smol_Client SHALL derive the Session_Key using HKDF-SHA256 with the shared secret and PSK, identical to the existing key derivation.
4. WHEN the Smol_Exit sends the session acceptance message, THE Smol_Exit SHALL derive the Session_Key using HKDF-SHA256 with the shared secret and PSK, identical to the existing key derivation.
5. THE session initiation and acceptance messages SHALL be authenticated with HMAC-SHA256 (truncated to 16 bytes) using the PSK, consistent with the existing control frame authentication.
6. IF the Smol_Client does not receive a session acceptance message within a configurable timeout (default 30 seconds), THEN THE Smol_Client SHALL abort the session and close the SOCKS5 connection with an error.

### Requirement 8: Packet Encryption and Framing

**User Story:** As a developer, I want IP packets produced by smoltcp to be encrypted before DNS transmission and decrypted on receipt, so that tunnel traffic remains confidential and authenticated.

#### Acceptance Criteria

1. WHEN an outbound IP_Packet is dequeued from the Virtual_Device, THE Smol_Client or Smol_Exit SHALL encrypt the IP_Packet using ChaCha20-Poly1305 with the Session_Key.
2. WHEN an encrypted payload is received from the DNS_Transport, THE Smol_Client or Smol_Exit SHALL decrypt the payload using ChaCha20-Poly1305 with the Session_Key.
3. IF decryption fails (authentication tag mismatch), THEN THE Smol_Client or Smol_Exit SHALL discard the packet and log a warning.
4. THE encryption nonce SHALL include a direction byte (0x00 for upstream, 0x01 for downstream) and a monotonically increasing sequence number to prevent nonce reuse.
5. THE encrypted payload SHALL be prefixed with a lightweight header containing the session ID (8 bytes) and the sequence number (4 bytes) so the receiver can identify the session and construct the decryption nonce.

### Requirement 9: Poll Loop Integration

**User Story:** As a developer, I want the smoltcp poll loop integrated with the DNS transport send/receive cycle, so that packets flow between smoltcp and the broker efficiently.

#### Acceptance Criteria

1. THE Smol_Client and Smol_Exit SHALL run a periodic poll loop that calls `Interface::poll` on the Virtual_Interface to process pending smoltcp timers and socket events.
2. WHEN `Interface::poll` produces outbound IP_Packets, THE poll loop SHALL encrypt and transmit each packet via DNS_Transport within the same poll cycle.
3. THE poll loop SHALL poll the broker for inbound messages, decrypt received IP_Packets, inject them into the Virtual_Device, and call `Interface::poll` again to process the new input.
4. THE poll loop SHALL use adaptive timing: polling at a faster rate (configurable, default 50ms) when data is flowing, and backing off to a slower rate (configurable, default 500ms) when idle.
5. WHEN `Interface::poll_delay` returns a delay hint, THE poll loop SHALL respect the hint as an upper bound on the next poll interval to ensure smoltcp timers fire on time.

### Requirement 10: Reuse of Existing Infrastructure

**User Story:** As a developer, I want the new smoltcp binaries to reuse the existing broker, DNS transport, encryption, SOCKS5 handshake, private network guard, and configuration modules, so that code duplication is minimized.

#### Acceptance Criteria

1. THE Smol_Client SHALL use the existing `socks::handshake` function for SOCKS5 negotiation.
2. THE Smol_Client and Smol_Exit SHALL use the existing `TransportBackend` trait and its implementations (`DnsTransport`, `DirectTransport`) for all broker communication.
3. THE Smol_Client and Smol_Exit SHALL use the existing `crypto` module for key exchange, key derivation, encryption, decryption, and HMAC authentication.
4. THE Smol_Exit SHALL use the existing `guard` module to enforce private network blocking on outbound connections.
5. THE Smol_Client and Smol_Exit SHALL accept the same broker-related CLI flags as the existing binaries (domain, resolver, PSK, node/client IDs) plus additional smoltcp-specific tuning flags.
6. THE existing `socks-client` and `exit-node` binaries SHALL remain fully functional and unmodified.

### Requirement 11: Concurrent Session Support

**User Story:** As a user, I want the smol_client to handle multiple concurrent SOCKS5 connections, so that I can use multiple applications through the proxy simultaneously.

#### Acceptance Criteria

1. THE Smol_Client SHALL support multiple concurrent SOCKS5 sessions, each with its own smoltcp TCP socket, session key, and broker channel pair.
2. THE Smol_Client SHALL enforce a configurable maximum number of concurrent sessions (default 8) using a semaphore-based limiter.
3. WHEN the maximum concurrent session limit is reached, THE Smol_Client SHALL queue incoming connections with a configurable timeout (default 30 seconds) before rejecting them.
4. WHEN a session terminates, THE Smol_Client SHALL release the semaphore permit and clean up all associated resources (smoltcp socket, broker channels, session key).

### Requirement 12: Graceful and Abrupt Session Teardown

**User Story:** As a developer, I want sessions to be torn down cleanly when either side closes the connection, so that resources are freed and the peer is notified.

#### Acceptance Criteria

1. WHEN the SOCKS5 client closes the connection, THE Smol_Client SHALL close the smoltcp TCP socket, which triggers smoltcp's standard TCP FIN handshake over the DNS link.
2. WHEN the real TcpStream on the Smol_Exit closes (EOF or error), THE Smol_Exit SHALL close the smoltcp TCP socket, which triggers smoltcp's standard TCP FIN handshake over the DNS link.
3. WHEN smoltcp completes the FIN handshake on either side, THE Smol_Client or Smol_Exit SHALL clean up the session (remove channels, release resources).
4. IF smoltcp's TCP connection times out (no response after maximum retransmissions), THEN THE Smol_Client or Smol_Exit SHALL clean up the session and close any associated real connections.
5. WHEN a session is cleaned up, THE Smol_Client or Smol_Exit SHALL send a session teardown notification on the control channel so the peer can clean up promptly without waiting for TCP timeout.
