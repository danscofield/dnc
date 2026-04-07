# Requirements Document

## Introduction

This feature introduces two new binaries — `dnsrelay` and `dnssocksrelay` — that provide a simplified, single-process deployment model for the smoltcp DNS tunnel. These binaries exist alongside the traditional multi-process deployment (broker + exit-node/smol-exit + socks-client/smol-client) and are designed specifically for the smoltcp tunnel's needs.

In the traditional deployment, the broker is a separate process that stores messages in per-channel FIFO queues (ChannelStore) with replay buffers, adaptive response sizing, and cursor-based advancement. A separate exit node process polls the broker for data. This store-and-forward model adds complexity and latency that is unnecessary when smoltcp already handles TCP reliability, retransmission, ordering, and flow control.

The `dnsrelay` binary combines the DNS listener and the smoltcp exit node into a single process. Instead of using the ChannelStore's FIFO queues, it uses a RelayStore — a per-sender single-slot buffer that overwrites on each write and broadcasts the latest packet to every TXT poll. There is no FIFO ordering, no replay buffer, no cursor tracking, and no adaptive sizing. The smoltcp TCP stack on each end handles all reliability concerns — the relay simply reflects the most recent packet written to a channel.

The `dnssocksrelay` binary is the client-side counterpart. It is a SOCKS5 proxy that tunnels traffic through `dnsrelay` using the same smoltcp tunnel protocol (Init/InitAck/Teardown handshake, encrypted IP packet framing, virtual device). It replaces `smol_client` for relay-mode deployments.

The traditional broker, socks-client, exit-node, smol-client, and smol-exit binaries remain completely unchanged.

## Glossary

- **Dnsrelay**: A new binary that combines a DNS listener, a RelayStore, and the smoltcp exit node logic into a single process. Listens for DNS queries and handles both relay data channels and control channel messages in-process.
- **Dnssocksrelay**: A new SOCKS5 proxy client binary that tunnels TCP traffic over DNS through a Dnsrelay instance using the smoltcp tunnel protocol.
- **Relay_Store**: A data structure that holds at most one packet per (channel, sender_id) pair. Writes overwrite the previous value. Reads return all non-expired slots for a channel without removing them.
- **Packet_Slot**: A single-entry buffer in the Relay_Store keyed by (channel, sender_id), holding the most recently written packet and its metadata.
- **Traditional_Broker**: The existing DNS message broker binary (`src/main.rs`) that uses ChannelStore with FIFO queues, replay buffers, and adaptive response sizing.
- **ChannelStore**: The existing per-channel FIFO message queue system in the Traditional_Broker.
- **Smol_Client**: The existing smoltcp-based SOCKS5 proxy client binary that communicates through the Traditional_Broker.
- **Smol_Exit**: The existing smoltcp-based exit node binary that communicates through the Traditional_Broker.
- **Virtual_Device**: The smoltcp device implementation that bridges IP packet I/O to in-memory queues (reused from the existing smoltcp tunnel).
- **Session_Key**: The ChaCha20-Poly1305 symmetric key derived from X25519 key exchange and PSK via HKDF-SHA256 (reused from the existing tunnel).
- **DNS_Transport**: The existing `TransportBackend` trait and its implementations used for broker communication over DNS.
- **Per_Session_Control_Channel**: A control channel scoped to a single session (e.g., `ctl-<session_id>`), used for sending InitAck and Teardown responses. Each session polls only its own control channel, eliminating the need for shared control channel polling or demultiplexing.

## Requirements

### Requirement 1: RelayStore Data Structure

**User Story:** As a developer, I want a simple single-slot-per-sender data structure for relay channels, so that the Dnsrelay can serve the latest packet without FIFO queue overhead.

#### Acceptance Criteria

1. THE Relay_Store SHALL store packets in Packet_Slots keyed by (channel, sender_id), where each key maps to at most one packet.
2. WHEN a write targets a (channel, sender_id) key that already has a Packet_Slot, THE Relay_Store SHALL overwrite the existing packet with the new packet.
3. WHEN a write targets a (channel, sender_id) key that has no Packet_Slot, THE Relay_Store SHALL create a new Packet_Slot for that key.
4. THE Relay_Store SHALL return a success acknowledgment for every valid write, regardless of whether a previous packet was overwritten.
5. WHEN a packet is written, THE Relay_Store SHALL record the write timestamp for expiry purposes.
6. THE Relay_Store SHALL assign a monotonically increasing sequence number to each packet write.
7. FOR ALL valid (channel, sender_id, payload) inputs, writing then reading the channel SHALL return a result containing the written payload (round-trip property).
8. FOR ALL channels, writing the same (channel, sender_id) key twice SHALL result in `slot_count` remaining unchanged (idempotence of slot count under overwrites).

### Requirement 2: RelayStore Read Semantics

**User Story:** As a developer, I want TXT polls on relay channels to return the latest packet from all senders, so that smoltcp receives the most recent data without queue management.

#### Acceptance Criteria

1. WHEN a read targets a channel, THE Relay_Store SHALL return the Packet_Slot contents from all senders that have a non-expired packet for that channel.
2. THE Relay_Store SHALL NOT remove packets from Packet_Slots after a read (packets persist until overwritten or expired).
3. THE Relay_Store SHALL NOT maintain a replay buffer.
4. THE Relay_Store SHALL NOT use cursor-based advancement.
5. THE Relay_Store SHALL NOT use adaptive response sizing.

### Requirement 3: RelayStore Expiry and Cleanup

**User Story:** As an operator, I want relay channel packets to expire after a configurable TTL, so that stale data does not persist indefinitely.

#### Acceptance Criteria

1. THE Relay_Store SHALL expire Packet_Slots whose write timestamp is older than the configured message TTL.
2. THE Relay_Store SHALL remove empty channels (no remaining Packet_Slots) during the expiry sweep.
3. THE Relay_Store SHALL support a `sweep_expired(now)` method for periodic cleanup.

### Requirement 4: RelayStore Status Query Support

**User Story:** As a developer, I want status queries on relay channels to report the number of active senders, so that monitoring and polling logic works consistently.

#### Acceptance Criteria

1. WHEN a status query targets a channel, THE Relay_Store SHALL return the count of non-expired Packet_Slots for that channel.
2. WHEN a channel has no active Packet_Slots, THE Relay_Store SHALL return 0.

### Requirement 5: Dnsrelay Binary — DNS Listener

**User Story:** As an operator, I want the Dnsrelay to listen for DNS queries on a configurable address and port, so that it can serve as the authoritative DNS server for the tunnel domain.

#### Acceptance Criteria

1. THE Dnsrelay SHALL listen on a configurable UDP address and port (defaulting to `0.0.0.0:53`) for incoming DNS queries.
2. THE Dnsrelay SHALL accept a `controlled_domain` configuration parameter specifying the domain the relay is authoritative for.
3. WHEN a DNS query targets a name outside the controlled domain, THE Dnsrelay SHALL respond with REFUSED.
4. WHEN a DNS query targets an unsupported record type (not A, AAAA, or TXT) under the controlled domain, THE Dnsrelay SHALL respond with REFUSED.

### Requirement 6: Dnsrelay Binary — Query Routing to RelayStore

**User Story:** As a developer, I want the Dnsrelay to route all data channel queries through the RelayStore, so that the smoltcp tunnel operates with single-slot semantics.

#### Acceptance Criteria

1. WHEN an A/AAAA query (send operation) targets a channel under the controlled domain, THE Dnsrelay SHALL decode the payload and write it to the Relay_Store.
2. WHEN a TXT query (receive operation) targets a channel under the controlled domain, THE Dnsrelay SHALL read from the Relay_Store and return all non-expired Packet_Slots as TXT records.
3. WHEN a status query targets a channel under the controlled domain, THE Dnsrelay SHALL return the Relay_Store slot count encoded as a status IP.
4. THE Dnsrelay SHALL use the same DNS query name format as the Traditional_Broker (`<nonce>.<payload_labels>.<sender_id>.<channel>.<domain>` for sends, `<nonce>.<channel>.<domain>` for receives, `<nonce>.status.<channel>.<domain>` for status).
5. WHEN a TXT query nonce includes a cursor suffix (`-c<N>`), THE Dnsrelay SHALL ignore the cursor value (relay channels do not use cursor advancement).

### Requirement 7: Dnsrelay Binary — Response Format Compatibility

**User Story:** As a developer, I want the Dnsrelay to use the same DNS response envelope format as the Traditional_Broker, so that existing transport code (DnsTransport) works without modification.

#### Acceptance Criteria

1. THE Dnsrelay SHALL encode TXT responses using the same pipe-delimited envelope format (`sender_id|sequence|timestamp|base32_payload`) as the Traditional_Broker.
2. THE Dnsrelay SHALL return A records with the same well-known IPs as the Traditional_Broker (`1.2.3.4` for ACK, `1.2.3.5` for payload too large, `1.2.3.6` for channel full).
3. THE Dnsrelay SHALL return status query responses using the same IP encoding as the Traditional_Broker (`0.0.0.0` for empty, `128.x.y.z` for depth).
4. THE Dnsrelay SHALL set TTL 0 on all response records.

### Requirement 8: Dnsrelay Binary — Integrated smoltcp Exit Node

**User Story:** As an operator, I want the Dnsrelay to handle smoltcp tunnel sessions directly without a separate exit node process, so that the relay deployment is a single binary.

#### Acceptance Criteria

1. THE Dnsrelay SHALL poll the control channel (`ctl-<node_id>`) from its own Relay_Store for incoming Init messages from clients.
2. WHEN an Init message is received, THE Dnsrelay SHALL extract the `client_id` and `session_id` from the Init payload.
3. WHEN an Init message is received, THE Dnsrelay SHALL perform X25519 key exchange using the existing crypto module and the shared PSK.
4. WHEN a session is established, THE Dnsrelay SHALL open a real TCP connection to the target address and port (subject to the private network guard).
5. WHEN a session is established, THE Dnsrelay SHALL create a smoltcp Virtual_Device, Interface, and TCP listener socket, and run the poll loop to bridge the smoltcp tunnel to the real TCP connection.
6. THE Dnsrelay SHALL read and write session data channels (`u-<session_id>`, `d-<session_id>`) directly from the in-process Relay_Store, bypassing DNS transport entirely.
7. THE Dnsrelay SHALL send InitAck and Teardown messages by writing directly to the Relay_Store on the Per_Session_Control_Channel (`ctl-<session_id>`) rather than a shared client control channel.
8. THE Dnsrelay SHALL support configurable smoltcp tuning parameters (`--smol-rto-ms`, `--smol-window-segments`, `--smol-mss`).
9. THE Dnsrelay SHALL support the existing private network guard (`--allow-private-networks`, `--disallow-network`) for outbound TCP connections.

### Requirement 9: Dnsrelay Binary — Expiry Sweeper

**User Story:** As an operator, I want the Dnsrelay to periodically clean up expired relay data, so that stale packets and inactive channels do not accumulate.

#### Acceptance Criteria

1. THE Dnsrelay SHALL run a periodic expiry sweeper task that calls `sweep_expired` on the Relay_Store.
2. THE Dnsrelay SHALL accept a configurable expiry sweep interval (defaulting to 30 seconds).

### Requirement 10: Dnssocksrelay Binary — SOCKS5 Proxy Client

**User Story:** As a user, I want a SOCKS5 proxy client that tunnels TCP traffic through a Dnsrelay instance, so that I can use the simplified relay deployment model.

#### Acceptance Criteria

1. THE Dnssocksrelay SHALL listen on a configurable local address and port (defaulting to `127.0.0.1:1080`) for incoming SOCKS5 connections.
2. WHEN a SOCKS5 CONNECT request is received, THE Dnssocksrelay SHALL perform the SOCKS5 handshake using the existing `socks::handshake` function.
3. WHEN a SOCKS5 CONNECT request is accepted, THE Dnssocksrelay SHALL generate a unique sender_id for the session (e.g., `<client_id>-<session_id>`).
4. WHEN a SOCKS5 CONNECT request is accepted, THE Dnssocksrelay SHALL send an Init message (containing the `client_id` and `session_id`) to the Dnsrelay's control channel (`ctl-<exit_node_id>`) via DNS_Transport.
5. WHEN waiting for an InitAck, THE Dnssocksrelay SHALL poll its own Per_Session_Control_Channel (`ctl-<session_id>`) for the InitAck or Teardown response.
6. WHEN an InitAck is received on the Per_Session_Control_Channel, THE Dnssocksrelay SHALL derive the Session_Key and create a smoltcp Virtual_Device, Interface, and TCP socket.
7. THE Dnssocksrelay SHALL run the smoltcp poll loop to bridge the local SOCKS5 connection to the Dnsrelay via encrypted IP packets over DNS.
8. THE Dnssocksrelay SHALL use the existing `DnsTransport` to communicate with the Dnsrelay (the Dnsrelay is the DNS resolver from the client's perspective).
9. THE Dnssocksrelay SHALL reuse the existing smoltcp tunnel protocol: Init/InitAck/Teardown handshake, encrypted IP packet framing, virtual device, and poll loop.
10. IF the Dnssocksrelay does not receive an InitAck on the Per_Session_Control_Channel within a configurable timeout (default 30 seconds), THEN THE Dnssocksrelay SHALL abort the session and close the SOCKS5 connection with an error.
11. THE Dnssocksrelay SHALL NOT require a shared control channel poller or control dispatcher — each session independently polls its own Per_Session_Control_Channel.

### Requirement 11: Dnsrelay Configuration

**User Story:** As an operator, I want the Dnsrelay to accept configuration via CLI flags, so that I can customize its behavior for my deployment.

#### Acceptance Criteria

1. THE Dnsrelay SHALL accept `--domain` (controlled domain), `--listen` (bind address, default `0.0.0.0:53`), `--node-id` (node identifier), and `--psk`/`--psk-file` (pre-shared key) as required CLI parameters.
2. THE Dnsrelay SHALL accept `--message-ttl-secs` (default 600) to configure the Relay_Store packet expiry TTL.
3. THE Dnsrelay SHALL accept `--expiry-interval-secs` (default 30) to configure the expiry sweep interval.
4. THE Dnsrelay SHALL accept `--connect-timeout-ms` (default 10000) to configure the TCP connect timeout for target connections.
5. THE Dnsrelay SHALL accept smoltcp tuning flags (`--smol-rto-ms`, `--smol-window-segments`, `--smol-mss`) consistent with the existing Smol_Exit binary.
6. THE Dnsrelay SHALL accept private network guard flags (`--allow-private-networks`, `--disallow-network`) consistent with the existing Smol_Exit binary.

### Requirement 12: Dnssocksrelay Configuration

**User Story:** As a user, I want the Dnssocksrelay to accept the same style of CLI flags as the existing smol-client, so that the configuration experience is consistent.

#### Acceptance Criteria

1. THE Dnssocksrelay SHALL accept `--domain`, `--resolver` (Dnsrelay address), `--client-id`, `--exit-node-id` (Dnsrelay's node-id), and `--psk`/`--psk-file` as required CLI parameters.
2. THE Dnssocksrelay SHALL accept `--listen-addr` (default `127.0.0.1`) and `--listen-port` (default 1080) for the local SOCKS5 listener.
3. THE Dnssocksrelay SHALL accept `--connect-timeout-ms` (default 30000), `--poll-active-ms` (default 50), `--poll-idle-ms` (default 500), and `--backoff-max-ms` for polling behavior.
4. THE Dnssocksrelay SHALL accept smoltcp tuning flags (`--smol-rto-ms`, `--smol-window-segments`, `--smol-mss`) consistent with the existing Smol_Client binary.

### Requirement 13: Traditional Deployment Unchanged

**User Story:** As an operator, I want the traditional broker, exit-node, socks-client, smol-client, and smol-exit binaries to remain completely unchanged, so that existing deployments are not affected.

#### Acceptance Criteria

1. THE Traditional_Broker binary SHALL remain unchanged in behavior and configuration.
2. THE existing `socks-client`, `exit-node`, `smol-client`, and `smol-exit` binaries SHALL remain unchanged in behavior and configuration.
3. THE ChannelStore data structure SHALL remain unchanged.
4. THE `dnc` and `dchat` examples SHALL remain unchanged.

### Requirement 14: Code Reuse Between Relay and Traditional Binaries

**User Story:** As a developer, I want the new relay binaries to reuse existing modules where possible, so that code duplication is minimized.

#### Acceptance Criteria

1. THE Dnsrelay and Dnssocksrelay SHALL reuse the existing `crypto` module for key exchange, key derivation, encryption, decryption, and HMAC authentication.
2. THE Dnsrelay and Dnssocksrelay SHALL reuse the existing `smol_device`, `smol_frame`, and `smol_poll` modules for the smoltcp tunnel.
3. THE Dnsrelay SHALL reuse the existing `dns` module (from the broker crate) for DNS query parsing and response building.
4. THE Dnsrelay SHALL reuse the existing `encoding` module (from the broker crate) for base32 encoding/decoding and envelope formatting.
5. THE Dnssocksrelay SHALL reuse the existing `socks` module for SOCKS5 handshake.
6. THE Dnssocksrelay SHALL reuse the existing `DnsTransport` for communicating with the Dnsrelay.
7. THE Dnsrelay SHALL reuse the existing `guard` module for private network blocking.

### Requirement 15: RelayStore Correctness Properties

**User Story:** As a developer, I want the RelayStore to have well-defined correctness properties, so that its behavior can be verified with property-based tests.

#### Acceptance Criteria

1. FOR ALL valid (channel, sender_id, payload) inputs, calling `write` then `read` on the channel SHALL return a result containing the written payload with the correct sender_id and a valid sequence number (round-trip property).
2. FOR ALL channels, calling `write` with the same (channel, sender_id) key N times SHALL result in `slot_count(channel)` equal to 1 (single-slot invariant).
3. FOR ALL channels with K distinct sender_ids, `slot_count(channel)` SHALL equal K (slot count equals distinct sender count).
4. FOR ALL Packet_Slots, after `sweep_expired` is called with a time beyond the TTL, the expired Packet_Slot SHALL no longer appear in `read` results (expiry correctness).
5. FOR ALL channels, `read` SHALL be idempotent — calling `read` twice in succession without intervening writes SHALL return the same result (non-destructive read invariant).
6. FOR ALL valid writes, the assigned sequence number SHALL be strictly greater than any previously assigned sequence number (monotonic sequence property).
