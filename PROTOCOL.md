# Protocol

This document describes the wire protocol used by the DNS tunnel system. The protocol has three layers: a base messaging layer (used by all components including `dnc`), a tunnel session layer (used by `socks-client` and `exit-node`), and an alternative smoltcp tunnel layer (used by `smol-client` and `smol-exit`).

## Base Layer: DNS Message Broker

The broker is a store-and-forward relay that uses DNS as the transport. It listens for standard DNS queries and maps them to channel operations.

### Channels

Messages are organized into named channels (arbitrary strings like `inbox`, `ctl-e1`, `u-aBcD1234`). Each channel is an independent FIFO queue with configurable capacity and TTL.

### Send (A query)

To send a message, the client encodes it as a DNS A query:

```
<nonce>.<payload_labels>.<sender_id>.<channel>.<controlled_domain>
```

- `nonce` — random 4-char alphanumeric string (cache-busting)
- `payload_labels` — base32-encoded payload split into labels of ≤63 chars each (RFC 1035 label limit)
- `sender_id` — identifier for the sender
- `channel` — destination channel name
- `controlled_domain` — the domain the broker is authoritative for

The broker decodes the payload, stores it in the channel queue, and responds with an A record:

| Response IP | Meaning |
|-------------|---------|
| `1.2.3.4` | Success (ACK) |
| `1.2.3.5` | Payload too large |
| `1.2.3.6` | Channel full |

### Receive (TXT query)

To receive messages, the client sends a DNS TXT query:

```
<nonce>.<channel>.<controlled_domain>
```

The nonce can optionally include a cursor suffix for replay advancement:

```
<random>-c<cursor>.<channel>.<controlled_domain>
```

When a cursor is present, the broker prunes replay entries with `sequence < cursor` before building the response. This allows clients to acknowledge received frames and prevent stale re-delivery.

The default behavior is non-destructive (peek with replay buffer). To consume messages destructively (pop), prefix the nonce with uppercase `P`:

```
P<nonce>.<channel>.<controlled_domain>
```

The SOCKS tunnel uses peek semantics for reliability over lossy UDP (its nonces are lowercase alphanumeric, never starting with `P`). The `dnc` tool uses pop semantics so messages are consumed on read.

The broker returns pending messages as TXT records. Each TXT record contains an envelope string:

```
<sender_id>|<sequence>|<timestamp>|<base32_payload>
```

- `sequence` — monotonically increasing per-broker counter
- `timestamp` — Unix epoch seconds when stored
- `base32_payload` — RFC 4648 base32, lowercase, no padding

#### Adaptive Response Sizing

The broker uses adaptive response sizing to maximize throughput while avoiding silent drops by recursive resolvers.

- **No EDNS0** (UDP buffer < 1232): always 1 message per response.
- **EDNS0 present** (UDP buffer ≥ 1232), peek mode: the broker uses an AIMD (Additive Increase, Multiplicative Decrease) algorithm per channel. New channels start conservatively at 2 messages. When the client's cursor advances between polls (confirming the previous response was received), the broker increases `max_messages` by 1 (up to a ceiling of 8). When the cursor stalls for 2 consecutive polls (suggesting the response was dropped), the broker halves `max_messages` (down to a floor of 2). This finds each resolver's sweet spot automatically.
- **EDNS0 present**, pop mode: uses a static formula `min(((udp_size - 100) / 250), 2)` — adaptive state is not consulted.
- **Config override**: setting `max_response_messages` in the broker config bypasses adaptive logic and uses a fixed value for all channels.

Without EDNS0, one message per response.

### Status (A query)

To check queue depth without consuming messages:

```
<nonce>.status.<channel>.<controlled_domain>
```

Response is an A record encoding the depth:

| Response IP | Meaning |
|-------------|---------|
| `0.0.0.0` | Empty (depth 0) |
| `128.x.y.z` | Depth encoded in lower 24 bits |

### Replay Buffer

The broker uses non-destructive reads (`peek_many`). Served messages move to a per-channel replay buffer so they can be re-delivered if the UDP response is lost.

**Cursor-based replay advancement:** The SOCKS tunnel client tracks the highest store sequence number received from broker responses. On subsequent polls, it encodes this as a cursor in the TXT query nonce (`<random>-c<cursor>`). The broker parses the cursor and prunes replay entries with `sequence < cursor`, retaining only unconfirmed frames for re-delivery. This eliminates the guessing heuristic that previously caused permanent data loss when UDP responses were dropped by recursive resolvers.

**Legacy (no cursor):** When no `-c` suffix is present in the nonce (e.g., `dnc` or older clients), the broker falls back to heuristic replay clearing:

- New messages arrive in the queue (stale replay is discarded, only new messages served)
- The queue is empty on re-poll (replay returned one final time, then cleared)

All response records have TTL 0 to prevent DNS caching.

### Encoding

- Base32: RFC 4648 lowercase alphabet (`a-z`, `2-7`), no padding
- DNS labels: max 63 characters each, total query name max 253 characters
- Envelope format: pipe-delimited (`sender|seq|timestamp|base32_payload`)

## Tunnel Session Layer: SOCKS Proxy Protocol

Built on top of the base messaging layer. Adds sessions, encryption, reliability, and flow control.

### Channels

Each tunnel uses three channel types:

| Channel | Format | Purpose |
|---------|--------|---------|
| Control | `ctl-<node_id>` | Session setup/teardown (SYN, SYN-ACK, FIN, RST) |
| Upstream | `u-<session_id>` | Client → exit node data |
| Downstream | `d-<session_id>` | Exit node → client data |

The control channel is shared across all sessions for a given client/exit-node pair. Data channels are per-session.

### Frame Format

All tunnel frames use a binary format with a 15-byte header:

```
Offset  Size  Field
0       1     session_id_len (always 8)
1       8     session_id (ASCII alphanumeric)
9       4     seq (big-endian u32)
13      1     frame_type
14      1     flags
15+     var   payload
```

Frame types:

| Type | Value | Direction | Description |
|------|-------|-----------|-------------|
| Data | `0x01` | Both | Encrypted application data |
| Ack | `0x02` | Both | Cumulative acknowledgment |
| Syn | `0x03` | Client → Exit | Session initiation |
| SynAck | `0x04` | Exit → Client | Session acceptance |
| Fin | `0x05` | Both | Graceful close |
| Rst | `0x06` | Both | Abrupt termination |

### Session Lifecycle

```
Client                          Exit Node
  |                                |
  |--- SYN (target, pubkey, cid) -->|
  |                                |--- TCP connect to target
  |<-- SYN-ACK (pubkey) -----------|
  |                                |
  |=== DATA (encrypted) ==========>|--- forward to target
  |<== DATA (encrypted) ===========|<-- response from target
  |                                |
  |--- FIN ----------------------->|
  |<-- FIN ------------------------|
```

Control frames (SYN, SYN-ACK, FIN, RST) are sent on the shared `ctl-<node_id>` channel and authenticated with HMAC-SHA256 (truncated to 16 bytes) using the PSK. A 16-byte MAC is appended after the frame bytes.

### SYN Payload

```
Offset  Size  Field
0       1     addr_type (0x01=IPv4, 0x03=Domain, 0x04=IPv6)
1       var   address (4 bytes IPv4, 1+N domain, 16 bytes IPv6)
var     2     target_port (big-endian)
var     32    x25519_public_key
var     1     client_id_len
var     var   client_id (ASCII)
```

### SYN-ACK Payload

```
Offset  Size  Field
0       32    x25519_public_key (exit node's ephemeral key)
```

### Key Exchange and Encryption

1. Client generates an X25519 ephemeral keypair, sends public key in SYN
2. Exit node generates its own keypair, sends public key in SYN-ACK
3. Both sides compute `shared_secret = DH(my_secret, their_public)`
4. Session keys derived via HKDF-SHA256:
   - IKM = `shared_secret || PSK`
   - Info = `"dns-socks-v1"`
   - Output: 64 bytes → first 32 = `data_key`, last 32 = `control_key`
5. DATA frames encrypted with ChaCha20-Poly1305 using `data_key`
6. Nonce construction (12 bytes): `[direction, 0, 0, 0, seq_be32, 0, 0, 0, 0]`
   - Direction: `0x00` = upstream, `0x01` = downstream

### Reliability

DATA frames use a sliding-window ARQ protocol:

- Sender maintains a `RetransmitBuffer` (default window size 8)
- Each DATA frame is tracked with a retransmission timer (default RTO 2s)
- Receiver sends cumulative ACKs (ACK seq N acknowledges all frames ≤ N)
- Receiver uses a `ReassemblyBuffer` to reorder out-of-order frames
- If a frame exceeds max retransmissions (default 10), sender sends RST

### Polling

Both endpoints poll their respective channels using adaptive exponential backoff:

- Starts at a minimum interval (e.g., 50ms)
- Doubles on empty responses, up to a maximum (e.g., 500ms)
- Resets to minimum when data arrives

The client uses a single shared control channel poller (`spawn_control_poller`) that dispatches incoming control frames to per-session mpsc channels via a `ControlDispatcher`. This prevents concurrent sessions from racing on the control channel.

Data channels use parallel TXT queries (`recv_frames_parallel`) to improve throughput — multiple queries are fired simultaneously on separate UDP sockets.

### Payload Budget

The maximum DATA payload per frame is constrained by DNS name length limits:

```
max_dns_name = 253 characters
fixed_overhead = nonce + sender_id + channel + domain + 4 dots
remaining = max_dns_name - fixed_overhead
payload_chars = (remaining + 1) * 63 / 64  (accounting for label dots)
raw_bytes = payload_chars * 5 / 8           (base32 → bytes)
budget = raw_bytes - 15 (header) - 16 (encryption tag)
```

Typical budget: ~104 bytes per frame with a short domain.

### Concurrency

The client supports concurrent sessions via a semaphore-based limiter (default max 2). Excess connections queue with a configurable timeout (default 30s).

### Transport Modes

The exit node supports two deployment modes:

| Mode | Transport | Description |
|------|-----------|-------------|
| Standalone | `DnsTransport` | Talks to a separate broker over DNS |
| Embedded | `DirectTransport` | Runs the broker in-process, calls the store directly |

`DirectTransport` uses non-destructive reads (`peek_many` with replay) since the client polls through a recursive resolver where UDP responses can be lost. `DnsTransport` also uses non-destructive reads with replay. Both transports support cursor-based replay advancement — the client tracks the highest store sequence from broker responses and passes `max_store_seq + 1` as the cursor on subsequent polls to prune confirmed replay entries.

## smoltcp Tunnel Session Layer

An alternative tunnel implementation using [smoltcp](https://github.com/smoltcp-rs/smoltcp), a userspace TCP/IP stack. Uses the same base messaging layer and encryption as the standard tunnel, but replaces the hand-rolled reliability protocol with a real TCP state machine. The smol binaries (smol-client, smol-exit) are not compatible with the standard binaries — they use different session setup messages and data framing.

### Channels

Same channel structure as the standard tunnel:

| Channel | Format | Purpose |
|---------|--------|---------|
| Control | `ctl-<node_id>` | Session setup (Init, InitAck, Teardown) |
| Upstream | `u-<session_id>` | Client → exit node encrypted IP packets |
| Downstream | `d-<session_id>` | Exit node → client encrypted IP packets |

### Session Setup Messages

The smol tunnel uses a different set of control messages (distinct from the standard SYN/SYN-ACK):

#### Init (0x10)

Sent by smol-client on `ctl-<exit_node_id>`:

```
Offset  Size  Field
0       1     msg_type (0x10)
1       8     session_id
9       1     addr_type (0x01=IPv4, 0x03=Domain, 0x04=IPv6)
10      var   address
var     2     target_port (big-endian)
var     32    x25519_public_key
var     1     client_id_len
var     var   client_id (ASCII)
```

Followed by 16-byte HMAC-SHA256 MAC (truncated, using PSK).

#### InitAck (0x11)

Sent by smol-exit on `ctl-<client_id>`:

```
Offset  Size  Field
0       1     msg_type (0x11)
1       8     session_id
9       32    x25519_public_key
```

Followed by 16-byte HMAC-SHA256 MAC.

#### Teardown (0x12)

Sent by either side on the peer's control channel:

```
Offset  Size  Field
0       1     msg_type (0x12)
1       8     session_id
```

Followed by 16-byte HMAC-SHA256 MAC.

### Key Exchange

Identical to the standard tunnel — X25519 ephemeral keys, HKDF-SHA256 with PSK, same `data_key` and `control_key` derivation.

### Encrypted IP Packet Framing

After session setup, smoltcp produces raw IPv4 packets. Each packet is encrypted and framed:

```
Offset  Size  Field
0       8     session_id
8       4     seq (big-endian u32, monotonically increasing)
12      var   ChaCha20-Poly1305 ciphertext (IP packet + 16-byte auth tag)
```

Total overhead: 12 bytes header + 16 bytes auth tag = 28 bytes per packet.

Encryption uses the same `data_key` and nonce construction as the standard tunnel:
- Nonce: `[direction, 0, 0, 0, seq_be32, 0, 0, 0, 0]`
- Direction: `0x00` = upstream, `0x01` = downstream

### Virtual Network

Each session creates a point-to-point virtual IP network:

| Role | Virtual IP | Purpose |
|------|-----------|---------|
| smol-client | `192.168.69.1` | Client-side smoltcp interface |
| smol-exit | `192.168.69.2` | Exit-side smoltcp interface |

The client's smoltcp TCP socket connects to `192.168.69.2:4321`. The exit's smoltcp TCP socket listens on `192.168.69.2:4321`. One TCP connection per smoltcp Interface — the virtual IPs are reused across sessions since each session has its own isolated Interface.

### MTU and MSS

```
dns_payload_budget = compute_payload_budget(domain_len, sender_id_len, channel_len, nonce_len)
mtu = dns_payload_budget - 28 (session_id + seq + auth tag)
mss = mtu - 40 (20 IPv4 header + 20 TCP header)
```

With a typical short domain: budget ~105 bytes, MTU ~77 bytes, MSS ~37 bytes.

Socket buffers are set to `max(mss * window_segments, 384)` bytes for both send and receive.

### Poll Architecture

The smol poll loop uses three concurrent tasks per session:

1. **Recv task** (spawned) — continuously polls the broker for inbound encrypted packets via its own dedicated `DnsTransport` (separate UDP socket). Decrypts IP packets and feeds them through an mpsc channel.
2. **Send task** (spawned) — reads encrypted packets from an mpsc channel and sends them via DNS. Each send is a blocking DNS round-trip but doesn't block the main loop.
3. **Main loop** — drains the inbound channel (non-blocking `try_recv`), calls `Interface::poll`, enqueues outbound packets (non-blocking `try_send`), and shuttles data between the smoltcp TCP socket and the local stream.

The recv and send tasks use separate `DnsTransport` instances (separate UDP sockets) to avoid response cross-contamination between A queries (send) and TXT queries (recv).

### Session Lifecycle

```
Client                              Exit Node
  |                                    |
  |--- Init (target, pubkey, cid) ---->| (on ctl-<exit_node_id>)
  |                                    |--- TCP connect to target
  |<--- InitAck (pubkey) -------------|  (on ctl-<client_id>)
  |                                    |
  | smoltcp TCP SYN =================>|  (encrypted IP packets on u-<sid>)
  |<================ smoltcp TCP SYN-ACK  (encrypted IP packets on d-<sid>)
  | smoltcp TCP ACK =================>|
  |                                    |
  |=== encrypted IP packets =========>|--- forward TCP data to target
  |<== encrypted IP packets ===========|<-- response from target
  |                                    |
  | smoltcp TCP FIN =================>|  (deferred until data drained)
  |<================ smoltcp TCP FIN  |
  |                                    |
  |--- Teardown --------------------->|  (on ctl-<exit_node_id>)
```

### Cursor Advancement

All broker channel reads use cursor-based advancement (`cursor + 1` after each batch) to avoid re-reading consumed messages. This is critical for the smol tunnel because smoltcp's retransmissions generate many packets — without cursor advancement, the same packets would be re-processed indefinitely.

## dnc Stream Framing

`dnc` adds a lightweight stream framing layer on top of the base messaging layer for transferring data larger than a single DNS message.

### Stream Frame Header

Each message payload is prefixed with a 4-byte header:

```
Offset  Size  Field
0       1     seq_hi (big-endian, high byte of 16-bit sequence)
1       1     seq_lo (big-endian, low byte of 16-bit sequence)
2       1     flags (0x00 = DATA, 0x01 = EOF)
3       1     reserved (0x00)
```

### Behavior

- Small messages that fit in a single DNS query are sent as a single frame with `seq=0` and `flags=EOF`
- Large inputs are chunked into multiple frames with incrementing sequence numbers; the last frame has `flags=EOF`
- The receiver reassembles frames in sequence order and outputs data as contiguous frames arrive
- Maximum stream size: 65535 frames × ~124 bytes/frame ≈ 8MB
- `dnc` uses pop semantics (nonce prefix `P`) so each frame is consumed on read
