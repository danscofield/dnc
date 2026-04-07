# dns-tunnel

Tunnel TCP traffic through DNS queries using a SOCKS5 interface.

The system has three components:

- **dns-message-broker** — A DNS server that acts as a per-channel FIFO message store. Clients send data by encoding it in DNS A query names; receivers poll with TXT queries. Can be used standalone as a simple DNS-based messaging channel without the SOCKS tunnel.
- **dnc** — A netcat-style CLI for sending and receiving messages through the broker directly. Useful for testing, scripting, or simple data exfiltration without the full tunnel stack.
- **dchat** — A dumb IRC-like chat over the broker. Join a room with a nickname and talk. Messages are plain DNS queries — no encryption, no sessions, just vibes.

There are two tunnel implementations that share the same broker, encryption, and SOCKS5 interface:

- **socks-client / exit-node** — The original tunnel. Uses a minimal hand-rolled reliability layer (sliding window, retransmit buffer, SYN/ACK/FIN state machine). Intentionally keeps the state machine as simple as possible — just enough to get data through. No congestion control, no flow control, no out-of-order reassembly beyond the sliding window.
- **smol-client / smol-exit** — Alternative tunnel using [smoltcp](https://github.com/smoltcp-rs/smoltcp), a userspace TCP/IP stack. The DNS channel is treated as a lossy datagram link carrying encrypted IP packets between two smoltcp instances. Gets a full TCP state machine — segmentation, retransmission, congestion control, flow control, FIN handshake — without needing a TUN device or root privileges.

Neither implementation is particularly reliable. The DNS channel is fundamentally hostile to TCP-like protocols: ~100-byte payloads, multi-second round-trips through recursive resolvers, store-and-forward message queues with finite capacity, and no guarantee of delivery order. Both implementations work for short request/response patterns (curl, API calls) but will struggle with sustained transfers or high concurrency. The hand-rolled version is more predictable because it was designed for this specific link. The smoltcp version is more correct but fights its own assumptions about how a network should behave.

## How it works

```
Application → SOCKS5 → client → DNS A queries → Broker → exit → Target
                              ← DNS TXT responses ←
```

Data is encrypted with ChaCha20-Poly1305 (per-session keys via X25519 + PSK) and encoded as DNS queries. The broker is a simple store-and-forward relay — all tunnel logic (sessions, reliability, encryption) lives in the two endpoints.

The standard tunnel (socks-client/exit-node) splits data into ~104-byte frames with a 15-byte header, sequence numbers, and explicit ACK/retransmit logic. The smoltcp tunnel (smol-client/smol-exit) wraps raw IP packets produced by smoltcp in a 12-byte header (session ID + sequence number) and encrypts them the same way. Both use the same broker channels and DNS encoding.

See [PROTOCOL.md](PROTOCOL.md) for the full wire protocol specification.

## Quick start

### 1. Generate a PSK

```bash
head -c 32 /dev/urandom > psk.key
```

Both sides need the same key.

### 2. Run the exit-node (server side)

Create a broker config (`broker.toml`):

```toml
controlled_domain = "tunnel.example.com"
listen_addr = "0.0.0.0"
listen_port = 53

# Optional: override adaptive response sizing with a fixed value.
# When omitted, the broker uses AIMD to auto-tune per channel (recommended).
# max_response_messages = 4
```

Run in embedded mode (broker + exit-node in one process):

```bash
./exit-node \
  --domain tunnel.example.com \
  --node-id e1 \
  --mode embedded \
  --broker-config broker.toml \
  --psk-file psk.key
```

### 3. Point your DNS

Add an NS record for `tunnel.example.com` pointing to your server's IP.

### 4. Run the socks-client (workstation side)

Direct to broker:

```bash
./socks-client \
  --domain tunnel.example.com \
  --resolver <server-ip>:53 \
  --client-id c1 \
  --exit-node-id e1 \
  --psk-file psk.key
```

Through a recursive resolver:

```bash
./socks-client \
  --domain tunnel.example.com \
  --resolver 1.1.1.1:53 \
  --client-id c1 \
  --exit-node-id e1 \
  --psk-file psk.key
```

### 5. Use it

```bash
curl -x socks5h://127.0.0.1:1080 http://icanhazip.com
```

Or configure Firefox: Settings → Network → SOCKS5 proxy → `127.0.0.1:1080`, check "Proxy DNS when using SOCKS v5".

### Alternative: smoltcp-based tunnel (smol-client / smol-exit)

The smol binaries are drop-in replacements that use smoltcp instead of the hand-rolled reliability layer. Same PSK, same broker, same SOCKS5 interface. You must pair smol-client with smol-exit — they can't mix with the standard binaries (different wire protocol for session setup and data framing).

Run the exit side:

```bash
./smol-exit \
  --domain tunnel.example.com \
  --node-id e1 \
  --mode embedded \
  --broker-config broker.toml \
  --psk-file psk.key
```

Run the client side:

```bash
./smol-client \
  --domain tunnel.example.com \
  --resolver <server-ip>:53 \
  --client-id c1 \
  --exit-node-id e1 \
  --psk-file psk.key \
  --max-concurrent-sessions 2
```

Then use it the same way:

```bash
curl -x socks5h://127.0.0.1:1080 http://icanhazip.com
```

Keep `--max-concurrent-sessions` low (2-3) when going through a recursive resolver. Each session runs independent DNS recv/send tasks, and too many concurrent sessions saturate the resolver.

For the broker config, lower TTLs help with session cleanup:

```toml
message_ttl_secs = 30
expiry_interval_secs = 5
```

## Building

```bash
make build          # build all binaries (release)
make test           # run all tests
make dist           # cross-compile for linux-x64, linux-arm64, macos-arm64
```

Requires [zig](https://ziglang.org/) and [cargo-zigbuild](https://github.com/rust-cross/cargo-zigbuild) for cross-compilation.

## Architecture

```
crates/
  dns-socks-proxy/        # SOCKS tunnel (all four binaries)
    src/
      lib.rs              # Crate root, re-exports
      frame.rs            # Binary frame protocol (15-byte header, encode/decode)
      crypto.rs           # X25519 key exchange, ChaCha20-Poly1305, HMAC-SHA256
      reliability.rs      # Retransmit buffer, reassembly buffer, sliding window
      transport.rs        # TransportBackend trait, DnsTransport, DirectTransport
      session.rs          # Session manager, state machine
      socks.rs            # SOCKS5 handshake and CONNECT parsing
      config.rs           # CLI argument parsing for all binaries
      guard.rs            # Private network guard (CIDR-based address blocking)
      smol_device.rs      # smoltcp VirtualDevice (in-memory packet queues, MTU calc)
      smol_frame.rs       # Init/InitAck/Teardown messages, encrypted IP packet framing
      smol_poll.rs        # smoltcp Interface helpers, poll loop, PollDirection
      bin/
        socks_client.rs   # SOCKS5 proxy client (hand-rolled reliability)
        exit_node.rs      # Exit node (hand-rolled reliability)
        smol_client.rs    # SOCKS5 proxy client (smoltcp)
        smol_exit.rs      # Exit node (smoltcp)
src/                      # DNS Message Broker
  lib.rs                  # Crate root, re-exports
  main.rs                 # Broker binary entry point
  server.rs               # UDP DNS server loop
  handler.rs              # Query routing (send via A, receive via TXT)
  store.rs                # Per-channel FIFO message store with replay buffer
  encoding.rs             # Base32 encoding, envelope format
  dns.rs                  # DNS packet building/parsing
  config.rs               # Broker TOML configuration
  error.rs                # Error types
examples/
  dnc.rs                  # DNS netcat — CLI tool for sending/receiving messages
  dchat.rs                # DNS chat — IRC-like rooms over the broker
```

## Reliability

DNS tunneling is inherently unreliable. The channel has ~100-byte payloads, multi-second round-trips through recursive resolvers, finite message queues, and no delivery guarantees. Both tunnel implementations handle this differently:

The standard tunnel (socks-client/exit-node) uses a minimal sliding window with explicit ACKs and retransmits. It's simple and predictable — designed specifically for this link. It doesn't try to be a full TCP implementation.

The smoltcp tunnel (smol-client/smol-exit) runs a real TCP/IP stack over the DNS link. It gets proper congestion control, flow control, and TCP state management, but smoltcp's internal timers (initial RTO ~700ms, min RTO 10ms) are tuned for real networks, not DNS relays. This causes aggressive retransmissions that can flood the broker's message queues. The smol binaries mitigate this with larger socket buffers, separate DNS sockets for send/recv, and deferred session cleanup, but it's still a TCP stack running over a channel that violates most of TCP's assumptions.

Both work for short request/response patterns. Neither is great for sustained transfers.

## Performance

Direct to broker: ~3 seconds for a simple HTTP request (SYN + request + response).

Through recursive resolver: slower due to extra DNS hops, but functional.

Each DNS message carries ~37-104 bytes of payload depending on domain length. The tunnel uses adaptive response sizing — the broker starts conservatively at 2 TXT records per response and ramps up (to a max of 8) as it confirms responses are getting through, or backs off when they're dropped.

## Security

- Per-session encryption: X25519 ephemeral key exchange authenticated by a pre-shared key
- DATA frames encrypted with ChaCha20-Poly1305
- Control frames (SYN/SYN-ACK/FIN/RST) authenticated with HMAC-SHA256 (truncated to 16 bytes)
- PSK must be at least 32 bytes
- Concurrent session limiter prevents resource exhaustion
- Private network guard blocks outbound connections to RFC 1918, loopback, link-local, and cloud metadata ranges by default (SSRF protection)

## CLI reference

### socks-client

| Flag | Default | Description |
|------|---------|-------------|
| `--domain` | required | Controlled DNS domain |
| `--resolver` | required | DNS resolver address (e.g. `1.1.1.1:53`) |
| `--client-id` | required | Client identifier |
| `--exit-node-id` | required | Exit node identifier |
| `--psk-file` | — | Path to PSK file (32+ bytes) |
| `--psk` | — | PSK as hex string |
| `--listen-addr` | `127.0.0.1` | Listen address |
| `--listen-port` | `1080` | Listen port |
| `--rto-ms` | `2000` | Retransmission timeout (ms) |
| `--max-retransmits` | `10` | Max retransmissions before RST |
| `--window-size` | `8` | Sliding window size |
| `--poll-active-ms` | `50` | Active poll interval (ms) |
| `--poll-idle-ms` | `500` | Idle poll interval (ms) |
| `--backoff-max-ms` | value of `--poll-idle-ms` | Maximum backoff interval (ms) |
| `--connect-timeout-ms` | `30000` | SYN-ACK timeout (ms) |
| `--max-parallel-queries` | `8` | Parallel TXT queries per poll cycle |
| `--max-concurrent-sessions` | `8` | Max concurrent active sessions |
| `--queue-timeout-ms` | `30000` | Wait timeout for queued connections (0 = reject immediately) |

### exit-node

| Flag | Default | Description |
|------|---------|-------------|
| `--domain` | required | Controlled DNS domain |
| `--node-id` | required | Node identifier |
| `--mode` | `standalone` | `standalone` or `embedded` |
| `--broker-config` | — | Broker TOML config (embedded mode) |
| `--resolver` | — | DNS resolver (standalone mode) |
| `--psk-file` | — | Path to PSK file |
| `--psk` | — | PSK as hex string |
| `--rto-ms` | `2000` | Retransmission timeout (ms) |
| `--max-retransmits` | `10` | Max retransmissions before RST |
| `--window-size` | `8` | Sliding window size |
| `--poll-active-ms` | `50` | Active poll interval (ms) |
| `--poll-idle-ms` | `500` | Idle poll interval (ms) |
| `--backoff-max-ms` | value of `--poll-idle-ms` | Maximum backoff interval (ms) |
| `--connect-timeout-ms` | `10000` | TCP connect timeout (ms) |
| `--max-parallel-queries` | `8` | Parallel TXT queries per poll cycle |
| `--allow-private-networks` | `false` | Disable default blocking of private/loopback/link-local ranges |
| `--disallow-network` | — | Additional CIDR range to block (repeatable) |

### smol-client

Drop-in replacement for socks-client using smoltcp. Same flags minus the hand-rolled reliability knobs, plus smoltcp tuning.

| Flag | Default | Description |
|------|---------|-------------|
| `--domain` | required | Controlled DNS domain |
| `--resolver` | required | DNS resolver address |
| `--client-id` | required | Client identifier |
| `--exit-node-id` | required | Exit node identifier |
| `--psk-file` | — | Path to PSK file |
| `--psk` | — | PSK as hex string |
| `--listen-addr` | `127.0.0.1` | Listen address |
| `--listen-port` | `1080` | Listen port |
| `--poll-active-ms` | `50` | Active poll interval (ms) |
| `--poll-idle-ms` | `500` | Idle poll interval (ms) |
| `--backoff-max-ms` | value of `--poll-idle-ms` | Maximum backoff interval (ms) |
| `--connect-timeout-ms` | `30000` | InitAck timeout (ms) |
| `--max-concurrent-sessions` | `8` | Max concurrent active sessions |
| `--queue-timeout-ms` | `30000` | Wait timeout for queued connections |
| `--query-interval-ms` | `0` | Min interval between DNS queries (ms) |
| `--no-edns` | `false` | Disable EDNS0 OPT record |
| `--smol-rto-ms` | `3000` | smoltcp initial retransmission timeout (ms) |
| `--smol-window-segments` | `4` | TCP window size in MSS multiples |
| `--smol-mss` | auto | Override MSS (default: derived from DNS payload budget) |

### smol-exit

Drop-in replacement for exit-node using smoltcp.

| Flag | Default | Description |
|------|---------|-------------|
| `--domain` | required | Controlled DNS domain |
| `--node-id` | required | Node identifier |
| `--mode` | `standalone` | `standalone` or `embedded` |
| `--broker-config` | — | Broker TOML config (embedded mode) |
| `--resolver` | — | DNS resolver (standalone mode) |
| `--psk-file` | — | Path to PSK file |
| `--psk` | — | PSK as hex string |
| `--poll-active-ms` | `50` | Active poll interval (ms) |
| `--poll-idle-ms` | `500` | Idle poll interval (ms) |
| `--backoff-max-ms` | value of `--poll-idle-ms` | Maximum backoff interval (ms) |
| `--connect-timeout-ms` | `10000` | TCP connect timeout (ms) |
| `--query-interval-ms` | `0` | Min interval between DNS queries (ms) |
| `--no-edns` | `false` | Disable EDNS0 OPT record |
| `--allow-private-networks` | `false` | Disable default blocking of private ranges |
| `--disallow-network` | — | Additional CIDR range to block (repeatable) |
| `--smol-rto-ms` | `3000` | smoltcp initial retransmission timeout (ms) |
| `--smol-window-segments` | `4` | TCP window size in MSS multiples |
| `--smol-mss` | auto | Override MSS (default: derived from DNS payload budget) |

### dns-message-broker

The broker is configured via a TOML file. Example with all fields:

```toml
controlled_domain = "tunnel.example.com"   # required
listen_addr = "0.0.0.0"                    # default: "::" (dual-stack)
listen_port = 53                           # default: 53
max_messages_per_channel = 100             # default: 100
message_ttl_secs = 600                     # default: 600
channel_inactivity_timeout_secs = 3600     # default: 3600
expiry_interval_secs = 30                  # default: 30
log_level = "info"                         # default: "info"

# Adaptive response sizing override (optional).
# Omit to use AIMD auto-tuning (recommended for most deployments).
# Set to a fixed number to bypass adaptive logic for all channels.
# max_response_messages = 4
```

| Field | Default | Description |
|-------|---------|-------------|
| `controlled_domain` | required | The DNS domain the broker is authoritative for |
| `listen_addr` | `::` | Address to bind (IPv6 `::` accepts both v4 and v6) |
| `listen_port` | `53` | UDP port |
| `max_messages_per_channel` | `100` | Max queued messages per channel |
| `message_ttl_secs` | `600` | Message expiry (seconds) |
| `channel_inactivity_timeout_secs` | `3600` | Idle channel cleanup (seconds) |
| `expiry_interval_secs` | `30` | Sweep interval for expired messages |
| `log_level` | `info` | Logging level (`trace`, `debug`, `info`, `warn`, `error`, `off`) |
| `max_response_messages` | adaptive | Fixed max TXT records per response. Omit for AIMD auto-tuning |

### dnc (DNS netcat)

A standalone tool for sending/receiving messages through the broker's channels directly (not through the SOCKS tunnel). Large inputs are automatically chunked into a stream of DNS messages and reassembled on the receiving end.

```bash
echo "hello" | dnc -d tunnel.example.com general              # send to channel "general"
echo "hello" | dnc -d tunnel.example.com -s alice general      # send with sender ID
cat bigfile.txt | dnc -d tunnel.example.com -s bob inbox       # auto-chunked stream
dnc -d tunnel.example.com -l general                           # listen on channel
dnc -d tunnel.example.com -l -1 general                        # receive one stream and exit
dnc -d tunnel.example.com -l -1 general > output.txt           # receive to file
```

| Flag | Default | Description |
|------|---------|-------------|
| `-l` | — | Listen mode (receive) |
| `-1` | — | Receive one complete stream and exit |
| `-s` | `anon` | Sender ID |
| `-b` | system resolver | Broker address (e.g. `127.0.0.1:5353`) |
| `-d` | `broker.example.com` | Controlled domain |
| `-v` | — | Verbose output on stderr |

### dchat (DNS chat)

IRC-like chat rooms over the DNS Message Broker. No encryption, no sessions — just nicknames and rooms. Features a split-screen TUI with scrolling chat and a fixed input line.

All participants in a room see all messages via cursor-based peek reads (non-destructive). Messages persist in the broker until they expire, so late joiners may see recent history.

```bash
dchat -n alice -r lobby                     # join "lobby" as "alice"
dchat -n bob -r lobby -b 127.0.0.1:5353     # direct to local broker
dchat -n eve -r secret -d tunnel.example.com  # different room and domain
```

Example session (two terminals):

```
# Terminal 1                          # Terminal 2
$ dchat -n alice -r lobby             $ dchat -n bob -r lobby
  joined #lobby as alice                joined #lobby as bob
> hey bob                             <alice> hey bob
<bob> sup                             > sup
```

| Flag | Default | Description |
|------|---------|-------------|
| `-n` | required | Your nickname |
| `-r` | `lobby` | Room (channel) to join |
| `-b` | system resolver | Broker address (e.g. `127.0.0.1:5353`) |
| `-d` | `broker.example.com` | Controlled domain |

Controls: type and press Enter to send, Ctrl+C or Esc to quit. The terminal is fully restored on exit.

## License

MIT
