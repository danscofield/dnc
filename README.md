# dns-tunnel

Tunnel TCP traffic through DNS queries using a SOCKS5 interface.

The system has three components:

- **dns-message-broker** — A DNS server that acts as a per-channel FIFO message store. Clients send data by encoding it in DNS A query names; receivers poll with TXT queries. Can be used standalone as a simple DNS-based messaging channel without the SOCKS tunnel.
- **dnc** — A netcat-style CLI for sending and receiving messages through the broker directly. Useful for testing, scripting, or simple data exfiltration without the full tunnel stack.
- **socks-client** — Runs on your workstation. Exposes a standard SOCKS5 proxy on localhost. Applications (browsers, curl, etc.) connect to it normally. Traffic is fragmented, encrypted, and tunneled through DNS.
- **exit-node** — Runs on a server. Receives tunneled requests via the broker, makes the actual TCP connections, and returns responses over DNS. Can run the broker in-process (embedded mode) or talk to a separate broker over DNS (standalone mode).

## How it works

```
Application → SOCKS5 → socks-client → DNS A queries → Broker → exit-node → Target
                                    ← DNS TXT responses ←
```

Data is split into ~104-byte frames, encrypted with ChaCha20-Poly1305 (per-session keys via X25519 + PSK), and encoded as DNS queries. The broker is a simple store-and-forward relay — all tunnel logic (sessions, reliability, encryption) lives in the two endpoints.

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
  dns-socks-proxy/        # SOCKS tunnel (socks-client + exit-node binaries)
    src/
      lib.rs              # Crate root, re-exports
      frame.rs            # Binary frame protocol (15-byte header, encode/decode)
      crypto.rs           # X25519 key exchange, ChaCha20-Poly1305, HMAC-SHA256
      reliability.rs      # Retransmit buffer, reassembly buffer, sliding window
      transport.rs        # TransportBackend trait, DnsTransport, DirectTransport
      session.rs          # Session manager, state machine
      socks.rs            # SOCKS5 handshake and CONNECT parsing
      config.rs           # CLI argument parsing for both binaries
      bin/
        socks_client.rs   # SOCKS5 proxy client binary
        exit_node.rs      # Exit node binary (standalone or embedded)
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
```

## Performance

Direct to broker: ~3 seconds for a simple HTTP request (SYN + request + response).

Through recursive resolver: slower due to extra DNS hops, but functional.

Each DNS message carries ~104 bytes of payload. The tunnel uses adaptive response sizing — the broker starts conservatively at 2 TXT records per response and ramps up (to a max of 8) as it confirms responses are getting through, or backs off when they're dropped. This keeps responses small enough to survive recursive resolvers while maximizing throughput. Cursor-based replay advancement ensures frames are re-delivered when DNS responses are lost, eliminating the previous heuristic that could permanently lose data.

## Security

- Per-session encryption: X25519 ephemeral key exchange authenticated by a pre-shared key
- DATA frames encrypted with ChaCha20-Poly1305
- Control frames (SYN/SYN-ACK/FIN/RST) authenticated with HMAC-SHA256 (truncated to 16 bytes)
- PSK must be at least 32 bytes
- Concurrent session limiter prevents resource exhaustion

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

## License

MIT
