# Examples

Example programs that use the DNS Message Broker directly (no SOCKS tunnel).

## dnc — DNS netcat

A netcat-style CLI for sending and receiving messages through the broker. Useful for testing, scripting, or piping data through DNS channels.

### Send mode

```bash
echo "hello" | dnc -d tunnel.example.com general           # send to channel "general"
echo "hello" | dnc -d tunnel.example.com -s alice general   # send with sender ID
cat bigfile.txt | dnc -d tunnel.example.com -s bob inbox    # auto-chunked stream
```

### Listen mode

```bash
dnc -d tunnel.example.com -l general        # listen on channel (continuous)
dnc -d tunnel.example.com -l -1 general     # receive one stream and exit
```

Large inputs are automatically chunked into a stream of DNS messages and reassembled on the receiving end. By default, queries go through your system resolver. Use `-b` to target a broker directly.

## dchat — DNS chat

IRC-like chat rooms over the DNS Message Broker. Join a room with a nickname and talk to other people in the same room. Features a split-screen TUI with scrolling chat history and a fixed input line at the bottom.

### How it works

- Each "room" is a broker channel
- Your nickname is the sender ID on each DNS message
- Messages are sent as A queries (same as dnc)
- Messages are received via cursor-based TXT polling (non-destructive peek, so all participants see everything)
- Poll interval is 3 seconds to keep DNS traffic low

### Usage

```bash
# Join "lobby" as "alice" (uses system resolver)
dchat -n alice -r lobby

# Join via a specific broker
dchat -n bob -r lobby -b 127.0.0.1:5353

# Use a custom domain
dchat -n eve -r secret -d tunnel.example.com
```

### Controls

- Type a message and press **Enter** to send
- **Ctrl+C** or **Esc** to quit
- Terminal is fully restored on exit

### Limitations

- No encryption — messages are plaintext in DNS queries
- No authentication — anyone who knows the room name can join
- ~3 second latency between messages (poll interval)
- Message size limited by what fits in a single DNS query name (~100 bytes)
- Messages expire from the broker after the configured TTL (default 10 minutes)

### Local testing

Start a broker, then open two terminals:

```bash
# Terminal 0: start the broker
./target/release/dns-message-broker  # or use the demo scripts

# Terminal 1
cargo run --example dchat -- -n alice -r test -b 127.0.0.1:5353 -d x.y.z

# Terminal 2
cargo run --example dchat -- -n bob -r test -b 127.0.0.1:5353 -d x.y.z
```
