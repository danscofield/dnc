# DNS Message Broker Demo

End-to-end demo using `dnc` (DNS netcat) — a single binary that sends and
receives messages through the broker, netcat-style.

## Quick start

```bash
./demo/run.sh
```

## dnc usage

```
dnc [OPTIONS] <CHANNEL>
```

Send mode (default) — reads from stdin:
```bash
echo "hello" | dnc general
echo "secret" | dnc -s alice inbox
cat file.txt | dnc -s bob uploads
```

Listen mode — prints messages to stdout:
```bash
dnc -l general              # poll continuously
dnc -l -1 general           # receive one message and exit
dnc -l -i 200 general       # poll every 200ms
```

Options:
```
-l          Listen mode (receive)
-1          Receive one message and exit
-s NAME     Sender ID (default: "anon")
-b ADDR     Broker address (default: 127.0.0.1:15353)
-d DOMAIN   Controlled domain (default: broker.example.com)
-i MS       Poll interval in ms (default: 500)
```

## Manual usage

Terminal 1 — start the broker:
```bash
cargo run -- demo/broker.toml
```

Terminal 2 — listen:
```bash
cargo run --example dnc -- -l inbox
```

Terminal 3 — send:
```bash
echo "hello world" | cargo run --example dnc -- -s alice inbox
```
