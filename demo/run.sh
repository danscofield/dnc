#!/usr/bin/env bash
#
# DNS Message Broker — interactive demo
#
# Builds the project, starts the broker, sends messages via dnc,
# receives them, and shuts everything down.
#
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

BROKER_PORT=15353
BROKER_ADDR="127.0.0.1:${BROKER_PORT}"
DOMAIN="broker.example.com"
CONFIG="demo/broker.toml"

cleanup() {
    if [[ -n "${BROKER_PID:-}" ]]; then
        echo ""
        echo "==> Stopping broker (pid $BROKER_PID)..."
        kill "$BROKER_PID" 2>/dev/null || true
        wait "$BROKER_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT

echo "==> Building project..."
cargo build --release --examples 2>&1 | tail -1

BROKER_BIN="$ROOT/target/release/dns-fifo-broker"
DNC="$ROOT/target/release/examples/dnc"

echo ""
echo "==> Starting broker on ${BROKER_ADDR}..."
"$BROKER_BIN" "$CONFIG" &
BROKER_PID=$!
sleep 1

if ! kill -0 "$BROKER_PID" 2>/dev/null; then
    echo "ERROR: Broker failed to start. Is port ${BROKER_PORT} already in use?"
    exit 1
fi
echo "    Broker running (pid $BROKER_PID)"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Sending messages"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

echo ""
echo '==> echo "hello bob" | dnc -b $BROKER_ADDR -s alice general'
echo "hello bob" | "$DNC" -b "$BROKER_ADDR" -s alice general

echo ""
echo '==> echo "how are you?" | dnc -b $BROKER_ADDR -s alice general'
echo "how are you?" | "$DNC" -b "$BROKER_ADDR" -s alice general

echo ""
echo '==> echo "hey alice" | dnc -b $BROKER_ADDR -s bob general'
echo "hey alice" | "$DNC" -b "$BROKER_ADDR" -s bob general

echo ""
echo '==> echo "secret stuff" | dnc -b $BROKER_ADDR -s charlie private'
echo "secret stuff" | "$DNC" -b "$BROKER_ADDR" -s charlie private

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Receiving messages"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

echo ""
echo "==> dnc -b $BROKER_ADDR -l -1 general  (3 times)"
for i in 1 2 3; do
    echo -n "    [$i] "
    "$DNC" -b "$BROKER_ADDR" -l -1 general
done

echo ""
echo "==> dnc -b $BROKER_ADDR -l -1 general  (expect empty, will timeout)"
timeout 2 "$DNC" -b "$BROKER_ADDR" -l -1 general 2>/dev/null || echo "    (no messages)"

echo ""
echo "==> dnc -b $BROKER_ADDR -l -1 private"
echo -n "    "
"$DNC" -b "$BROKER_ADDR" -l -1 private

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Demo complete!"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
