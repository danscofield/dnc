#!/usr/bin/env bash
# Run the exit-node in embedded mode (broker in-process).
# The broker listens on 0.0.0.0:5353 for DNS queries from socks-clients.

set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

exec "${SCRIPT_DIR}/../target/release/exit-node" \
  --domain x.y.z \
  --node-id exitnode1 \
  --mode embedded \
  --broker-config "${SCRIPT_DIR}/exit-node-broker.toml" \
  --psk-file "${SCRIPT_DIR}/psk.key"
