#!/usr/bin/env bash
# Run the smol-exit in embedded mode (broker in-process).
# The broker listens on 0.0.0.0:5353 for DNS queries from smol-clients.
#
# This is the smoltcp-based alternative to run-exit-node.sh.
# Uses the same PSK, same broker config, same domain — just a different
# TCP reliability layer under the hood.

set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

exec "${SCRIPT_DIR}/../target/release/smol-exit" \
  --domain x.y.z \
  --node-id exitnode1 \
  --mode embedded \
  --broker-config "${SCRIPT_DIR}/exit-node-broker.toml" \
  --psk-file "${SCRIPT_DIR}/psk.key"
