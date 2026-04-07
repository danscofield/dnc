# Relay Stale Slot Accumulation Bugfix Design

## Overview

The relay mode data transfer stalls when transferring payloads larger than ~160 bytes because the unique-sender-id-per-write strategy causes unbounded slot accumulation in the `RelayStore`. Each smoltcp packet creates a permanent slot (e.g., `client1-0`, `client1-1`, ...) that persists for the full 600s TTL. When the relay handler returns ALL accumulated slots in TXT responses, stale packets that smoltcp already processed are re-injected, filling the reassembly buffer and blocking new data delivery.

The fix reverts to the original single-slot-per-sender design. The unique-sender-id hack was the root cause — it was introduced to prevent rapid sends from overwriting each other, but the original single-slot design is correct because: (a) the in-process `RelayTransport` path reads frequently enough to catch each packet, and (b) the DNS TXT path relies on smoltcp retransmission to recover from overwrites, while the stale accumulation from unique sender IDs is far more damaging than occasional overwrites.

## Glossary

- **Bug_Condition (C)**: The condition that triggers the bug — unique sender_ids cause unbounded slot accumulation in the RelayStore, and TXT responses return all accumulated stale slots
- **Property (P)**: The desired behavior — each sender overwrites its single slot, preventing accumulation; TXT responses return only the latest packet per sender
- **Preservation**: Existing relay path behavior that must remain unchanged — in-process `RelayTransport` round-trip, A/AAAA send queries, status queries, adverse network resilience
- **RelayStore**: The single-slot-per-sender store in `src/relay_store.rs` that maps (channel, sender_id) → PacketSlot
- **RelayTransport**: The in-process transport in `crates/dns-socks-proxy/src/relay_transport.rs` that reads/writes RelayStore directly
- **DedupRecvTransport**: A wrapper transport that filters already-seen envelope sequences from `recv_frames`
- **handle_relay_send**: The function in `src/relay_handler.rs` that processes A/AAAA send queries and writes to RelayStore
- **DnsSimTransport**: Test transport in `smoltcp_relay_repro.rs` that simulates the DNS TXT encode/decode path

## Bug Details

### Bug Condition

The bug manifests when a sender writes multiple packets to the same data channel using unique sender_ids (e.g., `client1-0`, `client1-1`, ..., `client1-N`). Each unique sender_id creates a separate slot in the RelayStore that persists for the full TTL (600s). When the relay handler processes TXT queries, it returns ALL non-expired slots, including stale ones whose data smoltcp has already processed and ACK'd.

**Formal Specification:**
```
FUNCTION isBugCondition(input)
  INPUT: input of type (channel: String, sender_id: String, write_count: usize)
  OUTPUT: boolean
  
  RETURN write_count > 1
         AND each write uses a UNIQUE sender_id (e.g., sender_id-0, sender_id-1, ...)
         AND RelayStore.slot_count(channel) grows proportionally to write_count
         AND TXT response includes stale slots from earlier writes
END FUNCTION
```

### Examples

- Client sends SYN (slot `client1-0`), then SYN+data (slot `client1-1`): both slots persist, TXT response returns both even after server processed SYN
- Server sends 16 data segments at MSS 32 for a 512-byte payload: creates slots `server1-0` through `server1-15`, all returned on every TXT poll
- After 100 poll cycles, the same 16 stale slots are still returned (TTL 600s), re-injected into smoltcp, filling reassembly buffer
- Expected: each sender has exactly 1 slot (the latest packet), TXT response returns only the most recent data

## Expected Behavior

### Preservation Requirements

**Unchanged Behaviors:**
- In-process `RelayTransport` round-trip must continue to work (validated by `full_relay_path_round_trip` test)
- A/AAAA send queries must continue to write to RelayStore and return ACK IP
- Status queries must continue to return correct slot count
- Relay path must survive adverse network conditions (validated by `relay_path_survives_adverse_network` proptest)
- `DedupRecvTransport` batch-level dedup must continue to filter stale batches
- DNS TXT round-trip with small payloads must continue to work (validated by `full_relay_path_dns_sim_round_trip` test)

**Scope:**
All inputs that do NOT involve the unique-sender-id-per-write mechanism should be completely unaffected by this fix. This includes:
- TXT receive queries (read path is unchanged)
- Status queries
- Domain validation and routing logic
- Encryption/decryption of IP packets
- smoltcp poll loop logic

## Hypothesized Root Cause

Based on the bug description, the root cause is the unique-sender-id-per-write strategy introduced in two places:

1. **`RelayTransport.send_frame`** (relay_transport.rs): Uses `format!("{}-{}", self.sender_id, seq)` where `seq` is an atomic counter. Each call creates a new unique sender_id, so each packet gets its own permanent slot instead of overwriting the previous one.

2. **`handle_relay_send`** (relay_handler.rs): Uses `format!("{}-{}", sender_id, nonce)` where `nonce` is the DNS query's first label. Each DNS A query has a random nonce, so each send creates a new unique sender_id.

3. **`DnsSimTransport.send_frame`** (test file): Uses `format!("{}-{}", self.sender_id, seq)` — same pattern as `RelayTransport`.

The original single-slot-per-sender design was correct. The unique-sender-id hack was introduced to prevent rapid sends from overwriting each other (e.g., SYN-ACK + data in one poll cycle), but the cure is worse than the disease: unbounded slot accumulation causes connection stalls, while occasional overwrites are recovered by smoltcp retransmission.

## Correctness Properties

Property 1: Bug Condition - Single Slot Per Sender Prevents Accumulation

_For any_ sequence of N writes from the same sender to the same channel, the RelayStore SHALL contain exactly 1 slot for that (channel, sender_id) pair after all writes complete, with the slot containing the payload from the most recent write.

**Validates: Requirements 2.1, 2.2**

Property 2: Preservation - Relay Path Data Transfer

_For any_ relay path configuration (in-process or DNS TXT sim) with payloads up to 512 bytes, the fixed code SHALL complete the data transfer within the timeout, preserving the existing behavior validated by `full_relay_path_round_trip`, `full_relay_path_dns_sim_round_trip`, and `dns_sim_path_stale_slots` tests.

**Validates: Requirements 3.1, 3.2, 3.3, 3.4, 3.5**

## Fix Implementation

### Changes Required

Assuming our root cause analysis is correct:

**File**: `crates/dns-socks-proxy/src/relay_transport.rs`

**Function**: `RelayTransport::send_frame`

**Specific Changes**:
1. **Revert to using `self.sender_id` directly**: Remove the atomic counter suffix. Change from `format!("{}-{}", self.sender_id, seq)` to using `self.sender_id` as-is. This means each send overwrites the previous slot for the same sender.
2. **Remove `send_seq` field**: The `AtomicU64` counter is no longer needed.

**File**: `src/relay_handler.rs`

**Function**: `handle_relay_send`

**Specific Changes**:
3. **Revert to using `sender_id` directly**: Remove the nonce suffix. Change from `format!("{}-{}", sender_id, nonce)` to using `sender_id` as-is.

**File**: `crates/dns-socks-proxy/tests/smoltcp_relay_repro.rs`

**Struct**: `DnsSimTransport::send_frame`

**Specific Changes**:
4. **Revert to using `self.sender_id` directly**: Remove the atomic counter suffix, matching the fix in `RelayTransport`.
5. **Remove `send_seq` field**: The `AtomicU64` counter is no longer needed.

## Testing Strategy

### Validation Approach

The testing strategy follows a two-phase approach: first, confirm the bug exists on unfixed code via the `dns_sim_path_stale_slots` test (which times out), then verify the fix resolves it and preserves existing behavior.

### Exploratory Bug Condition Checking

**Goal**: Surface counterexamples that demonstrate the bug BEFORE implementing the fix. Confirm or refute the root cause analysis.

**Test Plan**: The `dns_sim_path_stale_slots` test already reproduces the bug deterministically — it times out after 10 seconds because 16+ unique-sender slots accumulate and are replayed on every TXT poll.

**Test Cases**:
1. **Stale Slot Accumulation Test** (`dns_sim_path_stale_slots`): 512-byte payload at MTU 72/77 via DnsSimTransport — times out on unfixed code
2. **Slot Count Growth**: After N sends from same sender, `slot_count` should be 1 (not N) — fails on unfixed code

**Expected Counterexamples**:
- `RelayStore.slot_count(channel)` grows to N after N sends (should stay at 1)
- TXT response contains N stale envelopes instead of 1 current envelope

### Fix Checking

**Goal**: Verify that for all inputs where the bug condition holds, the fixed function produces the expected behavior.

**Pseudocode:**
```
FOR ALL input WHERE isBugCondition(input) DO
  result := RelayStore_fixed.write(channel, sender_id, payload_N)
  slots := RelayStore_fixed.read(channel)
  ASSERT slots.len() == 1
  ASSERT slots[0].payload == payload_N
END FOR
```

### Preservation Checking

**Goal**: Verify that for all inputs where the bug condition does NOT hold, the fixed function produces the same result as the original function.

**Pseudocode:**
```
FOR ALL input WHERE NOT isBugCondition(input) DO
  ASSERT RelayStore_original(input) = RelayStore_fixed(input)
END FOR
```

**Testing Approach**: The existing test suite provides comprehensive preservation checking:
- `full_relay_path_round_trip`: In-process RelayTransport path
- `full_relay_path_dns_sim_round_trip`: DNS TXT sim path with small payload
- `relay_path_survives_adverse_network`: Property-based test with random network conditions

### Unit Tests

- Verify `RelayStore.write` overwrites existing slot for same (channel, sender_id)
- Verify `RelayStore.slot_count` stays at 1 after multiple writes from same sender
- Verify `RelayTransport.send_frame` uses `self.sender_id` without suffix
- Verify `handle_relay_send` uses `sender_id` without nonce suffix

### Property-Based Tests

- The existing `relay_path_survives_adverse_network` proptest validates preservation across random network conditions
- The `dns_sim_path_stale_slots` test validates the fix for the specific bug condition

### Integration Tests

- `full_relay_path_round_trip`: Full in-process relay path
- `full_relay_path_dns_sim_round_trip`: DNS TXT sim path
- `full_relay_path_udp_loopback`: Real UDP loopback path
- `dns_sim_path_stale_slots`: The specific reproduction test for this bug
