# Selective Sequence Fetch Bugfix Design

## Overview

The relay-mode TXT receive path (`handle_relay_receive`) returns all non-expired packet envelopes on every client poll. Each envelope is ~160-170 bytes after base32 encoding, so only ~7 fit in a 1232-byte EDNS0 response. When the ring buffer accumulates many slots, critical retransmits get crowded out by already-seen data, stalling TCP connections.

The fix introduces a two-phase selective fetch protocol: Phase 1 (manifest) returns a compact list of available sequence IDs, and Phase 2 (fetch) lets the client request only the specific IDs it needs. A legacy fallback preserves backward compatibility for clients that don't use the new protocol signaling.

## Glossary

- **Bug_Condition (C)**: The relay channel contains more non-expired slots than fit in a single DNS response (~7 records), and the client has already received some of them, causing needed retransmits to be crowded out
- **Property (P)**: The client can discover all available sequence IDs via a compact manifest and selectively fetch only the ones it needs, ensuring critical retransmits are always delivered
- **Preservation**: Existing send path (A queries), status queries, empty-channel responses, and legacy TXT queries (no prefix signaling) must remain unchanged
- **`handle_relay_receive`**: The function in `src/relay_handler.rs` that handles TXT queries and returns packet envelopes from the RelayStore
- **`DedupRecvTransport`**: The wrapper in `crates/dns-socks-proxy/src/relay_transport.rs` that filters already-seen sequence numbers on the client side
- **`DnsTransport`**: The DNS-based transport in `crates/dns-socks-proxy/src/transport.rs` that builds and sends DNS queries
- **Manifest**: A compact TXT response listing `seq_id,payload_len` pairs for all non-expired slots in a channel
- **Selective Fetch**: A TXT query encoding specific sequence IDs in the DNS query name, returning only those packet envelopes

## Bug Details

### Bug Condition

The bug manifests when the relay channel accumulates more non-expired slots than fit in a single DNS TXT response (~7 at 1232-byte EDNS0 budget). The client polls repeatedly, receiving the same ~7 highest-sequence envelopes each time. If a needed retransmit has a lower sequence number, it never gets delivered because it's crowded out by already-seen higher-sequence packets.

**Formal Specification:**
```
FUNCTION isBugCondition(input)
  INPUT: input of type TxtPollRequest { channel: String, known_sequences: Set<u64> }
  OUTPUT: boolean

  slots := relay_store.read_non_expired(input.channel)
  response_capacity := floor(1232 / avg_envelope_size)  // ~7

  RETURN slots.len() > response_capacity
         AND input.known_sequences.intersection(slots.top_by_seq(response_capacity)).len() > 0
         AND EXISTS seq IN slots WHERE seq NOT IN slots.top_by_seq(response_capacity)
                                   AND seq NOT IN input.known_sequences
END FUNCTION
```

### Examples

- Channel has 20 slots (seq 1-20). Client already has seq 14-20. Legacy poll returns seq 14-20 again. Client needs seq 10 (a retransmit) but never sees it → TCP stalls.
- Channel has 10 slots. Client has seq 5-10. Legacy poll returns seq 4-10. Seq 4 is new but seq 1-3 (needed retransmits) are crowded out.
- Channel has 5 slots, all fit in one response → no bug, legacy path works fine.
- Channel has 30 slots from 3 senders. Client needs 2 specific retransmits but gets 7 already-seen packets instead.

## Expected Behavior

### Preservation Requirements

**Unchanged Behaviors:**
- A/AAAA send queries write to the ring buffer and return ACK IP exactly as before
- Status queries (`<nonce>.status.<channel>.<domain>`) return slot count encoded as status IP
- Empty channels return NoError with zero answer records for any TXT query mode
- Legacy TXT queries (nonce without `m` or `f` prefix) return full packet envelopes in existing format
- `DedupRecvTransport` continues to deduplicate based on sequence numbers
- `ack_sequences` continues to remove acknowledged packets from the ring buffer
- DNS response records continue to have TTL 0 and AA flag set

**Scope:**
All inputs that do NOT use the new `m`-prefix (manifest) or `f`-prefix (fetch) signaling are completely unaffected. This includes:
- All A/AAAA queries (send and status paths)
- Legacy TXT queries with unprefixed nonces
- Any non-TXT query types (still return REFUSED)

## Hypothesized Root Cause

Based on the bug analysis, the root cause is architectural rather than a code defect:

1. **No client-to-relay feedback mechanism**: The relay has no way to know which sequences the client already has. It returns all non-expired slots sorted by sequence descending, and the response budget (~7 records) acts as a hard ceiling. The client's `DedupRecvTransport` filters duplicates after receipt, but the damage is done — the response budget was consumed by stale data.

2. **Monolithic response format**: Each envelope is ~160-170 bytes (base32 overhead), so the information density per response is low. A manifest of sequence IDs (4-8 chars each, comma-separated) would fit 50-60+ entries in a single TXT record, giving the client full visibility into available data.

3. **No selective retrieval**: The client cannot request specific packets. It must accept whatever the relay returns in sequence-descending order, which biases toward the newest packets and starves older retransmits that smoltcp needs to fill TCP gaps.

## Correctness Properties

Property 1: Bug Condition - Selective Fetch Delivers Requested Sequences

_For any_ TXT query where the client sends a fetch request (`f`-prefixed nonce) encoding specific sequence IDs that exist in the relay's non-expired slots, the relay SHALL return exactly those packet envelopes (and only those), ensuring that critical retransmits are delivered regardless of how many other slots exist in the channel.

**Validates: Requirements 2.2, 2.3**

Property 2: Preservation - Legacy Query Backward Compatibility

_For any_ TXT query where the nonce does NOT have an `m` or `f` prefix (legacy mode), the relay SHALL return the same response as the current implementation: all non-expired packet envelopes sorted by sequence descending, budget-limited to ~7 records, preserving full backward compatibility.

**Validates: Requirements 3.4, 3.1, 3.2, 3.3**


## Fix Implementation

### Changes Required

Assuming our root cause analysis is correct:

**File**: `src/relay_store.rs`

**New Method**: `read_sequences(channel, &[u64]) -> Vec<PacketSlot>`

**Specific Changes**:
1. **Add `read_sequences` method**: Fetch specific non-expired slots by sequence ID from a channel. Iterates all sender ring buffers, collects slots whose sequence is in the requested set. Returns owned `PacketSlot`s. This is the server-side enabler for selective fetch.

---

**File**: `src/relay_handler.rs`

**Function**: `handle_relay_receive`

**Specific Changes**:
1. **Detect query mode from nonce prefix**: After extracting the nonce label, check if it starts with `m` (manifest) or `f` (fetch). If neither, fall through to existing legacy behavior.

2. **Manifest mode (`m` prefix)**: Read all non-expired slots for the channel. For each slot, emit `seq_id,payload_len` as a compact entry. Pack entries as comma-separated values into TXT records (up to 255 chars per record, multiple records per response). Return these TXT records instead of full envelopes.

3. **Fetch mode (`f` prefix)**: Parse sequence IDs from the DNS query name. The format is `f<nonce>.<seq1>-<seq2>-<seq3>.<channel>.<domain>` — the label after the nonce contains dash-separated decimal sequence IDs. Call `store.read_sequences(channel, &seq_ids)` and return full envelopes for only those slots, using the existing `encode_envelope_parts` format and budget logic.

4. **Legacy mode (no prefix)**: No changes. Existing `handle_relay_receive` logic runs as-is.

---

**File**: `crates/dns-socks-proxy/src/transport.rs`

**Struct**: `DnsTransport`

**Specific Changes**:
1. **Add `build_manifest_query_name` method**: Builds `m<nonce>.<channel>.<domain>` for manifest queries.

2. **Add `build_fetch_query_name` method**: Builds `f<nonce>.<seq1>-<seq2>-<seq3>.<channel>.<domain>` for selective fetch queries. Sequence IDs are dash-separated decimal numbers in a single label (fits within 63-char label limit for typical 3-4 IDs of 4-8 digits each).

3. **Add `recv_manifest` method**: Sends a manifest TXT query, parses the response TXT records, returns a `Vec<(u64, usize)>` of `(seq_id, payload_len)` pairs.

4. **Add `recv_fetch` method**: Sends a selective fetch TXT query for specific sequence IDs, parses the response envelopes, returns `(Vec<Vec<u8>>, Option<u64>)` like existing `recv_frames`.

---

**File**: `crates/dns-socks-proxy/src/relay_transport.rs`

**Struct**: `DedupRecvTransport`

**Specific Changes**:
1. **Replace `recv_frames` with two-phase logic**: Instead of calling `inner.recv_frames()` directly, call `inner.recv_manifest()` first to get available sequence IDs. Filter out already-seen sequences using `last_seen`. If any new sequences remain, call `inner.recv_fetch()` with only the needed IDs. If all sequences are already seen, skip the fetch (saving a round-trip per requirement 2.4).

2. **Update `last_seen` tracking**: Track individual sequence IDs (not just max_seq) to support the manifest-based filtering. The `last_seen` map changes from `HashMap<String, u64>` to `HashMap<String, HashSet<u64>>` or similar, so the client knows exactly which sequences it has.

---

**File**: `crates/dns-socks-proxy/tests/smoltcp_relay_repro.rs`

**Struct**: `DnsSimTransport`

**Specific Changes**:
1. **Update `recv_frames` to use two-phase protocol**: Build manifest query (`m`-prefixed), parse manifest response, determine needed sequences, build fetch query (`f`-prefixed), parse fetch response. This exercises the full new wire format in the integration test.

## Testing Strategy

### Validation Approach

The testing strategy follows a two-phase approach: first, surface counterexamples that demonstrate the bug on unfixed code, then verify the fix works correctly and preserves existing behavior.

### Exploratory Bug Condition Checking

**Goal**: Surface counterexamples that demonstrate the bug BEFORE implementing the fix. Confirm that the current relay handler returns stale already-seen packets and crowds out needed retransmits.

**Test Plan**: Write tests that populate a relay channel with many slots, then issue TXT queries and verify that specific lower-sequence packets are unreachable due to the response budget. Run on UNFIXED code to observe the crowding-out behavior.

**Test Cases**:
1. **Crowding Out Test**: Write 20 slots to a channel, issue a legacy TXT query, verify only ~7 highest-sequence envelopes are returned and lower-sequence slots are inaccessible (will demonstrate the bug on unfixed code)
2. **Repeated Poll Stale Test**: Poll twice without new writes, verify the same ~7 envelopes are returned both times with no way to reach the remaining slots (will demonstrate the bug on unfixed code)
3. **Retransmit Starvation Test**: Write slots where a critical retransmit has a low sequence number, verify it's crowded out by higher-sequence already-seen packets (will demonstrate the bug on unfixed code)

**Expected Counterexamples**:
- Lower-sequence retransmit packets are never returned because the ~7-record budget is consumed by higher-sequence packets
- Possible causes: monolithic response format, no client feedback mechanism, no selective retrieval

### Fix Checking

**Goal**: Verify that for all inputs where the bug condition holds, the fixed function produces the expected behavior.

**Pseudocode:**
```
FOR ALL input WHERE isBugCondition(input) DO
  manifest := handle_relay_receive_manifest(input.channel)
  needed_seqs := manifest.seq_ids MINUS input.known_sequences
  result := handle_relay_receive_fetch(input.channel, needed_seqs)
  ASSERT result.envelopes.seq_ids == needed_seqs
  ASSERT result.envelopes DO NOT contain any seq IN input.known_sequences
END FOR
```

### Preservation Checking

**Goal**: Verify that for all inputs where the bug condition does NOT hold (legacy queries), the fixed function produces the same result as the original function.

**Pseudocode:**
```
FOR ALL input WHERE NOT has_manifest_or_fetch_prefix(input.nonce) DO
  ASSERT handle_relay_receive_fixed(input) == handle_relay_receive_original(input)
END FOR
```

**Testing Approach**: Property-based testing is recommended for preservation checking because:
- It generates many random channel states and query configurations
- It catches edge cases in nonce prefix detection and label parsing
- It provides strong guarantees that legacy behavior is unchanged

**Test Plan**: Observe behavior on UNFIXED code first for legacy TXT queries, then write property-based tests capturing that behavior and verifying it's preserved after the fix.

**Test Cases**:
1. **Legacy Query Preservation**: Verify that TXT queries with unprefixed nonces return the same envelopes as the current implementation
2. **Send Path Preservation**: Verify A queries continue to write and return ACK IP
3. **Status Path Preservation**: Verify status queries continue to return correct slot counts
4. **Empty Channel Preservation**: Verify empty channels return NoError with zero answers for all query modes

### Unit Tests

- Test manifest response format: correct `seq_id,payload_len` pairs, comma-separated, packed into TXT records
- Test fetch query parsing: dash-separated sequence IDs extracted correctly from DNS labels
- Test `read_sequences` returns only requested non-expired slots
- Test manifest mode with empty channel returns empty response
- Test fetch mode with non-existent sequence IDs returns empty response
- Test nonce prefix detection: `m`-prefix → manifest, `f`-prefix → fetch, no prefix → legacy
- Test fetch label parsing edge cases: single ID, maximum IDs, invalid IDs

### Property-Based Tests

- Generate random channel states (varying slot counts, sender IDs, sequences) and verify manifest lists all non-expired slots
- Generate random subsets of sequence IDs and verify fetch returns exactly those envelopes
- Generate random legacy queries (unprefixed nonces) and verify response matches original implementation
- Generate random nonce strings and verify prefix detection is correct

### Integration Tests

- Full round-trip via `DnsSimTransport`: manifest → filter → fetch → decode envelopes
- `DedupRecvTransport` two-phase flow: verify it skips fetch when all manifest sequences are already seen
- End-to-end smoltcp relay test with two-phase protocol: verify TCP data transfer completes without stalling
- Backward compatibility: legacy client (no prefix) talking to updated relay still works
