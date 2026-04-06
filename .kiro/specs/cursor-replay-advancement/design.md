# Cursor-Based Replay Advancement Bugfix Design

## Overview

The broker's `peek_many` replay mechanism uses a heuristic to decide when to clear the replay buffer: if a re-poll arrives with no new messages in the queue, it assumes the client received the previous batch and clears replay. This heuristic fails when UDP responses are lost through recursive DNS resolvers — the broker clears frames the client never received, creating permanent gaps and stalled sessions.

The fix introduces cursor-based replay advancement: the client encodes its highest contiguous received sequence number (`ack_seq`) into the TXT query nonce as `<random>-c<cursor>`. The broker parses this cursor and uses it to advance replay only past confirmed frames, eliminating the guessing heuristic for cursor-bearing queries.

## Glossary

- **Bug_Condition (C)**: A TXT recv query arrives at the broker after a UDP response was lost — the client's reassembly buffer has gaps, but the broker's heuristic clears the replay buffer on the next empty-queue re-poll, permanently losing unconfirmed frames
- **Property (P)**: When a cursor is present, `peek_many` drops only replay entries with `sequence < cursor`, retaining unconfirmed entries for re-delivery
- **Preservation**: Existing behavior for non-cursor queries (cursor=None), pop mode, send operations, sweep, queue_depth, and EDNS0 batching must remain unchanged
- **`peek_many`**: Method on `ChannelStore` in `src/store.rs` that returns messages non-destructively with a replay buffer for re-delivery
- **`ack_seq`**: Method on `ReassemblyBuffer` in `crates/dns-socks-proxy/src/reliability.rs` returning the highest contiguous sequence number received by the client (`next_expected - 1`)
- **Cursor**: The client's `ack_seq` value encoded into the TXT query nonce, telling the broker which frames have been confirmed received
- **Nonce**: The first DNS label in a recv query, used for cache-busting; format extended from `<4-char-random>` to `<8-char-random>-c<cursor_base10>` for cursor-bearing queries

## Bug Details

### Bug Condition

The bug manifests when a client polls for downstream data through a recursive DNS resolver and the UDP response carrying replayed frames is lost. The broker's `peek_many` sees no new messages on the next re-poll and clears the replay buffer, permanently losing frames the client never received.

**Formal Specification:**
```
FUNCTION isBugCondition(input)
  INPUT: input of type TxtRecvQuery
  OUTPUT: boolean

  RETURN input.channel HAS non-empty replay buffer
         AND input.channel.messages IS empty (no new messages)
         AND client HAS NOT received all replayed frames
         AND input.nonce DOES NOT contain cursor suffix
END FUNCTION
```

### Examples

- Client polls `d-aBcD1234`, broker returns frames [seq=5, seq=6, seq=7] from replay. UDP response lost. Client re-polls. Broker sees empty queue + non-empty replay → clears replay. Frames 5-7 permanently lost. Client's reassembly buffer stuck at seq=4.
- Client polls, receives frames [seq=0, seq=1]. UDP response arrives. Client re-polls. Broker sees empty queue + non-empty replay → clears replay (correct in this case). But indistinguishable from the lost-response case.
- With cursor fix: client re-polls with nonce `aB3kQ-c4` (ack_seq=4). Broker drops replay entries with seq < 4, keeps seq=5,6,7 for re-delivery. No data loss.
- Edge case: cursor=0 (no frames received yet) — broker retains entire replay buffer.

## Expected Behavior

### Preservation Requirements

**Unchanged Behaviors:**
- Queries without `-c` suffix in the nonce use existing two-phase replay (clear on confirming re-poll)
- Pop mode (nonce starts with `P`) continues to use destructive `pop_many` unaffected by cursor
- A queries (send operations) are completely unaffected — cursor only applies to TXT recv
- `push` maintains strictly monotonic sequences and FIFO ordering
- `queue_depth` returns `messages.len() + replay.len()` accurately
- `sweep_expired` removes expired messages from both queues and inactive channels
- EDNS0 batching (`max_messages` calculation) works correctly with cursor-based replay

**Scope:**
All inputs that do NOT involve TXT recv queries with a `-c` cursor suffix should be completely unaffected by this fix. This includes:
- All A queries (send operations)
- TXT queries with legacy nonces (no `-c` suffix)
- Pop-mode TXT queries (nonce starts with `P`)
- Status queries
- Store operations: push, pop, pop_many, queue_depth, sweep_expired

## Hypothesized Root Cause

Based on the bug description, the root cause is the broker's inability to distinguish between "client received the replay batch" and "UDP response was lost":

1. **No client feedback mechanism**: The current nonce is purely random (`<4-char>`) and carries no information about what the client has received. The broker must guess based on the re-poll pattern.

2. **Flawed heuristic in `peek_many`**: The "confirming re-poll" logic (`replay non-empty + queue empty → clear replay`) assumes the client received the previous batch. This is correct when UDP responses arrive, but catastrophically wrong when they're lost.

3. **Transport layer doesn't pass cursor**: `DnsTransport::build_recv_query_name`, `recv_frames`, and `recv_frames_parallel` generate nonces without any cursor information, even though the client has `ack_seq` available from its `ReassemblyBuffer`.

4. **Handler doesn't parse cursor**: `handle_receive` in `src/handler.rs` strips the nonce but doesn't extract any cursor information from it before calling `peek_many`.

## Correctness Properties

Property 1: Bug Condition — Cursor-bearing peek_many drops only confirmed replay entries

_For any_ channel state where the replay buffer contains entries and a cursor value is provided, `peek_many` with that cursor SHALL drop replay entries with `sequence < cursor` and retain entries with `sequence >= cursor`, ensuring unconfirmed frames are available for re-delivery.

**Validates: Requirements 2.3, 2.4**

Property 2: Preservation — Non-cursor peek_many retains existing two-phase behavior

_For any_ channel state where `peek_many` is called with `cursor = None`, the function SHALL produce the same result as the original implementation, preserving the existing two-phase replay behavior (replay returned once, cleared on confirming re-poll).

**Validates: Requirements 2.5, 3.1**

Property 3: Bug Condition — Nonce format encodes cursor within DNS label limit

_For any_ `ack_seq` value (u32), the generated nonce string `<8-char-random>-c<cursor_base10>` SHALL have length ≤ 63 bytes (DNS label limit) and SHALL be parseable back to the original cursor value.

**Validates: Requirements 2.1, 2.6**

Property 4: Preservation — Pop mode unaffected by cursor logic

_For any_ TXT recv query where the nonce starts with `P` (pop mode), the handler SHALL use `pop_many` regardless of whether a `-c` suffix is present, preserving destructive consume-once semantics.

**Validates: Requirements 3.6**

Property 5: Bug Condition — Handler parses cursor from nonce and passes to peek_many

_For any_ TXT recv query with a nonce containing `-c<number>`, the handler SHALL extract the cursor value and pass it to `peek_many`, and for nonces without `-c`, SHALL pass `None`.

**Validates: Requirements 2.2, 2.5**

## Fix Implementation

### Changes Required

Assuming our root cause analysis is correct:

**File**: `src/store.rs`

**Function**: `peek_many`

**Specific Changes**:
1. **Add cursor parameter**: Change signature from `peek_many(&mut self, channel: &str, max: usize)` to `peek_many(&mut self, channel: &str, max: usize, cursor: Option<u64>)`
2. **Cursor-based replay pruning**: When `cursor` is `Some(c)`, drop replay entries with `sequence < c` before building the result
3. **Disable confirming-re-poll clear**: When `cursor` is `Some(_)` and no new messages are drained, do NOT clear the replay buffer — advancement is driven exclusively by the cursor
4. **Preserve None behavior**: When `cursor` is `None`, keep the existing two-phase replay logic unchanged

---

**File**: `src/handler.rs`

**Function**: `handle_receive`

**Specific Changes**:
1. **Parse cursor from nonce**: After extracting the nonce label, check for `-c<number>` suffix. If present, parse the number as `u64` and pass as `Some(cursor)` to `peek_many`
2. **Backward compatibility**: If no `-c` suffix, pass `None` to `peek_many`
3. **Pop mode unaffected**: The `use_pop` check (nonce starts with `P`) remains before cursor parsing — pop mode bypasses cursor entirely

---

**File**: `crates/dns-socks-proxy/src/transport.rs`

**Functions**: `generate_nonce`, `build_recv_query_name`, `recv_frames`, `recv_single_parallel_query`

**Specific Changes**:
1. **Extend `generate_nonce`**: Add a variant or parameter that accepts an optional cursor value. When present, generate `<8-char-random>-c<cursor_base10>` instead of `<4-char-random>`
2. **Thread cursor through `build_recv_query_name`**: Accept optional cursor, pass to nonce generation
3. **Thread cursor through `recv_frames`**: The `TransportBackend::recv_frames` trait method needs a cursor parameter (or a new `recv_frames_with_cursor` method)
4. **Thread cursor through `recv_frames_parallel`**: Accept cursor parameter, pass to each parallel query's nonce generation

---

**File**: `crates/dns-socks-proxy/src/bin/socks_client.rs`

**Function**: `downstream_task`

**Specific Changes**:
1. **Pass ack_seq to recv_frames**: After each poll cycle, read `reassembly_buf.ack_seq()` and pass it as the cursor when building TXT queries

---

**File**: `crates/dns-socks-proxy/src/bin/exit_node.rs`

**Function**: `upstream_task` (standalone mode recv path)

**Specific Changes**:
1. **Pass ack_seq to recv_frames**: Same pattern as socks_client — read `reassembly_buf.ack_seq()` and pass as cursor

---

**File**: `crates/dns-socks-proxy/src/transport.rs`

**Struct**: `DirectTransport`

**Specific Changes**:
1. **Pass cursor through `recv_frames`**: `DirectTransport::recv_frames` calls `store.peek_many` — needs to pass the cursor parameter through

## Testing Strategy

### Validation Approach

The testing strategy follows a two-phase approach: first, surface counterexamples that demonstrate the bug on unfixed code, then verify the fix works correctly and preserves existing behavior.

### Exploratory Bug Condition Checking

**Goal**: Surface counterexamples that demonstrate the bug BEFORE implementing the fix. Confirm or refute the root cause analysis. If we refute, we will need to re-hypothesize.

**Test Plan**: Write property-based tests that simulate the lost-UDP-response scenario by calling `peek_many` with cursor values on unfixed code. Run these tests to observe failures and understand the root cause.

**Test Cases**:
1. **Lost Response Recovery Test**: Push messages → peek (creates replay) → peek again with cursor < max replay seq → assert replay entries >= cursor are retained (will fail on unfixed code because peek_many doesn't accept cursor)
2. **Cursor Prunes Confirmed Entries Test**: Push messages → peek → peek with cursor = highest seq → assert only unconfirmed entries remain (will fail on unfixed code)
3. **Cursor Prevents Heuristic Clear Test**: Push messages → peek (creates replay) → peek with cursor but no new messages → assert replay NOT cleared (will fail on unfixed code)

**Expected Counterexamples**:
- `peek_many` clears replay on confirming re-poll regardless of cursor
- Possible causes: no cursor parameter exists, heuristic always fires when queue is empty

### Fix Checking

**Goal**: Verify that for all inputs where the bug condition holds, the fixed function produces the expected behavior.

**Pseudocode:**
```
FOR ALL (channel_state, cursor) WHERE isBugCondition(channel_state, cursor) DO
  result := peek_many_fixed(channel, max, Some(cursor))
  ASSERT all replay entries with seq < cursor are dropped
  ASSERT all replay entries with seq >= cursor are retained
  ASSERT replay buffer is NOT cleared on empty queue when cursor is present
END FOR
```

### Preservation Checking

**Goal**: Verify that for all inputs where the bug condition does NOT hold, the fixed function produces the same result as the original function.

**Pseudocode:**
```
FOR ALL (channel_state) WHERE NOT isBugCondition(channel_state) DO
  ASSERT peek_many_fixed(channel, max, None) = peek_many_original(channel, max)
END FOR
```

**Testing Approach**: Property-based testing is recommended for preservation checking because:
- It generates many channel states automatically (varying message counts, replay sizes, sequences)
- It catches edge cases like empty channels, single-message replay, cursor=0
- It provides strong guarantees that the None-cursor path is unchanged

**Test Plan**: Observe behavior on UNFIXED code first for peek_many with no cursor, then write property-based tests capturing that behavior.

**Test Cases**:
1. **None-Cursor Preservation**: Verify peek_many(channel, max, None) produces identical results to the original peek_many(channel, max) for all channel states
2. **Pop Mode Preservation**: Verify pop_many behavior is completely unchanged regardless of cursor presence in the nonce
3. **Queue Depth Preservation**: Verify queue_depth returns correct values after cursor-based replay pruning
4. **Sweep Preservation**: Verify sweep_expired correctly removes expired entries from both queues after cursor-based operations

### Unit Tests

- Test `peek_many` with cursor=Some(c) drops entries with seq < c
- Test `peek_many` with cursor=Some(c) retains entries with seq >= c
- Test `peek_many` with cursor=Some(c) and empty queue does NOT clear replay
- Test `peek_many` with cursor=None preserves existing behavior
- Test nonce generation with cursor produces valid format
- Test nonce parsing extracts correct cursor value
- Test nonce parsing returns None for legacy nonces

### Property-Based Tests

- Generate random channel states (varying message counts, replay sizes) and verify cursor-based pruning correctness
- Generate random cursor values (u32 range) and verify nonce round-trip (generate → parse → same value)
- Generate random channel states and verify None-cursor path matches original behavior
- Generate random pop-mode queries and verify cursor has no effect

### Integration Tests

- Test full recv flow: build TXT query with cursor nonce → handler parses → peek_many receives cursor → correct replay pruning
- Test backward compatibility: legacy nonce (no cursor) → handler passes None → existing behavior
- Test pop mode with cursor-like nonce suffix → pop_many used, cursor ignored
