# Destructive Pop Data Loss Bugfix Design

## Overview

The broker's `pop_many` operation permanently removes messages from channel queues the instant a client polls. Since the transport is DNS over UDP — inherently unreliable — the response carrying those messages can be silently lost. The client never receives the data, its reassembly buffer develops gaps, ACKs are never sent, and the sender eventually RSTs the session.

The fix introduces a **replay window** in the broker's `ChannelStore`. Instead of destructively draining messages on poll, the store keeps a per-channel read cursor and retains recently-served messages in a replay buffer. If the client re-polls (because the previous DNS response was lost), it receives the same messages again. Messages are only permanently removed when they expire via TTL or when the replay window advances past them. The client's existing `ReassemblyBuffer` already discards duplicates, so re-delivery is safe without any protocol changes.

## Glossary

- **Bug_Condition (C)**: A client polls a data channel (TXT query or `DirectTransport::recv_frames`) and the DNS/UDP response is lost — the broker has already destroyed the messages via `pop_many`, so they cannot be re-delivered.
- **Property (P)**: Messages returned by a poll remain available for re-delivery until the replay window advances past them (via a subsequent successful poll or TTL expiry).
- **Preservation**: All existing behaviors — push semantics, FIFO ordering, capacity limits, TTL expiry, status queries, send path, client-side duplicate detection — must remain unchanged.
- **`pop_many`**: The method in `ChannelStore` (`src/store.rs`) that destructively drains up to N messages from a channel's `VecDeque`.
- **`handle_receive`**: The function in `src/handler.rs` that handles TXT queries by calling `pop_many` and encoding messages as TXT records.
- **`DirectTransport::recv_frames`**: The embedded-mode transport in `crates/dns-socks-proxy/src/transport.rs` that calls `pop_many` directly on the shared store.
- **Replay Window**: A bounded buffer of recently-served messages that can be re-delivered if the client re-polls.
- **Read Cursor**: A per-channel sequence number tracking the oldest unserved message; advances when the replay window slides forward.

## Bug Details

### Bug Condition

The bug manifests when a client polls a data channel and the broker returns messages that are then lost on the network. Because `pop_many` uses `VecDeque::drain`, the messages are permanently gone from the broker. The client's next poll returns only newer messages (if any), leaving a gap in the sequence space that `drain_contiguous` can never bridge.

**Formal Specification:**
```
FUNCTION isBugCondition(input)
  INPUT: input of type PollEvent { channel: String, response_lost: bool }
  OUTPUT: boolean

  messages := store.pop_many(input.channel, max_batch)
  RETURN messages.is_not_empty()
         AND input.response_lost == true
         AND store.queue_contains_none_of(messages)
END FUNCTION
```

### Examples

- Client polls channel "d-abc123", broker pops messages [seq 0, 1, 2] and returns them as TXT records. The UDP response is dropped by the network. Client re-polls — broker returns empty (or only seq 3+). Client's reassembly buffer has gap at 0-2, `drain_contiguous` returns nothing, no ACK is sent, sender eventually RSTs.
- In embedded mode, `DirectTransport::recv_frames` calls `pop_many(channel, 10)`. If the calling code fails to process the returned `Vec<Vec<u8>>` (e.g., task panic between pop and consumption), those messages are lost.
- Client polls a channel with 5 messages. Broker pops all 5. DNS response is truncated by an intermediate resolver that doesn't support EDNS0. Client receives 0 messages. All 5 are permanently lost.
- Client polls an empty channel — no messages are popped, no data loss. (Not a bug condition.)

## Expected Behavior

### Preservation Requirements

**Unchanged Behaviors:**
- `push` stores messages in FIFO order with monotonic sequence numbers, capacity limits, and TTL expiry
- Empty channel polls return NOERROR with zero TXT answers
- `ChannelFull` error is returned when `max_messages_per_channel` is reached
- `sweep_expired` removes messages past TTL and inactive channels past inactivity timeout
- `queue_depth` / status queries return the correct count of unconsumed messages without side effects
- The send path (`handle_send` / `push`) requires no protocol changes
- Client-side `ReassemblyBuffer` duplicate detection and `RetransmitBuffer` ACK processing are unmodified

**Scope:**
All inputs that do NOT involve polling a data channel (TXT queries / `DirectTransport::recv_frames`) are completely unaffected. This includes:
- A/AAAA send queries
- Status queries
- Push operations
- Expiry sweeps
- Client-side frame processing

## Hypothesized Root Cause

Based on the code analysis, the root cause is straightforward:

1. **Destructive drain in `pop_many`**: `ChannelStore::pop_many` calls `ch.messages.drain(..count)` which permanently removes messages from the `VecDeque`. There is no copy, no replay buffer, and no way to recover them.

2. **No delivery confirmation**: `handle_receive` calls `pop_many`, encodes the messages into TXT records, builds a DNS response, and returns the bytes. The messages are already gone from the store before the UDP packet even leaves the server. There is no mechanism for the client to confirm receipt.

3. **Same issue in `DirectTransport`**: `DirectTransport::recv_frames` calls `store.write().await` then `pop_many(channel, 10)`, returning owned `Vec<Vec<u8>>`. If anything goes wrong after the pop (task cancellation, panic), the messages are lost.

4. **UDP's unreliability is the trigger**: DNS over UDP provides no delivery guarantee. Packet loss rates of 1-5% are normal on the internet, and DNS responses can also be dropped by intermediate resolvers, firewalls, or rate limiters.

## Correctness Properties

Property 1: Bug Condition - Polled Messages Remain Available for Re-delivery

_For any_ poll of a non-empty channel, the messages returned by the poll SHALL remain available in the store's replay window such that an identical subsequent poll (before the replay window advances) returns the same messages. The store's logical queue depth SHALL NOT decrease until the replay window slides forward.

**Validates: Requirements 2.1, 2.2**

Property 2: Replay Window Advancement - Acknowledged Messages Are Removed

_For any_ sequence of polls where the replay window advances (because a new poll requests messages beyond the current cursor), the previously-served messages that fall outside the replay window SHALL be permanently removed from the store, and the queue depth SHALL decrease accordingly.

**Validates: Requirements 2.3, 2.4**

Property 3: Preservation - Push and Capacity Semantics Unchanged

_For any_ sequence of push operations, the store SHALL maintain FIFO ordering, monotonic sequence numbering, and return `ChannelFull` at the configured capacity limit, identically to the original implementation.

**Validates: Requirements 3.2, 3.3**

Property 4: Preservation - Expiry and Sweep Unchanged

_For any_ store state, `sweep_expired` SHALL remove messages past their TTL (including messages in the replay window) and inactive channels past their inactivity timeout, identically to the original implementation.

**Validates: Requirements 3.4, 3.5**

## Fix Implementation

### Approach Selection

Three approaches were considered:

| Approach | Pros | Cons |
|----------|------|------|
| Peek + explicit ACK | Most robust, exact delivery semantics | Adds a round-trip per batch (expensive over DNS) |
| Cursor-based consumption | Per-consumer tracking, precise | Requires consumer identity tracking, complex |
| Replay window (selected) | No protocol changes, simple, client already handles duplicates | May re-deliver already-received messages (safe due to ReassemblyBuffer) |

**Selected: Replay Window.** This approach is the best fit because:
- No protocol changes needed — the client just re-polls and gets the same messages
- The client's `ReassemblyBuffer::insert` already returns `false` for duplicates
- Implementation is contained entirely in the broker layer (`store.rs` + `handler.rs`)
- No extra DNS round-trips (the most expensive resource in this system)

### Changes Required

**File**: `src/store.rs`

**Struct**: `Channel`

**Specific Changes**:
1. **Add replay buffer to `Channel`**: Add a `replay: VecDeque<StoredMessage>` field that holds recently-served messages. Add a `replay_cursor: u64` tracking the sequence number of the oldest message in the replay buffer.

2. **New `peek_many` method**: Instead of draining from `messages`, copy/clone up to N messages starting from the read cursor. Move served messages from `messages` into `replay`. Return references or clones.

3. **Replay window sliding**: When `peek_many` is called and the replay buffer exceeds a configurable `max_replay_size`, drop the oldest entries from the replay buffer. This implicitly "acknowledges" old messages — the window slides forward as new polls arrive.

4. **Re-delivery on re-poll**: If `peek_many` is called and the replay buffer is non-empty (previous poll's messages haven't been superseded), return the replay buffer contents first, then any new messages up to the batch limit.

5. **Make `StoredMessage` cloneable**: Add `#[derive(Clone)]` to `StoredMessage` so messages can exist in both the replay buffer and be returned to callers.

**File**: `src/store.rs`

**Struct**: `ChannelStore`

**Specific Changes**:
6. **Add `max_replay_size` config**: Add a constructor parameter controlling the replay window size (e.g., 32 messages). This bounds memory usage.

7. **Replace `pop_many` usage**: Add `peek_many` as the primary read method. Keep `pop_many` available but mark it for internal/test use. `peek_many` returns messages without permanently removing them.

8. **Update `sweep_expired`**: Ensure expired messages are also removed from the replay buffer, not just from the main queue.

9. **Update `queue_depth`**: Return the count of messages that haven't been served yet (main queue length), NOT including replay buffer entries. This keeps status queries accurate for "new data available" semantics.

**File**: `src/handler.rs`

**Function**: `handle_receive`

**Specific Changes**:
10. **Replace `pop_many` with `peek_many`**: Change the call from `store.pop_many(channel, max_messages)` to `store.peek_many(channel, max_messages)`. The rest of the function (encoding, response building) stays identical.

**File**: `crates/dns-socks-proxy/src/transport.rs`

**Struct**: `DirectTransport`

**Specific Changes**:
11. **Replace `pop_many` with `peek_many`**: In `DirectTransport::recv_frames`, change `store.pop_many(channel, 10)` to `store.peek_many(channel, 10)`. The returned `Vec<Vec<u8>>` is constructed the same way.

## Testing Strategy

### Validation Approach

The testing strategy follows a two-phase approach: first, surface counterexamples that demonstrate the bug on unfixed code, then verify the fix works correctly and preserves existing behavior.

### Exploratory Bug Condition Checking

**Goal**: Surface counterexamples that demonstrate the bug BEFORE implementing the fix. Confirm or refute the root cause analysis. If we refute, we will need to re-hypothesize.

**Test Plan**: Write tests that push messages to a channel, call `pop_many` to simulate a poll, then verify the messages are gone from the store. Run these tests on the UNFIXED code to observe the destructive behavior.

**Test Cases**:
1. **Destructive Pop Test**: Push 3 messages, call `pop_many(3)`, verify `queue_depth` is 0 and a second `pop_many` returns empty (will demonstrate the bug on unfixed code)
2. **Lost Response Simulation**: Push messages, pop them, simulate "response lost" by not processing the returned messages, verify they cannot be recovered (will demonstrate the bug on unfixed code)
3. **DirectTransport Destructive Test**: Push messages via store, call `DirectTransport::recv_frames`, verify messages are gone from store (will demonstrate the bug on unfixed code)
4. **Gap Creation Test**: Push seq 0-4, pop seq 0-2 (simulating first poll), then pop seq 3-4 (simulating second poll). Verify that if first poll's response is lost, seq 0-2 are unrecoverable (will demonstrate the bug on unfixed code)

**Expected Counterexamples**:
- After `pop_many`, `queue_depth` returns 0 and subsequent polls return empty
- Messages are permanently destroyed even though no client confirmed receipt
- Possible root cause confirmed: `VecDeque::drain` is the destructive operation

### Fix Checking

**Goal**: Verify that for all inputs where the bug condition holds, the fixed function produces the expected behavior.

**Pseudocode:**
```
FOR ALL input WHERE isBugCondition(input) DO
  messages := store.peek_many(input.channel, batch_size)
  // Simulate lost response — don't process messages
  messages_again := store.peek_many(input.channel, batch_size)
  ASSERT messages == messages_again  // same messages re-delivered
  ASSERT store.queue_depth(input.channel) > 0  // messages still counted
END FOR
```

### Preservation Checking

**Goal**: Verify that for all inputs where the bug condition does NOT hold, the fixed function produces the same result as the original function.

**Pseudocode:**
```
FOR ALL input WHERE NOT isBugCondition(input) DO
  ASSERT push_original(input) == push_fixed(input)
  ASSERT queue_depth_original(input) == queue_depth_fixed(input)
  ASSERT sweep_expired_original(input) == sweep_expired_fixed(input)
END FOR
```

**Testing Approach**: Property-based testing is recommended for preservation checking because:
- It generates many test cases automatically across the input domain
- It catches edge cases that manual unit tests might miss
- It provides strong guarantees that behavior is unchanged for all non-buggy inputs

**Test Plan**: Observe behavior on UNFIXED code first for push, queue_depth, and sweep operations, then write property-based tests capturing that behavior.

**Test Cases**:
1. **Push Preservation**: Observe that push stores messages in FIFO order with monotonic sequences on unfixed code, then verify this continues after fix
2. **Capacity Preservation**: Observe that ChannelFull is returned at max capacity on unfixed code, then verify this continues after fix
3. **Expiry Preservation**: Observe that sweep_expired removes expired messages and inactive channels on unfixed code, then verify this continues after fix (including replay buffer entries)
4. **Status Query Preservation**: Observe that queue_depth returns correct counts on unfixed code, then verify this continues after fix

### Unit Tests

- Test `peek_many` returns messages without removing them from the store
- Test replay window: peek, then peek again returns same messages
- Test replay window sliding: after enough new polls, old replay entries are dropped
- Test `sweep_expired` cleans up replay buffer entries past TTL
- Test `queue_depth` reflects unserved messages accurately
- Test `handle_receive` with `peek_many` produces identical TXT responses
- Test `DirectTransport::recv_frames` with `peek_many` returns same payloads

### Property-Based Tests

- Generate random sequences of push + peek operations and verify messages are never lost (re-peekable until window slides)
- Generate random push sequences and verify FIFO ordering and capacity limits are preserved
- Generate random time advances and verify expiry behavior is preserved for both main queue and replay buffer
- Generate random interleaved push/peek/sweep sequences and verify queue_depth consistency

### Integration Tests

- Test full send → peek → re-peek cycle through `handle_send` and `handle_receive`
- Test that `DirectTransport::recv_frames` returns consistent results on repeated calls
- Test that status queries reflect correct depth after peek (messages still counted until window slides)
