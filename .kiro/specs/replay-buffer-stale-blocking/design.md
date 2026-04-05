# Replay Buffer Stale Blocking Bugfix Design

## Overview

The `peek_many()` method in `src/store.rs` uses a replay buffer to protect against lost UDP DNS responses. However, when multiple sequential SOCKS sessions share a control channel (`ctl-<client_id>`), stale replay frames from a completed session block delivery of new frames for the next session. The current implementation requires 3 poll cycles to fully drain stale replay (deliver → re-deliver → confirming re-poll clears), during which a new session's SYN-ACK is stuck behind stale entries. The fix must allow new messages to be delivered immediately when they exist in the queue, while preserving the replay mechanism for genuine lost-response recovery.

## Glossary

- **Bug_Condition (C)**: The condition where `peek_many()` is called on a channel whose replay buffer contains stale frames from a previous session while new messages exist in the queue, or where the replay buffer blocks delivery by requiring extra poll cycles to clear
- **Property (P)**: New messages in the queue are delivered immediately regardless of replay buffer state; stale replay clears in at most 1 poll cycle (not 2-3)
- **Preservation**: The replay mechanism must still re-deliver the same batch when no new messages have been pushed between polls (lost UDP response recovery)
- **peek_many()**: The method in `ChannelStore` (`src/store.rs`) that non-destructively reads messages, moving served messages from `messages` to `replay` for re-delivery
- **replay buffer**: Per-channel `VecDeque<StoredMessage>` that holds recently-served messages for re-delivery on re-poll
- **replay_cursor**: Sequence number of the oldest message in the replay buffer, used to track the replay window position
- **stale frames**: Replay buffer entries from a completed session that will be discarded by the control dispatcher because the session is deregistered

## Bug Details

### Bug Condition

The bug manifests when `peek_many()` is called on a channel where the replay buffer contains frames from a previous (completed) session, and either (a) new messages have been pushed to the queue, or (b) no new messages exist but the replay takes multiple poll cycles to clear.

In case (a), `peek_many()` returns stale replay frames concatenated with new messages. The stale frames are dispatched to a deregistered session ID and discarded, while the new message (e.g., SYN-ACK) is delayed or buried.

In case (b), `peek_many()` returns the stale replay one more time, then requires a *confirming re-poll* (a third call) to finally clear the replay buffer. This introduces a minimum 2-poll-cycle delay before new messages can be delivered cleanly.

**Formal Specification:**
```
FUNCTION isBugCondition(input)
  INPUT: input of type { channel: String, replay: VecDeque<StoredMessage>, messages: VecDeque<StoredMessage> }
  OUTPUT: boolean

  // Case A: stale replay blocks new messages
  LET hasStaleReplay = input.replay.len() > 0
  LET hasNewMessages = input.messages.len() > 0
  LET caseA = hasStaleReplay AND hasNewMessages

  // Case B: stale replay takes multiple polls to clear when queue is empty
  LET caseB = hasStaleReplay AND NOT hasNewMessages

  RETURN caseA OR caseB
END FUNCTION
```

### Examples

- **Session handover (Case A)**: Session #1 completes, its FIN frame is in replay. Session #2's SYN-ACK is pushed to the queue. `peek_many()` returns `[FIN_replay, SYN-ACK]`. The FIN is dispatched to deregistered session #1 and discarded. SYN-ACK is delivered but was unnecessarily delayed by being batched with stale data.
- **Stale drain delay (Case B, poll 1)**: Replay contains `[FIN]`, queue is empty. `peek_many()` returns `[FIN]` (re-delivery). Replay is NOT cleared because the code only clears on a "confirming re-poll."
- **Stale drain delay (Case B, poll 2)**: Replay still contains `[FIN]`, queue is empty. `peek_many()` enters the `else` branch and clears replay. Returns `[FIN]` again (third delivery of same frame).
- **Stale drain delay (Case B, poll 3)**: Replay is finally empty. New messages can now be delivered. But 2 extra poll cycles were wasted.
- **Expected behavior**: When new messages exist in the queue, `peek_many()` should return only the new messages (not stale replay). When the queue is empty and replay is stale, replay should clear on the first poll that finds no new messages.

## Expected Behavior

### Preservation Requirements

**Unchanged Behaviors:**
- When no new messages have been pushed between two consecutive `peek_many()` calls (genuine re-poll for lost UDP response), the replay buffer must re-deliver the same batch
- Messages must be returned in FIFO order with correct payloads and sequence numbers
- `push()` must continue to reject with `StoreError::ChannelFull` at capacity
- `sweep_expired()` must continue to remove expired messages and inactive channels
- `queue_depth()` must remain read-only with no side effects
- `pop()` and `pop_many()` behavior must be completely unchanged

**Scope:**
All inputs that do NOT involve `peek_many()` with a non-empty replay buffer should be completely unaffected by this fix. This includes:
- Direct `pop()` / `pop_many()` calls (used by `DirectTransport`)
- `push()` operations
- `queue_depth()` queries
- `sweep_expired()` garbage collection
- Status query handling

## Hypothesized Root Cause

Based on the code analysis of `peek_many()` in `src/store.rs` (lines ~175-220), the root cause is the replay buffer clearing logic:

1. **New messages mixed with stale replay**: When `peek_many()` finds a non-empty replay buffer AND new messages in the queue, it returns replay contents first, then drains new messages and appends them. This means stale replay frames are always prepended to new messages, blocking immediate delivery of new data.

2. **Two-phase clearing requires extra poll cycle**: The `else` branch (no new messages drained, replay non-empty) clears the replay buffer but still returns the stale replay contents from the `result` vector that was already populated. The *next* call will find an empty replay and empty queue, finally returning empty. This means clearing takes 2 polls after the last genuine delivery: one to "return and clear," one to "confirm empty."

3. **No distinction between "genuine re-poll" and "stale replay"**: The current code has no mechanism to distinguish between a re-poll for a lost UDP response (where replay should be re-delivered) and a poll where new messages have arrived (where stale replay should be discarded). The fix needs to detect when new messages exist and prioritize them.

## Correctness Properties

Property 1: Bug Condition - New Messages Delivered Immediately Despite Stale Replay

_For any_ channel state where the replay buffer is non-empty AND new messages exist in the `messages` queue, calling `peek_many()` SHALL return the new messages without requiring the caller to first re-consume stale replay entries. The new messages must be present in the returned batch.

**Validates: Requirements 2.1, 2.2**

Property 2: Bug Condition - Replay Clears in One Poll When Queue Empty

_For any_ channel state where the replay buffer is non-empty AND the `messages` queue is empty, calling `peek_many()` SHALL clear the replay buffer such that the immediately subsequent `peek_many()` call returns empty (no additional confirming re-poll required).

**Validates: Requirements 2.3**

Property 3: Preservation - Replay Re-delivers When No New Messages Pushed

_For any_ sequence of messages pushed to a channel, after `peek_many()` moves them to the replay buffer, a subsequent `peek_many()` call (with no intervening `push()`) SHALL return the same messages from the replay buffer, preserving the lost-UDP-response recovery mechanism.

**Validates: Requirements 3.1, 3.2**

Property 4: Preservation - Push/Pop/Sweep Unchanged

_For any_ inputs that do NOT involve `peek_many()` with a non-empty replay buffer, the fixed code SHALL produce exactly the same results as the original code, preserving FIFO ordering, capacity limits, expiry behavior, and queue_depth read-only semantics.

**Validates: Requirements 3.2, 3.3, 3.4, 3.5**

## Fix Implementation

### Changes Required

Assuming our root cause analysis is correct:

**File**: `src/store.rs`

**Function**: `peek_many()`

**Specific Changes**:

1. **Detect new messages and skip stale replay**: When the replay buffer is non-empty AND the `messages` queue is also non-empty, treat the replay as stale. Clear the replay buffer and serve only from the `messages` queue. This handles Case A (session handover).

2. **Immediate replay clearing on empty queue**: When the replay buffer is non-empty AND the `messages` queue is empty, return the replay contents one final time AND clear the replay buffer in the same call. This eliminates the extra "confirming re-poll" cycle (Case B). The current code already returns replay contents but defers clearing to the next call — the fix moves the clear into the same call.

3. **Preserve genuine re-poll behavior**: The key insight is that a "genuine re-poll" (lost UDP response) happens when no new messages have been pushed between polls. In the fixed logic:
   - If replay is non-empty and queue has new messages → stale replay, clear it, serve new messages only
   - If replay is non-empty and queue is empty → re-poll or final drain, return replay and clear it
   - If replay is empty → normal path, serve from queue and populate replay

4. **Update replay_cursor**: After clearing stale replay, reset `replay_cursor` to 0 or update it to reflect the new replay window.

5. **No changes to other methods**: `push()`, `pop()`, `pop_many()`, `queue_depth()`, and `sweep_expired()` remain unchanged.

**Pseudocode for fixed `peek_many()`:**
```
FUNCTION peek_many(channel, max)
  ch = get_channel(channel)
  IF ch is None THEN RETURN []

  IF ch.replay is non-empty AND ch.messages is non-empty THEN
    // Stale replay — new data arrived, discard replay and serve new messages
    ch.replay.clear()
    ch.replay_cursor = 0
    // Fall through to serve from messages queue
  ELSE IF ch.replay is non-empty AND ch.messages is empty THEN
    // Re-poll or final drain — return replay contents and clear
    result = ch.replay.iter().take(max).cloned().collect()
    ch.replay.clear()
    ch.replay_cursor = 0
    RETURN result
  END IF

  // Serve from messages queue (replay is empty at this point)
  new_msgs = ch.messages.drain(..min(max, ch.messages.len()))
  FOR msg IN new_msgs DO
    result.push(msg.clone())
    ch.replay.push_back(msg.clone())
  END FOR

  // Trim replay to max_replay_size
  WHILE ch.replay.len() > max_replay_size DO
    ch.replay.pop_front()
  END WHILE

  // Update replay_cursor
  IF ch.replay.front() exists THEN
    ch.replay_cursor = ch.replay.front().sequence
  END IF

  RETURN result
END FUNCTION
```

## Testing Strategy

### Validation Approach

The testing strategy follows a two-phase approach: first, surface counterexamples that demonstrate the bug on unfixed code, then verify the fix works correctly and preserves existing behavior.

### Exploratory Bug Condition Checking

**Goal**: Surface counterexamples that demonstrate the bug BEFORE implementing the fix. Confirm or refute the root cause analysis. If we refute, we will need to re-hypothesize.

**Test Plan**: Write property-based tests that create replay buffer states and then push new messages, asserting that `peek_many()` delivers new messages immediately. Run these tests on the UNFIXED code to observe failures.

**Test Cases**:
1. **Stale Replay Blocks New Message**: Push messages, peek (creates replay), push new message, peek again — assert new message is in the result without stale replay entries (will fail on unfixed code)
2. **Multi-Cycle Drain Delay**: Push messages, peek (creates replay), peek with empty queue — assert next peek returns empty (will fail on unfixed code because it takes 2 more polls)
3. **Session Handover Scenario**: Simulate session #1 frames in replay, session #2 SYN-ACK in queue — assert SYN-ACK is delivered on first peek (will fail on unfixed code)
4. **Rapid Sequential Sessions**: Multiple push-peek-push cycles simulating rapid session turnover (will fail on unfixed code)

**Expected Counterexamples**:
- `peek_many()` returns stale replay frames concatenated with new messages instead of just new messages
- After replay is populated and queue is empty, it takes 2 additional `peek_many()` calls to get an empty result instead of 1

### Fix Checking

**Goal**: Verify that for all inputs where the bug condition holds, the fixed function produces the expected behavior.

**Pseudocode:**
```
FOR ALL input WHERE isBugCondition(input) DO
  result := peek_many_fixed(input.channel, max)
  IF input.messages.len() > 0 THEN
    ASSERT result contains new messages
    ASSERT result does NOT contain stale replay entries
  ELSE
    // Empty queue with stale replay — returns replay one last time
    next_result := peek_many_fixed(input.channel, max)
    ASSERT next_result is empty  // No extra confirming re-poll needed
  END IF
END FOR
```

### Preservation Checking

**Goal**: Verify that for all inputs where the bug condition does NOT hold, the fixed function produces the same result as the original function.

**Pseudocode:**
```
FOR ALL input WHERE NOT isBugCondition(input) DO
  ASSERT peek_many_original(input) = peek_many_fixed(input)
END FOR
```

**Testing Approach**: Property-based testing is recommended for preservation checking because:
- It generates many test cases automatically across the input domain
- It catches edge cases that manual unit tests might miss
- It provides strong guarantees that behavior is unchanged for all non-buggy inputs

**Test Plan**: Observe behavior on UNFIXED code first for push/pop/sweep/queue_depth operations, then write property-based tests capturing that behavior.

**Test Cases**:
1. **Replay Re-delivery Preserved**: Push N messages, peek (creates replay), peek again with no new pushes — assert same messages returned (must pass on both unfixed and fixed code)
2. **FIFO Order Preserved**: Push messages, peek_many — assert FIFO order with correct payloads and sequences
3. **Push/Pop Unchanged**: Verify push, pop, pop_many behavior is identical
4. **Sweep Unchanged**: Verify sweep_expired removes expired messages and inactive channels correctly
5. **Queue Depth Unchanged**: Verify queue_depth is read-only

### Unit Tests

- Test peek_many with stale replay + new messages → new messages delivered immediately
- Test peek_many with stale replay + empty queue → clears in one poll
- Test peek_many with empty replay + new messages → normal delivery path
- Test peek_many with empty replay + empty queue → returns empty
- Test replay re-delivery when no new messages pushed between polls

### Property-Based Tests

- Generate random message sequences and verify new messages are always delivered immediately when replay is stale
- Generate random replay states and verify clearing happens in at most 1 extra poll cycle
- Generate random push/peek sequences and verify FIFO order is always maintained
- Generate random store states and verify push/pop/sweep/queue_depth behavior is unchanged

### Integration Tests

- Test full session handover scenario: session #1 frames in replay, session #2 SYN-ACK delivery
- Test rapid sequential sessions on shared control channel
- Test that control channel poller receives frames without stale blocking delay
