# Adaptive Response Sizing Bugfix Design

## Overview

The broker's `handle_receive` in `src/handler.rs` calculates `max_messages` for EDNS0 TXT responses using a formula that can yield up to 4-5 messages, producing DNS UDP responses of ~1300 bytes. Recursive resolvers (e.g., Cloudflare 1.1.1.1) silently drop these oversized responses, causing sessions to stall and eventually RST. A temporary hard cap of `max_messages = 2` prevents drops but wastes bandwidth when the resolver can handle more.

The fix introduces per-channel adaptive response sizing using an AIMD (Additive Increase, Multiplicative Decrease) algorithm — the same principle as TCP congestion control. The broker observes cursor advancement patterns in TXT recv queries: when the cursor advances (response got through), it increases `max_messages`; when the cursor stalls (response likely dropped), it decreases. A CLI/config override allows operators to bypass adaptive logic with a fixed value.

## Glossary

- **Bug_Condition (C)**: EDNS0 is present and the broker's `max_messages` calculation yields a value that produces an oversized UDP response, which the recursive resolver silently drops
- **Property (P)**: The broker adapts `max_messages` per-channel based on cursor advancement feedback, starting conservatively and growing only when responses are confirmed received
- **Preservation**: Non-EDNS0 queries (max 1 message), pop mode, cursor-based replay pruning, empty-channel behavior, and embedded mode must remain unchanged
- **`handle_receive`**: Function in `src/handler.rs` that processes TXT recv queries and determines how many messages to batch into the response
- **`AdaptiveState`**: New per-channel struct tracking `max_messages`, `last_cursor_seen`, and `stall_count` for the AIMD algorithm
- **AIMD**: Additive Increase / Multiplicative Decrease — increase `max_messages` by 1 on cursor advance, halve on stall (floor to minimum)
- **Cursor**: The client's highest confirmed store sequence number, encoded as `-c<number>` in the TXT query nonce

## Bug Details

### Bug Condition

The bug manifests when EDNS0 is present with a UDP buffer ≥1232 bytes and the broker batches too many messages into a single TXT response. The resulting UDP packet exceeds what the recursive resolver will forward, causing silent drops. The client never receives downstream data and the session stalls.

**Formal Specification:**
```
FUNCTION isBugCondition(input)
  INPUT: input of type TxtRecvQuery
  OUTPUT: boolean

  RETURN input.edns_udp_size >= 1232
         AND computed_max_messages(input.edns_udp_size) > safe_threshold_for_resolver
         AND response_size(messages, computed_max_messages) > resolver_forward_limit
END FUNCTION
```

### Examples

- Client polls with EDNS0 buffer=4096. Old formula: `(4096-100)/250 = 15`, capped to 2 by temporary fix. Without cap, broker returns 15 TXT records (~4000 bytes), resolver drops the response. Client retransmits forever.
- Client polls with EDNS0 buffer=1232. Old formula: `(1232-100)/250 = 4`. Broker returns 4 TXT records (~1100 bytes). Some resolvers forward this, others drop it. Unpredictable.
- With adaptive fix: new channel starts at `max_messages=2` (~500 bytes). Client cursor advances → broker increases to 3. Cursor advances again → 4. Cursor stalls → broker halves to 2. Finds the resolver's sweet spot.
- Edge case: client never sends cursor (legacy `dnc` with pop mode) → adaptive state not consulted, pop_many used directly.

## Expected Behavior

### Preservation Requirements

**Unchanged Behaviors:**
- Non-EDNS0 queries (UDP buffer < 1232) return at most 1 message per response
- Pop mode (nonce starts with `P`) uses `pop_many` unaffected by adaptive sizing
- Cursor-based replay pruning (`sequence < cursor` dropped) works exactly as before
- Empty channels return NOERROR with zero answers
- Embedded mode via `DirectTransport` functions identically (adaptive state is in the store)
- Send operations (A queries), status queries, and sweep behavior are completely unaffected

**Scope:**
All inputs that do NOT involve EDNS0-bearing TXT recv queries in peek mode should be completely unaffected by this fix. This includes:
- All A queries (send operations)
- TXT queries without EDNS0 (max_messages stays at 1)
- Pop-mode TXT queries (nonce starts with `P`)
- Status queries
- Store operations: push, pop, pop_many, queue_depth, sweep_expired

## Hypothesized Root Cause

Based on the bug description, the root cause is the static `max_messages` calculation in `handle_receive`:

1. **No feedback loop**: The current formula `((edns_udp_size - 100) / 250).max(1).min(2)` (with the temporary cap) uses only the client's advertised EDNS0 buffer size. It has no information about whether the recursive resolver between client and broker will actually forward responses of that size.

2. **Resolver behavior is opaque**: Different recursive resolvers have different UDP forwarding limits. Cloudflare drops responses above ~512-600 bytes in some configurations. Google DNS may forward larger responses. The broker cannot know the limit a priori.

3. **Cursor advancement is an unused signal**: The cursor-based replay system already provides a reliable signal for whether responses are getting through. When the cursor advances, the previous response was received. When it stalls, the response was likely dropped. This signal is currently ignored for sizing decisions.

4. **Per-channel state is missing**: The `Channel` struct in `src/store.rs` has no fields for tracking delivery success patterns. The `max_messages` decision is made statelessly in `handle_receive` on every query.

## Correctness Properties

Property 1: Bug Condition — Adaptive state starts conservatively for new channels

_For any_ channel with no prior adaptive state (new or reset), when an EDNS0-bearing TXT recv query arrives, the effective `max_messages` SHALL be the initial conservative value (2), regardless of the EDNS0 advertised buffer size.

**Validates: Requirements 2.1**

Property 2: Bug Condition — Cursor advancement increases max_messages

_For any_ channel where the client's cursor advances between consecutive polls (cursor > last_cursor_seen), the adaptive algorithm SHALL increase `max_messages` by 1 (additive increase), up to the configured ceiling.

**Validates: Requirements 2.2**

Property 3: Bug Condition — Cursor stall decreases max_messages

_For any_ channel where the client's cursor does NOT advance across consecutive polls (cursor == last_cursor_seen for two or more polls), the adaptive algorithm SHALL reduce `max_messages` by halving it (multiplicative decrease), down to the configured floor (2).

**Validates: Requirements 2.3**

Property 4: Bug Condition — Config override bypasses adaptive logic

_For any_ channel state and any cursor advancement pattern, when `max_response_messages` is set in the config, the effective `max_messages` SHALL equal the configured override value, and adaptive state SHALL NOT be updated.

**Validates: Requirements 2.4, 2.5**

Property 5: Preservation — Non-EDNS0 queries unaffected

_For any_ TXT recv query where `edns_udp_size < 1232`, the effective `max_messages` SHALL be 1, regardless of adaptive state or config override, preserving the existing single-message behavior for non-EDNS0 clients.

**Validates: Requirements 3.1**

Property 6: Preservation — Pop mode unaffected by adaptive sizing

_For any_ TXT recv query where the nonce starts with `P` (pop mode), the handler SHALL use `pop_many` with the same sizing logic as before (EDNS0-based, not adaptive), and SHALL NOT read or update the channel's adaptive state.

**Validates: Requirements 3.2**

## Fix Implementation

### Changes Required

Assuming our root cause analysis is correct:

**File**: `src/store.rs`

**Struct**: `Channel`

**Specific Changes**:
1. **Add `AdaptiveState` struct**: New struct with fields:
   - `max_messages: usize` — current adaptive limit (default: 2)
   - `last_cursor_seen: Option<u64>` — cursor value from the previous poll
   - `stall_count: u32` — consecutive polls where cursor did not advance
2. **Add `adaptive` field to `Channel`**: `pub adaptive: AdaptiveState`
3. **Initialize in `push` and `peek_many`**: When a channel is auto-created, initialize `AdaptiveState` with defaults

**File**: `src/store.rs`

**Function**: New `update_adaptive_state` method on `ChannelStore`

**Specific Changes**:
1. **Cursor comparison**: Compare incoming cursor with `last_cursor_seen`
2. **Advance path**: If `cursor > last_cursor_seen`, set `stall_count = 0`, increment `max_messages` by 1 (capped at ceiling, e.g., 8)
3. **Stall path**: If `cursor == last_cursor_seen`, increment `stall_count`. If `stall_count >= 2`, halve `max_messages` (floored at 2), reset `stall_count`
4. **Update `last_cursor_seen`**: Always update to the current cursor value
5. **Return**: The current effective `max_messages`

**File**: `src/store.rs`

**Function**: New `get_adaptive_max_messages` method on `ChannelStore`

**Specific Changes**:
1. **Read-only accessor**: Returns the channel's current `adaptive.max_messages` without modifying state
2. **Default for missing channels**: Returns the initial conservative value (2) if the channel doesn't exist

**File**: `src/handler.rs`

**Function**: `handle_receive`

**Specific Changes**:
1. **Replace static formula**: Instead of `((edns_udp_size - 100) / 250).max(1).min(2)`, use the channel's adaptive `max_messages` when EDNS0 is present
2. **Update adaptive state**: After extracting the cursor from the nonce, call `update_adaptive_state(channel, cursor)` before building the response
3. **Config override**: If `config.max_response_messages` is `Some(n)`, use `n` directly and skip adaptive state update
4. **Non-EDNS0 unchanged**: When `edns_udp_size < 1232`, continue returning `max_messages = 1`
5. **Pop mode unchanged**: When `use_pop` is true, use the existing EDNS0-based formula (or fixed override) without touching adaptive state

**File**: `src/config.rs`

**Struct**: `Config`

**Specific Changes**:
1. **Add optional field**: `pub max_response_messages: Option<usize>` with `#[serde(default)]`
2. **No default function needed**: `Option<usize>` defaults to `None` via serde

**File**: `src/main.rs` (or CLI argument parsing)

**Specific Changes**:
1. **Add CLI flag**: `--max-response-messages N` that sets `config.max_response_messages = Some(N)`
2. **TOML support**: The field is already serde-deserializable from the config file

### Constants

```
ADAPTIVE_INITIAL_MAX: usize = 2      // Conservative starting point
ADAPTIVE_FLOOR: usize = 2            // Minimum max_messages (never go below)
ADAPTIVE_CEILING: usize = 8          // Maximum max_messages (never exceed)
STALL_THRESHOLD: u32 = 2             // Consecutive stalls before decrease
```

### Algorithm Pseudocode

```
FUNCTION update_adaptive_state(channel, cursor)
  state := channel.adaptive

  IF cursor IS None THEN
    RETURN state.max_messages  // No cursor, no update
  END IF

  IF state.last_cursor_seen IS None THEN
    // First poll with cursor — just record it
    state.last_cursor_seen := cursor
    state.stall_count := 0
    RETURN state.max_messages
  END IF

  IF cursor > state.last_cursor_seen THEN
    // Cursor advanced — response got through
    state.stall_count := 0
    state.max_messages := MIN(state.max_messages + 1, ADAPTIVE_CEILING)
  ELSE IF cursor == state.last_cursor_seen THEN
    // Cursor stalled — response may have been dropped
    state.stall_count := state.stall_count + 1
    IF state.stall_count >= STALL_THRESHOLD THEN
      state.max_messages := MAX(state.max_messages / 2, ADAPTIVE_FLOOR)
      state.stall_count := 0
    END IF
  END IF
  // cursor < last_cursor_seen: ignore (stale/reordered query)

  state.last_cursor_seen := cursor
  RETURN state.max_messages
END FUNCTION
```

## Testing Strategy

### Validation Approach

The testing strategy follows a two-phase approach: first, surface counterexamples that demonstrate the bug on unfixed code, then verify the fix works correctly and preserves existing behavior.

### Exploratory Bug Condition Checking

**Goal**: Surface counterexamples that demonstrate the bug BEFORE implementing the fix. Confirm or refute the root cause analysis. If we refute, we will need to re-hypothesize.

**Test Plan**: Write tests that exercise `handle_receive` with EDNS0-bearing queries and observe the static `max_messages` behavior. Run these tests on the UNFIXED code to confirm the formula produces a fixed value regardless of cursor advancement patterns.

**Test Cases**:
1. **Static Max Messages Test**: Send multiple TXT queries with advancing cursors to the same channel. Assert that `max_messages` changes between queries (will fail on unfixed code because the value is always 2).
2. **No Per-Channel State Test**: Send queries to two different channels with different cursor patterns. Assert that each channel has independent `max_messages` (will fail on unfixed code because there is no per-channel state).
3. **Config Override Ignored Test**: Set a config override and verify it's used (will fail on unfixed code because the config field doesn't exist).

**Expected Counterexamples**:
- `max_messages` is always 2 regardless of cursor advancement history
- No per-channel adaptive state exists
- Possible causes: static formula in handle_receive, no AdaptiveState struct, no config field

### Fix Checking

**Goal**: Verify that for all inputs where the bug condition holds, the fixed function produces the expected behavior.

**Pseudocode:**
```
FOR ALL (channel_state, cursor_sequence) WHERE isBugCondition(channel_state) DO
  FOR EACH cursor IN cursor_sequence DO
    max_msgs := update_adaptive_state(channel, cursor)
    IF cursor advanced THEN
      ASSERT max_msgs >= previous_max_msgs  // non-decreasing on advance
    ELSE IF cursor stalled >= STALL_THRESHOLD THEN
      ASSERT max_msgs <= previous_max_msgs  // non-increasing on stall
    END IF
    ASSERT max_msgs >= ADAPTIVE_FLOOR
    ASSERT max_msgs <= ADAPTIVE_CEILING
  END FOR
END FOR
```

### Preservation Checking

**Goal**: Verify that for all inputs where the bug condition does NOT hold, the fixed function produces the same result as the original function.

**Pseudocode:**
```
FOR ALL input WHERE NOT isBugCondition(input) DO
  ASSERT handle_receive_fixed(input) = handle_receive_original(input)
END FOR
```

**Testing Approach**: Property-based testing is recommended for preservation checking because:
- It generates many query configurations automatically (varying EDNS0 sizes, nonce formats, channel states)
- It catches edge cases like EDNS0 size exactly at 1232, empty channels, pop mode with cursor-like nonces
- It provides strong guarantees that non-EDNS0 and pop-mode paths are unchanged

**Test Plan**: Observe behavior on UNFIXED code first for non-EDNS0 queries and pop-mode queries, then write property-based tests capturing that behavior.

**Test Cases**:
1. **Non-EDNS0 Preservation**: Verify that queries with `edns_udp_size < 1232` always produce at most 1 TXT record, regardless of adaptive state
2. **Pop Mode Preservation**: Verify that pop-mode queries use `pop_many` and do not read or update adaptive state
3. **Cursor Pruning Preservation**: Verify that cursor-based replay pruning in `peek_many` continues to work correctly alongside adaptive sizing
4. **Empty Channel Preservation**: Verify that empty channels return NOERROR with zero answers regardless of adaptive state

### Unit Tests

- Test `AdaptiveState` initialization defaults to `max_messages = 2`
- Test `update_adaptive_state` with advancing cursor increases `max_messages`
- Test `update_adaptive_state` with stalling cursor decreases `max_messages` after threshold
- Test `update_adaptive_state` with `cursor < last_cursor_seen` is ignored
- Test `max_messages` never exceeds ceiling (8) or drops below floor (2)
- Test config override bypasses adaptive logic entirely
- Test non-EDNS0 queries always return 1 message

### Property-Based Tests

- Generate random sequences of cursor values and verify AIMD invariants hold (max_messages always in [floor, ceiling], monotonic increase on advance, decrease on stall)
- Generate random channel states with adaptive state and verify config override always wins
- Generate random non-EDNS0 queries and verify max_messages is always 1
- Generate random pop-mode queries and verify adaptive state is untouched

### Integration Tests

- Test full recv flow: EDNS0 query with cursor → handler reads adaptive state → peek_many uses adaptive max_messages → response contains correct number of TXT records
- Test multi-channel independence: two channels with different cursor patterns have independent adaptive states
- Test config override: set `max_response_messages = 5` → all channels use 5 regardless of cursor patterns
