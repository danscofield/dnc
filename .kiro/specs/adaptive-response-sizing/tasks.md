# Implementation Plan

- [x] 1. Write bug condition exploration test
  - **Property 1: Bug Condition** — Static max_messages ignores cursor advancement
  - **CRITICAL**: This test MUST FAIL on unfixed code — failure confirms the bug exists
  - **DO NOT attempt to fix the test or the code when it fails**
  - **NOTE**: This test encodes the expected behavior — it will validate the fix when it passes after implementation
  - **GOAL**: Surface counterexamples that demonstrate the broker uses a static `max_messages` regardless of cursor advancement history
  - **Scoped PBT Approach**: For any EDNS0-bearing TXT recv query (edns_udp_size ≥ 1232) in peek mode, generate a sequence of cursor values where the cursor advances between polls. Assert that `max_messages` increases after cursor advancement (additive increase). On unfixed code, `max_messages` is always 2 regardless of cursor history — test will FAIL.
  - **Test location**: `src/store.rs` (test the AIMD algorithm via `update_adaptive_state` once it exists; on unfixed code, the method doesn't exist so test the static formula in `handle_receive` by observing response TXT record counts)
  - **Bug Condition from design**: `isBugCondition(input)` — EDNS0 present with UDP buffer ≥ 1232 AND computed max_messages is static (no per-channel adaptive state)
  - **Expected Behavior from design**: After cursor advances, `max_messages` should increase by 1 (up to ceiling of 8); after stall threshold (2 consecutive stalls), `max_messages` should halve (down to floor of 2)
  - Generate random sequences of advancing cursor values and verify the response message count changes accordingly
  - Run test on UNFIXED code — expect FAILURE (max_messages is always 2, never adapts)
  - Document counterexamples found (e.g., "After 3 cursor advances, max_messages is still 2 instead of expected 5")
  - Mark task complete when test is written, run, and failure is documented
  - _Requirements: 1.1, 1.2, 1.3, 2.1, 2.2, 2.3_

- [x] 2. Write preservation property tests (BEFORE implementing fix)
  - **Property 2: Preservation** — Non-EDNS0, pop mode, and store operations unaffected
  - **IMPORTANT**: Follow observation-first methodology
  - **Test location**: `src/store.rs` tests module and/or `src/handler.rs` tests module
  - Observe on UNFIXED code:
    - Non-EDNS0 queries (edns_udp_size < 1232) always return at most 1 TXT record
    - Pop-mode queries (nonce starts with `P`) use `pop_many` and return correct messages
    - Empty channels return NOERROR with zero answers
    - Store operations (push, pop, pop_many, peek_many, queue_depth, sweep_expired) behave identically
    - Cursor-based replay pruning works correctly
  - Write property-based tests:
    - **Non-EDNS0 preservation**: For all TXT recv queries with edns_udp_size < 1232, response contains at most 1 TXT record regardless of channel state or adaptive state
    - **Pop mode preservation**: For all TXT recv queries with nonce starting with `P`, messages are consumed destructively via pop_many, adaptive state is not consulted or modified
    - **Empty channel preservation**: For all TXT recv queries on empty/nonexistent channels, response is NOERROR with zero answers
    - **Store operation preservation**: push/pop/pop_many/peek_many/queue_depth/sweep_expired produce identical results for non-EDNS0 inputs
  - Verify all tests PASS on UNFIXED code
  - **EXPECTED OUTCOME**: Tests PASS (this confirms baseline behavior to preserve)
  - Mark task complete when tests are written, run, and passing on unfixed code
  - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5_

- [x] 3. Implement adaptive response sizing fix

  - [x] 3.1 Add `AdaptiveState` struct and constants to `src/store.rs`
    - Add constants: `ADAPTIVE_INITIAL_MAX: usize = 2`, `ADAPTIVE_FLOOR: usize = 2`, `ADAPTIVE_CEILING: usize = 8`, `STALL_THRESHOLD: u32 = 2`
    - Add `AdaptiveState` struct with fields: `max_messages: usize` (default 2), `last_cursor_seen: Option<u64>` (default None), `stall_count: u32` (default 0)
    - Implement `Default` for `AdaptiveState` with `max_messages = ADAPTIVE_INITIAL_MAX`
    - Add `pub adaptive: AdaptiveState` field to `Channel` struct
    - Initialize `adaptive: AdaptiveState::default()` in channel auto-creation within `push` and `peek_many`
    - _Bug_Condition: isBugCondition(input) where EDNS0 ≥ 1232 AND max_messages is static_
    - _Expected_Behavior: Per-channel adaptive state tracks delivery success via cursor advancement_
    - _Preservation: Channel auto-creation in push/peek_many must still work identically for all other fields_
    - _Requirements: 2.1, 2.2, 2.3_

  - [x] 3.2 Add `update_adaptive_state` and `get_adaptive_max_messages` methods to `ChannelStore`
    - Implement `update_adaptive_state(&mut self, channel: &str, cursor: Option<u64>) -> usize`:
      - If cursor is None, return current max_messages (no update)
      - If last_cursor_seen is None (first poll), record cursor and return current max_messages
      - If cursor > last_cursor_seen: reset stall_count to 0, increment max_messages by 1 (capped at ADAPTIVE_CEILING)
      - If cursor == last_cursor_seen: increment stall_count; if stall_count >= STALL_THRESHOLD, halve max_messages (floored at ADAPTIVE_FLOOR), reset stall_count
      - If cursor < last_cursor_seen: ignore (stale/reordered query)
      - Always update last_cursor_seen to current cursor
      - Return current effective max_messages
    - Implement `get_adaptive_max_messages(&self, channel: &str) -> usize`:
      - Read-only accessor returning channel's adaptive.max_messages
      - Returns ADAPTIVE_INITIAL_MAX if channel doesn't exist
    - _Bug_Condition: Static max_messages formula in handle_receive ignores cursor feedback_
    - _Expected_Behavior: AIMD algorithm from design pseudocode — additive increase on advance, multiplicative decrease on stall_
    - _Preservation: Method only modifies adaptive state, not messages/replay/replay_cursor_
    - _Requirements: 2.1, 2.2, 2.3_

  - [x] 3.3 Add `max_response_messages` config field to `src/config.rs`
    - Add `pub max_response_messages: Option<usize>` field to `Config` struct with `#[serde(default)]`
    - No default function needed — `Option<usize>` defaults to `None` via serde
    - _Bug_Condition: No config override exists to bypass adaptive logic_
    - _Expected_Behavior: When set, fixed value used for all channels; when None, adaptive mode is default_
    - _Preservation: All existing config fields and parsing behavior unchanged_
    - _Requirements: 2.4, 2.5_

  - [x] 3.4 Update `handle_receive` in `src/handler.rs` to use adaptive max_messages
    - Replace static formula `((edns_udp_size - 100) / 250).max(1).min(2)` with adaptive logic:
      - If `config.max_response_messages` is `Some(n)`: use `n` directly, skip adaptive state update
      - Else if `edns_udp_size >= 1232` (EDNS0 present): call `store.update_adaptive_state(channel, cursor)` to get adaptive max_messages
      - Else (no EDNS0): use `max_messages = 1` (unchanged)
    - Pop mode (`use_pop = true`): use existing EDNS0-based formula (or config override) WITHOUT touching adaptive state
    - Non-EDNS0 path unchanged: `max_messages = 1`
    - _Bug_Condition: handle_receive uses static formula ignoring cursor advancement signal_
    - _Expected_Behavior: handle_receive consults per-channel adaptive state for EDNS0 peek-mode queries_
    - _Preservation: Non-EDNS0 (max 1), pop mode, empty channel, cursor pruning all unchanged_
    - _Requirements: 1.1, 1.2, 1.3, 2.1, 2.2, 2.3, 2.4, 2.5, 3.1, 3.2, 3.3, 3.4_

  - [x] 3.5 Verify bug condition exploration test now passes
    - **Property 1: Expected Behavior** — Adaptive max_messages responds to cursor advancement
    - **IMPORTANT**: Re-run the SAME test from task 1 — do NOT write a new test
    - The test from task 1 encodes the expected behavior (AIMD invariants)
    - When this test passes, it confirms adaptive sizing works correctly
    - Run bug condition exploration test from step 1
    - **EXPECTED OUTCOME**: Test PASSES (confirms bug is fixed — max_messages now adapts based on cursor feedback)
    - _Requirements: 2.1, 2.2, 2.3_

  - [x] 3.6 Verify preservation tests still pass
    - **Property 2: Preservation** — Non-EDNS0, pop mode, and store operations unaffected
    - **IMPORTANT**: Re-run the SAME tests from task 2 — do NOT write new tests
    - Run preservation property tests from step 2
    - **EXPECTED OUTCOME**: Tests PASS (confirms no regressions)
    - Confirm all preservation tests still pass after fix (non-EDNS0 still returns 1, pop mode unchanged, empty channels unchanged, store operations unchanged)

- [x] 4. Checkpoint — Ensure all tests pass
  - Run `cargo test` to verify all existing tests plus new property-based tests pass
  - Ensure no regressions in existing store.rs and handler.rs tests
  - Ensure all property-based tests (bug condition + preservation) pass
  - Ask the user if questions arise
