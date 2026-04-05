# Implementation Plan

- [x] 1. Write bug condition exploration test
  - **Property 1: Bug Condition** - Destructive Pop Loses Messages on Re-poll
  - **CRITICAL**: This test MUST FAIL on unfixed code — failure confirms the bug exists
  - **DO NOT attempt to fix the test or the code when it fails**
  - **NOTE**: This test encodes the expected behavior — it will validate the fix when it passes after implementation
  - **GOAL**: Surface counterexamples that demonstrate messages are permanently lost after `pop_many`
  - **Scoped PBT Approach**: Generate arbitrary non-empty message batches (1–10 messages with random payloads), push them to a channel, call `pop_many` to simulate a poll, then immediately call `pop_many` again (simulating a re-poll after lost response). The property asserts that the second `pop_many` (or future `peek_many`) returns the same messages — i.e., messages remain available for re-delivery.
  - Test that for any channel with N>0 pushed messages, after `pop_many(N)`, a subsequent `pop_many(N)` returns the same N messages (from Bug Condition in design: `isBugCondition` — messages popped AND response lost AND store contains none of them)
  - Also verify `queue_depth` remains > 0 after the first poll (messages not yet confirmed)
  - Run test on UNFIXED code — expect FAILURE (this confirms the bug exists: `pop_many` drains messages, second call returns empty, `queue_depth` returns 0)
  - Document counterexamples found (e.g., "pushed 3 messages, `pop_many(3)` returned them, second `pop_many(3)` returned empty vec, `queue_depth` is 0 — messages permanently lost")
  - Mark task complete when test is written, run, and failure is documented
  - _Requirements: 1.1, 1.2, 2.1, 2.2_

- [x] 2. Write preservation property tests (BEFORE implementing fix)
  - **Property 2: Preservation** - Push, Capacity, Expiry, and Status Semantics Unchanged
  - **IMPORTANT**: Follow observation-first methodology
  - **Observe on UNFIXED code:**
    - `push` stores messages in FIFO order with monotonically increasing sequence numbers
    - `push` returns `ChannelFull` when `max_messages_per_channel` is reached
    - `sweep_expired` removes messages past TTL and inactive channels past inactivity timeout
    - `queue_depth` returns the correct count of pending messages without side effects
    - Empty channel polls return empty results
  - **Write property-based tests capturing observed behavior:**
    - For all sequences of push operations on a channel (random sender_ids, random payloads up to 256 bytes, random channel names): sequence numbers are strictly monotonically increasing and FIFO order is preserved when messages are read back
    - For all push sequences that exceed `max_messages_per_channel`: the (N+1)th push returns `StoreError::ChannelFull`
    - For all store states with messages, after advancing the mock clock past `message_ttl` and calling `sweep_expired`: all expired messages are removed and `queue_depth` returns 0
    - For all store states with channels, after advancing the mock clock past `channel_inactivity_timeout` and calling `sweep_expired`: inactive channels are removed entirely
    - For all channels, calling `queue_depth` twice in succession returns the same value (read-only, no side effects)
  - Verify all tests PASS on UNFIXED code
  - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5_

- [x] 3. Implement replay window fix for non-destructive message delivery

  - [x] 3.1 Add replay buffer and `peek_many` to `ChannelStore` in `src/store.rs`
    - Add `#[derive(Clone)]` to `StoredMessage`
    - Add `replay: VecDeque<StoredMessage>` and `replay_cursor: u64` fields to `Channel`
    - Add `max_replay_size: usize` parameter to `ChannelStore::new`
    - Implement `peek_many(&mut self, channel: &str, max: usize) -> Vec<StoredMessage>`:
      - If replay buffer is non-empty (previous poll not yet superseded), return replay contents first, then new messages up to batch limit
      - Move served messages from `messages` into `replay`
      - When replay exceeds `max_replay_size`, drop oldest entries (sliding window)
    - Update `sweep_expired` to also remove expired messages from replay buffers
    - Keep `queue_depth` returning count of unserved messages in `messages` (not replay)
    - Keep existing `pop_many` available for backward compatibility
    - _Bug_Condition: isBugCondition(input) where pop_many permanently removes messages before delivery confirmation_
    - _Expected_Behavior: peek_many returns messages without permanent removal; re-poll returns same messages until window advances_
    - _Preservation: push semantics, FIFO ordering, capacity limits, TTL expiry, queue_depth accuracy unchanged_
    - _Requirements: 2.1, 2.2, 2.3, 2.4, 3.1, 3.2, 3.3, 3.4, 3.5_

  - [x] 3.2 Replace `pop_many` with `peek_many` in `handle_receive` in `src/handler.rs`
    - Change `store.pop_many(channel, max_messages)` to `store.peek_many(channel, max_messages)`
    - No other changes needed — envelope encoding and response building remain identical
    - _Bug_Condition: handle_receive calls pop_many which destroys messages before UDP response is confirmed delivered_
    - _Expected_Behavior: handle_receive uses peek_many so messages survive response loss_
    - _Preservation: TXT response format, NOERROR for empty channels, envelope encoding unchanged_
    - _Requirements: 2.1, 2.2, 2.5, 3.1_

  - [x] 3.3 Replace `pop_many` with `peek_many` in `DirectTransport::recv_frames` in `crates/dns-socks-proxy/src/transport.rs`
    - Change `store.pop_many(channel, 10)` to `store.peek_many(channel, 10)`
    - Return `Vec<Vec<u8>>` constructed the same way from `msg.payload`
    - _Bug_Condition: DirectTransport::recv_frames calls pop_many which destroys messages if task panics or fails between pop and consumption_
    - _Expected_Behavior: DirectTransport::recv_frames uses peek_many so messages survive failures_
    - _Preservation: Return type and payload format unchanged_
    - _Requirements: 2.5, 3.6_

  - [x] 3.4 Verify bug condition exploration test now passes
    - **Property 1: Expected Behavior** - Destructive Pop Loses Messages on Re-poll
    - **IMPORTANT**: Re-run the SAME test from task 1 — do NOT write a new test
    - The test from task 1 encodes the expected behavior (re-poll returns same messages)
    - When this test passes, it confirms `peek_many` preserves messages for re-delivery
    - Run bug condition exploration test from step 1
    - **EXPECTED OUTCOME**: Test PASSES (confirms bug is fixed)
    - _Requirements: 2.1, 2.2, 2.3, 2.4_

  - [x] 3.5 Verify preservation tests still pass
    - **Property 2: Preservation** - Push, Capacity, Expiry, and Status Semantics Unchanged
    - **IMPORTANT**: Re-run the SAME tests from task 2 — do NOT write new tests
    - Run preservation property tests from step 2
    - **EXPECTED OUTCOME**: Tests PASS (confirms no regressions)
    - Confirm push FIFO ordering, capacity limits, TTL expiry, queue_depth accuracy all unchanged after fix

- [x] 4. Checkpoint — Ensure all tests pass
  - Run full test suite (`cargo test` for both workspace root and `crates/dns-socks-proxy`)
  - Ensure all property-based tests (bug condition + preservation) pass
  - Ensure all existing unit tests in `src/store.rs`, `src/handler.rs`, and `crates/dns-socks-proxy/src/transport.rs` still pass
  - Ask the user if questions arise
