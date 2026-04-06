# Implementation Plan

- [x] 1. Write bug condition exploration test
  - **Property 1: Bug Condition** — Cursor-bearing peek_many drops only confirmed replay entries
  - **CRITICAL**: This test MUST FAIL on unfixed code — failure confirms the bug exists
  - **DO NOT attempt to fix the test or the code when it fails**
  - **NOTE**: This test encodes the expected behavior — it will validate the fix when it passes after implementation
  - **GOAL**: Surface counterexamples that demonstrate the bug exists
  - **Scoped PBT Approach**: For deterministic bugs, scope the property to concrete failing cases where `peek_many` is called with a cursor value on a channel with replay entries
  - Write a property-based test in `src/store.rs` (or a dedicated test file) that:
    1. Pushes N messages to a channel (generating sequences s0..sN-1)
    2. Calls `peek_many(channel, max)` to move messages into the replay buffer
    3. Calls `peek_many(channel, max, Some(cursor))` where cursor is between s0 and sN-1
    4. Asserts: replay entries with `sequence < cursor` are dropped
    5. Asserts: replay entries with `sequence >= cursor` are retained and returned
    6. Asserts: replay buffer is NOT cleared on empty queue when cursor is present
  - `isBugCondition`: channel has non-empty replay buffer AND `peek_many` is called with `Some(cursor)` AND client has not received all replayed frames
  - `expectedBehavior`: only replay entries with `sequence >= cursor` are returned; entries with `sequence < cursor` are pruned; replay is NOT cleared heuristically
  - Run test on UNFIXED code — the current `peek_many` signature does not accept a cursor parameter, so the test will fail to compile or will demonstrate the heuristic clearing behavior
  - **EXPECTED OUTCOME**: Test FAILS (this is correct — it proves the bug exists)
  - Document counterexamples found to understand root cause
  - Mark task complete when test is written, run, and failure is documented
  - _Requirements: 2.3, 2.4_

- [x] 2. Write preservation property tests (BEFORE implementing fix)
  - **Property 2: Preservation** — Non-cursor peek_many retains existing two-phase behavior
  - **IMPORTANT**: Follow observation-first methodology
  - Observe behavior on UNFIXED code for non-buggy inputs (all cases where cursor is `None`)
  - Write property-based tests in `src/store.rs` capturing observed behavior patterns:
    1. **None-cursor two-phase replay**: For any channel state, `peek_many(channel, max, None)` produces the same result as the original `peek_many(channel, max)` — replay returned once, cleared on confirming re-poll
    2. **Pop mode unaffected**: For any TXT recv query where nonce starts with `P`, `pop_many` is used regardless of cursor presence — destructive consume-once semantics preserved
    3. **Push FIFO and monotonic sequences**: Push operations continue to assign strictly increasing sequence numbers and maintain FIFO order
    4. **Queue depth accuracy**: `queue_depth` returns `messages.len() + replay.len()` correctly after cursor-based operations
    5. **Sweep preservation**: `sweep_expired` removes expired messages from both queues and inactive channels
  - Observe: `peek_many("ch", 10)` with no cursor returns messages, moves them to replay; second call with empty queue returns replay and clears it; third call returns empty
  - Observe: `pop_many("ch", 10)` drains messages destructively regardless of replay state
  - Verify tests pass on UNFIXED code
  - **EXPECTED OUTCOME**: Tests PASS (this confirms baseline behavior to preserve)
  - Mark task complete when tests are written, run, and passing on unfixed code
  - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5, 3.6_

- [x] 3. Implement cursor-based replay advancement

  - [x] 3.1 Add cursor parameter to `peek_many` in `src/store.rs`
    - Change signature from `peek_many(&mut self, channel: &str, max: usize)` to `peek_many(&mut self, channel: &str, max: usize, cursor: Option<u64>)`
    - When `cursor` is `Some(c)`: drop replay entries with `sequence < c` before building result; do NOT clear replay on empty queue (advancement driven exclusively by cursor)
    - When `cursor` is `None`: preserve existing two-phase replay logic unchanged
    - Update `replay_cursor` tracking after cursor-based pruning
    - _Bug_Condition: isBugCondition(input) where channel has non-empty replay AND peek_many called with Some(cursor) AND client hasn't received all replayed frames_
    - _Expected_Behavior: replay entries with seq < cursor dropped, entries with seq >= cursor retained, no heuristic clear when cursor present_
    - _Preservation: cursor=None path identical to original two-phase behavior_
    - _Requirements: 2.3, 2.4, 2.5, 3.1_

  - [x] 3.2 Update all `peek_many` call sites to pass cursor
    - `src/handler.rs` `handle_receive`: pass cursor parsed from nonce (task 3.3) to `peek_many`
    - `crates/dns-socks-proxy/src/transport.rs` `DirectTransport::recv_frames`: pass `None` for now (DirectTransport doesn't have cursor context yet)
    - _Requirements: 2.2, 2.5_

  - [x] 3.3 Parse cursor from nonce in `src/handler.rs` `handle_receive`
    - After extracting the nonce label, check for `-c<number>` suffix
    - If present, parse the number as `u64` and pass as `Some(cursor)` to `peek_many`
    - If absent, pass `None` to `peek_many` (backward compatibility)
    - Pop mode check (`nonce.starts_with('P')`) remains before cursor parsing — pop mode bypasses cursor entirely
    - _Bug_Condition: nonce contains `-c<number>` suffix but handler doesn't extract cursor_
    - _Expected_Behavior: cursor parsed and passed to peek_many; None for legacy nonces_
    - _Requirements: 2.2, 2.5, 3.6_

  - [x] 3.4 Extend nonce generation in `crates/dns-socks-proxy/src/transport.rs`
    - Add `generate_nonce_with_cursor(cursor: Option<u64>) -> String` that produces `<8-char-random>-c<cursor_base10>` when cursor is Some, or `<4-char-random>` when None
    - Update `build_recv_query_name` to accept optional cursor and use the new nonce generator
    - Update `DnsTransport::recv_frames` to accept cursor parameter and thread it through
    - Update `recv_frames_parallel` and `recv_single_parallel_query` to accept cursor parameter and thread it through nonce generation
    - Ensure generated nonce fits within 63-byte DNS label limit
    - _Requirements: 2.1, 2.6, 2.7_

  - [x] 3.5 Update `TransportBackend` trait to support cursor
    - Add cursor parameter to `recv_frames` trait method: `recv_frames(&self, channel: &str, cursor: Option<u64>)`
    - Update `DnsTransport::recv_frames` implementation to pass cursor to `build_recv_query_name`
    - Update `DirectTransport::recv_frames` to pass cursor to `store.peek_many`
    - Update `recv_frame` default method accordingly
    - _Requirements: 2.7, 3.1_

  - [x] 3.6 Thread cursor through client-side callers
    - `crates/dns-socks-proxy/src/bin/socks_client.rs` `downstream_task`: read `reassembly_buf.ack_seq()` and pass as cursor to `transport.recv_frames`
    - `crates/dns-socks-proxy/src/bin/exit_node.rs` `upstream_task`: read `reassembly_buf.ack_seq()` and pass as cursor to `transport.recv_frames` and `recv_frames_parallel`
    - All send operations (A queries) remain unchanged — cursor only applies to TXT recv
    - _Requirements: 2.7, 3.7_

  - [x] 3.7 Verify bug condition exploration test now passes
    - **Property 1: Expected Behavior** — Cursor-bearing peek_many drops only confirmed replay entries
    - **IMPORTANT**: Re-run the SAME test from task 1 — do NOT write a new test
    - The test from task 1 encodes the expected behavior
    - When this test passes, it confirms the expected behavior is satisfied
    - Run bug condition exploration test from step 1
    - **EXPECTED OUTCOME**: Test PASSES (confirms bug is fixed)
    - _Requirements: 2.3, 2.4_

  - [x] 3.8 Verify preservation tests still pass
    - **Property 2: Preservation** — Non-cursor peek_many retains existing two-phase behavior
    - **IMPORTANT**: Re-run the SAME tests from task 2 — do NOT write new tests
    - Run preservation property tests from step 2
    - **EXPECTED OUTCOME**: Tests PASS (confirms no regressions)
    - Confirm all tests still pass after fix (no regressions)

- [x] 4. Checkpoint — Ensure all tests pass
  - Run `cargo test` to verify all existing and new tests pass
  - Verify no compiler warnings related to the changes
  - Ensure all tests pass, ask the user if questions arise
