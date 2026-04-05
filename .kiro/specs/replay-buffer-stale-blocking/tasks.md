# Tasks — Replay Buffer Stale Blocking Bugfix

## Task 1: Exploratory Bug Condition Tests (Pre-Fix)

Write property-based tests that demonstrate the bug on UNFIXED code.

- [x] 1.1 Write PBT: stale replay blocks new message delivery — push messages, peek (creates replay), push new message, peek again. Assert new message is returned without stale replay entries. Expected to FAIL on unfixed code.
  - File: `src/store.rs` (test module)
  - Property: For any non-empty replay buffer with new messages in the queue, peek_many returns the new messages immediately
  - Validates: Property 1 (design.md)

- [x] 1.2 Write PBT: replay buffer requires extra poll cycle to clear — push messages, peek (creates replay), peek with empty queue, peek again. Assert the third peek returns empty. Expected to FAIL on unfixed code (third peek still returns stale data).
  - File: `src/store.rs` (test module)
  - Property: For any non-empty replay buffer with empty queue, one peek_many call clears the replay so the next returns empty
  - Validates: Property 2 (design.md)

## Task 2: Preservation Tests (Pre-Fix, Must Pass)

Write property-based tests capturing correct behavior that must be preserved.

- [x] 2.1 Write PBT: replay re-delivers same batch when no new messages pushed — push N messages, peek (creates replay), peek again with no intervening push. Assert same messages returned. Must PASS on unfixed code.
  - File: `src/store.rs` (test module)
  - Property: For any messages moved to replay, a re-poll with no new pushes returns the same batch
  - Validates: Property 3 (design.md)

- [x] 2.2 Verify existing preservation PBTs still pass — run existing `preservation_push_fifo_and_monotonic_sequences`, `preservation_channel_full_at_capacity`, `preservation_sweep_removes_expired_messages`, `preservation_sweep_removes_inactive_channels`, `preservation_queue_depth_is_readonly` tests.
  - Validates: Property 4 (design.md)

## Task 3: Implement the Fix

- [x] 3.1 Modify `peek_many()` in `src/store.rs` to detect stale replay when new messages exist in the queue — clear replay and serve only new messages
  - When replay is non-empty AND messages queue is non-empty: clear replay, reset replay_cursor, then serve from messages queue
  - Validates: Requirements 2.1, 2.2

- [x] 3.2 Modify `peek_many()` in `src/store.rs` to clear replay immediately on empty-queue poll — return replay contents one final time and clear in the same call
  - When replay is non-empty AND messages queue is empty: collect replay contents, clear replay, reset replay_cursor, return collected contents
  - Validates: Requirement 2.3

## Task 4: Post-Fix Verification

- [x] 4.1 Run exploratory bug condition tests (Task 1) — they should now PASS on fixed code
- [x] 4.2 Run preservation tests (Task 2) — they must still PASS on fixed code
- [x] 4.3 Run all existing tests in `src/store.rs` — no regressions
- [x] 4.4 Run all existing tests in `src/handler.rs` — no regressions
