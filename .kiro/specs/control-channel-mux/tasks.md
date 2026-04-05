# Implementation Plan

- [x] 1. Write bug condition exploration test
  - **Property 1: Bug Condition** - Control frame dispatch to correct session
  - **CRITICAL**: This test MUST FAIL on unfixed code - failure confirms the bug exists
  - **DO NOT attempt to fix the test or the code when it fails**
  - **NOTE**: This test encodes the expected behavior - it will validate the fix when it passes after implementation
  - **GOAL**: Surface counterexamples that demonstrate the race condition where one session steals another session's control frame
  - **Scoped PBT Approach**: Generate random sets of 2-10 session IDs, register all with a `ControlDispatcher`, dispatch a control frame for a randomly chosen session, and assert only that session's receiver gets the frame while all other receivers remain empty
  - The bug condition is: `isBugCondition(state) = active_sessions.count() >= 2 AND EXISTS frame WHERE frame.session_id != poller_that_wins_race.session_id`
  - In the current code, there is no `ControlDispatcher` — each `handle_connection` independently calls `transport.recv_frame()` on the shared control channel, so any task can pop and discard another session's frame
  - The test should create a `ControlDispatcher`, register N sessions (N >= 2), dispatch a frame targeting session K, and verify:
    - Session K's mpsc receiver gets the frame bytes
    - All other sessions' receivers are empty (no cross-delivery)
  - Since `ControlDispatcher` does not exist yet, this test will fail to compile on unfixed code, confirming the bug condition (no multiplexing exists)
  - Write the test in `crates/dns-socks-proxy/src/bin/socks_client.rs` inside a `#[cfg(test)] mod tests` block
  - Use `proptest` or manual property iteration: generate random session IDs and random frame payloads
  - Run test on UNFIXED code
  - **EXPECTED OUTCOME**: Test FAILS (compilation error — `ControlDispatcher` does not exist, confirming the bug: no dispatch mechanism)
  - Document the failure: "ControlDispatcher struct does not exist; each handle_connection polls independently, enabling the race condition"
  - Mark task complete when test is written, run, and failure is documented
  - _Requirements: 1.1, 1.2, 1.3, 2.1, 2.2, 2.3_

- [x] 2. Write preservation property tests (BEFORE implementing fix)
  - **Property 2: Preservation** - Single-session handshake and frame processing unchanged
  - **IMPORTANT**: Follow observation-first methodology
  - Observe on UNFIXED code: single-session SYN-ACK polling works correctly when only one `handle_connection` is active — MAC verification, frame decoding, key derivation all succeed
  - Observe on UNFIXED code: RST during setup returns SOCKS5 `0x05`, timeout returns SOCKS5 `0x04`
  - Observe on UNFIXED code: `decode_frame` correctly extracts `session_id` from the first 9 bytes (1-byte length + 8-byte ID) of any valid frame
  - Write property-based tests that capture these observed behaviors:
    - For any valid encoded frame, `decode_frame` extracts the correct `session_id` (this is the dispatch key the new code will use)
    - For any single registered session, dispatching a frame with that session's ID delivers it to the receiver
    - For any frame with an unknown session ID, dispatch discards it without panic
  - These tests validate the frame decoding and session lookup logic that both old and new code share
  - Write tests in `crates/dns-socks-proxy/src/bin/socks_client.rs` `#[cfg(test)] mod tests` block
  - Verify tests pass on UNFIXED code (the frame decode tests will pass; the dispatcher tests will be skipped/conditional since ControlDispatcher doesn't exist yet — focus on frame decode preservation)
  - **EXPECTED OUTCOME**: Frame decode property tests PASS on unfixed code (confirms baseline behavior to preserve)
  - Mark task complete when tests are written, run, and passing on unfixed code
  - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5_

- [x] 3. Implement control channel multiplexing fix

  - [x] 3.1 Add `ControlDispatcher` struct
    - Add `ControlDispatcher` struct in `socks_client.rs` with `Arc<Mutex<HashMap<SessionId, mpsc::Sender<Vec<u8>>>>>`
    - Implement `register(session_id: SessionId) -> mpsc::Receiver<Vec<u8>>` — creates an mpsc channel (buffer size 4), stores the `Sender`, returns the `Receiver`
    - Implement `deregister(session_id: &SessionId)` — removes the sender, dropping the channel
    - Implement `dispatch(frame_bytes: &[u8])` — decodes the first 9 bytes to extract `session_id`, looks up the sender in the map, sends the full raw bytes; if session not found, logs warning and discards
    - _Bug_Condition: isBugCondition(state) = multiple handle_connection tasks independently polling recv_control_channel_
    - _Expected_Behavior: Every control frame delivered exactly to the matching session's mpsc channel_
    - _Preservation: Single-session handshake, MAC verification, key derivation unchanged_
    - _Requirements: 2.1, 2.2, 2.4, 2.5, 2.6_

  - [x] 3.2 Add `spawn_control_poller` function
    - Add `spawn_control_poller` function that spawns a background `tokio::spawn` task
    - The task owns a dedicated `DnsTransport` for the control channel `ctl-<client_id>`
    - Uses `AdaptiveBackoff::new(config.poll_active, config.backoff_max)` for poll intervals
    - Calls `transport.recv_frame(&recv_control_channel)` in a loop
    - For each received frame: verifies MAC with PSK, then calls `dispatcher.dispatch(frame_bytes)` to route to the correct session
    - If MAC verification fails, logs debug and discards (same as current behavior)
    - Uses a `tokio_util::sync::CancellationToken` (or `tokio::sync::watch`) for graceful shutdown
    - Backoff resets on frame received, increases on empty poll
    - _Bug_Condition: Single poller replaces N independent pollers, eliminating the race_
    - _Expected_Behavior: All control frames routed through one poller to per-session channels_
    - _Preservation: AdaptiveBackoff behavior identical to existing downstream polling_
    - _Requirements: 2.1, 2.2, 2.6_

  - [x] 3.3 Modify `main()` to create dispatcher and spawn poller
    - Create `ControlDispatcher` (wrapped in `Arc`) before the accept loop
    - Create a dedicated `DnsTransport` for the control channel poller
    - Call `spawn_control_poller(transport, dispatcher.clone(), config.clone())` before entering the accept loop
    - Pass `Arc<ControlDispatcher>` to each `handle_connection` call alongside existing args
    - _Requirements: 2.1_

  - [x] 3.4 Modify `handle_connection()` to use dispatcher
    - Add `dispatcher: Arc<ControlDispatcher>` parameter
    - Call `dispatcher.register(session_id.clone())` before sending SYN to get `mpsc::Receiver<Vec<u8>>`
    - Replace the SYN-ACK polling loop (`loop { transport.recv_frame(...) }`) with `tokio::time::timeout(connect_timeout, receiver.recv())`
    - Process received raw bytes identically: MAC verify, `decode_frame`, session_id check, key exchange (MAC is already verified by poller, but keep the check for defense-in-depth or remove if design says poller handles it)
    - Handle `Err(Elapsed)` as timeout → SOCKS5 `0x04` + cleanup (same as current)
    - Handle `Ok(None)` (channel closed) as dispatcher shutdown → cleanup
    - Call `dispatcher.deregister(&session_id)` in ALL cleanup/exit paths: timeout, RST, error, and normal session end
    - Remove the per-task `DnsTransport` creation for control channel polling (data transport remains per-session)
    - _Bug_Condition: handle_connection no longer polls control channel directly_
    - _Expected_Behavior: SYN-ACK received via dedicated mpsc receiver, no cross-session interference_
    - _Preservation: MAC verification, frame decoding, key derivation, SOCKS5 replies all unchanged_
    - _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5, 3.1, 3.2, 3.3, 3.4, 3.5_

  - [x] 3.5 Ensure cleanup/deregistration in all exit paths
    - Audit all `return` and error paths in `handle_connection` to ensure `dispatcher.deregister(&session_id)` is called
    - Paths to cover: SYN-ACK timeout, RST during setup, payload budget zero, upstream/downstream/retransmit task completion, session ending cleanup
    - Consider using a `Drop` guard or `defer`-style pattern to guarantee deregistration
    - _Requirements: 2.5_

  - [x] 3.6 Verify bug condition exploration test now passes
    - **Property 1: Expected Behavior** - Control frame dispatch to correct session
    - **IMPORTANT**: Re-run the SAME test from task 1 - do NOT write a new test
    - The test from task 1 encodes the expected behavior: for N registered sessions, a frame for session K is delivered only to K's receiver
    - Now that `ControlDispatcher` exists, the test should compile and pass
    - Run bug condition exploration test from step 1
    - **EXPECTED OUTCOME**: Test PASSES (confirms the dispatch mechanism works correctly and the race condition is eliminated)
    - _Requirements: 2.1, 2.2, 2.3, 2.6_

  - [x] 3.7 Verify preservation tests still pass
    - **Property 2: Preservation** - Single-session handshake and frame processing unchanged
    - **IMPORTANT**: Re-run the SAME tests from task 2 - do NOT write new tests
    - Run preservation property tests from step 2
    - **EXPECTED OUTCOME**: Tests PASS (confirms no regressions in frame decoding, session lookup, single-session behavior)
    - Confirm all tests still pass after fix (no regressions)
    - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5_

- [x] 4. Checkpoint - Ensure all tests pass
  - Run `cargo test -p dns-socks-proxy` to verify all existing and new tests pass
  - Run `cargo build -p dns-socks-proxy` to verify no compilation errors
  - Ensure all property tests (bug condition + preservation) pass
  - Ensure existing unit tests in `frame.rs`, `session.rs`, `transport.rs`, `config.rs` still pass
  - Ask the user if questions arise
