# Control Channel Mux Bugfix Design

## Overview

Multiple concurrent `handle_connection` tasks in the socks-client binary race on the shared control channel `ctl-<client_id>`, destructively popping each other's SYN-ACK (and FIN/RST) frames. The fix introduces a `ControlDispatcher` struct that owns a single background poller task for the control channel and demultiplexes incoming frames to per-session `tokio::mpsc` channels. Each `handle_connection` task registers its session ID before sending SYN, receives its SYN-ACK through a dedicated mpsc receiver, and deregisters on cleanup. The exit-node is unaffected.

## Glossary

- **Bug_Condition (C)**: Two or more concurrent `handle_connection` tasks independently call `transport.recv_frame(&recv_control_channel)`, racing on the same broker FIFO queue
- **Property (P)**: Every control frame (SYN-ACK, FIN, RST) is delivered exactly to the session whose `session_id` matches the frame, via a per-session mpsc channel
- **Preservation**: Single-session handshake, MAC verification, key derivation, SOCKS5 error replies, established-session data flow, and exit-node behavior remain unchanged
- **ControlDispatcher**: New struct in `socks_client.rs` that holds a `HashMap<SessionId, mpsc::Sender<Vec<u8>>>` behind an `Arc<Mutex<_>>` and manages session registration/deregistration
- **Poller task**: A single `tokio::spawn`'d background task that calls `transport.recv_frame(&recv_control_channel)` in a loop with `AdaptiveBackoff`, decodes the `session_id` from each frame, and forwards the raw bytes to the matching mpsc sender
- **recv_control_channel**: The channel name `ctl-<client_id>` that the broker uses to deliver control frames addressed to this client

## Bug Details

### Bug Condition

The bug manifests when two or more `handle_connection` tasks concurrently poll the shared control channel `ctl-<client_id>` using `transport.recv_frame()`. Because the broker's channel is a FIFO queue and `recv_frame` pops messages destructively, any task can consume a frame intended for a different session. The task checks `frame.session_id != session_id`, logs "control frame for different session, ignoring", and drops the frame permanently.

**Formal Specification:**
```
FUNCTION isBugCondition(state)
  INPUT: state of type ClientState
  OUTPUT: boolean

  LET active_sessions = state.handle_connection_tasks
                          .filter(t => t.is_polling_control_channel)
  
  RETURN active_sessions.count() >= 2
         AND state.control_channel_has_pending_frame
         AND EXISTS frame IN state.pending_frames:
               frame.session_id != active_sessions[poller_that_wins_race].session_id
END FUNCTION
```

### Examples

- **Two concurrent sessions**: Session A and Session B both poll `ctl-myclient`. Exit-node sends SYN-ACK for session A. Session B's poll fires first, pops the SYN-ACK, sees `session_id != B`, discards it. Session A never receives its SYN-ACK and times out after 30s.
- **Three concurrent sessions**: Sessions A, B, C all polling. SYN-ACK for B arrives. Session C pops it and discards. B times out.
- **FIN frame stolen**: Session A is in SYN-ACK wait. A FIN for session B arrives on the control channel. Session A pops it, discards it (wrong session_id and wrong frame type). Session B never learns it was terminated.
- **Single session (no bug)**: Only one `handle_connection` task is active. It polls the control channel and always receives its own SYN-ACK. No race condition.

## Expected Behavior

### Preservation Requirements

**Unchanged Behaviors:**
- Single-session SYN / SYN-ACK handshake completes successfully
- MAC verification, frame decoding, X25519 key exchange, and session key derivation work identically (the dispatcher forwards raw `Vec<u8>` bytes; MAC/decode happens in `handle_connection`)
- RST during setup returns SOCKS5 `0x05` (connection refused)
- SYN-ACK timeout returns SOCKS5 `0x04` (host unreachable)
- Established-session upstream, downstream, and retransmit tasks run with the same bidirectional data flow
- Exit-node binary is completely unmodified

**Scope:**
All inputs that do NOT involve multiple concurrent sessions polling the control channel are unaffected. This includes:
- Single-session operation
- Data channel polling (per-session `u-<sid>` / `d-<sid>` channels)
- All exit-node control channel handling
- All SOCKS5 protocol handling

## Hypothesized Root Cause

Based on the code in `socks_client.rs`, the root cause is clear and confirmed:

1. **No control channel multiplexing**: Each `handle_connection` task creates its own `DnsTransport` and independently calls `transport.recv_frame(&recv_control_channel)` in a polling loop (lines ~130-180 of `socks_client.rs`). There is no coordination between tasks.

2. **Destructive pop semantics**: `recv_frame` calls `recv_frames` which issues a TXT query to the broker. The broker's `pop` / `pop_many` operation removes the message from the queue. Once popped, the message is gone.

3. **Discard-on-mismatch logic**: When `frame.session_id != session_id`, the code logs a debug message and `continue`s, permanently losing the frame. There is no mechanism to re-enqueue or forward the frame to the correct session.

4. **Race window**: The race window is the entire SYN-ACK polling loop duration (up to `connect_timeout`, default 30s). Any overlapping `handle_connection` task that enters this loop creates a race.

## Correctness Properties

Property 1: Bug Condition - Control frame dispatch to correct session

_For any_ set of N registered sessions (N ≥ 1) and a control frame whose `session_id` matches session K, the `ControlDispatcher` SHALL deliver that frame's raw bytes to session K's mpsc receiver and to no other session's receiver.

**Validates: Requirements 2.1, 2.2, 2.3**

Property 2: Preservation - Single-session handshake unchanged

_For any_ single-session scenario where only one `handle_connection` task is active, the fixed code SHALL complete the SYN / SYN-ACK handshake identically to the original code, preserving MAC verification, key derivation, and session establishment.

**Validates: Requirements 3.1, 3.2, 3.5**

Property 3: Bug Condition - Frames for unknown sessions are discarded safely

_For any_ control frame whose `session_id` does not match any registered session, the `ControlDispatcher` SHALL discard the frame and log a warning without affecting any registered session's mpsc channel.

**Validates: Requirements 2.6**

Property 4: Preservation - Session lifecycle correctness

_For any_ session that registers with the dispatcher before sending SYN and deregisters during cleanup, the dispatcher's internal map SHALL contain the session's entry for exactly the duration between register and deregister calls, and the mpsc channel SHALL be dropped on deregister.

**Validates: Requirements 2.4, 2.5**

## Fix Implementation

### Changes Required

Assuming our root cause analysis is correct:

**File**: `crates/dns-socks-proxy/src/bin/socks_client.rs`

**New struct**: `ControlDispatcher`

**Specific Changes**:

1. **Add `ControlDispatcher` struct**: A struct holding `Arc<Mutex<HashMap<SessionId, mpsc::Sender<Vec<u8>>>>>` that provides `register(session_id) -> mpsc::Receiver<Vec<u8>>` and `deregister(session_id)` methods. The mpsc channel buffer size should be small (e.g., 4) since control frames are infrequent.

2. **Add `spawn_control_poller` function**: Spawns a background `tokio::spawn` task that:
   - Owns a dedicated `DnsTransport` for the control channel
   - Uses `AdaptiveBackoff` (from the parallel-status-polling feature) to govern poll intervals
   - Calls `transport.recv_frame(&recv_control_channel)` in a loop
   - For each received frame: verifies MAC with the PSK, decodes just enough to extract the `session_id` (first 9 bytes: 1-byte length + 8-byte session ID), looks up the session in the dispatcher's map, and sends the full raw bytes (including MAC) through the mpsc sender
   - If the session is not found, logs a warning and discards
   - The task runs until a `CancellationToken` (or similar) is triggered during shutdown

3. **Modify `main()`**: Before the accept loop, create the `ControlDispatcher` and spawn the control poller task. Pass `Arc<ControlDispatcher>` to each `handle_connection` call.

4. **Modify `handle_connection()`**: 
   - Remove the per-task control channel polling loop (the `loop { ... match transport.recv_frame(&recv_control_channel) ... }` block)
   - Call `dispatcher.register(session_id)` before sending SYN to get an `mpsc::Receiver<Vec<u8>>`
   - After sending SYN, wait for SYN-ACK by calling `receiver.recv()` with a `tokio::time::timeout(connect_timeout, ...)`
   - Process the received raw bytes identically to the current code (MAC verify, decode, key exchange)
   - Call `dispatcher.deregister(session_id)` in the cleanup path (both success and error paths)

5. **Poller MAC handling decision**: The poller verifies the MAC before dispatch (since it has access to the PSK). This prevents forwarding garbage to sessions. The session still receives the full frame bytes for decoding.

### Integration with parallel-status-polling

The control channel poller task uses `AdaptiveBackoff::new(config.poll_active, config.backoff_max)` for its poll interval, consistent with how the data channel polling already works. When a frame is received, backoff resets; when the channel is empty, backoff increases. This avoids hammering the broker when no sessions are active while remaining responsive during handshakes.

## Testing Strategy

### Validation Approach

The testing strategy follows a two-phase approach: first, surface counterexamples that demonstrate the bug on unfixed code, then verify the fix works correctly and preserves existing behavior.

### Exploratory Bug Condition Checking

**Goal**: Surface counterexamples that demonstrate the bug BEFORE implementing the fix. Confirm that the race condition exists in the current code.

**Test Plan**: Write a test that simulates two concurrent sessions polling the same control channel. Inject a SYN-ACK for session A while session B is also polling. Observe that session B steals the frame and session A never receives it.

**Test Cases**:
1. **Two-session SYN-ACK race**: Create two `handle_connection` tasks for different targets. Send SYN-ACK for session A. Verify session B pops and discards it (will fail on unfixed code — session A times out)
2. **Three-session race**: Three concurrent sessions, SYN-ACK for the middle one. Verify it gets stolen by one of the others (will fail on unfixed code)
3. **FIN frame stolen**: Two sessions, FIN for session B arrives while session A is in SYN-ACK wait. Verify session A discards it (will fail on unfixed code — session B never sees FIN)

**Expected Counterexamples**:
- Session A's SYN-ACK is popped by session B and discarded
- Session A times out with SOCKS5 "host unreachable"
- Root cause confirmed: no multiplexing, destructive pop, discard-on-mismatch

### Fix Checking

**Goal**: Verify that for all inputs where the bug condition holds, the fixed function produces the expected behavior.

**Pseudocode:**
```
FOR ALL (sessions, frame) WHERE isBugCondition(sessions, frame) DO
  dispatcher := ControlDispatcher::new()
  FOR EACH session IN sessions DO
    receiver := dispatcher.register(session.id)
  END FOR
  
  dispatcher.dispatch(frame)
  
  target_receiver := receivers[frame.session_id]
  ASSERT target_receiver.try_recv() == Ok(frame.raw_bytes)
  
  FOR EACH other_receiver IN receivers WHERE id != frame.session_id DO
    ASSERT other_receiver.try_recv() == Err(Empty)
  END FOR
END FOR
```

### Preservation Checking

**Goal**: Verify that for all inputs where the bug condition does NOT hold, the fixed function produces the same result as the original function.

**Pseudocode:**
```
FOR ALL input WHERE NOT isBugCondition(input) DO
  // Single-session scenario: register one session, dispatch its SYN-ACK
  dispatcher := ControlDispatcher::new()
  receiver := dispatcher.register(session_id)
  dispatcher.dispatch(synack_frame_for_session_id)
  
  ASSERT receiver.try_recv() == Ok(synack_frame.raw_bytes)
  // Verify MAC, decode, key derivation produce identical results
END FOR
```

**Testing Approach**: Property-based testing is recommended for preservation checking because:
- It generates many session ID combinations to verify dispatch correctness
- It catches edge cases like session IDs that are prefixes of each other
- It provides strong guarantees that single-session behavior is unchanged

**Test Plan**: Observe behavior on UNFIXED code first for single-session handshakes, then write property-based tests capturing that behavior.

**Test Cases**:
1. **Single-session handshake preservation**: Verify a single session registers, receives its SYN-ACK through mpsc, and completes key exchange identically
2. **MAC verification preservation**: Verify invalid-MAC frames are still rejected (by the poller, before dispatch)
3. **Timeout preservation**: Verify that if no SYN-ACK arrives, the session still times out with SOCKS5 "host unreachable"
4. **RST handling preservation**: Verify RST during setup still produces SOCKS5 "connection refused"

### Unit Tests

- `ControlDispatcher::register` creates an mpsc channel and stores the sender
- `ControlDispatcher::deregister` removes the sender and drops the channel
- `ControlDispatcher::register` for duplicate session ID replaces the old sender
- Dispatch to registered session delivers the frame bytes
- Dispatch to unregistered session discards without panic
- Dispatch to deregistered session discards without panic
- Multiple concurrent dispatches to different sessions deliver correctly

### Property-Based Tests

- Generate random sets of 1-10 session IDs, register all, dispatch a frame for a randomly chosen session, verify only that session's receiver gets the frame
- Generate random session IDs and frame bytes, verify dispatch + receive round-trip preserves the exact bytes
- Generate random register/deregister sequences, verify the dispatcher's internal map is consistent after each operation

### Integration Tests

- Full two-session handshake: both sessions register, both SYN-ACKs arrive, both sessions establish successfully
- Session cleanup: session deregisters, subsequent frames for that session are discarded
- Poller shutdown: cancellation token triggers, poller task exits cleanly
