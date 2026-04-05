# Bugfix Requirements Document

## Introduction

When multiple sequential SOCKS proxy sessions use the same shared control channel (`ctl-<client_id>`), the `peek_many()` replay buffer in `src/store.rs` causes stale frames from a completed session to block delivery of new frames for the next session. The replay buffer requires 3 poll cycles to fully drain (deliver → re-deliver → confirming re-poll clears), and during that window, a new session's SYN-ACK is stuck behind the stale replay entries. The SYN-ACK cannot be delivered until the replay clears, but by then the 30-second connect timeout has already fired, causing the second connection to fail.

## Bug Analysis

### Current Behavior (Defect)

1.1 WHEN session #1 completes and its control frames (FIN, etc.) remain in the replay buffer, AND session #2 sends a SYN and the exit node responds with a SYN-ACK, THEN the system delivers session #1's stale replay frames first, blocking session #2's SYN-ACK behind the replay buffer

1.2 WHEN the control channel replay buffer contains stale frames from a completed session AND a new message is pushed to the same channel, THEN `peek_many()` returns the stale replay frames concatenated with the new message, causing the stale frames to be dispatched to a deregistered session ID and discarded

1.3 WHEN the control channel replay buffer contains only stale frames (no new messages in the queue) AND a poll occurs, THEN `peek_many()` returns the stale frames one more time and only clears the replay on the subsequent confirming re-poll, introducing a minimum 2-poll-cycle delay before new messages can be delivered cleanly

### Expected Behavior (Correct)

2.1 WHEN session #1 completes and its control frames remain in the replay buffer, AND session #2's SYN-ACK is pushed to the same control channel, THEN the system SHALL deliver session #2's SYN-ACK without delay from stale replay entries

2.2 WHEN the control channel replay buffer contains stale frames from a completed session AND a new message is pushed to the same channel, THEN `peek_many()` SHALL prioritize delivering the new message without forcing the caller to first re-consume stale replay frames that will be discarded

2.3 WHEN the control channel replay buffer contains only stale frames (no new messages in the queue) AND a poll occurs, THEN `peek_many()` SHALL clear the replay buffer immediately on the first poll that finds no new messages, rather than requiring an additional confirming re-poll cycle

### Unchanged Behavior (Regression Prevention)

3.1 WHEN a UDP DNS response is lost and the client re-polls the same channel, THEN the system SHALL CONTINUE TO re-deliver the previously served messages from the replay buffer so no data is lost

3.2 WHEN messages are pushed to a channel and consumed via `peek_many()`, THEN the system SHALL CONTINUE TO return messages in FIFO order with correct payloads and sequence numbers

3.3 WHEN a channel reaches `max_messages_per_channel`, THEN the system SHALL CONTINUE TO reject additional pushes with `StoreError::ChannelFull`

3.4 WHEN messages expire or channels become inactive, THEN `sweep_expired()` SHALL CONTINUE TO remove expired messages and inactive channels correctly

3.5 WHEN `queue_depth()` is called, THEN the system SHALL CONTINUE TO return the count of unserved messages without side effects
