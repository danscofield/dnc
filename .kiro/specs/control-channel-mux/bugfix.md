# Bugfix Requirements Document

## Introduction

When the socks-client handles multiple overlapping TCP connections, each `handle_connection` task independently polls the shared control channel `ctl-<client_id>` for SYN-ACK responses using `transport.recv_frame()`. Because the broker's channel is a FIFO queue and `recv_frame` pops messages destructively, one session can pop another session's SYN-ACK, find the session ID doesn't match, log "control frame for different session, ignoring", and silently drop it. The intended recipient session never receives its SYN-ACK and times out after 30 seconds.

The root cause is that multiple concurrent `handle_connection` tasks each independently call `transport.recv_frame(&recv_control_channel)` in their SYN-ACK polling loops, racing on the same broker queue (`ctl-<client_id>`). Whichever task polls first pops the message, and if it belongs to a different session, it is discarded.

## Bug Analysis

### Current Behavior (Defect)

1.1 WHEN two or more concurrent `handle_connection` tasks poll the shared control channel `ctl-<client_id>` for SYN-ACK responses THEN the system allows any task to destructively pop a control frame intended for a different session

1.2 WHEN a `handle_connection` task pops a SYN-ACK whose `session_id` does not match its own THEN the system logs "control frame for different session, ignoring" and silently discards the frame, making it permanently lost

1.3 WHEN a session's SYN-ACK is consumed and discarded by a different session's polling loop THEN the intended recipient session never receives its SYN-ACK and times out after the `connect_timeout` (default 30 seconds)

1.4 WHEN multiple sessions race on the control channel THEN control frames of types FIN and RST destined for a specific session can also be consumed and discarded by a different session's polling loop (during the SYN-ACK wait phase)

### Expected Behavior (Correct)

2.1 WHEN two or more concurrent sessions exist THEN the system SHALL use a single shared control channel poller task that receives all control frames from `ctl-<client_id>` and dispatches them to the correct session via per-session channels

2.2 WHEN the shared poller receives a control frame (SYN-ACK, FIN, RST) with a given `session_id` THEN the system SHALL deliver that frame to the corresponding session's dedicated receiver channel without dropping it

2.3 WHEN a session is waiting for its SYN-ACK THEN the system SHALL receive it through its dedicated per-session channel, ensuring no other session can consume or discard it

2.4 WHEN a session registers with the control channel dispatcher THEN the system SHALL create a per-session `tokio::mpsc` channel and route all control frames matching that session's ID to it

2.5 WHEN a session completes or is cleaned up THEN the system SHALL deregister its session ID from the dispatcher so the per-session channel is dropped

2.6 WHEN the shared poller receives a control frame for an unknown or already-deregistered session ID THEN the system SHALL log a warning and discard the frame without affecting other sessions

### Unchanged Behavior (Regression Prevention)

3.1 WHEN a single session is active (no concurrency) THEN the system SHALL CONTINUE TO successfully complete the SYN / SYN-ACK handshake and establish the session

3.2 WHEN the exit-node sends a SYN-ACK on the client's control channel THEN the system SHALL CONTINUE TO verify the MAC, decode the frame, extract the exit-node's X25519 public key, and derive the session key

3.3 WHEN a session receives a RST during setup THEN the system SHALL CONTINUE TO reply with SOCKS5 "connection refused" and clean up the session

3.4 WHEN the SYN-ACK is not received within `connect_timeout` THEN the system SHALL CONTINUE TO reply with SOCKS5 "host unreachable" and clean up the session

3.5 WHEN the session is established THEN the system SHALL CONTINUE TO run the upstream, downstream, and retransmit tasks with the same bidirectional data flow behavior

3.6 WHEN the exit-node binary handles its control channel THEN the system SHALL CONTINUE TO use its existing single-poller loop unchanged, since the exit-node processes one SYN at a time and does not have this race condition
