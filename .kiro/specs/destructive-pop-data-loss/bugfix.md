# Bugfix Requirements Document

## Introduction

The broker's `pop_many` operation destructively removes messages from channel queues when a client polls for data. Because the transport layer is DNS over UDP — an inherently unreliable protocol — the DNS response carrying those messages can be silently lost on the network. When this happens, the popped messages are permanently gone from the broker: the client never receives them, its reassembly buffer develops gaps at the missing sequence numbers, `drain_contiguous` can never advance past the gap, no ACKs are sent back to the sender, and the sender eventually hits `max retransmissions exceeded` and kills the session with RST.

This affects both the `handle_receive` path in the broker (DNS TXT queries from standalone-mode clients) and the `DirectTransport::recv_frames` path (embedded-mode exit-node), since both call `pop_many` which irreversibly drains messages from the queue.

## Bug Analysis

### Current Behavior (Defect)

1.1 WHEN a client polls a data channel via TXT query and the broker calls `pop_many` to retrieve messages THEN the system permanently removes those messages from the channel queue, even before confirming the client received the DNS response.

1.2 WHEN the DNS/UDP response carrying popped messages is lost on the network (packet loss, resolver drop, timeout) THEN the system has no copy of those messages and cannot re-deliver them on subsequent polls.

1.3 WHEN the client's reassembly buffer has gaps due to lost messages (e.g., missing seq 0-6) and later frames arrive (e.g., seq 7-9) THEN the system cannot advance `drain_contiguous` past the gap, no contiguous data is delivered, and no ACKs are sent.

1.4 WHEN the sender's retransmit buffer fills up and the oldest unacknowledged frame exceeds `max_retransmits` THEN the system sends RST and terminates the session, even though the root cause was broker-side message loss rather than a genuine connectivity failure.

1.5 WHEN `DirectTransport::recv_frames` is called in embedded mode THEN the system also calls `pop_many` destructively, making embedded-mode sessions equally vulnerable to any failure between pop and consumption.

### Expected Behavior (Correct)

2.1 WHEN a client polls a data channel via TXT query THEN the system SHALL return the pending messages without permanently removing them from the queue until the client explicitly confirms receipt.

2.2 WHEN a DNS/UDP response carrying messages is lost on the network THEN the system SHALL still hold those messages in the channel queue so they can be re-delivered on the client's next poll.

2.3 WHEN the client successfully receives messages and polls again (or sends an explicit acknowledgment) THEN the system SHALL advance the consumption cursor and remove only the confirmed messages from the queue.

2.4 WHEN messages are re-delivered because a previous response was lost THEN the system SHALL allow the client's existing duplicate-detection logic (`ReassemblyBuffer::insert` returns `false` for duplicates) to discard redundant frames without side effects.

2.5 WHEN `DirectTransport::recv_frames` is called in embedded mode THEN the system SHALL use the same non-destructive delivery mechanism as the DNS path, ensuring embedded-mode sessions are equally resilient.

### Unchanged Behavior (Regression Prevention)

3.1 WHEN a client polls an empty channel THEN the system SHALL CONTINUE TO return NOERROR with zero TXT answers.

3.2 WHEN a sender pushes messages to a channel THEN the system SHALL CONTINUE TO store them in FIFO order with the existing sequence numbering, capacity limits, and TTL expiry behavior.

3.3 WHEN the channel reaches `max_messages_per_channel` THEN the system SHALL CONTINUE TO return `ChannelFull` error to senders.

3.4 WHEN `sweep_expired` runs THEN the system SHALL CONTINUE TO remove messages past their TTL and inactive channels past their inactivity timeout.

3.5 WHEN a status query (`query_status` / `queue_depth`) is issued THEN the system SHALL CONTINUE TO return the correct number of unconsumed messages without modifying the queue.

3.6 WHEN the exit-node sends DATA frames to the broker THEN the system SHALL CONTINUE TO accept and store them via the existing `push` / `handle_send` path without any protocol changes on the sender side.

3.7 WHEN the client's `ReassemblyBuffer` receives duplicate frames THEN the system SHALL CONTINUE TO detect and discard them (returning `false` from `insert`).

3.8 WHEN the sender's `RetransmitBuffer` receives a cumulative ACK THEN the system SHALL CONTINUE TO remove all acknowledged frames and free window capacity.
