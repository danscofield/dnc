# Bugfix Requirements Document

## Introduction

The broker's `peek_many` replay mechanism causes permanent frame loss and stuck sessions when clients poll through recursive DNS resolvers (e.g., Cloudflare 1.1.1.1). The two-phase replay logic assumes that if no new messages arrive on a re-poll, the client received the previous batch — but UDP responses through recursive resolvers can be lost or truncated. This causes the broker to clear replay frames the client never received, creating permanent gaps in the client's reassembly buffer and stalling sessions indefinitely.

The fix introduces cursor-based replay advancement: the client encodes its highest contiguous received sequence number into the TXT query nonce, and the broker uses this cursor to advance replay only past confirmed frames instead of guessing when to clear.

## Bug Analysis

### Current Behavior (Defect)

1.1 WHEN the client polls for downstream data through a recursive resolver and the UDP response is lost or truncated THEN the broker's `peek_many` clears the replay buffer on the next re-poll (seeing "no new messages"), permanently losing frames the client never received

1.2 WHEN the client has gaps in its reassembly buffer due to lost replay frames THEN the broker continues replaying only the frames that were added after the lost batch, causing the client to receive stale frames it already has while never recovering the missing frames

1.3 WHEN the broker's `peek_many` is called with no new messages in the queue and a non-empty replay buffer THEN the replay buffer is cleared unconditionally regardless of whether the client actually received the replayed frames

1.4 WHEN the client's nonce in TXT recv queries contains only random characters THEN the broker has no mechanism to determine which frames the client has actually received, forcing it to rely on the flawed "confirming re-poll" heuristic

### Expected Behavior (Correct)

2.1 WHEN the client polls for downstream data THEN the client SHALL encode its highest contiguous received sequence number (ack_seq / cursor) into the TXT query nonce using the format `<random>-c<cursor>` where cursor is a base10-encoded sequence number

2.2 WHEN the broker receives a TXT query with a cursor-bearing nonce (containing `-c<number>`) THEN the broker SHALL parse the cursor value and pass it to `peek_many` as an optional cursor parameter

2.3 WHEN `peek_many` receives a cursor value THEN it SHALL drop replay entries with sequence numbers strictly less than the cursor value, retaining only unconfirmed replay entries and new messages

2.4 WHEN `peek_many` receives a cursor value THEN it SHALL NOT clear the replay buffer on a "confirming re-poll" (no new messages) — replay advancement SHALL be driven exclusively by the client cursor

2.5 WHEN the client's nonce does not contain a `-c` suffix (backward compatibility) THEN the broker SHALL fall back to the existing two-phase replay behavior (clear on confirming re-poll)

2.6 WHEN the client encodes a cursor into the nonce THEN the total nonce string (e.g., `aB3kQ-c00007`) SHALL fit within the 63-byte DNS label limit

2.7 WHEN `recv_frames` or `recv_frames_parallel` builds a TXT recv query THEN the nonce SHALL include the cursor suffix derived from the downstream `ReassemblyBuffer.ack_seq()` value

### Unchanged Behavior (Regression Prevention)

3.1 WHEN `peek_many` is called without a cursor (cursor is `None`) THEN the system SHALL CONTINUE TO use the existing two-phase replay behavior (replay returned once, cleared on confirming re-poll)

3.2 WHEN messages are pushed to a channel THEN the system SHALL CONTINUE TO assign strictly monotonically increasing sequence numbers and maintain FIFO ordering

3.3 WHEN a channel reaches `max_messages_per_channel` THEN the system SHALL CONTINUE TO return `StoreError::ChannelFull`

3.4 WHEN `queue_depth` is called on a channel THEN the system SHALL CONTINUE TO return `messages.len() + replay.len()` accurately reflecting both unserved and replay entries

3.5 WHEN `sweep_expired` is called THEN the system SHALL CONTINUE TO remove expired messages from both the message queue and the replay buffer, and remove inactive channels

3.6 WHEN the nonce starts with uppercase `P` (pop mode for dnc) THEN the system SHALL CONTINUE TO use destructive `pop_many` semantics unaffected by cursor logic

3.7 WHEN the client sends A queries (send operations) THEN the nonce format and send path SHALL CONTINUE TO work unchanged — cursor encoding only applies to TXT recv queries

3.8 WHEN EDNS0 is enabled or disabled THEN the batching behavior (max_messages based on EDNS0 buffer size) SHALL CONTINUE TO work correctly with cursor-based replay
