# Bugfix Requirements Document

## Introduction

The broker's EDNS0 TXT response batching in `handle_receive` uses a fixed `max_messages` calculation that can produce UDP responses up to ~1300 bytes. Recursive DNS resolvers (e.g., Cloudflare 1.1.1.1) frequently drop these oversized UDP responses silently, causing the client to never receive downstream data. Sessions stall with infinite retransmissions until the max retransmit limit is exceeded and the session is RST'd.

A temporary workaround caps `max_messages` to 2 (keeping responses under ~600 bytes), which works reliably but wastes bandwidth when the resolver can handle larger responses. The fix should implement adaptive response sizing on the broker side, using cursor advancement as the signal for whether responses are getting through, with a CLI override for users who know their resolver's limits.

## Bug Analysis

### Current Behavior (Defect)

1.1 WHEN EDNS0 is present with UDP buffer ≥1232 bytes THEN the system calculates `max_messages` using a formula that can yield values up to ~4-5, producing DNS UDP responses up to ~1300 bytes that recursive resolvers silently drop

1.2 WHEN a recursive resolver drops an oversized UDP response THEN the client never receives downstream data, causing the session to stall with repeated retransmissions of the same batch until `max_retransmits` is exceeded and the session is RST'd

1.3 WHEN the temporary cap of `max_messages = 2` is applied THEN the system uses a static limit for all channels regardless of whether the resolver could handle larger responses, wasting available bandwidth

### Expected Behavior (Correct)

2.1 WHEN a channel has no delivery history (new or reset) THEN the system SHALL default to a conservative `max_messages` starting value (2 messages, keeping responses under ~600 bytes) to avoid drops by recursive resolvers

2.2 WHEN the client advances its cursor on subsequent polls (indicating the previous response was received) THEN the system SHALL gradually increase `max_messages` for that channel (up to a configured ceiling) to utilize more bandwidth

2.3 WHEN the client re-requests the same batch (cursor does not advance across consecutive polls) THEN the system SHALL reduce `max_messages` for that channel back toward the conservative minimum, interpreting the stall as a dropped oversized response

2.4 WHEN the broker CLI flag `--max-response-messages N` is provided THEN the system SHALL use `N` as a fixed `max_messages` for all channels, bypassing adaptive logic entirely

2.5 WHEN no `--max-response-messages` flag is provided THEN the system SHALL use adaptive mode as the default behavior

### Unchanged Behavior (Regression Prevention)

3.1 WHEN EDNS0 is not present (UDP buffer < 1232 bytes) THEN the system SHALL CONTINUE TO return at most 1 message per TXT response

3.2 WHEN pop mode is used (nonce starts with `P`, e.g., `dnc` tool) THEN the system SHALL CONTINUE TO use `pop_many` semantics unaffected by adaptive sizing

3.3 WHEN cursor-based replay advancement is used by the client THEN the system SHALL CONTINUE TO prune replay entries with `sequence < cursor` before building the response

3.4 WHEN a channel has no pending messages THEN the system SHALL CONTINUE TO return NOERROR with zero answers

3.5 WHEN the broker is used in embedded mode via `DirectTransport` THEN the system SHALL CONTINUE TO function identically to standalone mode for response sizing
