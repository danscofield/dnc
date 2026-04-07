# Bugfix Requirements Document

## Introduction

The relay-mode TXT response path (`handle_relay_receive`) returns ALL non-expired packets in the ring buffer as full base32-encoded TXT records on every client poll. Each encrypted IP packet (~72 bytes) becomes ~160-170 bytes on the wire after base32 encoding plus envelope metadata (`sender_id|seq|timestamp|base32_payload`). With a 1232-byte EDNS0 budget, only ~7 records fit per response.

When the ring buffer accumulates many slots (up to 64 per sender), the client can only see 7 per poll. The `DedupRecvTransport` filters already-seen sequence numbers, but the relay keeps re-sending them. Critical retransmits that smoltcp needs to fill TCP sequence gaps get crowded out by stale data the client already has. This causes the connection to hang with data remaining untransferred.

The fix introduces a two-phase selective fetch protocol: Phase 1 (manifest) returns a compact list of available sequence IDs that fit dozens per response, and Phase 2 (fetch) lets the client request only the specific sequence IDs it needs by encoding them in the DNS query name.

## Bug Analysis

### Current Behavior (Defect)

1.1 WHEN the client sends a TXT query to poll for downstream data AND the relay channel contains more non-expired slots than fit in a single DNS response (~7 records at 1232-byte EDNS0 budget) THEN the relay returns only the first ~7 full base32-encoded packet envelopes, with no mechanism for the client to retrieve the remaining slots without re-receiving the same ones

1.2 WHEN the client polls repeatedly AND the relay channel contains slots the client has already received THEN the relay re-sends those already-seen slots in every response, consuming response budget that could carry new or needed retransmit packets

1.3 WHEN smoltcp needs a specific retransmitted packet to fill a TCP sequence gap AND that packet exists in the relay's ring buffer but is crowded out by already-seen stale slots in the ~7-record response window THEN the client never receives the needed retransmit and the TCP connection stalls

### Expected Behavior (Correct)

2.1 WHEN the client sends a TXT query to poll for downstream data (Phase 1 — manifest mode) THEN the relay SHALL return a compact list of available (sequence_id, payload_length) pairs for all non-expired slots in the channel, fitting dozens of entries per response instead of ~7 full packets

2.2 WHEN the client receives a manifest and determines which sequence IDs it still needs THEN the client SHALL send a follow-up TXT query encoding the requested sequence IDs in the DNS query name (Phase 2 — selective fetch mode) AND the relay SHALL return only the requested packet envelopes

2.3 WHEN the relay receives a selective fetch request for specific sequence IDs THEN the relay SHALL return only the packets matching those IDs, ensuring that critical retransmits are always delivered without being crowded out by already-seen data

2.4 WHEN the client already has all sequences listed in the manifest THEN the client SHALL skip the Phase 2 fetch query entirely, saving a round-trip

### Unchanged Behavior (Regression Prevention)

3.1 WHEN the relay receives an A/AAAA send query THEN the system SHALL CONTINUE TO write the packet to the ring buffer and return the ACK IP, with no change to the send path

3.2 WHEN the relay receives a status query THEN the system SHALL CONTINUE TO return the slot count encoded as a status IP address

3.3 WHEN the relay channel is empty and the client sends a TXT query THEN the system SHALL CONTINUE TO return a NoError response with zero answer records

3.4 WHEN the relay channel contains slots and a legacy TXT query is received (no manifest/fetch signaling) THEN the system SHALL CONTINUE TO return full packet envelopes in the existing format for backward compatibility

3.5 WHEN the `DedupRecvTransport` receives frames THEN the system SHALL CONTINUE TO deduplicate based on sequence numbers, preventing duplicate delivery to the smoltcp stack

3.6 WHEN packets are acknowledged via `ack_sequences` THEN the relay store SHALL CONTINUE TO remove those packets from the ring buffer
