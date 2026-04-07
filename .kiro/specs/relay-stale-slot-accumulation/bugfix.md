# Bugfix Requirements Document

## Introduction

The relay mode data transfer stalls when transferring payloads larger than ~160 bytes (more than ~5 TCP segments at MSS 32). The unique-sender-id-per-write strategy in `RelayTransport.send_frame` and `handle_relay_send` causes each smoltcp packet to create a permanent slot in the `RelayStore`. When the relay handler's TXT response returns ALL accumulated slots, stale packets that smoltcp already processed are re-injected into the TCP state machine, filling the reassembly buffer with duplicate data at already-ACK'd sequence numbers and blocking new data delivery.

The `dns_sim_path_stale_slots` test reproduces this deterministically: a 512-byte payload at MTU 72/77 generates ~16 unique-sender slots that persist for the full 600s TTL, causing the connection to time out at 10 seconds.

## Bug Analysis

### Current Behavior (Defect)

1.1 WHEN `RelayTransport.send_frame` or `handle_relay_send` writes a packet THEN the system creates a new permanent slot with a unique sender_id (e.g., `client1-0`, `client1-1`, ..., `client1-N`) that persists until TTL expiry (600s), causing unbounded slot accumulation proportional to the number of packets sent

1.2 WHEN the relay handler processes a TXT query for a data channel via `handle_relay_receive` THEN the system returns ALL non-expired slots for that channel (up to the `max_records` cap of 4 with EDNS), including stale slots whose data smoltcp has already processed and ACK'd

1.3 WHEN the client's `DedupRecvTransport` receives a TXT response containing multiple envelopes THEN the system uses only the batch-level `max_seq` for deduplication, so if ANY envelope in the batch has a new sequence number, ALL envelopes in the batch (including stale ones) are delivered to smoltcp

1.4 WHEN smoltcp receives duplicate IP packets containing data at already-ACK'd TCP sequence numbers THEN the system's reassembly buffer fills with stale data, blocking acceptance of new segments and stalling the TCP connection

### Expected Behavior (Correct)

2.1 WHEN a sender writes multiple packets to the same data channel THEN the system SHALL bound the number of slots per sender to a small fixed limit (e.g., N most recent packets), preventing unbounded accumulation while still allowing multiple in-flight packets to coexist

2.2 WHEN the relay handler processes a TXT query for a data channel THEN the system SHALL return only the most recent bounded set of slots, ensuring stale packets that have been superseded are not included in the response

2.3 WHEN the client's dedup layer receives a batch of envelopes THEN the system SHALL filter out individual envelopes whose sequence numbers have already been seen, rather than accepting or rejecting the entire batch based on a single max_seq value

2.4 WHEN smoltcp processes incoming IP packets after the fix THEN the system SHALL deliver data without stalling, completing a 512-byte transfer through the DNS TXT path within the 10-second timeout (as validated by the `dns_sim_path_stale_slots` test)

### Unchanged Behavior (Regression Prevention)

3.1 WHEN two or more packets are sent in rapid succession by the same sender (e.g., SYN-ACK + data in one poll cycle) THEN the system SHALL CONTINUE TO preserve all in-flight packets without overwriting, so that the receiver sees every packet (the original motivation for unique sender_ids)

3.2 WHEN `RelayTransport` is used directly (bypassing DNS TXT encode/decode) THEN the system SHALL CONTINUE TO transfer data correctly, as validated by the `full_relay_path_round_trip` test

3.3 WHEN the relay handler receives A/AAAA send queries THEN the system SHALL CONTINUE TO write packets to the RelayStore and return the ACK IP

3.4 WHEN the relay handler receives status queries THEN the system SHALL CONTINUE TO return the correct slot count encoded as a status IP

3.5 WHEN the relay path operates under adverse network conditions (latency, packet loss, varying MTUs) THEN the system SHALL CONTINUE TO complete data transfers, as validated by the `relay_path_survives_adverse_network` property test
