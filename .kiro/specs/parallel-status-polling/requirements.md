# Requirements Document

## Introduction

The DNS tunnel currently polls for downstream data sequentially — one TXT query per poll cycle, waiting for each response before sending the next. This limits throughput to one batch per DNS round-trip. The parallel-status-polling feature introduces a lightweight status query mechanism that reports queue depth, enabling the client to fire multiple concurrent TXT data-retrieval queries in parallel. Combined with adaptive exponential backoff, this maximizes throughput when data is flowing and minimizes unnecessary DNS traffic when idle.

This feature applies symmetrically: the socks-client uses it for downstream polling and the exit-node uses it for upstream polling.

## Glossary

- **Broker**: The `dns-message-broker` server that stores and relays messages between tunnel endpoints via DNS queries. Implemented in the `src/` crate.
- **Client**: Either the socks-client or exit-node binary that polls a channel for incoming data via DNS queries. Implemented in the `crates/dns-socks-proxy/` crate.
- **Status_Query**: A lightweight DNS A query sent by the Client to the Broker to determine how many messages are waiting in a channel's queue.
- **Status_Response**: The Broker's A record reply to a Status_Query, encoding the queue depth in the IP address.
- **Data_Query**: A DNS TXT query sent by the Client to the Broker to pop and retrieve message batches from a channel. Uses the existing `recv_frames` mechanism.
- **Queue_Depth**: The number of messages currently pending in a channel's FIFO queue on the Broker.
- **Nonce**: A random alphanumeric string prepended to DNS query names to prevent caching and deduplication by recursive resolvers.
- **Status_IP_Encoding**: The scheme for encoding Queue_Depth in an A record: the high octet is `128` (bit 7 set) to distinguish from existing ACK/error IPs, and the lower 24 bits encode the Queue_Depth as a big-endian unsigned integer.
- **No_Data_IP**: The fixed IP address `0.0.0.0` returned by the Broker when a channel's queue is empty.
- **Backoff_Interval**: The current polling delay, which increases exponentially during idle periods and resets when data is detected.
- **DnsTransport**: The existing struct in `crates/dns-socks-proxy/src/transport.rs` that sends and receives DNS queries over UDP.
- **ChannelStore**: The existing message store in `src/store.rs` that manages per-channel FIFO queues on the Broker.
- **Parallel_Slots**: The set of concurrent TXT Data_Queries fired by the Client, one per pending message reported by the Status_Response.

## Requirements

### Requirement 1: Broker Status Query Handling

**User Story:** As a tunnel endpoint, I want to query the Broker for the number of messages waiting in my channel, so that I know how many parallel data retrievals to issue.

#### Acceptance Criteria

1. WHEN the Broker receives an A query with the name format `<nonce>.status.<channel>.<controlled_domain>`, THE Broker SHALL interpret the query as a Status_Query for the specified channel.
2. WHEN the Broker receives a valid Status_Query for a channel containing one or more messages, THE Broker SHALL respond with an A record where the first octet is `128` and the remaining 24 bits encode the Queue_Depth as a big-endian unsigned integer.
3. WHEN the Broker receives a valid Status_Query for a channel that is empty or does not exist, THE Broker SHALL respond with an A record containing the No_Data_IP `0.0.0.0`.
4. WHEN the Queue_Depth exceeds 16,777,215 (the maximum value representable in 24 bits), THE Broker SHALL clamp the encoded value to 16,777,215.
5. THE Broker SHALL process Status_Queries without modifying the channel's message queue (read-only operation).
6. THE Broker SHALL set the TTL of Status_Response A records to 0.

### Requirement 2: Status IP Encoding and Decoding

**User Story:** As a developer, I want a well-defined encoding for queue depth in A record IP addresses, so that both the Broker and Client interpret status responses identically.

#### Acceptance Criteria

1. THE Status_IP_Encoding module SHALL encode a Queue_Depth value into an `Ipv4Addr` where the first octet is `128` and octets 2-4 contain the Queue_Depth as a big-endian 24-bit unsigned integer.
2. THE Status_IP_Encoding module SHALL decode an `Ipv4Addr` with first octet `128` back into the original Queue_Depth value.
3. FOR ALL Queue_Depth values in the range 0 to 16,777,215, encoding then decoding SHALL produce the original Queue_Depth value (round-trip property).
4. WHEN the Client receives an A record response with IP `0.0.0.0`, THE Client SHALL interpret the Queue_Depth as 0.
5. WHEN the Client receives an A record response with first octet `128`, THE Client SHALL extract the Queue_Depth from the lower 24 bits.
6. WHEN the Client receives an A record response that is neither `0.0.0.0` nor has first octet `128`, THE Client SHALL treat the response as an unrecognized status and log a warning.

### Requirement 3: Client Status Query Sending

**User Story:** As a tunnel endpoint, I want to send a status query before polling for data, so that I can determine whether data is available and how much.

#### Acceptance Criteria

1. THE Client SHALL construct Status_Query DNS names in the format `<nonce>.status.<channel>.<controlled_domain>` where the Nonce is a random 4-character alphanumeric string.
2. WHEN the Client initiates a poll cycle, THE Client SHALL send a Status_Query as a DNS A query to the resolver and await the response.
3. WHEN the Status_Response indicates Queue_Depth of 0 (No_Data_IP or encoded zero), THE Client SHALL skip Data_Query retrieval for that poll cycle.
4. WHEN the Status_Response indicates a Queue_Depth greater than 0, THE Client SHALL proceed to fire parallel Data_Queries equal to the reported Queue_Depth.
5. IF the Status_Query times out or returns an error, THEN THE Client SHALL treat the Queue_Depth as unknown and fall back to issuing a single Data_Query.

### Requirement 4: Parallel Data Retrieval

**User Story:** As a tunnel endpoint, I want to retrieve multiple data batches concurrently, so that I can drain the queue faster than one-at-a-time sequential polling.

#### Acceptance Criteria

1. WHEN the Status_Response reports a Queue_Depth of N (where N > 0), THE Client SHALL send N TXT Data_Queries concurrently.
2. THE Client SHALL assign each parallel Data_Query a unique Nonce to prevent recursive resolver deduplication.
3. THE Client SHALL send each parallel Data_Query on a separate UDP socket to avoid response cross-contamination.
4. THE Client SHALL await all N parallel Data_Query responses (or their individual timeouts) before processing the results.
5. WHEN one or more parallel Data_Queries return data frames, THE Client SHALL deliver all received frames to the existing frame-processing pipeline (decryption, reassembly, ACK).
6. WHEN a parallel Data_Query times out or fails, THE Client SHALL log the failure and continue processing results from the remaining queries.
7. THE Client SHALL cap the number of concurrent parallel Data_Queries to a configurable maximum (default: 8) to prevent resource exhaustion.

### Requirement 5: Adaptive Polling with Exponential Backoff

**User Story:** As a tunnel operator, I want the polling interval to adapt to traffic conditions, so that the tunnel minimizes DNS traffic when idle and maximizes throughput when data is flowing.

#### Acceptance Criteria

1. WHILE the Status_Response indicates Queue_Depth of 0 for consecutive poll cycles, THE Client SHALL increase the Backoff_Interval exponentially, doubling the interval after each idle cycle.
2. THE Client SHALL clamp the Backoff_Interval to a configurable maximum (default: the existing `poll_idle` duration).
3. WHEN the Status_Response indicates Queue_Depth greater than 0, THE Client SHALL reset the Backoff_Interval to the configured active poll interval (`poll_active`).
4. WHEN the Client completes draining parallel Data_Queries and the queue may still contain data, THE Client SHALL immediately issue another Status_Query without waiting for the Backoff_Interval.
5. THE Client SHALL use the configured `poll_active` duration as the initial and minimum Backoff_Interval.

### Requirement 6: Broker Query Routing for Status Queries

**User Story:** As a Broker operator, I want status queries to be routed correctly alongside existing send and receive queries, so that the new mechanism integrates without breaking existing functionality.

#### Acceptance Criteria

1. WHEN the Broker's query router receives an A query whose name contains the label `status` in the position immediately before the channel label, THE Broker SHALL route the query to the status handler.
2. WHEN the Broker's query router receives an A query that does not contain the `status` label in the expected position, THE Broker SHALL continue routing the query to the existing send handler.
3. THE Broker SHALL reject Status_Queries for names not under the controlled domain with a REFUSED response code.

### Requirement 7: ChannelStore Queue Depth Inspection

**User Story:** As a Broker developer, I want to query the number of pending messages in a channel without popping them, so that the status handler can report queue depth.

#### Acceptance Criteria

1. THE ChannelStore SHALL provide a `queue_depth` method that returns the number of pending messages for a given channel name.
2. WHEN the specified channel does not exist, THE ChannelStore `queue_depth` method SHALL return 0.
3. THE ChannelStore `queue_depth` method SHALL complete without acquiring a write lock or modifying any state.

### Requirement 8: Transport Layer Status Query Support

**User Story:** As a developer, I want the TransportBackend trait and DnsTransport to support status queries, so that both DNS-based and direct transports can query queue depth.

#### Acceptance Criteria

1. THE TransportBackend trait SHALL include a `query_status` method that accepts a channel name and returns a Queue_Depth value.
2. THE DnsTransport SHALL implement `query_status` by sending a Status_Query A query and decoding the Status_Response IP address.
3. THE DirectTransport SHALL implement `query_status` by calling the ChannelStore `queue_depth` method directly.
4. IF the `query_status` call fails due to a timeout or network error, THEN THE TransportBackend SHALL return a `TransportError`.

### Requirement 9: Parallel Socket Management

**User Story:** As a developer, I want each parallel data query to use its own UDP socket, so that responses are not mixed up between concurrent queries.

#### Acceptance Criteria

1. WHEN the Client fires N parallel Data_Queries, THE Client SHALL bind N ephemeral UDP sockets, one per query.
2. THE Client SHALL close each ephemeral UDP socket after its corresponding Data_Query response is received or times out.
3. IF binding an ephemeral UDP socket fails, THEN THE Client SHALL skip that particular parallel Data_Query and log the error.

### Requirement 10: Configuration Parameters

**User Story:** As a tunnel operator, I want to configure the parallel polling behavior, so that I can tune it for my network conditions.

#### Acceptance Criteria

1. THE socks-client and exit-node binaries SHALL accept a `--max-parallel-queries` CLI argument with a default value of 8.
2. THE socks-client and exit-node binaries SHALL accept a `--backoff-max-ms` CLI argument specifying the maximum backoff interval in milliseconds, defaulting to the value of `--poll-idle-ms`.
3. WHEN `--max-parallel-queries` is set to 1, THE Client SHALL behave equivalently to sequential polling with status-query gating.
