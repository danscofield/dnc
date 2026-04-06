# Requirements Document

## Introduction

When the socks-client polls for downstream data through a recursive resolver (e.g. Cloudflare 1.1.1.1), the EDNS0 OPT record causes the broker to batch multiple TXT records into a single response. Some recursive resolvers truncate or silently drop these larger responses, causing data loss and session stalls. This feature adds a `--no-edns` CLI flag to the socks-client and exit-node (standalone mode) that suppresses the EDNS0 OPT record on TXT queries. Without EDNS0, the broker defaults to `max_messages=1` and the total response stays under 512 bytes — the classic DNS UDP limit that all resolvers handle correctly. The tradeoff is throughput (1 frame per round trip instead of batching) but reliability through recursive resolvers improves dramatically.

## Glossary

- **Socks_Client**: The `socks-client` binary that accepts local SOCKS5 connections and tunnels TCP traffic over DNS queries to the broker.
- **Exit_Node**: The `exit-node` binary that terminates DNS-tunneled TCP connections and forwards them to their target. Supports standalone (DNS) and embedded (direct store) deployment modes.
- **DnsTransport**: The transport backend in `transport.rs` that sends and receives data via DNS A and TXT queries through a resolver.
- **DirectTransport**: The transport backend used in embedded mode that calls the ChannelStore directly, bypassing DNS entirely.
- **EDNS0_OPT_Record**: The EDNS0 extension mechanism for DNS (RFC 6891) that advertises a larger UDP buffer size, allowing the broker to batch multiple TXT records into a single response.
- **TXT_Query**: A DNS query of type TXT used to receive (poll) downstream data from the broker.
- **A_Query**: A DNS query of type A used to send upstream data to the broker.
- **Broker**: The DNS message broker that stores and forwards messages between tunnel endpoints.
- **Recursive_Resolver**: A third-party DNS resolver (e.g. 1.1.1.1, 8.8.8.8) that the socks-client may use to reach the broker.
- **Parallel_Recv**: The `recv_frames_parallel` function that fires multiple TXT queries on separate UDP sockets to improve throughput.

## Requirements

### Requirement 1: CLI Flag for Socks-Client

**User Story:** As a user running the socks-client through a recursive resolver, I want a `--no-edns` CLI flag so that I can disable EDNS0 on TXT queries to avoid truncation and data loss.

#### Acceptance Criteria

1. THE Socks_Client SHALL accept an optional `--no-edns` CLI flag.
2. WHEN the `--no-edns` flag is not provided, THE Socks_Client SHALL enable EDNS0 on TXT queries (preserving backward-compatible default behavior).
3. WHEN the `--no-edns` flag is provided, THE Socks_Client SHALL store the flag value in the validated `SocksClientConfig` struct for use by the transport layer.

### Requirement 2: CLI Flag for Exit-Node (Standalone Mode)

**User Story:** As a user running the exit-node in standalone mode through a recursive resolver, I want a `--no-edns` CLI flag so that I can disable EDNS0 on TXT queries to avoid truncation and data loss.

#### Acceptance Criteria

1. THE Exit_Node SHALL accept an optional `--no-edns` CLI flag.
2. WHEN the `--no-edns` flag is not provided, THE Exit_Node SHALL enable EDNS0 on TXT queries (preserving backward-compatible default behavior).
3. WHEN the `--no-edns` flag is provided, THE Exit_Node SHALL store the flag value in the validated `ExitNodeConfig` struct for use by the transport layer.

### Requirement 3: DnsTransport EDNS0 Suppression on TXT Queries

**User Story:** As a developer, I want the DnsTransport to conditionally include or omit the EDNS0 OPT record on TXT queries so that the broker limits its response size when EDNS0 is disabled.

#### Acceptance Criteria

1. THE DnsTransport SHALL accept a configurable boolean flag controlling whether EDNS0 is added to TXT queries.
2. WHEN the EDNS0 flag is enabled, THE DnsTransport SHALL include an EDNS0 OPT record with `max_payload=1232` in TXT queries (current behavior).
3. WHEN the EDNS0 flag is disabled, THE DnsTransport SHALL omit the EDNS0 OPT record from TXT queries.
4. THE DnsTransport SHALL include the EDNS0 OPT record in TXT queries by default when no flag is explicitly set (backward compatibility).

### Requirement 4: A Queries Remain Unaffected

**User Story:** As a developer, I want to ensure that the `--no-edns` flag only affects TXT queries so that the send path (A queries) continues to work identically.

#### Acceptance Criteria

1. WHEN the EDNS0 flag is disabled, THE DnsTransport SHALL continue to build A queries without an EDNS0 OPT record (A queries do not use EDNS0 today).
2. WHEN the EDNS0 flag is disabled, THE DnsTransport SHALL only suppress the EDNS0 OPT record for queries of type TXT.

### Requirement 5: Parallel Recv Respects EDNS0 Flag

**User Story:** As a developer, I want the parallel TXT query path (`recv_frames_parallel`) to also respect the `--no-edns` flag so that all TXT queries behave consistently.

#### Acceptance Criteria

1. THE Parallel_Recv function SHALL accept a parameter controlling whether EDNS0 is added to TXT queries.
2. WHEN the EDNS0 flag is disabled, THE Parallel_Recv function SHALL build TXT queries without an EDNS0 OPT record.
3. WHEN the EDNS0 flag is enabled, THE Parallel_Recv function SHALL build TXT queries with an EDNS0 OPT record with `max_payload=1232`.

### Requirement 6: Transport Construction Passes EDNS0 Flag

**User Story:** As a developer, I want the binary entry points (socks-client main, exit-node main) to propagate the `--no-edns` configuration to the DnsTransport instances they create so that the flag takes effect at runtime.

#### Acceptance Criteria

1. WHEN the Socks_Client creates a DnsTransport instance, THE Socks_Client SHALL configure the transport's EDNS0 flag based on the parsed CLI configuration.
2. WHEN the Exit_Node creates a DnsTransport instance in standalone mode, THE Exit_Node SHALL configure the transport's EDNS0 flag based on the parsed CLI configuration.
3. WHEN the Socks_Client creates the control-channel poller transport, THE Socks_Client SHALL configure the poller transport's EDNS0 flag based on the parsed CLI configuration.
