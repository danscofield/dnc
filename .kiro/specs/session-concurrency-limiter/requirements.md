# Requirements Document

## Introduction

The SOCKS client (`socks_client` binary) currently accepts incoming TCP connections in an unbounded loop, spawning a new tokio task per connection with no concurrency control. Each session creates its own `DnsTransport` (UDP socket), registers with the `ControlDispatcher`, and runs upstream/downstream/retransmit tasks — all of which generate DNS queries that compete for the shared DNS tunnel bandwidth.

When too many sessions are active simultaneously, the tunnel becomes overwhelmed: DNS queries time out, retransmissions spike, and throughput collapses for all sessions. This feature introduces a concurrency limiter that caps the number of simultaneously active sessions and queues excess incoming connections with backpressure and timeout semantics.

## Glossary

- **Socks_Client**: The `socks_client` binary that listens for SOCKS5 TCP connections and tunnels them over DNS.
- **Session**: A single SOCKS5 connection lifecycle from TCP accept through SYN/SYN-ACK handshake, bidirectional data transfer, and teardown. Each session occupies one slot in the concurrency limiter while active.
- **Concurrency_Limiter**: A component that enforces a maximum number of simultaneously active sessions by gating admission via a semaphore.
- **Semaphore**: A tokio counting semaphore used to limit the number of concurrently running `handle_connection` tasks.
- **Permit**: A semaphore permit acquired before a session begins and held for the session's entire lifetime. Releasing the permit allows a queued connection to proceed.
- **Wait_Queue**: The implicit FIFO queue of connections waiting to acquire a semaphore permit when all permits are in use.
- **Queue_Timeout**: The maximum duration a connection waits in the Wait_Queue before being dropped.
- **Accept_Loop**: The `loop` in `main()` that calls `listener.accept()` and spawns per-connection tasks.

## Requirements

### Requirement 1: Semaphore-Based Concurrency Limiting

**User Story:** As an operator, I want the SOCKS client to limit the number of concurrent active sessions, so that the DNS tunnel is not overwhelmed by too many simultaneous connections.

#### Acceptance Criteria

1. THE Concurrency_Limiter SHALL enforce a maximum number of simultaneously active sessions using a counting Semaphore.
2. WHEN a new TCP connection is accepted and the number of active sessions is below the configured maximum, THE Socks_Client SHALL acquire a Permit and begin processing the connection immediately.
3. WHEN a new TCP connection is accepted and the number of active sessions equals the configured maximum, THE Socks_Client SHALL place the connection in the Wait_Queue until a Permit becomes available.
4. WHEN a Session ends (via FIN, RST, error, or timeout), THE Concurrency_Limiter SHALL release the Permit, allowing the next queued connection to proceed.

### Requirement 2: Queue Timeout for Waiting Connections

**User Story:** As an operator, I want queued connections to time out after a configurable duration, so that clients receive timely feedback instead of waiting indefinitely.

#### Acceptance Criteria

1. WHILE a TCP connection is waiting in the Wait_Queue, THE Concurrency_Limiter SHALL enforce the configured Queue_Timeout.
2. IF a connection's wait time in the Wait_Queue exceeds the Queue_Timeout, THEN THE Socks_Client SHALL close the TCP connection and log a warning with the peer address.
3. THE Socks_Client SHALL continue accepting new connections from the TCP listener while other connections are waiting in the Wait_Queue.

### Requirement 3: Configurable Concurrency Limit

**User Story:** As an operator, I want to configure the maximum number of concurrent sessions via a CLI flag, so that I can tune the limit based on my DNS tunnel's throughput capacity.

#### Acceptance Criteria

1. THE Socks_Client SHALL accept a `--max-concurrent-sessions` CLI flag that specifies the maximum number of simultaneously active sessions.
2. THE Socks_Client SHALL use a default value of 8 for the maximum concurrent sessions when the `--max-concurrent-sessions` flag is not provided.
3. WHEN the `--max-concurrent-sessions` flag is set to a value less than 1, THE Socks_Client SHALL reject the configuration and exit with an error message.

### Requirement 4: Configurable Queue Timeout

**User Story:** As an operator, I want to configure the queue timeout duration via a CLI flag, so that I can balance responsiveness against burst tolerance.

#### Acceptance Criteria

1. THE Socks_Client SHALL accept a `--queue-timeout-ms` CLI flag that specifies the Queue_Timeout in milliseconds.
2. THE Socks_Client SHALL use a default value of 30000 milliseconds (30 seconds) for the Queue_Timeout when the `--queue-timeout-ms` flag is not provided.
3. WHEN the `--queue-timeout-ms` flag is set to 0, THE Socks_Client SHALL reject connections immediately when all Permits are in use instead of queuing them.

### Requirement 5: Permit Lifecycle Tied to Session Lifetime

**User Story:** As an operator, I want the concurrency permit to be held for the entire session lifetime, so that the active session count accurately reflects resource usage.

#### Acceptance Criteria

1. THE Concurrency_Limiter SHALL hold the Permit from the moment a connection begins processing (before the SOCKS5 handshake) until the `handle_connection` function returns.
2. IF the `handle_connection` function exits via any path (success, error, panic), THEN THE Concurrency_Limiter SHALL release the Permit.
3. THE Concurrency_Limiter SHALL use an RAII guard pattern (analogous to the existing `DispatcherGuard`) to guarantee Permit release on all exit paths.

### Requirement 6: Observability of Concurrency State

**User Story:** As an operator, I want to see log messages about concurrency limiting activity, so that I can diagnose throughput issues and tune the configuration.

#### Acceptance Criteria

1. WHEN a TCP connection is accepted and all Permits are in use, THE Socks_Client SHALL log an info-level message indicating the connection is queued, including the peer address and current queue depth.
2. WHEN a queued connection acquires a Permit and begins processing, THE Socks_Client SHALL log an info-level message indicating the connection was dequeued, including the peer address and wait duration.
3. WHEN a queued connection is dropped due to Queue_Timeout, THE Socks_Client SHALL log a warning-level message including the peer address and the configured timeout value.
4. WHEN the Socks_Client starts, THE Socks_Client SHALL log the configured maximum concurrent sessions and queue timeout values at info level.
