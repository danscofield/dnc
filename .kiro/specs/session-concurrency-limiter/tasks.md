# Tasks: Session Concurrency Limiter

## Task 1: Add CLI flags and config fields

- [x] 1.1 Add `max_concurrent_sessions` (u16, default 8) and `queue_timeout_ms` (u64, default 30000) fields to `SocksClientCli` in `crates/dns-socks-proxy/src/config.rs`
- [x] 1.2 Add `max_concurrent_sessions: usize` and `queue_timeout: Duration` fields to `SocksClientConfig`
- [x] 1.3 Add `ConfigError::InvalidMaxConcurrentSessions { got: usize }` variant
- [x] 1.4 Update `SocksClientCli::into_config()` to validate `max_concurrent_sessions >= 1` and map both new fields into `SocksClientConfig`
- [x] 1.5 Update the `base_socks_cli()` test helper to include the new fields with default values

## Task 2: Implement semaphore-based concurrency limiting in the accept loop

- [x] 2.1 Add `use tokio::sync::Semaphore` and `OwnedSemaphorePermit` imports in `socks_client.rs`
- [x] 2.2 Create `Arc<Semaphore>` in `main()` after config parsing, sized to `config.max_concurrent_sessions`
- [x] 2.3 Implement `acquire_permit()` helper function that handles three cases: immediate acquire, timed wait with timeout, and zero-timeout immediate rejection via `try_acquire_owned()`
- [x] 2.4 Modify the accept loop to call `acquire_permit()` before spawning, move the `OwnedSemaphorePermit` into the spawned task closure so it is held for the session lifetime and dropped on any exit path
- [x] 2.5 Add startup log line showing `max_concurrent_sessions` and `queue_timeout` values

## Task 3: Add logging for concurrency state observability

- [x] 3.1 In `acquire_permit()`, log info when a connection is queued (all permits in use), including peer address
- [x] 3.2 In `acquire_permit()`, log info when a queued connection is dequeued, including peer address and wait duration
- [x] 3.3 In `acquire_permit()`, log warning when a connection is dropped due to queue timeout, including peer address and timeout value

## Task 4: Unit tests for config validation

- [x] 4.1 Add unit test verifying `max_concurrent_sessions` defaults to 8 and `queue_timeout` defaults to 30s
- [x] 4.2 Add unit test verifying `max_concurrent_sessions == 0` produces `ConfigError::InvalidMaxConcurrentSessions`
- [x] 4.3 Add unit test verifying `queue_timeout_ms == 0` produces `Duration::ZERO` in config

## Task 5: Property-based tests

- [x] 5.1 Property 1 test: semaphore capacity invariant — for random capacity N and random acquire/release sequences, held permits never exceed N `[Feature: session-concurrency-limiter, Property 1: Semaphore capacity invariant]`
- [x] 5.2 Property 2 test: permit lifecycle round-trip — for random capacity and random subset of dropped permits, `available_permits()` equals capacity minus still-held count `[Feature: session-concurrency-limiter, Property 2: Permit lifecycle round-trip]`
- [x] 5.3 Property 3 test: queue timeout enforcement — for random capacity at full utilization, timed acquire fails after timeout; releasing a permit before timeout allows acquire to succeed `[Feature: session-concurrency-limiter, Property 3: Queue timeout enforcement]`
- [x] 5.4 Property 4 test: config parsing round-trip — for random valid `max_concurrent_sessions` (1..=1000) and `queue_timeout_ms` (0..=120000), `into_config()` output matches input `[Feature: session-concurrency-limiter, Property 4: Config parsing round-trip]`
