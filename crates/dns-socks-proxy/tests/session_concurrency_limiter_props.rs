// Property-based tests for the session concurrency limiter.
//
// These tests verify the concurrency invariants using `tokio::sync::Semaphore`
// directly, without spinning up the full application.

use std::sync::Arc;
use std::time::Duration;

use proptest::prelude::*;
use tokio::sync::Semaphore;

// ---------------------------------------------------------------------------
// Property 1: Semaphore capacity invariant
// [Feature: session-concurrency-limiter, Property 1: Semaphore capacity invariant]
// **Validates: Requirements 1.1, 1.2, 1.3**
//
// For any semaphore with capacity N and any sequence of acquire/release
// operations, the number of simultaneously held permits never exceeds N.
// ---------------------------------------------------------------------------

proptest! {
    #[test]
    fn semaphore_capacity_invariant(
        capacity in 1usize..=64,
        ops in prop::collection::vec(any::<bool>(), 1..128),
    ) {
        let sem = Semaphore::new(capacity);
        let mut held: usize = 0;

        for acquire in &ops {
            if *acquire {
                // Try to acquire without blocking.
                if let Ok(_permit) = sem.try_acquire() {
                    held += 1;
                    // Immediately forget the permit so the semaphore stays
                    // decremented — we track count manually.
                    std::mem::forget(_permit);
                }
            } else if held > 0 {
                // Simulate releasing a permit.
                sem.add_permits(1);
                held -= 1;
            }
            prop_assert!(
                held <= capacity,
                "held ({held}) exceeded capacity ({capacity})"
            );
        }
    }
}


// ---------------------------------------------------------------------------
// Property 2: Permit lifecycle round-trip
// [Feature: session-concurrency-limiter, Property 2: Permit lifecycle round-trip]
// **Validates: Requirements 1.4, 5.1, 5.2**
//
// For any capacity N, acquiring K permits (K <= N) and dropping a random
// subset of them leaves `available_permits()` == N - still_held_count.
// ---------------------------------------------------------------------------

proptest! {
    #[test]
    fn permit_lifecycle_round_trip(
        capacity in 1usize..=64,
        k_ratio in 0.0f64..=1.0,
        drop_bits in prop::collection::vec(any::<bool>(), 0..64),
    ) {
        let k = ((k_ratio * capacity as f64).floor() as usize).min(capacity);
        let sem = Semaphore::new(capacity);

        // Acquire k permits.
        let mut permits: Vec<_> = (0..k)
            .map(|_| sem.try_acquire().expect("should have capacity"))
            .collect();

        // Drop a random subset determined by drop_bits.
        let mut still_held = permits.len();
        let mut i = 0;
        permits.retain(|_| {
            let keep = drop_bits.get(i).copied().unwrap_or(true);
            i += 1;
            if !keep {
                still_held -= 1;
            }
            keep
        });

        prop_assert_eq!(
            sem.available_permits(),
            capacity - still_held,
        );
    }
}


// ---------------------------------------------------------------------------
// Property 3: Queue timeout enforcement
// [Feature: session-concurrency-limiter, Property 3: Queue timeout enforcement]
// **Validates: Requirements 2.1, 2.2**
//
// For any semaphore at full capacity, a timed acquire that is not fulfilled
// within the timeout shall fail. Conversely, if a permit is released before
// the timeout elapses, the waiting acquire shall succeed.
// ---------------------------------------------------------------------------

proptest! {
    #[test]
    fn queue_timeout_enforcement(
        capacity in 1usize..=4,
        timeout_ms in 5u64..=50,
    ) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let sem = Arc::new(Semaphore::new(capacity));

            // Acquire all permits to fill the semaphore.
            let mut permits = Vec::new();
            for _ in 0..capacity {
                permits.push(sem.clone().acquire_owned().await.unwrap());
            }

            // A timed acquire should fail (timeout).
            let result = tokio::time::timeout(
                Duration::from_millis(timeout_ms),
                sem.clone().acquire_owned(),
            )
            .await;
            prop_assert!(result.is_err(), "should have timed out");

            // Release one permit.
            permits.pop();

            // Now acquire should succeed within a generous timeout.
            let result = tokio::time::timeout(
                Duration::from_secs(1),
                sem.clone().acquire_owned(),
            )
            .await;
            prop_assert!(result.is_ok(), "should have acquired after release");

            Ok(())
        })?;
    }
}


// ---------------------------------------------------------------------------
// Property 4: Config parsing round-trip
// [Feature: session-concurrency-limiter, Property 4: Config parsing round-trip]
// **Validates: Requirements 3.1, 4.1**
//
// For any valid `max_concurrent_sessions` (>= 1) and any valid
// `queue_timeout_ms` (>= 0), constructing a `SocksClientCli` and calling
// `into_config()` produces matching output fields.
// ---------------------------------------------------------------------------

use dns_socks_proxy::config::SocksClientCli;

proptest! {
    #[test]
    fn config_parsing_round_trip(
        max_sessions in 1usize..=1000,
        timeout_ms in 0u64..=120_000,
    ) {
        let cli = SocksClientCli {
            listen_addr: "127.0.0.1".parse().unwrap(),
            listen_port: 1080,
            domain: "tunnel.example.com".into(),
            resolver: "127.0.0.1:5353".parse().unwrap(),
            client_id: "myclient".into(),
            exit_node_id: "mynode".into(),
            psk: Some("aa".repeat(32)),
            psk_file: None,
            rto_ms: 2000,
            max_retransmits: 10,
            window_size: 8,
            poll_active_ms: 50,
            poll_idle_ms: 500,
            connect_timeout_ms: 30000,
            max_parallel_queries: 8,
            backoff_max_ms: None,
            max_concurrent_sessions: max_sessions,
            queue_timeout_ms: timeout_ms,
        };
        let cfg = cli.into_config().unwrap();
        prop_assert_eq!(cfg.max_concurrent_sessions, max_sessions);
        prop_assert_eq!(cfg.queue_timeout, Duration::from_millis(timeout_ms));
    }
}
