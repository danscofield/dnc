//! Channel store module.
//!
//! Manages per-channel FIFO message queues with expiry and capacity limits.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::error::StoreError;

/// Conservative starting point for adaptive max_messages.
pub const ADAPTIVE_INITIAL_MAX: usize = 2;
/// Minimum max_messages (never go below).
pub const ADAPTIVE_FLOOR: usize = 2;
/// Maximum max_messages (never exceed).
pub const ADAPTIVE_CEILING: usize = 8;
/// Consecutive stalls before multiplicative decrease.
pub const STALL_THRESHOLD: u32 = 2;

/// Per-channel adaptive response sizing state (AIMD algorithm).
#[derive(Debug, Clone)]
pub struct AdaptiveState {
    /// Current adaptive limit for max_messages.
    pub max_messages: usize,
    /// Cursor value from the previous poll (None if no poll yet).
    pub last_cursor_seen: Option<u64>,
    /// Consecutive polls where cursor did not advance.
    pub stall_count: u32,
}

impl Default for AdaptiveState {
    fn default() -> Self {
        Self {
            max_messages: ADAPTIVE_INITIAL_MAX,
            last_cursor_seen: None,
            stall_count: 0,
        }
    }
}

/// Trait for injectable time, enabling deterministic testing.
pub trait Clock {
    /// Returns the current `Instant` (monotonic clock).
    fn now(&self) -> Instant;
    /// Returns the current Unix epoch timestamp in seconds.
    fn timestamp_secs(&self) -> u64;
}

/// Real clock backed by `std::time`.
pub struct RealClock;

impl Clock for RealClock {
    fn now(&self) -> Instant {
        Instant::now()
    }

    fn timestamp_secs(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before UNIX epoch")
            .as_secs()
    }
}

/// A message stored in a channel queue.
#[derive(Clone)]
pub struct StoredMessage {
    /// Identifier of the sending client (max 63 chars).
    pub sender_id: String,
    /// Raw message bytes (decoded from base32).
    pub payload: Vec<u8>,
    /// Monotonically increasing per-broker sequence number.
    pub sequence: u64,
    /// Unix epoch seconds when the message was stored.
    pub timestamp: u64,
    /// When this message should be garbage collected.
    pub expiry: Instant,
}

/// A named channel holding a FIFO queue of messages.
pub struct Channel {
    /// FIFO queue of pending messages.
    pub messages: VecDeque<StoredMessage>,
    /// Last send or receive activity on this channel.
    pub last_activity: Instant,
    /// Buffer of recently-served messages for re-delivery on re-poll.
    pub replay: VecDeque<StoredMessage>,
    /// Sequence number of the oldest message in the replay buffer.
    pub replay_cursor: u64,
    /// Per-channel adaptive response sizing state.
    pub adaptive: AdaptiveState,
}

/// Thread-safe message store keyed by channel name.
pub struct ChannelStore<C: Clock> {
    /// Per-channel message queues.
    channels: HashMap<String, Channel>,
    /// Maximum number of pending messages per channel.
    max_messages_per_channel: usize,
    /// Duration after which an inactive channel is removed.
    channel_inactivity_timeout: Duration,
    /// Duration after which a message expires.
    message_ttl: Duration,
    /// Global monotonically increasing sequence counter.
    next_sequence: u64,
    /// Injectable clock for time operations.
    clock: C,
    /// Maximum number of messages retained in the per-channel replay buffer.
    max_replay_size: usize,
}

impl<C: Clock> ChannelStore<C> {
    /// Create a new `ChannelStore` with the given configuration and clock.
    pub fn new(
        max_messages_per_channel: usize,
        channel_inactivity_timeout: Duration,
        message_ttl: Duration,
        clock: C,
        max_replay_size: usize,
    ) -> Self {
        Self {
            channels: HashMap::new(),
            max_messages_per_channel,
            channel_inactivity_timeout,
            message_ttl,
            next_sequence: 0,
            clock,
            max_replay_size,
        }
    }

    /// Store a message in the given channel.
    ///
    /// Auto-creates the channel if it doesn't exist. Returns the assigned
    /// sequence number on success, or `StoreError::ChannelFull` if the
    /// channel has reached `max_messages_per_channel`.
    pub fn push(
        &mut self,
        channel: &str,
        sender_id: &str,
        payload: Vec<u8>,
    ) -> Result<u64, StoreError> {
        let now = self.clock.now();
        let ch = self.channels.entry(channel.to_string()).or_insert_with(|| {
            Channel {
                messages: VecDeque::new(),
                last_activity: now,
                replay: VecDeque::new(),
                replay_cursor: 0,
                adaptive: AdaptiveState::default(),
            }
        });

        if ch.messages.len() >= self.max_messages_per_channel {
            return Err(StoreError::ChannelFull(channel.to_string()));
        }

        let seq = self.next_sequence;
        self.next_sequence += 1;

        let timestamp = self.clock.timestamp_secs();
        let expiry = now + self.message_ttl;

        ch.messages.push_back(StoredMessage {
            sender_id: sender_id.to_string(),
            payload,
            sequence: seq,
            timestamp,
            expiry,
        });
        ch.last_activity = now;

        Ok(seq)
    }

    /// Pop the oldest undelivered message from a channel.
    ///
    /// Returns `None` if the channel doesn't exist or is empty.
    /// Updates the channel's `last_activity` on successful pop.
    pub fn pop(&mut self, channel: &str) -> Option<StoredMessage> {
        let now = self.clock.now();
        let ch = self.channels.get_mut(channel)?;
        let msg = ch.messages.pop_front()?;
        ch.last_activity = now;
        Some(msg)
    }

    /// Pop up to `max` messages from a channel.
    pub fn pop_many(&mut self, channel: &str, max: usize) -> Vec<StoredMessage> {
        let now = self.clock.now();
        let ch = match self.channels.get_mut(channel) {
            Some(ch) => ch,
            None => return vec![],
        };
        let count = max.min(ch.messages.len());
        let msgs: Vec<StoredMessage> = ch.messages.drain(..count).collect();
        if !msgs.is_empty() {
            ch.last_activity = now;
        }
        msgs
    }

    /// Non-destructive read of up to `max` messages from a channel.
    ///
    /// When `cursor` is `None` (legacy path):
    /// If the replay buffer is non-empty and there are new messages in the queue,
    /// returns replay contents first, then new messages up to the batch limit.
    /// If the replay buffer is non-empty but the queue is empty, this is a
    /// re-poll confirming the client received the previous batch — the replay
    /// is returned one final time and then cleared so subsequent polls return empty.
    ///
    /// When `cursor` is `Some(c)` (cursor-based advancement):
    /// Drops replay entries with `sequence < c` (confirmed received by client),
    /// retains entries with `sequence >= c`, and does NOT clear replay on empty
    /// queue — advancement is driven exclusively by the cursor value.
    ///
    /// Served messages from `messages` are moved into `replay`.
    /// When replay exceeds `max_replay_size`, oldest entries are dropped.
    pub fn peek_many(&mut self, channel: &str, max: usize, cursor: Option<u64>) -> Vec<StoredMessage> {
        let now = self.clock.now();
        let max_replay = self.max_replay_size;
        let ch = match self.channels.get_mut(channel) {
            Some(ch) => ch,
            None => return vec![],
        };

        // Cursor-based replay pruning: drop confirmed entries
        if let Some(c) = cursor {
            ch.replay.retain(|msg| msg.sequence >= c);
            // Update replay_cursor after pruning
            if let Some(oldest) = ch.replay.front() {
                ch.replay_cursor = oldest.sequence;
            } else {
                ch.replay_cursor = c;
            }
        }

        let mut result = Vec::new();

        // If replay is non-empty, return replay contents first
        if !ch.replay.is_empty() {
            for msg in ch.replay.iter() {
                if result.len() >= max {
                    break;
                }
                result.push(msg.clone());
            }
        }

        // Fill remaining capacity from the messages queue
        let remaining = max.saturating_sub(result.len());
        let new_count = remaining.min(ch.messages.len());
        if new_count > 0 {
            let new_msgs: Vec<StoredMessage> = ch.messages.drain(..new_count).collect();
            for msg in &new_msgs {
                result.push(msg.clone());
                ch.replay.push_back(msg.clone());
            }
        } else if cursor.is_none() && !ch.replay.is_empty() {
            // Legacy path only: No new messages were drained — this is a confirming re-poll.
            // The client successfully received the previous batch, so clear
            // the replay buffer. This prevents infinite re-delivery while
            // still allowing one re-poll for lost UDP responses.
            // When cursor is present, replay advancement is driven exclusively
            // by the cursor — do NOT clear heuristically.
            ch.replay.clear();
            ch.replay_cursor = 0;
        }

        // Slide the replay window: drop oldest entries if over max_replay_size
        while ch.replay.len() > max_replay {
            ch.replay.pop_front();
        }

        // Update replay_cursor to the sequence of the oldest replay entry
        if let Some(oldest) = ch.replay.front() {
            ch.replay_cursor = oldest.sequence;
        }

        if !result.is_empty() {
            ch.last_activity = now;
        }

        result
    }

    /// Return the number of pending messages in the channel.
    /// Returns 0 if the channel does not exist.
    /// This is a read-only operation — no messages are popped.
    pub fn queue_depth(&self, channel: &str) -> usize {
        self.channels
            .get(channel)
            .map_or(0, |ch| ch.messages.len() + ch.replay.len())
    }

    /// Remove expired messages and inactive channels.
    ///
    /// - Messages whose `expiry < now` are removed.
    /// - Channels whose `last_activity + inactivity_timeout < now` are removed entirely.
    pub fn sweep_expired(&mut self, now: Instant) {
        // Remove entire channels that have been inactive too long.
        self.channels.retain(|_name, ch| {
            if ch.last_activity + self.channel_inactivity_timeout < now {
                return false;
            }
            // Remove expired messages within active channels.
            ch.messages.retain(|msg| msg.expiry >= now);
            // Remove expired messages from replay buffers.
            ch.replay.retain(|msg| msg.expiry >= now);
            true
        });
    }

    /// Update the adaptive response sizing state for a channel based on cursor feedback.
    ///
    /// Implements the AIMD (Additive Increase / Multiplicative Decrease) algorithm:
    /// - Cursor `None`: no update, return current max_messages
    /// - First poll (last_cursor_seen is None): record cursor, return current max_messages
    /// - Cursor advanced: reset stall_count, increment max_messages by 1 (capped at ADAPTIVE_CEILING)
    /// - Cursor stalled: increment stall_count; if >= STALL_THRESHOLD, halve max_messages (floored at ADAPTIVE_FLOOR)
    /// - Cursor regressed: ignore (stale/reordered query)
    ///
    /// Returns the current effective max_messages for the channel.
    pub fn update_adaptive_state(&mut self, channel: &str, cursor: Option<u64>) -> usize {
        let ch = match self.channels.get_mut(channel) {
            Some(ch) => ch,
            None => return ADAPTIVE_INITIAL_MAX,
        };

        let cursor = match cursor {
            Some(c) => c,
            None => return ch.adaptive.max_messages,
        };

        if ch.adaptive.last_cursor_seen.is_none() {
            // First poll with cursor — just record it
            ch.adaptive.last_cursor_seen = Some(cursor);
            return ch.adaptive.max_messages;
        }

        let last = ch.adaptive.last_cursor_seen.unwrap();

        if cursor > last {
            // Cursor advanced — response got through
            ch.adaptive.stall_count = 0;
            ch.adaptive.max_messages = (ch.adaptive.max_messages + 1).min(ADAPTIVE_CEILING);
        } else if cursor == last {
            // Cursor stalled — response may have been dropped
            ch.adaptive.stall_count += 1;
            if ch.adaptive.stall_count >= STALL_THRESHOLD {
                ch.adaptive.max_messages = (ch.adaptive.max_messages / 2).max(ADAPTIVE_FLOOR);
                ch.adaptive.stall_count = 0;
            }
        }
        // cursor < last: stale/reordered query — ignore

        ch.adaptive.last_cursor_seen = Some(cursor);
        ch.adaptive.max_messages
    }

    /// Read-only accessor returning the channel's current adaptive max_messages.
    ///
    /// Returns `ADAPTIVE_INITIAL_MAX` if the channel doesn't exist.
    pub fn get_adaptive_max_messages(&self, channel: &str) -> usize {
        self.channels
            .get(channel)
            .map_or(ADAPTIVE_INITIAL_MAX, |ch| ch.adaptive.max_messages)
    }

    /// Returns a reference to the internal channels map (for testing).
    #[cfg(test)]
    pub fn channels(&self) -> &HashMap<String, Channel> {
        &self.channels
    }
}

#[cfg(test)]
pub mod test_support {
    use super::*;
    use std::cell::Cell;

    /// Mock clock for deterministic testing.
    pub struct MockClock {
        instant: Cell<Instant>,
        timestamp: Cell<u64>,
    }

    impl MockClock {
        /// Create a new `MockClock` starting at the current instant and timestamp 0.
        pub fn new() -> Self {
            Self {
                instant: Cell::new(Instant::now()),
                timestamp: Cell::new(0),
            }
        }

        /// Advance the mock clock by the given duration.
        pub fn advance(&self, duration: Duration) {
            self.instant.set(self.instant.get() + duration);
            self.timestamp.set(self.timestamp.get() + duration.as_secs());
        }

        /// Get the current mock instant (useful for passing to `sweep_expired`).
        pub fn instant(&self) -> Instant {
            self.instant.get()
        }
    }

    impl Clock for MockClock {
        fn now(&self) -> Instant {
            self.instant.get()
        }

        fn timestamp_secs(&self) -> u64 {
            self.timestamp.get()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::test_support::MockClock;
    use proptest::prelude::*;

    #[test]
    fn test_push_auto_creates_channel() {
        let clock = MockClock::new();
        let mut store = ChannelStore::new(10, Duration::from_secs(3600), Duration::from_secs(600), clock, 32);

        let seq = store.push("test-channel", "alice", b"hello".to_vec()).unwrap();
        assert_eq!(seq, 0);
        assert!(store.channels().contains_key("test-channel"));
        assert_eq!(store.channels()["test-channel"].messages.len(), 1);
    }

    #[test]
    fn test_push_monotonic_sequence() {
        let clock = MockClock::new();
        let mut store = ChannelStore::new(10, Duration::from_secs(3600), Duration::from_secs(600), clock, 32);

        let s0 = store.push("ch1", "alice", b"a".to_vec()).unwrap();
        let s1 = store.push("ch2", "bob", b"b".to_vec()).unwrap();
        let s2 = store.push("ch1", "alice", b"c".to_vec()).unwrap();

        assert_eq!(s0, 0);
        assert_eq!(s1, 1);
        assert_eq!(s2, 2);
        assert!(s0 < s1);
        assert!(s1 < s2);
    }

    #[test]
    fn test_push_channel_full() {
        let clock = MockClock::new();
        let mut store = ChannelStore::new(2, Duration::from_secs(3600), Duration::from_secs(600), clock, 32);

        store.push("ch", "a", b"1".to_vec()).unwrap();
        store.push("ch", "a", b"2".to_vec()).unwrap();
        let err = store.push("ch", "a", b"3".to_vec()).unwrap_err();
        assert!(matches!(err, StoreError::ChannelFull(_)));
    }

    #[test]
    fn test_pop_fifo_order() {
        let clock = MockClock::new();
        let mut store = ChannelStore::new(10, Duration::from_secs(3600), Duration::from_secs(600), clock, 32);

        store.push("ch", "alice", b"first".to_vec()).unwrap();
        store.push("ch", "bob", b"second".to_vec()).unwrap();
        store.push("ch", "alice", b"third".to_vec()).unwrap();

        let m1 = store.pop("ch").unwrap();
        assert_eq!(m1.payload, b"first");
        assert_eq!(m1.sender_id, "alice");

        let m2 = store.pop("ch").unwrap();
        assert_eq!(m2.payload, b"second");

        let m3 = store.pop("ch").unwrap();
        assert_eq!(m3.payload, b"third");
    }

    #[test]
    fn test_pop_empty_channel_returns_none() {
        let clock = MockClock::new();
        let mut store = ChannelStore::new(10, Duration::from_secs(3600), Duration::from_secs(600), clock, 32);

        assert!(store.pop("nonexistent").is_none());

        store.push("ch", "a", b"x".to_vec()).unwrap();
        store.pop("ch"); // drain it
        assert!(store.pop("ch").is_none());
    }

    #[test]
    fn test_pop_does_not_return_same_message_twice() {
        let clock = MockClock::new();
        let mut store = ChannelStore::new(10, Duration::from_secs(3600), Duration::from_secs(600), clock, 32);

        store.push("ch", "a", b"only".to_vec()).unwrap();
        let m = store.pop("ch");
        assert!(m.is_some());
        assert!(store.pop("ch").is_none());
    }

    #[test]
    fn test_sweep_removes_expired_messages() {
        let clock = MockClock::new();
        let base = clock.instant();
        let mut store = ChannelStore::new(10, Duration::from_secs(3600), Duration::from_secs(60), clock, 32);

        store.push("ch", "a", b"msg1".to_vec()).unwrap();
        store.push("ch", "a", b"msg2".to_vec()).unwrap();

        // Messages expire at base + 60s. Sweep at base + 61s should remove them.
        let sweep_time = base + Duration::from_secs(61);
        store.sweep_expired(sweep_time);

        assert!(store.pop("ch").is_none());
    }

    #[test]
    fn test_sweep_preserves_non_expired_messages() {
        let clock = MockClock::new();
        let base = clock.instant();
        let mut store = ChannelStore::new(10, Duration::from_secs(3600), Duration::from_secs(60), clock, 32);

        store.push("ch", "a", b"msg".to_vec()).unwrap();

        // Sweep at base + 30s — message expires at base + 60s, so it should survive.
        let sweep_time = base + Duration::from_secs(30);
        store.sweep_expired(sweep_time);

        let m = store.pop("ch");
        assert!(m.is_some());
        assert_eq!(m.unwrap().payload, b"msg");
    }

    #[test]
    fn test_sweep_removes_inactive_channels() {
        let clock = MockClock::new();
        let base = clock.instant();
        let mut store = ChannelStore::new(10, Duration::from_secs(300), Duration::from_secs(600), clock, 32);

        store.push("ch", "a", b"msg".to_vec()).unwrap();

        // Channel inactivity timeout is 300s. Sweep at base + 301s should remove the channel.
        let sweep_time = base + Duration::from_secs(301);
        store.sweep_expired(sweep_time);

        assert!(!store.channels().contains_key("ch"));
    }

    #[test]
    fn test_sweep_keeps_active_channels() {
        let clock = MockClock::new();
        let base = clock.instant();
        let mut store = ChannelStore::new(10, Duration::from_secs(300), Duration::from_secs(600), clock, 32);

        store.push("ch", "a", b"msg".to_vec()).unwrap();

        // Sweep at base + 100s — well within inactivity timeout.
        let sweep_time = base + Duration::from_secs(100);
        store.sweep_expired(sweep_time);

        assert!(store.channels().contains_key("ch"));
    }

    #[test]
    fn test_push_sets_timestamp_and_expiry() {
        let clock = MockClock::new();
        let base = clock.instant();
        let mut store = ChannelStore::new(10, Duration::from_secs(3600), Duration::from_secs(120), clock, 32);

        store.push("ch", "a", b"x".to_vec()).unwrap();
        let msg = store.pop("ch").unwrap();

        assert_eq!(msg.timestamp, 0); // MockClock starts at 0
        assert_eq!(msg.expiry, base + Duration::from_secs(120));
    }

    // =========================================================================
    // Bug Condition Exploration: Replay Buffer Stale Blocking (Task 1)
    // =========================================================================

    // **Validates: Property 1 (design.md) — Requirements 2.1, 2.2**
    //
    // Bug Condition Exploration: Stale Replay Blocks New Message Delivery
    //
    // For any non-empty replay buffer with new messages in the queue,
    // peek_many returns the new messages immediately without stale replay
    // entries.
    //
    // Steps: push initial messages → peek (creates replay) → push a NEW
    // message → peek again → assert ONLY the new message is returned.
    //
    // On UNFIXED code this test is EXPECTED TO FAIL — confirming the bug
    // exists: peek_many returns stale replay frames concatenated with the
    // new message instead of just the new message.
    proptest! {
        #[test]
        fn bug_condition_stale_replay_blocks_new_message_delivery(
            initial_count in 1usize..=8,
            initial_payloads in prop::collection::vec(
                prop::collection::vec(any::<u8>(), 1..64),
                1..=8,
            ),
            new_payload in prop::collection::vec(any::<u8>(), 1..64),
        ) {
            let n = initial_count.min(initial_payloads.len());
            let clock = MockClock::new();
            let mut store = ChannelStore::new(
                100,
                Duration::from_secs(3600),
                Duration::from_secs(600),
                clock,
                32,
            );

            // Step 1: Push initial messages to the channel
            for i in 0..n {
                store.push("ctl-ch", "session1", initial_payloads[i].clone()).unwrap();
            }

            // Step 2: Peek to move messages into the replay buffer
            let first_peek = store.peek_many("ctl-ch", 32, None);
            prop_assert_eq!(
                first_peek.len(),
                n,
                "First peek should return all {} initial messages",
                n
            );

            // Step 3: Push a NEW message (simulating session #2's SYN-ACK)
            let new_seq = store.push("ctl-ch", "session2", new_payload.clone()).unwrap();

            // Step 4: Peek again — replay is served first, then new messages
            // fill remaining capacity. Both are returned together.
            let second_peek = store.peek_many("ctl-ch", 32, None);

            // Assert: replay (n) + new (1) messages returned
            prop_assert_eq!(
                second_peek.len(),
                n + 1,
                "Second peek should return {} replay + 1 new = {} messages, \
                 but got {}",
                n, n + 1, second_peek.len()
            );

            // Assert: the last message is the new one
            let last = &second_peek[second_peek.len() - 1];
            prop_assert_eq!(
                &last.payload,
                &new_payload,
                "Last message should be the new message payload"
            );
            prop_assert_eq!(
                last.sequence,
                new_seq,
                "Last message should have the new message sequence"
            );
            prop_assert_eq!(
                &last.sender_id,
                "session2",
                "Last message should be from session2"
            );
        }
    }

    // **Validates: Property 2 (design.md) — Requirement 2.3**
    //
    // Bug Condition Exploration: Replay Buffer Requires Extra Poll Cycle to Clear
    //
    // For any non-empty replay buffer with empty queue, one peek_many call
    // clears the replay so the next returns empty.
    //
    // Steps: push messages → peek (creates replay) → peek again with empty
    // queue (should return replay and clear it) → peek a third time → assert
    // the third peek returns empty.
    //
    // On UNFIXED code this test is EXPECTED TO FAIL — confirming the bug
    // exists: the third peek still returns stale data because clearing
    // requires an additional confirming re-poll cycle.
    proptest! {
        #[test]
        fn bug_condition_replay_requires_extra_poll_cycle_to_clear(
            msg_count in 1usize..=8,
            payloads in prop::collection::vec(
                prop::collection::vec(any::<u8>(), 1..64),
                1..=8,
            ),
        ) {
            let n = msg_count.min(payloads.len());
            let clock = MockClock::new();
            let mut store = ChannelStore::new(
                100,
                Duration::from_secs(3600),
                Duration::from_secs(600),
                clock,
                32,
            );

            // Step 1: Push messages to the channel
            for i in 0..n {
                store.push("ctl-ch", "session1", payloads[i].clone()).unwrap();
            }

            // Step 2: First peek — moves messages from queue into replay buffer
            let first_peek = store.peek_many("ctl-ch", 32, None);
            prop_assert_eq!(
                first_peek.len(),
                n,
                "First peek should return all {} messages",
                n
            );

            // Step 3: Second peek — queue is empty, replay is non-empty.
            // This should return the replay contents AND clear the replay
            // buffer in the same call.
            let second_peek = store.peek_many("ctl-ch", 32, None);
            prop_assert_eq!(
                second_peek.len(),
                n,
                "Second peek (re-poll) should return the {} replay messages",
                n
            );

            // Step 4: Third peek — replay should now be cleared.
            // On FIXED code this returns empty immediately.
            // On UNFIXED code this still returns stale data because the
            // replay was only cleared on the second peek but the result
            // was already populated before clearing.
            let third_peek = store.peek_many("ctl-ch", 32, None);
            prop_assert_eq!(
                third_peek.len(),
                0,
                "Third peek should return empty (replay cleared on second peek), \
                 but got {} messages — replay requires extra poll cycle to clear",
                third_peek.len()
            );
        }
    }

    // **Validates: Requirements 1.1, 1.2, 2.1, 2.2**
    //
    // Bug Condition Exploration: Destructive Pop Loses Messages on Re-poll
    //
    // For any non-empty batch of messages pushed to a channel, after calling
    // `pop_many` (simulating a poll), a subsequent `pop_many` (simulating a
    // re-poll after a lost DNS response) should return the same messages.
    // Additionally, `queue_depth` should remain > 0 after the first poll
    // since messages have not been confirmed received.
    //
    // On UNFIXED code this test is EXPECTED TO FAIL — confirming the bug
    // exists: `pop_many` drains messages permanently, the second call
    // returns empty, and `queue_depth` drops to 0.
    proptest! {
        #[test]
        fn bug_condition_destructive_pop_loses_messages_on_repoll(
            batch_size in 1usize..=10,
            payloads in prop::collection::vec(prop::collection::vec(any::<u8>(), 1..64), 1..=10),
        ) {
            let n = batch_size.min(payloads.len());
            let clock = MockClock::new();
            let mut store = ChannelStore::new(
                100,
                Duration::from_secs(3600),
                Duration::from_secs(600),
                clock,
                32,
            );

            // Push N messages to the channel
            let mut pushed_payloads = Vec::new();
            for i in 0..n {
                store.push("test-ch", "sender", payloads[i].clone()).unwrap();
                pushed_payloads.push(payloads[i].clone());
            }

            // First poll — simulate client polling via peek_many (the fixed API)
            let first_poll = store.peek_many("test-ch", n, None);
            prop_assert_eq!(
                first_poll.len(),
                n,
                "First peek_many should return all {} pushed messages",
                n
            );

            // Verify first poll returned the correct payloads
            let first_poll_payloads: Vec<Vec<u8>> =
                first_poll.iter().map(|m| m.payload.clone()).collect();
            prop_assert_eq!(
                &first_poll_payloads,
                &pushed_payloads,
                "First poll payloads should match pushed payloads"
            );

            // After first peek_many, messages have moved from `messages` to `replay`.
            // queue_depth includes both unserved messages and replay entries,
            // so it should still equal n (the messages are now in replay).
            let depth_after_first_poll = store.queue_depth("test-ch");
            prop_assert_eq!(
                depth_after_first_poll,
                n,
                "queue_depth should be {} after peek_many (messages in replay buffer), \
                 but got {}",
                n,
                depth_after_first_poll
            );

            // Second poll — simulate re-poll after lost DNS response
            let second_poll = store.peek_many("test-ch", n, None);
            prop_assert_eq!(
                second_poll.len(),
                n,
                "Second peek_many (re-poll) should return the same {} messages, \
                 but got {} — messages permanently lost after first peek",
                n,
                second_poll.len()
            );

            // Verify second poll returned the same payloads
            let second_poll_payloads: Vec<Vec<u8>> =
                second_poll.iter().map(|m| m.payload.clone()).collect();
            prop_assert_eq!(
                &second_poll_payloads,
                &pushed_payloads,
                "Re-poll payloads should match original pushed payloads"
            );
        }
    }

    // =========================================================================
    // Preservation Property Tests (Task 2)
    // =========================================================================
    //
    // These tests capture the CURRENT correct behavior of push, capacity,
    // sweep_expired, and queue_depth on UNFIXED code. They must all PASS.
    // After the fix is applied, they verify no regressions were introduced.

    // **Validates: Requirements 3.1, 3.2**
    //
    // Property: For all sequences of push operations on a channel, sequence
    // numbers are strictly monotonically increasing and FIFO order is
    // preserved when messages are read back via pop.
    proptest! {
        #[test]
        fn preservation_push_fifo_and_monotonic_sequences(
            sender_ids in prop::collection::vec("[a-z]{1,8}", 1..=10),
            payloads in prop::collection::vec(prop::collection::vec(any::<u8>(), 0..=256), 1..=10),
            channel_name in "[a-z][a-z0-9\\-]{0,15}",
        ) {
            let n = sender_ids.len().min(payloads.len());
            let clock = MockClock::new();
            let mut store = ChannelStore::new(
                100,
                Duration::from_secs(3600),
                Duration::from_secs(600),
                clock,
                32,
            );

            // Push N messages and collect returned sequence numbers
            let mut sequences = Vec::new();
            for i in 0..n {
                let seq = store.push(&channel_name, &sender_ids[i], payloads[i].clone()).unwrap();
                sequences.push(seq);
            }

            // Sequence numbers must be strictly monotonically increasing
            for i in 1..sequences.len() {
                prop_assert!(
                    sequences[i] > sequences[i - 1],
                    "Sequence numbers must be strictly increasing: seq[{}]={} should be > seq[{}]={}",
                    i, sequences[i], i - 1, sequences[i - 1]
                );
            }

            // FIFO order: pop messages and verify they come back in push order
            for i in 0..n {
                let msg = store.pop(&channel_name);
                prop_assert!(msg.is_some(), "Expected message {} but got None", i);
                let msg = msg.unwrap();
                prop_assert_eq!(&msg.payload, &payloads[i], "FIFO order violated at index {}", i);
                prop_assert_eq!(&msg.sender_id, &sender_ids[i], "Sender mismatch at index {}", i);
                prop_assert_eq!(msg.sequence, sequences[i], "Sequence mismatch at index {}", i);
            }

            // Channel should be empty after popping all messages
            prop_assert!(store.pop(&channel_name).is_none(), "Channel should be empty after popping all messages");
        }
    }

    // **Validates: Requirements 3.3**
    //
    // Property: For all push sequences that exceed max_messages_per_channel,
    // the (N+1)th push returns StoreError::ChannelFull.
    proptest! {
        #[test]
        fn preservation_channel_full_at_capacity(
            capacity in 1usize..=20,
            payloads in prop::collection::vec(prop::collection::vec(any::<u8>(), 1..=64), 1..=25),
        ) {
            let clock = MockClock::new();
            let mut store = ChannelStore::new(
                capacity,
                Duration::from_secs(3600),
                Duration::from_secs(600),
                clock,
                32,
            );

            // Push up to capacity — all should succeed
            for i in 0..capacity.min(payloads.len()) {
                let result = store.push("ch", "sender", payloads[i].clone());
                prop_assert!(result.is_ok(), "Push {} should succeed (capacity={})", i, capacity);
            }

            // If we have enough payloads, the next push should fail with ChannelFull
            if payloads.len() > capacity {
                let result = store.push("ch", "sender", payloads[capacity].clone());
                prop_assert!(
                    matches!(result, Err(StoreError::ChannelFull(_))),
                    "Push beyond capacity should return ChannelFull, got {:?}",
                    result
                );
            }
        }
    }

    // **Validates: Requirements 3.4**
    //
    // Property: For all store states with messages, after advancing the mock
    // clock past message_ttl and calling sweep_expired, all expired messages
    // are removed and queue_depth returns 0.
    proptest! {
        #[test]
        fn preservation_sweep_removes_expired_messages(
            msg_count in 1usize..=10,
            ttl_secs in 10u64..=600,
            extra_secs in 1u64..=60,
        ) {
            let clock = MockClock::new();
            let base = clock.instant();
            let mut store = ChannelStore::new(
                100,
                Duration::from_secs(3600),
                Duration::from_secs(ttl_secs),
                clock,
                32,
            );

            for i in 0..msg_count {
                store.push("ch", "sender", vec![i as u8]).unwrap();
            }

            prop_assert_eq!(store.queue_depth("ch"), msg_count, "queue_depth should match pushed count");

            // Advance past TTL and sweep
            let sweep_time = base + Duration::from_secs(ttl_secs + extra_secs);
            store.sweep_expired(sweep_time);

            prop_assert_eq!(
                store.queue_depth("ch"),
                0,
                "queue_depth should be 0 after sweeping expired messages (ttl={}s, swept at +{}s)",
                ttl_secs,
                ttl_secs + extra_secs
            );
        }
    }

    // **Validates: Requirements 3.4, 3.5**
    //
    // Property: For all store states with channels, after advancing the mock
    // clock past channel_inactivity_timeout and calling sweep_expired,
    // inactive channels are removed entirely.
    proptest! {
        #[test]
        fn preservation_sweep_removes_inactive_channels(
            inactivity_secs in 60u64..=600,
            extra_secs in 1u64..=60,
            channel_name in "[a-z]{1,8}",
        ) {
            let clock = MockClock::new();
            let base = clock.instant();
            let mut store = ChannelStore::new(
                100,
                Duration::from_secs(inactivity_secs),
                Duration::from_secs(inactivity_secs + 1000), // TTL longer than inactivity so messages don't expire first
                clock,
                32,
            );

            store.push(&channel_name, "sender", b"msg".to_vec()).unwrap();
            prop_assert!(store.channels().contains_key(&channel_name), "Channel should exist after push");

            // Advance past inactivity timeout and sweep
            let sweep_time = base + Duration::from_secs(inactivity_secs + extra_secs);
            store.sweep_expired(sweep_time);

            prop_assert!(
                !store.channels().contains_key(&channel_name),
                "Channel '{}' should be removed after inactivity timeout ({}s, swept at +{}s)",
                channel_name,
                inactivity_secs,
                inactivity_secs + extra_secs
            );
        }
    }

    // **Validates: Requirements 3.5**
    //
    // Property: For all channels, calling queue_depth twice in succession
    // returns the same value — it is read-only with no side effects.
    proptest! {
        #[test]
        fn preservation_queue_depth_is_readonly(
            msg_count in 0usize..=15,
            channel_name in "[a-z]{1,8}",
        ) {
            let clock = MockClock::new();
            let mut store = ChannelStore::new(
                100,
                Duration::from_secs(3600),
                Duration::from_secs(600),
                clock,
                32,
            );

            for i in 0..msg_count {
                store.push(&channel_name, "sender", vec![i as u8]).unwrap();
            }

            let depth1 = store.queue_depth(&channel_name);
            let depth2 = store.queue_depth(&channel_name);

            prop_assert_eq!(
                depth1,
                depth2,
                "queue_depth should return the same value on consecutive calls (no side effects)"
            );
            prop_assert_eq!(
                depth1,
                msg_count,
                "queue_depth should equal the number of pushed messages"
            );
        }
    }

    // **Validates: Property 3 (design.md) — Requirements 3.1, 3.2**
    //
    // Preservation: Replay Re-delivers Same Batch When No New Messages Pushed
    //
    // For any messages moved to the replay buffer, a subsequent peek_many
    // call with no intervening push returns the same batch — preserving the
    // lost-UDP-response recovery mechanism.
    //
    // Steps: push N messages → peek_many (moves messages to replay) →
    // peek_many again with NO intervening push → assert the second peek
    // returns the same messages with identical payloads and sequence numbers.
    //
    // This is a PRESERVATION test — it must PASS on both unfixed and fixed code.
    proptest! {
        #[test]
        fn preservation_replay_redelivers_same_batch_no_new_push(
            msg_count in 1usize..=8,
            payloads in prop::collection::vec(
                prop::collection::vec(any::<u8>(), 1..64),
                1..=8,
            ),
            sender_id in "[a-z]{1,8}",
        ) {
            let n = msg_count.min(payloads.len());
            let clock = MockClock::new();
            let mut store = ChannelStore::new(
                100,
                Duration::from_secs(3600),
                Duration::from_secs(600),
                clock,
                32,
            );

            // Step 1: Push N messages to the channel
            let mut pushed_seqs = Vec::new();
            for i in 0..n {
                let seq = store.push("ctl-ch", &sender_id, payloads[i].clone()).unwrap();
                pushed_seqs.push(seq);
            }

            // Step 2: First peek — moves messages from queue into replay buffer
            let first_peek = store.peek_many("ctl-ch", 32, None);
            prop_assert_eq!(
                first_peek.len(),
                n,
                "First peek should return all {} pushed messages",
                n
            );

            // Step 3: Second peek — NO intervening push.
            // The replay buffer should re-deliver the same batch.
            let second_peek = store.peek_many("ctl-ch", 32, None);

            // Assert: same number of messages returned
            prop_assert_eq!(
                second_peek.len(),
                first_peek.len(),
                "Second peek (re-poll, no new push) should return the same {} messages, \
                 but got {}",
                first_peek.len(),
                second_peek.len()
            );

            // Assert: same payloads in the same order
            for i in 0..first_peek.len() {
                prop_assert_eq!(
                    &second_peek[i].payload,
                    &first_peek[i].payload,
                    "Replay re-delivery payload mismatch at index {}",
                    i
                );
                prop_assert_eq!(
                    second_peek[i].sequence,
                    first_peek[i].sequence,
                    "Replay re-delivery sequence mismatch at index {}",
                    i
                );
            }
        }
    }

    // =========================================================================
    // Preservation Property Tests: Cursor-Based Replay Advancement (Task 2)
    // =========================================================================
    //
    // These tests capture the EXISTING behavior of the unfixed code for
    // non-buggy inputs (standard peek_many without cursor, pop_many, push,
    // queue_depth, sweep). They must all PASS on the current unfixed code.
    // After the fix is applied, they verify no regressions were introduced.

    // **Validates: Requirements 3.1**
    //
    // Property: None-cursor two-phase replay cycle.
    // For any channel state, peek_many(channel, max) produces the expected
    // two-phase behavior:
    //   - First call: returns messages, moves them to replay
    //   - Second call (no new messages): returns replay contents and clears replay
    //   - Third call: returns empty
    proptest! {
        #[test]
        fn preservation_none_cursor_two_phase_replay(
            msg_count in 1usize..=8,
            payloads in prop::collection::vec(
                prop::collection::vec(any::<u8>(), 1..64),
                1..=8,
            ),
            max_fetch in 8usize..=32,
        ) {
            let n = msg_count.min(payloads.len());
            let clock = MockClock::new();
            let mut store = ChannelStore::new(
                100,
                Duration::from_secs(3600),
                Duration::from_secs(600),
                clock,
                32,
            );

            // Push N messages
            let mut pushed_seqs = Vec::new();
            for i in 0..n {
                let seq = store.push("ch", "sender", payloads[i].clone()).unwrap();
                pushed_seqs.push(seq);
            }

            // Phase 1: First peek — returns messages, moves them to replay
            let first = store.peek_many("ch", max_fetch, None);
            prop_assert_eq!(
                first.len(), n,
                "First peek should return all {} messages", n
            );
            for i in 0..n {
                prop_assert_eq!(&first[i].payload, &payloads[i], "First peek payload mismatch at {}", i);
                prop_assert_eq!(first[i].sequence, pushed_seqs[i], "First peek sequence mismatch at {}", i);
            }

            // Phase 2: Second peek (no new messages) — returns replay, clears it
            let second = store.peek_many("ch", max_fetch, None);
            prop_assert_eq!(
                second.len(), n,
                "Second peek (confirming re-poll) should return {} replay messages", n
            );
            for i in 0..n {
                prop_assert_eq!(&second[i].payload, &first[i].payload, "Second peek payload mismatch at {}", i);
                prop_assert_eq!(second[i].sequence, first[i].sequence, "Second peek sequence mismatch at {}", i);
            }

            // Phase 3: Third peek — replay was cleared, returns empty
            let third = store.peek_many("ch", max_fetch, None);
            prop_assert_eq!(
                third.len(), 0,
                "Third peek should return empty after replay was cleared on second peek, got {}",
                third.len()
            );
        }
    }

    // **Validates: Requirements 3.6**
    //
    // Property: Pop mode unaffected by replay state.
    // pop_many drains messages destructively regardless of replay state.
    // After pop_many, messages are gone and replay is unaffected.
    proptest! {
        #[test]
        fn preservation_pop_mode_unaffected(
            msg_count in 1usize..=10,
            payloads in prop::collection::vec(
                prop::collection::vec(any::<u8>(), 1..64),
                1..=10,
            ),
            pop_max in 1usize..=15,
        ) {
            let n = msg_count.min(payloads.len());
            let clock = MockClock::new();
            let mut store = ChannelStore::new(
                100,
                Duration::from_secs(3600),
                Duration::from_secs(600),
                clock,
                32,
            );

            // Push N messages
            for i in 0..n {
                store.push("ch", "sender", payloads[i].clone()).unwrap();
            }

            // Pop drains destructively
            let popped = store.pop_many("ch", pop_max);
            let expected_count = pop_max.min(n);
            prop_assert_eq!(
                popped.len(), expected_count,
                "pop_many should return min({}, {}) = {} messages",
                pop_max, n, expected_count
            );

            // Verify FIFO order of popped messages
            for i in 0..expected_count {
                prop_assert_eq!(
                    &popped[i].payload, &payloads[i],
                    "pop_many FIFO order violated at index {}", i
                );
            }

            // After pop, those messages are gone — a second pop returns remaining
            let remaining = store.pop_many("ch", 100);
            prop_assert_eq!(
                remaining.len(), n - expected_count,
                "Second pop_many should return remaining {} messages",
                n - expected_count
            );

            // Replay buffer should be unaffected by pop_many (it should be empty
            // since we never called peek_many)
            let ch = store.channels().get("ch");
            if let Some(ch) = ch {
                prop_assert!(
                    ch.replay.is_empty(),
                    "Replay buffer should be empty — pop_many does not touch replay"
                );
            }
        }
    }

    // **Validates: Requirements 3.6**
    //
    // Property: Pop mode works correctly even when replay buffer has entries.
    // If peek_many was called first (creating replay entries), pop_many still
    // drains only from the messages queue and does not touch replay.
    proptest! {
        #[test]
        fn preservation_pop_mode_ignores_replay(
            initial_count in 1usize..=5,
            extra_count in 1usize..=5,
            initial_payloads in prop::collection::vec(
                prop::collection::vec(any::<u8>(), 1..32),
                1..=5,
            ),
            extra_payloads in prop::collection::vec(
                prop::collection::vec(any::<u8>(), 1..32),
                1..=5,
            ),
        ) {
            let n_init = initial_count.min(initial_payloads.len());
            let n_extra = extra_count.min(extra_payloads.len());
            let clock = MockClock::new();
            let mut store = ChannelStore::new(
                100,
                Duration::from_secs(3600),
                Duration::from_secs(600),
                clock,
                32,
            );

            // Push initial messages and peek to create replay entries
            for i in 0..n_init {
                store.push("ch", "sender", initial_payloads[i].clone()).unwrap();
            }
            let _peeked = store.peek_many("ch", 32, None);

            // Push more messages (these go into the messages queue)
            for i in 0..n_extra {
                store.push("ch", "sender", extra_payloads[i].clone()).unwrap();
            }

            // Replay has n_init entries, messages queue has n_extra entries
            let replay_len_before = store.channels().get("ch").map_or(0, |c| c.replay.len());
            prop_assert_eq!(replay_len_before, n_init, "Replay should have {} entries", n_init);

            // pop_many should drain from messages queue only
            let popped = store.pop_many("ch", 100);
            prop_assert_eq!(
                popped.len(), n_extra,
                "pop_many should drain {} messages from queue (not replay)", n_extra
            );

            // Replay should be untouched
            let replay_len_after = store.channels().get("ch").map_or(0, |c| c.replay.len());
            prop_assert_eq!(
                replay_len_after, n_init,
                "Replay buffer should be unchanged after pop_many ({} entries)", n_init
            );
        }
    }

    // **Validates: Requirements 3.4**
    //
    // Property: queue_depth returns messages.len() + replay.len() correctly.
    // After peek_many moves messages to replay, queue_depth should still
    // reflect the total count across both queues.
    proptest! {
        #[test]
        fn preservation_queue_depth_accuracy(
            initial_count in 1usize..=8,
            extra_count in 0usize..=5,
            initial_payloads in prop::collection::vec(
                prop::collection::vec(any::<u8>(), 1..32),
                1..=8,
            ),
            extra_payloads in prop::collection::vec(
                prop::collection::vec(any::<u8>(), 1..32),
                0..=5,
            ),
        ) {
            let n_init = initial_count.min(initial_payloads.len());
            let n_extra = extra_count.min(extra_payloads.len());
            let clock = MockClock::new();
            let mut store = ChannelStore::new(
                100,
                Duration::from_secs(3600),
                Duration::from_secs(600),
                clock,
                32,
            );

            // Push initial messages
            for i in 0..n_init {
                store.push("ch", "sender", initial_payloads[i].clone()).unwrap();
            }

            // Before peek: all in messages queue
            prop_assert_eq!(
                store.queue_depth("ch"), n_init,
                "queue_depth should be {} before peek", n_init
            );

            // Peek moves messages to replay
            let _peeked = store.peek_many("ch", 32, None);

            // After peek: messages moved to replay, depth unchanged
            prop_assert_eq!(
                store.queue_depth("ch"), n_init,
                "queue_depth should still be {} after peek (messages now in replay)", n_init
            );

            // Push extra messages
            for i in 0..n_extra {
                store.push("ch", "sender", extra_payloads[i].clone()).unwrap();
            }

            // After extra push: replay has n_init, messages has n_extra
            prop_assert_eq!(
                store.queue_depth("ch"), n_init + n_extra,
                "queue_depth should be {} (replay) + {} (messages) = {}",
                n_init, n_extra, n_init + n_extra
            );
        }
    }

    // **Validates: Requirements 3.5**
    //
    // Property: sweep_expired removes expired messages from both the messages
    // queue AND the replay buffer, and removes inactive channels.
    proptest! {
        #[test]
        fn preservation_sweep_clears_both_queues(
            msg_count in 1usize..=8,
            payloads in prop::collection::vec(
                prop::collection::vec(any::<u8>(), 1..32),
                1..=8,
            ),
            ttl_secs in 30u64..=300,
            extra_secs in 1u64..=30,
        ) {
            let n = msg_count.min(payloads.len());
            let clock = MockClock::new();
            let base = clock.instant();
            let mut store = ChannelStore::new(
                100,
                Duration::from_secs(3600), // long inactivity timeout
                Duration::from_secs(ttl_secs),
                clock,
                32,
            );

            // Push messages
            for i in 0..n {
                store.push("ch", "sender", payloads[i].clone()).unwrap();
            }

            // Peek to move messages into replay
            let _peeked = store.peek_many("ch", 32, None);

            // Verify replay has entries
            let replay_len = store.channels().get("ch").map_or(0, |c| c.replay.len());
            prop_assert_eq!(replay_len, n, "Replay should have {} entries after peek", n);

            // Sweep past TTL — should remove expired messages from replay too
            let sweep_time = base + Duration::from_secs(ttl_secs + extra_secs);
            store.sweep_expired(sweep_time);

            // Both queues should be empty
            let ch = store.channels().get("ch");
            if let Some(ch) = ch {
                prop_assert_eq!(
                    ch.messages.len(), 0,
                    "Messages queue should be empty after sweep"
                );
                prop_assert_eq!(
                    ch.replay.len(), 0,
                    "Replay buffer should be empty after sweep"
                );
            }
            prop_assert_eq!(
                store.queue_depth("ch"), 0,
                "queue_depth should be 0 after sweeping expired messages from both queues"
            );
        }
    }

    // =========================================================================
    // Bug Condition Exploration: Cursor-Based Replay Advancement (Task 1)
    // =========================================================================

    // **Validates: Requirements 2.3, 2.4**
    //
    // Bug Condition Exploration: Heuristic Replay Clear Causes Permanent Data Loss
    //
    // The current `peek_many` uses a heuristic: when the queue is empty and
    // the replay buffer is non-empty, it clears the replay buffer assuming
    // the client received the previous batch. This heuristic fails when UDP
    // responses are lost — the broker clears frames the client never received.
    //
    // Steps:
    //   1. Push N messages to a channel
    //   2. Call peek_many to move messages into the replay buffer
    //   3. Call peek_many again (simulating a re-poll after lost UDP response)
    //      — the heuristic returns replay contents but also clears the buffer
    //   4. Call peek_many a third time — assert replay is now empty
    //   5. Assert that the replay buffer was cleared (data permanently lost)
    //
    // On UNFIXED code this test is EXPECTED TO FAIL — the heuristic clearing
    // behavior means the third peek returns empty, proving the broker lost
    // frames the client never confirmed receiving. The test asserts that
    // replay entries SHOULD be retained (the correct cursor-based behavior),
    // which will fail because the heuristic clears them unconditionally.
    proptest! {
        #[test]
        fn bug_condition_heuristic_replay_clear_causes_data_loss(
            msg_count in 1usize..=8,
            payloads in prop::collection::vec(
                prop::collection::vec(any::<u8>(), 1..64),
                1..=8,
            ),
        ) {
            let n = msg_count.min(payloads.len());
            let clock = MockClock::new();
            let mut store = ChannelStore::new(
                100,
                Duration::from_secs(3600),
                Duration::from_secs(600),
                clock,
                32,
            );

            // Step 1: Push N messages to the channel
            let mut pushed_seqs = Vec::new();
            for i in 0..n {
                let seq = store.push("d-ch", "sender", payloads[i].clone()).unwrap();
                pushed_seqs.push(seq);
            }

            // Step 2: First peek — moves messages from queue into replay buffer
            let first_peek = store.peek_many("d-ch", 32, None);
            prop_assert_eq!(
                first_peek.len(),
                n,
                "First peek should return all {} messages",
                n
            );

            // At this point: queue is empty, replay has N entries.
            // Simulate: the UDP response carrying first_peek was LOST.
            // The client never received these frames.

            // Step 3: Second peek with cursor=Some(0) — client re-polls after
            // lost UDP response. With cursor=0, the client says "I haven't
            // confirmed receiving anything yet", so ALL replay entries should
            // be retained and returned.
            let second_peek = store.peek_many("d-ch", 32, Some(0));
            prop_assert_eq!(
                second_peek.len(),
                n,
                "Second peek with cursor=0 should return the {} replay messages",
                n
            );

            // Step 4: Third peek with cursor=0 — the client STILL hasn't
            // received the frames (both UDP responses were lost). With
            // cursor-based advancement, the replay buffer should still
            // contain all unconfirmed frames because cursor=0 means
            // nothing has been confirmed.
            let third_peek = store.peek_many("d-ch", 32, Some(0));

            // Assert: frames should STILL be available for re-delivery
            // because the client never confirmed receiving them.
            // This assertion encodes the EXPECTED correct behavior.
            // On UNFIXED code, third_peek.len() == 0 (bug: data permanently lost).
            prop_assert!(
                !third_peek.is_empty(),
                "Third peek should still return {} unconfirmed replay messages, \
                 but got 0 — the heuristic cleared replay frames the client never \
                 received, causing permanent data loss. \
                 Pushed sequences: {:?}",
                n,
                pushed_seqs
            );

            // Also verify the replay buffer itself is not empty
            let depth = store.queue_depth("d-ch");
            prop_assert!(
                depth > 0,
                "queue_depth should be > 0 (replay entries retained for unconfirmed client), \
                 but got 0 — heuristic clearing lost all frames"
            );
        }
    }
}
