//! Channel store module.
//!
//! Manages per-channel FIFO message queues with expiry and capacity limits.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::error::StoreError;

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
}

impl<C: Clock> ChannelStore<C> {
    /// Create a new `ChannelStore` with the given configuration and clock.
    pub fn new(
        max_messages_per_channel: usize,
        channel_inactivity_timeout: Duration,
        message_ttl: Duration,
        clock: C,
    ) -> Self {
        Self {
            channels: HashMap::new(),
            max_messages_per_channel,
            channel_inactivity_timeout,
            message_ttl,
            next_sequence: 0,
            clock,
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
            true
        });
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

    #[test]
    fn test_push_auto_creates_channel() {
        let clock = MockClock::new();
        let mut store = ChannelStore::new(10, Duration::from_secs(3600), Duration::from_secs(600), clock);

        let seq = store.push("test-channel", "alice", b"hello".to_vec()).unwrap();
        assert_eq!(seq, 0);
        assert!(store.channels().contains_key("test-channel"));
        assert_eq!(store.channels()["test-channel"].messages.len(), 1);
    }

    #[test]
    fn test_push_monotonic_sequence() {
        let clock = MockClock::new();
        let mut store = ChannelStore::new(10, Duration::from_secs(3600), Duration::from_secs(600), clock);

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
        let mut store = ChannelStore::new(2, Duration::from_secs(3600), Duration::from_secs(600), clock);

        store.push("ch", "a", b"1".to_vec()).unwrap();
        store.push("ch", "a", b"2".to_vec()).unwrap();
        let err = store.push("ch", "a", b"3".to_vec()).unwrap_err();
        assert!(matches!(err, StoreError::ChannelFull(_)));
    }

    #[test]
    fn test_pop_fifo_order() {
        let clock = MockClock::new();
        let mut store = ChannelStore::new(10, Duration::from_secs(3600), Duration::from_secs(600), clock);

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
        let mut store = ChannelStore::new(10, Duration::from_secs(3600), Duration::from_secs(600), clock);

        assert!(store.pop("nonexistent").is_none());

        store.push("ch", "a", b"x".to_vec()).unwrap();
        store.pop("ch"); // drain it
        assert!(store.pop("ch").is_none());
    }

    #[test]
    fn test_pop_does_not_return_same_message_twice() {
        let clock = MockClock::new();
        let mut store = ChannelStore::new(10, Duration::from_secs(3600), Duration::from_secs(600), clock);

        store.push("ch", "a", b"only".to_vec()).unwrap();
        let m = store.pop("ch");
        assert!(m.is_some());
        assert!(store.pop("ch").is_none());
    }

    #[test]
    fn test_sweep_removes_expired_messages() {
        let clock = MockClock::new();
        let base = clock.instant();
        let mut store = ChannelStore::new(10, Duration::from_secs(3600), Duration::from_secs(60), clock);

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
        let mut store = ChannelStore::new(10, Duration::from_secs(3600), Duration::from_secs(60), clock);

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
        let mut store = ChannelStore::new(10, Duration::from_secs(300), Duration::from_secs(600), clock);

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
        let mut store = ChannelStore::new(10, Duration::from_secs(300), Duration::from_secs(600), clock);

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
        let mut store = ChannelStore::new(10, Duration::from_secs(3600), Duration::from_secs(120), clock);

        store.push("ch", "a", b"x".to_vec()).unwrap();
        let msg = store.pop("ch").unwrap();

        assert_eq!(msg.timestamp, 0); // MockClock starts at 0
        assert_eq!(msg.expiry, base + Duration::from_secs(120));
    }
}
