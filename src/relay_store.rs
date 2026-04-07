//! Relay store module.
//!
//! Provides a bounded-ring-buffer-per-sender relay store with per-channel locking.
//! Each (channel, sender_id) pair maps to a bounded VecDeque of `PacketSlot`s.
//! Writes push to the ring buffer; when full, the oldest entry is dropped.
//! Reads return all non-expired slots across all senders, flattened.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use crate::store::{Clock, RealClock};

/// Default maximum number of slots per sender in a channel.
/// Must be large enough to hold a full TCP window of segments plus
/// retransmits. 16 accommodates window_segments=4 with room for
/// retransmission overlap.
const DEFAULT_MAX_SLOTS_PER_SENDER: usize = 64;

/// A single packet entry in the ring buffer.
#[derive(Clone)]
pub struct PacketSlot {
    pub sender_id: String,
    pub payload: Vec<u8>,
    pub sequence: u64,
    pub timestamp: u64,
    pub written_at: Instant,
}

/// Per-channel collection of packet ring buffers (one per sender_id).
pub struct RelayChannel {
    /// Each sender_id maps to a bounded ring buffer of recent packets.
    pub slots: HashMap<String, VecDeque<PacketSlot>>,
}

/// Bounded-ring-buffer-per-sender relay store with per-channel locking.
pub struct RelayStore<C: Clock> {
    channels: RwLock<HashMap<String, Arc<RwLock<RelayChannel>>>>,
    message_ttl: Duration,
    next_sequence: AtomicU64,
    clock: C,
    max_slots_per_sender: usize,
}

/// Shared relay store type for production use.
pub type SharedRelayStore = Arc<RelayStore<RealClock>>;

impl<C: Clock> RelayStore<C> {
    /// Create a new `RelayStore` with the given message TTL and clock.
    pub fn new(message_ttl: Duration, clock: C) -> Self {
        Self {
            channels: RwLock::new(HashMap::new()),
            message_ttl,
            next_sequence: AtomicU64::new(1),
            clock,
            max_slots_per_sender: DEFAULT_MAX_SLOTS_PER_SENDER,
        }
    }

    /// Write a packet to the store. Pushes to the sender's ring buffer,
    /// dropping the oldest entry if the buffer exceeds `max_slots_per_sender`.
    /// Returns the assigned sequence number.
    pub fn write(&self, channel: &str, sender_id: &str, payload: Vec<u8>) -> u64 {
        let seq = self.next_sequence.fetch_add(1, Ordering::Relaxed);
        let slot = PacketSlot {
            sender_id: sender_id.to_string(),
            payload,
            sequence: seq,
            timestamp: self.clock.timestamp_secs(),
            written_at: self.clock.now(),
        };
        let max = self.max_slots_per_sender;

        // Fast path: channel already exists — only need outer read lock.
        {
            let map = self.channels.read().unwrap();
            if let Some(ch) = map.get(channel) {
                let ch = Arc::clone(ch);
                drop(map);
                let mut ch = ch.write().unwrap();
                let ring = ch.slots.entry(sender_id.to_string()).or_insert_with(VecDeque::new);
                ring.push_back(slot);
                while ring.len() > max {
                    ring.pop_front();
                }
                return seq;
            }
        }

        // Slow path: channel doesn't exist — acquire outer write lock.
        {
            let mut map = self.channels.write().unwrap();
            let ch = map
                .entry(channel.to_string())
                .or_insert_with(|| {
                    Arc::new(RwLock::new(RelayChannel {
                        slots: HashMap::new(),
                    }))
                });
            let ch = Arc::clone(ch);
            drop(map);
            let mut ch = ch.write().unwrap();
            let ring = ch.slots.entry(sender_id.to_string()).or_insert_with(VecDeque::new);
            ring.push_back(slot);
            while ring.len() > max {
                ring.pop_front();
            }
        }

        seq
    }

    /// Read all non-expired slots for a channel, flattened across all senders.
    /// Non-destructive. Returns owned `PacketSlot`s cloned from behind the lock.
    pub fn read(&self, channel: &str) -> Vec<PacketSlot> {
        let ch = {
            let map = self.channels.read().unwrap();
            match map.get(channel) {
                Some(ch) => Arc::clone(ch),
                None => return Vec::new(),
            }
        };

        let now = self.clock.now();
        let ch = ch.read().unwrap();
        ch.slots
            .values()
            .flat_map(|ring| ring.iter())
            .filter(|slot| now.duration_since(slot.written_at) < self.message_ttl)
            .cloned()
            .collect()
    }

    /// Read specific non-expired slots by sequence number for a channel.
    /// Returns only slots whose sequence is in the requested set.
    /// Non-destructive. Returns owned `PacketSlot`s cloned from behind the lock.
    pub fn read_sequences(&self, channel: &str, sequences: &[u64]) -> Vec<PacketSlot> {
        let ch = {
            let map = self.channels.read().unwrap();
            match map.get(channel) {
                Some(ch) => Arc::clone(ch),
                None => return Vec::new(),
            }
        };

        let requested: HashSet<u64> = sequences.iter().copied().collect();
        let now = self.clock.now();
        let ch = ch.read().unwrap();
        ch.slots
            .values()
            .flat_map(|ring| ring.iter())
            .filter(|slot| now.duration_since(slot.written_at) < self.message_ttl)
            .filter(|slot| requested.contains(&slot.sequence))
            .cloned()
            .collect()
    }

    /// Read slots for a channel with optional cursor-based filtering.
    /// Non-destructive. Use `ack_sequence` to remove specific delivered packets.
    pub fn read_and_advance(&self, channel: &str, cursor: Option<u64>) -> Vec<PacketSlot> {
        let ch = {
            let map = self.channels.read().unwrap();
            match map.get(channel) {
                Some(ch) => Arc::clone(ch),
                None => return Vec::new(),
            }
        };

        let now = self.clock.now();
        let ch = ch.read().unwrap();
        let min_seq = cursor.unwrap_or(0);
        ch.slots
            .values()
            .flat_map(|ring| ring.iter())
            .filter(|slot| slot.sequence >= min_seq)
            .filter(|slot| now.duration_since(slot.written_at) < self.message_ttl)
            .cloned()
            .collect()
    }

    /// Remove a specific packet by sequence number from a channel.
    /// Used for per-packet acknowledgement — the receiver confirms it
    /// got a specific packet, and the relay removes it so it's never
    /// re-delivered.
    pub fn ack_sequence(&self, channel: &str, sequence: u64) {
        let ch = {
            let map = self.channels.read().unwrap();
            match map.get(channel) {
                Some(ch) => Arc::clone(ch),
                None => return,
            }
        };

        let mut ch = ch.write().unwrap();
        for ring in ch.slots.values_mut() {
            ring.retain(|slot| slot.sequence != sequence);
        }
    }

    /// Remove multiple packets by sequence number from a channel.
    pub fn ack_sequences(&self, channel: &str, sequences: &[u64]) {
        if sequences.is_empty() {
            return;
        }
        let ch = {
            let map = self.channels.read().unwrap();
            match map.get(channel) {
                Some(ch) => Arc::clone(ch),
                None => return,
            }
        };

        let set: std::collections::HashSet<u64> = sequences.iter().copied().collect();
        let mut ch = ch.write().unwrap();
        for ring in ch.slots.values_mut() {
            ring.retain(|slot| !set.contains(&slot.sequence));
        }
    }

    /// Return the count of non-expired slots for a channel (across all senders).
    pub fn slot_count(&self, channel: &str) -> usize {
        let ch = {
            let map = self.channels.read().unwrap();
            match map.get(channel) {
                Some(ch) => Arc::clone(ch),
                None => return 0,
            }
        };

        let now = self.clock.now();
        let ch = ch.read().unwrap();
        ch.slots
            .values()
            .flat_map(|ring| ring.iter())
            .filter(|slot| now.duration_since(slot.written_at) < self.message_ttl)
            .count()
    }

    /// Remove expired slots and empty channels.
    pub fn sweep_expired(&self) {
        let now = self.clock.now();

        let channel_entries: Vec<(String, Arc<RwLock<RelayChannel>>)> = {
            let map = self.channels.read().unwrap();
            map.iter()
                .map(|(k, v)| (k.clone(), Arc::clone(v)))
                .collect()
        };

        let mut empty_channels = Vec::new();
        for (name, ch) in &channel_entries {
            let mut ch = ch.write().unwrap();
            // Remove expired entries from each sender's ring buffer.
            for ring in ch.slots.values_mut() {
                ring.retain(|slot| now.duration_since(slot.written_at) < self.message_ttl);
            }
            // Remove senders with empty ring buffers.
            ch.slots.retain(|_, ring| !ring.is_empty());
            if ch.slots.is_empty() {
                empty_channels.push(name.clone());
            }
        }

        if !empty_channels.is_empty() {
            let mut map = self.channels.write().unwrap();
            for name in &empty_channels {
                if let Some(ch) = map.get(name) {
                    if ch.read().unwrap().slots.is_empty() {
                        map.remove(name);
                    }
                }
            }
        }
    }
}
