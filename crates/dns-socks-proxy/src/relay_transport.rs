// Relay transport: reads/writes the in-process RelayStore directly.
// Analogous to DirectTransport but for the RelayStore's single-slot-per-sender semantics.
//
// Also provides `DedupRecvTransport` — a wrapper that adds sequence-based
// deduplication on top of any `TransportBackend`. Used by `dnssocksrelay`
// where the relay ignores cursor-based advancement and the client would
// otherwise re-process the same stale packets on every poll.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;

use dns_message_broker::relay_store::SharedRelayStore;

use crate::transport::{TransportBackend, TransportError};

/// Direct RelayStore transport: bypasses DNS, calls RelayStore directly.
/// Used by the dnsrelay binary where the exit node runs in-process.
///
/// Uses single-slot-per-sender semantics: each send overwrites the previous
/// slot for the same (channel, sender_id) pair. smoltcp retransmission
/// recovers any packets lost to overwrites.
pub struct RelayTransport {
    store: SharedRelayStore,
    sender_id: String,
    /// Per-channel last-seen sequence number for deduplication.
    last_seen: Mutex<HashMap<String, u64>>,
}

impl RelayTransport {
    /// Create a new `RelayTransport` wrapping a shared `RelayStore`.
    pub fn new(store: SharedRelayStore, sender_id: String) -> Self {
        Self {
            store,
            sender_id,
            last_seen: Mutex::new(HashMap::new()),
        }
    }
}

#[async_trait]
impl TransportBackend for RelayTransport {
    async fn send_frame(
        &self,
        channel: &str,
        _sender_id: &str,
        frame_bytes: &[u8],
    ) -> Result<(), TransportError> {
        self.store.write(channel, &self.sender_id, frame_bytes.to_vec());
        Ok(())
    }

    async fn recv_frames(
        &self,
        channel: &str,
        _cursor: Option<u64>,
    ) -> Result<(Vec<Vec<u8>>, Option<u64>), TransportError> {
        let slots = self.store.read(channel);
        if slots.is_empty() {
            return Ok((vec![], None));
        }

        let mut last_seen = self.last_seen.lock().unwrap();
        let prev_seq = last_seen.get(channel).copied().unwrap_or(0);

        let mut max_seq: Option<u64> = None;
        let mut frames = Vec::new();

        for slot in &slots {
            if slot.sequence > prev_seq {
                frames.push(slot.payload.clone());
                max_seq = Some(max_seq.map_or(slot.sequence, |m: u64| m.max(slot.sequence)));
            }
        }

        if let Some(seq) = max_seq {
            last_seen.insert(channel.to_string(), seq);
        }

        Ok((frames, max_seq))
    }

    async fn query_status(&self, channel: &str) -> Result<usize, TransportError> {
        Ok(self.store.slot_count(channel))
    }
}

// ---------------------------------------------------------------------------
// DedupRecvTransport — sequence-based dedup wrapper for any TransportBackend
// ---------------------------------------------------------------------------

/// Wraps a `TransportBackend` and uses a two-phase manifest+fetch protocol
/// to avoid re-receiving already-seen sequences. On each `recv_frames` call:
///
/// 1. Calls `inner.recv_manifest(channel)` to get available `(seq_id, payload_len)` pairs
/// 2. Filters out already-seen sequences using a per-channel `HashSet<u64>`
/// 3. If new sequences exist, calls `inner.recv_fetch(channel, &needed_ids)`
/// 4. If all sequences are already seen, skips the fetch (saves a round-trip)
///
/// Falls back to the old `recv_frames` behavior if `recv_manifest` returns
/// empty (backward compatibility with transports that don't support manifest).
///
/// `send_frame` and `query_status` are passed through unchanged.
pub struct DedupRecvTransport {
    inner: Arc<dyn TransportBackend>,
    /// Per-channel set of already-delivered sequence IDs.
    last_seen: Mutex<HashMap<String, HashSet<u64>>>,
}

impl DedupRecvTransport {
    pub fn new(inner: Arc<dyn TransportBackend>) -> Self {
        Self {
            inner,
            last_seen: Mutex::new(HashMap::new()),
        }
    }
}

#[async_trait]
impl TransportBackend for DedupRecvTransport {
    async fn send_frame(
        &self,
        channel: &str,
        sender_id: &str,
        frame_bytes: &[u8],
    ) -> Result<(), TransportError> {
        self.inner.send_frame(channel, sender_id, frame_bytes).await
    }

    async fn recv_frames(
        &self,
        channel: &str,
        cursor: Option<u64>,
    ) -> Result<(Vec<Vec<u8>>, Option<u64>), TransportError> {
        // Phase 1: get manifest of available sequences.
        let manifest = self.inner.recv_manifest(channel).await?;

        if manifest.is_empty() {
            // Transport doesn't support manifest — fall back to legacy recv_frames
            // with max_seq-based dedup for backward compatibility.
            let (frames, max_seq) = self.inner.recv_frames(channel, cursor).await?;
            if frames.is_empty() {
                return Ok((vec![], max_seq));
            }
            // Legacy fallback: use max_seq to do basic dedup.
            if let Some(seq) = max_seq {
                let mut last_seen = self.last_seen.lock().unwrap();
                let seen = last_seen.entry(channel.to_string()).or_default();
                if seen.contains(&seq) {
                    return Ok((vec![], None));
                }
                seen.insert(seq);
            }
            return Ok((frames, max_seq));
        }

        // Filter out already-seen sequences.
        let needed_ids: Vec<u64> = {
            let last_seen = self.last_seen.lock().unwrap();
            let seen = last_seen.get(channel);
            manifest
                .iter()
                .filter(|(seq_id, _)| {
                    seen.map_or(true, |s| !s.contains(seq_id))
                })
                .map(|(seq_id, _)| *seq_id)
                .collect()
        };

        // All sequences already seen — skip fetch (saves a round-trip, req 2.4).
        if needed_ids.is_empty() {
            return Ok((vec![], None));
        }

        // Phase 2: fetch needed sequences in batches.
        // Each fetch query encodes sequence IDs as dash-separated decimals in
        // a single DNS label (max 63 chars). Batch size is limited to keep the
        // label within bounds. Typical seq IDs are 1-6 digits, so 5-6 IDs per
        // batch is safe.
        const FETCH_BATCH_SIZE: usize = 5;

        let mut all_frames = Vec::new();
        let mut overall_max_seq: Option<u64> = None;

        for batch in needed_ids.chunks(FETCH_BATCH_SIZE) {
            let (frames, max_seq) = self.inner.recv_fetch(channel, batch).await?;

            if let Some(s) = max_seq {
                overall_max_seq = Some(overall_max_seq.map_or(s, |m: u64| m.max(s)));
            }

            // Only mark sequences as seen if we actually got frames back.
            if !frames.is_empty() {
                let mut last_seen = self.last_seen.lock().unwrap();
                let seen = last_seen.entry(channel.to_string()).or_default();
                for id in batch {
                    seen.insert(*id);
                }
            }

            all_frames.extend(frames);
        }

        Ok((all_frames, overall_max_seq))
    }

    async fn query_status(&self, channel: &str) -> Result<usize, TransportError> {
        self.inner.query_status(channel).await
    }

    async fn recv_manifest(&self, channel: &str) -> Result<Vec<(u64, usize)>, TransportError> {
        self.inner.recv_manifest(channel).await
    }

    async fn recv_fetch(&self, channel: &str, seq_ids: &[u64]) -> Result<(Vec<Vec<u8>>, Option<u64>), TransportError> {
        self.inner.recv_fetch(channel, seq_ids).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dns_message_broker::relay_store::RelayStore;
    use dns_message_broker::store::RealClock;
    use std::sync::Arc;
    use std::time::Duration;

    fn make_store() -> SharedRelayStore {
        Arc::new(RelayStore::new(Duration::from_secs(600), RealClock))
    }

    #[tokio::test]
    async fn send_then_recv_round_trip() {
        let store = make_store();
        let transport = RelayTransport::new(store.clone(), "node1".to_string());

        transport
            .send_frame("ch1", "ignored", b"hello")
            .await
            .unwrap();

        let (frames, seq) = transport.recv_frames("ch1", None).await.unwrap();
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0], b"hello");
        assert!(seq.is_some());
    }

    #[tokio::test]
    async fn recv_deduplicates_already_seen() {
        let store = make_store();
        let transport = RelayTransport::new(store.clone(), "node1".to_string());

        transport
            .send_frame("ch1", "ignored", b"data1")
            .await
            .unwrap();

        // First read returns the frame.
        let (frames, _) = transport.recv_frames("ch1", None).await.unwrap();
        assert_eq!(frames.len(), 1);

        // Second read without new writes returns empty (deduplication).
        let (frames, _) = transport.recv_frames("ch1", None).await.unwrap();
        assert!(frames.is_empty());
    }

    #[tokio::test]
    async fn recv_returns_new_after_second_send() {
        let store = make_store();
        let transport = RelayTransport::new(store.clone(), "node1".to_string());

        transport
            .send_frame("ch1", "ignored", b"first")
            .await
            .unwrap();
        let (frames, _) = transport.recv_frames("ch1", None).await.unwrap();
        assert_eq!(frames, vec![b"first".to_vec()]);

        // Second send creates a new slot (unique sender_id).
        transport
            .send_frame("ch1", "ignored", b"second")
            .await
            .unwrap();
        let (frames, _) = transport.recv_frames("ch1", None).await.unwrap();
        assert_eq!(frames, vec![b"second".to_vec()]);
    }

    #[tokio::test]
    async fn query_status_returns_slot_count() {
        let store = make_store();
        let transport = RelayTransport::new(store.clone(), "node1".to_string());

        assert_eq!(transport.query_status("ch1").await.unwrap(), 0);

        transport
            .send_frame("ch1", "ignored", b"x")
            .await
            .unwrap();
        assert_eq!(transport.query_status("ch1").await.unwrap(), 1);
    }

    #[tokio::test]
    async fn recv_empty_channel() {
        let store = make_store();
        let transport = RelayTransport::new(store, "node1".to_string());

        let (frames, seq) = transport.recv_frames("nonexistent", None).await.unwrap();
        assert!(frames.is_empty());
        assert!(seq.is_none());
    }

    #[tokio::test]
    async fn cursor_parameter_is_ignored() {
        let store = make_store();
        let transport = RelayTransport::new(store.clone(), "node1".to_string());

        transport
            .send_frame("ch1", "ignored", b"payload")
            .await
            .unwrap();

        // Passing a cursor value should not affect results.
        let (frames, _) = transport.recv_frames("ch1", Some(999)).await.unwrap();
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0], b"payload");
    }

    #[tokio::test]
    async fn uses_own_sender_id_not_parameter() {
        let store = make_store();
        let transport = RelayTransport::new(store.clone(), "real-sender".to_string());

        transport
            .send_frame("ch1", "should-be-ignored", b"data")
            .await
            .unwrap();

        // Verify the store has the slot under "real-sender" (no suffix),
        // not "should-be-ignored".
        let slots = store.read("ch1");
        assert_eq!(slots.len(), 1);
        assert_eq!(slots[0].sender_id, "real-sender");
    }
}
