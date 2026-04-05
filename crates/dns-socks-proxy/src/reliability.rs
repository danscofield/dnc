// Reliability module: retransmission and reassembly buffers.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use crate::frame::Frame;

// ---------------------------------------------------------------------------
// RetransmitEntry
// ---------------------------------------------------------------------------

/// An entry in the retransmission buffer tracking a sent-but-unacknowledged frame.
pub struct RetransmitEntry {
    pub frame: Frame,
    pub sent_at: Instant,
    pub retransmit_count: usize,
}

// ---------------------------------------------------------------------------
// RetransmitBuffer
// ---------------------------------------------------------------------------

/// Retransmission buffer: holds sent-but-unacknowledged frames and provides
/// sliding-window flow control, RTO-based retransmission detection, and
/// cumulative ACK processing.
pub struct RetransmitBuffer {
    frames: BTreeMap<u32, RetransmitEntry>,
    window_size: usize,
    max_retransmits: usize,
    rto: Duration,
}

impl RetransmitBuffer {
    /// Create a new `RetransmitBuffer` with the given configuration.
    pub fn new(window_size: usize, max_retransmits: usize, rto: Duration) -> Self {
        Self {
            frames: BTreeMap::new(),
            window_size,
            max_retransmits,
            rto,
        }
    }

    /// Queue a frame for retransmission tracking.
    pub fn insert(&mut self, seq: u32, frame: Frame) {
        self.frames.insert(
            seq,
            RetransmitEntry {
                frame,
                sent_at: Instant::now(),
                retransmit_count: 0,
            },
        );
    }

    /// Acknowledge all frames with sequence number ≤ `ack_seq` (cumulative ACK).
    /// Returns the number of frames removed.
    pub fn acknowledge(&mut self, ack_seq: u32) -> usize {
        // Collect keys to remove (all keys <= ack_seq).
        let to_remove: Vec<u32> = self
            .frames
            .range(..=ack_seq)
            .map(|(&k, _)| k)
            .collect();
        let count = to_remove.len();
        for k in to_remove {
            self.frames.remove(&k);
        }
        count
    }

    /// Returns references to frames that need retransmission (sent_at + rto < now).
    pub fn get_retransmittable(&self, now: Instant) -> Vec<&Frame> {
        self.frames
            .values()
            .filter(|entry| now.duration_since(entry.sent_at) >= self.rto)
            .map(|entry| &entry.frame)
            .collect()
    }

    /// Mark a frame as retransmitted: increment `retransmit_count` and update `sent_at`.
    pub fn mark_retransmitted(&mut self, seq: u32, now: Instant) {
        if let Some(entry) = self.frames.get_mut(&seq) {
            entry.retransmit_count += 1;
            entry.sent_at = now;
        }
    }

    /// Returns `true` if the number of unacknowledged frames equals or exceeds
    /// the configured window size.
    pub fn is_window_full(&self) -> bool {
        self.frames.len() >= self.window_size
    }

    /// Check if any frame has exceeded the maximum retransmission count.
    /// Returns `Some(seq)` for the first such frame, or `None`.
    pub fn has_exceeded_max_retransmits(&self) -> Option<u32> {
        self.frames
            .iter()
            .find(|(_, entry)| entry.retransmit_count >= self.max_retransmits)
            .map(|(&seq, _)| seq)
    }

    /// Returns the number of unacknowledged frames currently in the buffer.
    pub fn len(&self) -> usize {
        self.frames.len()
    }

    /// Returns `true` if the buffer contains no unacknowledged frames.
    pub fn is_empty(&self) -> bool {
        self.frames.is_empty()
    }
}

// ---------------------------------------------------------------------------
// ReassemblyBuffer
// ---------------------------------------------------------------------------

/// Reassembly buffer: reorders received DATA frame payloads by sequence number
/// and delivers contiguous payload bytes in order.
pub struct ReassemblyBuffer {
    buffer: BTreeMap<u32, Vec<u8>>,
    next_expected: u32,
    max_buffer_size: usize,
}

impl ReassemblyBuffer {
    /// Create a new `ReassemblyBuffer` with the given maximum buffer size.
    pub fn new(max_buffer_size: usize) -> Self {
        Self {
            buffer: BTreeMap::new(),
            next_expected: 0,
            max_buffer_size,
        }
    }

    /// Insert a received DATA frame payload.
    ///
    /// Returns `true` if the frame was new (not a duplicate).
    /// Returns `false` if the sequence number has already been drained
    /// (`seq < next_expected`) or is already buffered.
    pub fn insert(&mut self, seq: u32, payload: Vec<u8>) -> bool {
        // Already drained — this seq was delivered in a previous drain_contiguous call.
        if seq < self.next_expected {
            return false;
        }
        // Already buffered — duplicate.
        if self.buffer.contains_key(&seq) {
            return false;
        }
        self.buffer.insert(seq, payload);
        true
    }

    /// Drain contiguous payloads starting from `next_expected`.
    ///
    /// Removes entries from the buffer as long as the next expected sequence
    /// number is present, concatenates their payloads, and advances
    /// `next_expected` accordingly. Returns the concatenated bytes (empty if
    /// nothing is contiguous).
    pub fn drain_contiguous(&mut self) -> Vec<u8> {
        let mut result = Vec::new();
        while let Some(payload) = self.buffer.remove(&self.next_expected) {
            result.extend_from_slice(&payload);
            self.next_expected += 1;
        }
        result
    }

    /// Returns the highest contiguous sequence number received.
    ///
    /// This is `next_expected - 1` when at least one frame has been consumed,
    /// or `0` if no frames have been consumed yet.
    pub fn ack_seq(&self) -> u32 {
        if self.next_expected > 0 {
            self.next_expected - 1
        } else {
            0
        }
    }

    /// Returns `true` if the number of buffered (out-of-order) entries exceeds
    /// the configured `max_buffer_size`.
    pub fn is_overflowed(&self) -> bool {
        self.buffer.len() > self.max_buffer_size
    }

    /// Returns the number of entries currently buffered.
    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    /// Returns `true` if the buffer contains no entries.
    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    /// Returns the next expected sequence number.
    pub fn next_expected(&self) -> u32 {
        self.next_expected
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::{Frame, FrameFlags, FrameType, SessionId};

    /// Helper to create a simple DATA frame with the given sequence number.
    fn make_frame(seq: u32) -> Frame {
        Frame {
            session_id: SessionId(*b"test0001"),
            seq,
            frame_type: FrameType::Data,
            flags: FrameFlags::empty(),
            payload: vec![seq as u8],
        }
    }

    // -- insert and acknowledge -----------------------------------------------

    #[test]
    fn insert_and_acknowledge_single() {
        let mut buf = RetransmitBuffer::new(8, 10, Duration::from_secs(2));
        buf.insert(1, make_frame(1));
        assert_eq!(buf.len(), 1);

        let removed = buf.acknowledge(1);
        assert_eq!(removed, 1);
        assert!(buf.is_empty());
    }

    #[test]
    fn acknowledge_cumulative_removes_all_leq() {
        let mut buf = RetransmitBuffer::new(8, 10, Duration::from_secs(2));
        for seq in 1..=5 {
            buf.insert(seq, make_frame(seq));
        }
        assert_eq!(buf.len(), 5);

        // ACK seq 3 should remove 1, 2, 3
        let removed = buf.acknowledge(3);
        assert_eq!(removed, 3);
        assert_eq!(buf.len(), 2);

        // Remaining should be 4 and 5
        let removed = buf.acknowledge(5);
        assert_eq!(removed, 2);
        assert!(buf.is_empty());
    }

    #[test]
    fn acknowledge_with_no_matching_entries() {
        let mut buf = RetransmitBuffer::new(8, 10, Duration::from_secs(2));
        buf.insert(5, make_frame(5));
        buf.insert(6, make_frame(6));

        // ACK seq 3 — nothing ≤ 3 in the buffer
        let removed = buf.acknowledge(3);
        assert_eq!(removed, 0);
        assert_eq!(buf.len(), 2);
    }

    // -- window full ----------------------------------------------------------

    #[test]
    fn window_full_detection() {
        let mut buf = RetransmitBuffer::new(3, 10, Duration::from_secs(2));
        assert!(!buf.is_window_full());

        buf.insert(1, make_frame(1));
        buf.insert(2, make_frame(2));
        assert!(!buf.is_window_full());

        buf.insert(3, make_frame(3));
        assert!(buf.is_window_full());

        // Acknowledge one — should no longer be full
        buf.acknowledge(1);
        assert!(!buf.is_window_full());
    }

    #[test]
    fn window_full_at_exact_boundary() {
        let window = 4;
        let mut buf = RetransmitBuffer::new(window, 10, Duration::from_secs(2));
        for seq in 1..=(window as u32) {
            buf.insert(seq, make_frame(seq));
        }
        assert!(buf.is_window_full());
    }

    // -- retransmittable frames past RTO --------------------------------------

    #[test]
    fn get_retransmittable_returns_past_rto() {
        let rto = Duration::from_millis(50);
        let mut buf = RetransmitBuffer::new(8, 10, rto);

        let before = Instant::now();
        buf.insert(1, make_frame(1));

        // Immediately — nothing should be retransmittable
        let retrans = buf.get_retransmittable(before);
        assert!(retrans.is_empty());

        // After RTO has elapsed
        std::thread::sleep(rto + Duration::from_millis(10));
        let now = Instant::now();
        let retrans = buf.get_retransmittable(now);
        assert_eq!(retrans.len(), 1);
        assert_eq!(retrans[0].seq, 1);
    }

    #[test]
    fn mark_retransmitted_resets_timer() {
        let rto = Duration::from_millis(50);
        let mut buf = RetransmitBuffer::new(8, 10, rto);

        buf.insert(1, make_frame(1));

        // Wait past RTO
        std::thread::sleep(rto + Duration::from_millis(10));
        let now = Instant::now();
        assert_eq!(buf.get_retransmittable(now).len(), 1);

        // Mark retransmitted — should reset the timer
        buf.mark_retransmitted(1, now);
        let retrans = buf.get_retransmittable(now);
        assert!(retrans.is_empty());
    }

    // -- max retransmits exceeded ---------------------------------------------

    #[test]
    fn has_exceeded_max_retransmits_none_initially() {
        let mut buf = RetransmitBuffer::new(8, 3, Duration::from_secs(2));
        buf.insert(1, make_frame(1));
        assert_eq!(buf.has_exceeded_max_retransmits(), None);
    }

    #[test]
    fn has_exceeded_max_retransmits_after_limit() {
        let max = 3;
        let mut buf = RetransmitBuffer::new(8, max, Duration::from_secs(2));
        buf.insert(1, make_frame(1));

        let now = Instant::now();
        for _ in 0..max {
            buf.mark_retransmitted(1, now);
        }

        // retransmit_count is now == max_retransmits → exceeded
        assert_eq!(buf.has_exceeded_max_retransmits(), Some(1));
    }

    #[test]
    fn has_exceeded_returns_first_offender() {
        let max = 2;
        let mut buf = RetransmitBuffer::new(8, max, Duration::from_secs(2));
        buf.insert(1, make_frame(1));
        buf.insert(2, make_frame(2));
        buf.insert(3, make_frame(3));

        let now = Instant::now();
        // Only seq 2 exceeds
        for _ in 0..max {
            buf.mark_retransmitted(2, now);
        }

        assert_eq!(buf.has_exceeded_max_retransmits(), Some(2));
    }

    // -- cumulative ACK edge cases -------------------------------------------

    #[test]
    fn acknowledge_on_empty_buffer() {
        let mut buf = RetransmitBuffer::new(8, 10, Duration::from_secs(2));
        let removed = buf.acknowledge(100);
        assert_eq!(removed, 0);
    }

    #[test]
    fn acknowledge_all_at_once() {
        let mut buf = RetransmitBuffer::new(8, 10, Duration::from_secs(2));
        for seq in 0..8 {
            buf.insert(seq, make_frame(seq));
        }
        let removed = buf.acknowledge(7);
        assert_eq!(removed, 8);
        assert!(buf.is_empty());
    }

    // =========================================================================
    // ReassemblyBuffer tests
    // =========================================================================

    // -- in-order insertion and drain -----------------------------------------

    #[test]
    fn reassembly_in_order_insert_and_drain() {
        let mut buf = ReassemblyBuffer::new(32);
        assert!(buf.insert(0, vec![0xAA]));
        assert!(buf.insert(1, vec![0xBB]));
        assert!(buf.insert(2, vec![0xCC]));

        let data = buf.drain_contiguous();
        assert_eq!(data, vec![0xAA, 0xBB, 0xCC]);
        assert_eq!(buf.next_expected(), 3);
        assert!(buf.is_empty());
    }

    // -- out-of-order insertion and drain -------------------------------------

    #[test]
    fn reassembly_out_of_order_insert_and_drain() {
        let mut buf = ReassemblyBuffer::new(32);
        // Insert out of order: 2, 0, 1
        assert!(buf.insert(2, vec![0xCC]));
        assert!(buf.insert(0, vec![0xAA]));
        assert!(buf.insert(1, vec![0xBB]));

        let data = buf.drain_contiguous();
        assert_eq!(data, vec![0xAA, 0xBB, 0xCC]);
        assert_eq!(buf.next_expected(), 3);
    }

    // -- partial drain (gap in sequence) --------------------------------------

    #[test]
    fn reassembly_partial_drain_with_gap() {
        let mut buf = ReassemblyBuffer::new(32);
        assert!(buf.insert(0, vec![0xAA]));
        assert!(buf.insert(1, vec![0xBB]));
        // Skip seq 2
        assert!(buf.insert(3, vec![0xDD]));

        let data = buf.drain_contiguous();
        assert_eq!(data, vec![0xAA, 0xBB]);
        assert_eq!(buf.next_expected(), 2);
        // seq 3 is still buffered
        assert_eq!(buf.len(), 1);

        // Now fill the gap
        assert!(buf.insert(2, vec![0xCC]));
        let data = buf.drain_contiguous();
        assert_eq!(data, vec![0xCC, 0xDD]);
        assert_eq!(buf.next_expected(), 4);
    }

    // -- duplicate detection: already buffered --------------------------------

    #[test]
    fn reassembly_duplicate_already_buffered() {
        let mut buf = ReassemblyBuffer::new(32);
        assert!(buf.insert(0, vec![0xAA]));
        assert!(buf.insert(1, vec![0xBB]));

        // Duplicate of seq 1 (still buffered, not yet drained)
        assert!(!buf.insert(1, vec![0xFF]));
        assert_eq!(buf.len(), 2);
    }

    // -- duplicate detection: already drained ---------------------------------

    #[test]
    fn reassembly_duplicate_already_drained() {
        let mut buf = ReassemblyBuffer::new(32);
        assert!(buf.insert(0, vec![0xAA]));
        assert!(buf.insert(1, vec![0xBB]));
        let _ = buf.drain_contiguous();

        // seq 0 and 1 have been drained (next_expected is now 2)
        assert!(!buf.insert(0, vec![0xFF]));
        assert!(!buf.insert(1, vec![0xFF]));
        assert!(buf.is_empty());
    }

    // -- overflow detection ---------------------------------------------------

    #[test]
    fn reassembly_overflow_detection() {
        let max = 4;
        let mut buf = ReassemblyBuffer::new(max);

        // Insert out-of-order frames (skip seq 0 so nothing drains)
        for i in 1..=(max as u32) {
            assert!(buf.insert(i, vec![i as u8]));
        }
        // At exactly max entries, not overflowed
        assert!(!buf.is_overflowed());

        // One more pushes it over
        assert!(buf.insert(max as u32 + 1, vec![0xFF]));
        assert!(buf.is_overflowed());
    }

    // -- ack_seq correctness --------------------------------------------------

    #[test]
    fn reassembly_ack_seq_initial() {
        let buf = ReassemblyBuffer::new(32);
        // No frames consumed yet
        assert_eq!(buf.ack_seq(), 0);
    }

    #[test]
    fn reassembly_ack_seq_after_drain() {
        let mut buf = ReassemblyBuffer::new(32);
        buf.insert(0, vec![0xAA]);
        buf.insert(1, vec![0xBB]);
        buf.insert(2, vec![0xCC]);
        let _ = buf.drain_contiguous();

        // next_expected is 3, so ack_seq = 2
        assert_eq!(buf.ack_seq(), 2);
    }

    #[test]
    fn reassembly_ack_seq_with_gap() {
        let mut buf = ReassemblyBuffer::new(32);
        buf.insert(0, vec![0xAA]);
        // Skip seq 1
        buf.insert(2, vec![0xCC]);
        let _ = buf.drain_contiguous();

        // Only seq 0 was drained, next_expected = 1, ack_seq = 0
        assert_eq!(buf.ack_seq(), 0);
    }

    // -- empty buffer drain returns empty vec ---------------------------------

    #[test]
    fn reassembly_drain_empty_buffer() {
        let mut buf = ReassemblyBuffer::new(32);
        let data = buf.drain_contiguous();
        assert!(data.is_empty());
        assert_eq!(buf.next_expected(), 0);
    }

    #[test]
    fn reassembly_drain_with_only_future_seqs() {
        let mut buf = ReassemblyBuffer::new(32);
        // Only insert seq 5 — nothing contiguous from 0
        buf.insert(5, vec![0xFF]);
        let data = buf.drain_contiguous();
        assert!(data.is_empty());
        assert_eq!(buf.next_expected(), 0);
        assert_eq!(buf.len(), 1);
    }
}
