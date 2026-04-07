/// Virtual smoltcp device backed by in-memory packet queues.
/// The poll loop drains tx_queue for encryption/sending and fills
/// rx_queue with decrypted inbound packets.
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::time::Instant;
use std::collections::VecDeque;

pub struct VirtualDevice {
    rx_queue: VecDeque<Vec<u8>>,
    tx_queue: VecDeque<Vec<u8>>,
    mtu: usize,
}

impl VirtualDevice {
    pub fn new(mtu: usize) -> Self {
        Self {
            rx_queue: VecDeque::new(),
            tx_queue: VecDeque::new(),
            mtu,
        }
    }

    /// Push a decrypted IP packet into the receive queue.
    pub fn inject_rx(&mut self, packet: Vec<u8>) {
        self.rx_queue.push_back(packet);
    }

    /// Drain all outbound IP packets produced by smoltcp.
    pub fn drain_tx(&mut self) -> Vec<Vec<u8>> {
        self.tx_queue.drain(..).collect()
    }
}

impl Device for VirtualDevice {
    type RxToken<'a> = VirtualRxToken;
    type TxToken<'a> = VirtualTxToken<'a>;

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        caps
    }

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let packet = self.rx_queue.pop_front()?;
        let rx = VirtualRxToken(packet);
        let tx = VirtualTxToken(&mut self.tx_queue);
        Some((rx, tx))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(VirtualTxToken(&mut self.tx_queue))
    }
}

pub struct VirtualRxToken(Vec<u8>);

impl RxToken for VirtualRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.0)
    }
}

pub struct VirtualTxToken<'a>(&'a mut VecDeque<Vec<u8>>);

impl<'a> TxToken for VirtualTxToken<'a> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buf = vec![0u8; len];
        let result = f(&mut buf);
        self.0.push_back(buf);
        result
    }
}

/// Compute the MTU for the VirtualDevice given a DNS payload budget.
///
/// Subtracts the encrypted packet header overhead:
/// - 8 bytes session_id
/// - 4 bytes sequence number (big-endian u32)
/// - 16 bytes Poly1305 authentication tag
///
/// Returns 0 if the budget is too small.
pub fn compute_mtu(dns_payload_budget: usize) -> usize {
    dns_payload_budget.saturating_sub(28)
}
