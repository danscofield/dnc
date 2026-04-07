use std::net::Ipv4Addr;
use std::time::Duration;

use smoltcp::iface::{Interface, SocketHandle};
use smoltcp::wire::{HardwareAddress, IpCidr, Ipv4Address};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tracing::{debug, warn};

use crate::config::SmolTuningConfig;
use crate::crypto::{Direction, SessionKey};
use crate::frame::SessionId;
use crate::smol_device::VirtualDevice;
use crate::smol_frame::{decrypt_ip_packet, encrypt_ip_packet};
use crate::transport::{AdaptiveBackoff, TransportBackend};

pub struct SmolPollConfig {
    pub poll_active: Duration,
    pub poll_idle: Duration,
    pub backoff_max: Duration,
    pub query_interval: Duration,
    pub no_edns: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PollDirection {
    Client,
    Exit,
}

impl PollDirection {
    fn encrypt_direction(self) -> Direction {
        match self {
            PollDirection::Client => Direction::Upstream,
            PollDirection::Exit => Direction::Downstream,
        }
    }
    fn decrypt_direction(self) -> Direction {
        match self {
            PollDirection::Client => Direction::Downstream,
            PollDirection::Exit => Direction::Upstream,
        }
    }
}

pub fn create_smol_interface(
    device: &mut VirtualDevice,
    local_ip: Ipv4Addr,
    gateway_ip: Ipv4Addr,
) -> Interface {
    let config = smoltcp::iface::Config::new(HardwareAddress::Ip);
    let mut iface = Interface::new(config, device, smoltcp::time::Instant::from_millis(0));
    iface.update_ip_addrs(|addrs| {
        addrs.push(IpCidr::new(Ipv4Address::from(local_ip).into(), 24)).unwrap();
    });
    iface.routes_mut().add_default_ipv4_route(Ipv4Address::from(gateway_ip)).unwrap();
    iface
}

pub fn create_tcp_socket(
    tuning: &SmolTuningConfig,
    mss: usize,
) -> smoltcp::socket::tcp::Socket<'static> {
    // Ensure buffers are at least 536 bytes even if the computed
    // mss * window_segments is smaller. smoltcp needs enough buffer room
    // to reassemble out-of-order TCP segments over the high-latency DNS link.
    let buf_size = (mss * tuning.window_segments).max(384);
    let rx_buf = smoltcp::socket::tcp::SocketBuffer::new(vec![0u8; buf_size]);
    let tx_buf = smoltcp::socket::tcp::SocketBuffer::new(vec![0u8; buf_size]);
    let mut socket = smoltcp::socket::tcp::Socket::new(rx_buf, tx_buf);
    socket.set_timeout(Some(smoltcp::time::Duration::from_secs(10)));
    // Disable Nagle — send segments immediately, don't wait to coalesce.
    // On a high-latency DNS link, Nagle adds unnecessary delay.
    socket.set_nagle_enabled(false);
    // No keep-alive — it generates extra traffic on the constrained DNS link.
    socket
}

/// Run the bidirectional poll loop for a single smoltcp session.
///
/// Spawns background tasks for DNS recv and send so the smoltcp poll cycle
/// never blocks on DNS I/O. Communication happens via mpsc channels:
/// - recv task → inbound_rx: decrypted IP packets arriving from broker
/// - outbound_tx → send task: encrypted IP packets to send to broker
#[allow(clippy::too_many_arguments)]
pub async fn run_session_poll_loop(
    iface: &mut Interface,
    device: &mut VirtualDevice,
    sockets: &mut smoltcp::iface::SocketSet<'_>,
    socket_handle: SocketHandle,
    send_transport: std::sync::Arc<dyn TransportBackend>,
    recv_transport: std::sync::Arc<dyn TransportBackend>,
    session_id: &SessionId,
    session_key: &SessionKey,
    upstream_channel: &str,
    downstream_channel: &str,
    direction: PollDirection,
    local_read: &mut (dyn tokio::io::AsyncRead + Unpin + Send),
    local_write: &mut (dyn tokio::io::AsyncWrite + Unpin + Send),
    config: &SmolPollConfig,
    sender_id: &str,
    tx_seq: &mut u32,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let encrypt_dir = direction.encrypt_direction();
    let decrypt_dir = direction.decrypt_direction();

    let (recv_channel, send_channel) = match direction {
        PollDirection::Client => (downstream_channel, upstream_channel),
        PollDirection::Exit => (upstream_channel, downstream_channel),
    };

    // --- Background recv task: polls broker, decrypts, feeds channel ---
    let (inbound_tx, mut inbound_rx) = mpsc::channel::<Vec<u8>>(64);
    let recv_channel_owned = recv_channel.to_string();
    let decrypt_key = SessionKey {
        data_key: session_key.data_key,
        control_key: session_key.control_key,
    };
    let recv_poll_active = config.poll_active;
    let recv_backoff_max = config.backoff_max;
    let recv_transport_clone = recv_transport.clone();
    let (cancel_tx, mut cancel_rx) = mpsc::channel::<()>(1);

    let recv_handle = tokio::spawn(async move {
        let mut backoff = AdaptiveBackoff::new(recv_poll_active, recv_backoff_max);
        let mut cursor: Option<u64> = None;
        let mut poll_count: u64 = 0;

        loop {
            poll_count += 1;
            tokio::select! {
                _ = cancel_rx.recv() => break,
                result = recv_transport_clone.recv_frames(&recv_channel_owned, cursor) => {
                    match result {
                        Ok((frames, new_cursor)) if !frames.is_empty() => {
                            debug!(
                                count = frames.len(),
                                cursor = ?cursor,
                                new_cursor = ?new_cursor,
                                poll_count,
                                "recv task: got {} packets", frames.len()
                            );
                            if let Some(c) = new_cursor {
                                cursor = Some(c + 1);
                            }
                            for encrypted in &frames {
                                match decrypt_ip_packet(encrypted, decrypt_dir, &decrypt_key) {
                                    Ok((_sid, _seq, ip_packet)) => {
                                        debug!(ip_len = ip_packet.len(), "recv task: decrypted IP packet");
                                        if inbound_tx.send(ip_packet).await.is_err() {
                                            return;
                                        }
                                    }
                                    Err(e) => {
                                        debug!("recv task: decrypt failed: {e}");
                                    }
                                }
                            }
                            backoff.reset();
                        }
                        Ok(_) => {
                            if poll_count % 20 == 0 {
                                debug!(
                                    channel = %recv_channel_owned,
                                    cursor = ?cursor,
                                    backoff_ms = backoff.current().as_millis() as u64,
                                    poll_count,
                                    "recv task: empty poll"
                                );
                            }
                            backoff.increase();
                        }
                        Err(e) => {
                            debug!("recv task: error: {e}");
                            backoff.increase();
                        }
                    }
                }
            }
            tokio::time::sleep(backoff.current()).await;
        }
    });

    // --- Background send task: takes encrypted packets, sends via DNS ---
    let (outbound_tx, mut outbound_rx) = mpsc::channel::<Vec<u8>>(64);
    let send_channel_owned = send_channel.to_string();
    let sender_id_owned = sender_id.to_string();
    let send_transport = send_transport.clone();

    let send_handle = tokio::spawn(async move {
        while let Some(encrypted) = outbound_rx.recv().await {
            if let Err(e) = send_transport
                .send_frame(&send_channel_owned, &sender_id_owned, &encrypted)
                .await
            {
                debug!("send task: error: {e}");
            }
        }
    });

    // --- Main loop: process smoltcp, shuttle data, never blocks on DNS ---
    let mut backoff = AdaptiveBackoff::new(config.poll_active, config.backoff_max);
    let mut local_eof = false;
    let mut loop_count: u64 = 0;

    let result = loop {
        loop_count += 1;
        let now_millis = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;
        let smol_now = smoltcp::time::Instant::from_millis(now_millis);
        let mut activity = false;

        // --- Drain inbound channel (non-blocking) ---
        let mut inbound_count = 0;
        while let Ok(ip_packet) = inbound_rx.try_recv() {
            inbound_count += 1;
            device.inject_rx(ip_packet);
            activity = true;
        }

        // --- Process smoltcp ---
        iface.poll(smol_now, device, sockets);

        // --- Send outbound packets (non-blocking enqueue) ---
        let outbound = device.drain_tx();
        if inbound_count > 0 || !outbound.is_empty() {
            debug!(
                inbound_count,
                outbound_count = outbound.len(),
                loop_count,
                "main loop: processed packets"
            );
        }
        for ip_packet in &outbound {
            let encrypted =
                encrypt_ip_packet(session_id, *tx_seq, encrypt_dir, session_key, ip_packet);
            *tx_seq = tx_seq.wrapping_add(1);
            // Non-blocking: just enqueue, the send task handles DNS I/O
            if outbound_tx.try_send(encrypted).is_err() {
                debug!("outbound channel full, dropping packet");
            }
            activity = true;
        }

        // --- Transfer data between smoltcp socket and local stream ---
        {
            let socket = sockets.get_mut::<smoltcp::socket::tcp::Socket>(socket_handle);

            let state = socket.state();
            if loop_count % 10 == 0 {
                debug!(
                    ?state,
                    loop_count,
                    local_eof,
                    can_send = socket.can_send(),
                    can_recv = socket.can_recv(),
                    "main loop: socket state"
                );
            }
            if state == smoltcp::socket::tcp::State::Closed
                || state == smoltcp::socket::tcp::State::TimeWait
            {
                debug!("smoltcp socket in terminal state: {:?}", state);
                break Ok(());
            }

            // Local stream → smoltcp send buffer
            if !local_eof && socket.can_send() {
                let mut buf = [0u8; 1024];
                match tokio::time::timeout(Duration::from_millis(1), local_read.read(&mut buf))
                    .await
                {
                    Ok(Ok(0)) => {
                        debug!("local stream EOF, stopping local reads");
                        local_eof = true;
                    }
                    Ok(Ok(n)) => {
                        if let Err(e) = socket.send_slice(&buf[..n]) {
                            debug!("smoltcp send_slice error: {e}");
                        } else {
                            activity = true;
                        }
                    }
                    Ok(Err(e)) => {
                        debug!("local read error: {e}");
                        local_eof = true;
                    }
                    Err(_) => {}
                }
            }

            // smoltcp recv buffer → local stream
            if socket.can_recv() {
                let recv_result: Result<Vec<u8>, _> = socket.recv(|data: &mut [u8]| {
                    let len = data.len();
                    let owned = data.to_vec();
                    (len, owned)
                });
                match recv_result {
                    Ok(data) if !data.is_empty() => {
                        if let Err(e) = local_write.write_all(&data).await {
                            warn!("local write error: {e}");
                            break Ok(());
                        }
                        activity = true;
                    }
                    Ok(_) => {}
                    Err(e) => {
                        debug!("smoltcp recv error: {e}");
                    }
                }
            }

            // Deferred close: once the local side has closed and we've drained
            // all receivable data from smoltcp, initiate the TCP FIN exchange.
            // This handles both sides:
            // - Client: curl closed → local_eof, wait for response → !may_recv → close
            // - Exit: target closed → local_eof, response fully sent → !can_send (buffer empty) → close
            if local_eof {
                let should_close = match direction {
                    PollDirection::Client => !socket.may_recv(),
                    PollDirection::Exit => !socket.can_send(), // send buffer drained
                };
                if should_close {
                    debug!("local EOF and transfer complete, closing smoltcp socket");
                    socket.close();
                }
            }
        }

        // --- Adaptive sleep ---
        if activity {
            backoff.reset();
        } else {
            backoff.increase();
        }

        let adaptive = backoff.current();
        let poll_delay = iface
            .poll_delay(smol_now, sockets)
            .map(|d| Duration::from_millis(d.total_millis() as u64));
        let sleep_dur = match poll_delay {
            Some(hint) => adaptive.min(hint),
            None => adaptive,
        };

        tokio::time::sleep(sleep_dur).await;
    };

    // --- Cleanup: cancel background tasks ---
    let _ = cancel_tx.send(()).await;
    drop(outbound_tx); // close send channel → send task exits
    recv_handle.abort();
    send_handle.abort();

    result
}
