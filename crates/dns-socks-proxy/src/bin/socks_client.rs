use std::sync::Arc;
use std::time::Instant;

use clap::Parser;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};

use dns_socks_proxy::config::{SocksClientCli, SocksClientConfig};
use dns_socks_proxy::crypto::{
    compute_control_mac, decrypt_data, derive_session_key, encrypt_data, generate_keypair,
    Direction, Psk, SessionKey,
};
use dns_socks_proxy::frame::{
    decode_frame, encode_frame, encode_syn_payload, Frame, FrameFlags,
    FrameType, SessionId,
};
use dns_socks_proxy::session::{SessionManager, SessionState};
use dns_socks_proxy::socks::{socks5_handshake, socks5_reply};
use dns_socks_proxy::transport::{compute_payload_budget, DnsTransport, TransportBackend};

/// Nonce length used in DNS queries.
const NONCE_LEN: usize = 4;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = SocksClientCli::parse();
    let config = cli.into_config()?;

    info!(
        listen = %format!("{}:{}", config.listen_addr, config.listen_port),
        domain = %config.controlled_domain,
        resolver = %config.resolver_addr,
        client_id = %config.client_id,
        "socks-client starting"
    );

    // Bind TCP listener.
    let listen_addr = format!("{}:{}", config.listen_addr, config.listen_port);
    let listener = TcpListener::bind(&listen_addr).await?;
    info!("listening on {}", listen_addr);

    // Initialize session manager.
    let session_manager = Arc::new(Mutex::new(SessionManager::new()));

    // Shared config values wrapped in Arc for spawned tasks.
    let shared_config = Arc::new(config);

    // Accept loop.
    loop {
        let (stream, peer_addr) = listener.accept().await?;
        info!(%peer_addr, "accepted connection");

        let session_manager = Arc::clone(&session_manager);
        let config = Arc::clone(&shared_config);

        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, session_manager, config).await {
                warn!(%peer_addr, error = %e, "session failed");
            }
        });
    }
}

/// Handle a single SOCKS5 connection through its full lifecycle.
async fn handle_connection(
    mut stream: TcpStream,
    session_manager: Arc<Mutex<SessionManager>>,
    config: Arc<SocksClientConfig>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Create a per-session DNS transport (own UDP socket to avoid response cross-contamination).
    let transport = Arc::new(
        DnsTransport::new(config.resolver_addr, config.controlled_domain.clone()).await?,
    );

    // 1. SOCKS5 handshake.
    let connect_req = match socks5_handshake(&mut stream).await {
        Ok(req) => req,
        Err(e) => {
            debug!(error = %e, "SOCKS5 handshake failed");
            return Ok(());
        }
    };

    info!(
        target_addr = ?connect_req.target_addr,
        target_port = connect_req.target_port,
        "CONNECT request"
    );

    // 2. Create session.
    let (session_id, upstream_channel, downstream_channel) = {
        let mut mgr = session_manager.lock().await;
        let session = mgr.create_session(connect_req.clone())?;
        let id = session.id.clone();
        let up = session.upstream_channel.clone();
        let down = session.downstream_channel.clone();
        (id, up, down)
    };

    let send_control_channel = format!("ctl-{}", config.exit_node_id);
    let recv_control_channel = format!("ctl-{}", config.client_id);
    info!(session_id = %session_id, "session created");

    // 3. Generate X25519 keypair and send SYN.
    let (secret, pubkey) = generate_keypair();
    let syn_payload = encode_syn_payload(&connect_req, pubkey.as_bytes(), &config.client_id);
    let syn_frame = Frame {
        session_id: session_id.clone(),
        seq: 0,
        frame_type: FrameType::Syn,
        flags: FrameFlags::empty(),
        payload: syn_payload,
    };
    let mut syn_bytes = encode_frame(&syn_frame);
    let mac = compute_control_mac(&config.psk, &syn_bytes);
    syn_bytes.extend_from_slice(&mac);

    transport
        .send_frame(&send_control_channel, &config.client_id, &syn_bytes)
        .await?;
    debug!(session_id = %session_id, "SYN sent");

    // 4. Poll client's control channel for SYN-ACK with timeout.
    let connect_timeout = config.connect_timeout;
    let deadline = tokio::time::Instant::now() + connect_timeout;
    let session_key: SessionKey;

    loop {
        if tokio::time::Instant::now() >= deadline {
            warn!(session_id = %session_id, "SYN-ACK timeout");
            socks5_reply(&mut stream, 0x04).await.ok(); // host unreachable
            cleanup_session(&session_manager, &session_id).await;
            return Ok(());
        }

        tokio::time::sleep(config.poll_active).await;

        match transport.recv_frame(&recv_control_channel).await {
            Ok(Some(data)) => {
                // Need at least 16 bytes for MAC at the end.
                if data.len() < 16 {
                    debug!("control frame too short, ignoring");
                    continue;
                }
                let (frame_bytes, received_mac) = data.split_at(data.len() - 16);
                let mut mac_arr = [0u8; 16];
                mac_arr.copy_from_slice(received_mac);

                if !dns_socks_proxy::crypto::verify_control_mac(
                    &config.psk,
                    frame_bytes,
                    &mac_arr,
                ) {
                    debug!("control frame MAC verification failed, ignoring");
                    continue;
                }

                let frame = match decode_frame(frame_bytes) {
                    Ok(f) => f,
                    Err(e) => {
                        debug!(error = %e, "failed to decode control frame");
                        continue;
                    }
                };

                if frame.session_id != session_id {
                    debug!("control frame for different session, ignoring");
                    continue;
                }

                match frame.frame_type {
                    FrameType::SynAck => {
                        // Extract exit node pubkey (first 32 bytes of payload).
                        if frame.payload.len() < 32 {
                            warn!(session_id = %session_id, "SYN-ACK payload too short");
                            continue;
                        }
                        let mut exit_pubkey = [0u8; 32];
                        exit_pubkey.copy_from_slice(&frame.payload[..32]);

                        let exit_public =
                            x25519_dalek::PublicKey::from(exit_pubkey);
                        let shared_secret = secret.diffie_hellman(&exit_public);

                        session_key =
                            derive_session_key(shared_secret.as_bytes(), &config.psk)?;

                        // Update session state.
                        {
                            let mut mgr = session_manager.lock().await;
                            if let Some(session) = mgr.get_session(&session_id) {
                                session.state = SessionState::Established;
                                session.session_key = Some(SessionKey {
                                    data_key: session_key.data_key,
                                    control_key: session_key.control_key,
                                });
                            }
                        }

                        info!(session_id = %session_id, "session established");
                        break;
                    }
                    FrameType::Rst => {
                        warn!(session_id = %session_id, "received RST during setup");
                        socks5_reply(&mut stream, 0x05).await.ok(); // connection refused
                        cleanup_session(&session_manager, &session_id).await;
                        return Ok(());
                    }
                    _ => {
                        debug!(frame_type = ?frame.frame_type, "unexpected control frame type during setup");
                        continue;
                    }
                }
            }
            Ok(None) => continue,
            Err(e) => {
                debug!(error = %e, "transport error polling control channel");
                continue;
            }
        }
    }

    // 5. Send SOCKS5 success reply.
    socks5_reply(&mut stream, 0x00).await?;

    // 6. Compute payload budget.
    let payload_budget = compute_payload_budget(
        config.controlled_domain.len(),
        config.client_id.len(),
        upstream_channel.len(),
        NONCE_LEN,
    );
    if payload_budget == 0 {
        error!("payload budget is zero — domain/channel names too long");
        send_rst(&transport, &send_control_channel, &config.client_id, &session_id, &config.psk).await;
        cleanup_session(&session_manager, &session_id).await;
        return Ok(());
    }
    debug!(payload_budget, "computed payload budget");

    // 7. Split TCP stream and run bidirectional data flow.
    let (tcp_read, tcp_write) = stream.into_split();

    // Shared state for the session tasks.
    let session_id_up = session_id.clone();
    let session_id_down = session_id.clone();
    let session_id_retx = session_id.clone();
    let transport_up = Arc::clone(&transport);
    let transport_down = Arc::clone(&transport);
    let transport_retx = Arc::clone(&transport);
    let mgr_up = Arc::clone(&session_manager);
    let mgr_down = Arc::clone(&session_manager);
    let mgr_retx = Arc::clone(&session_manager);
    let config_up = Arc::clone(&config);
    let config_down = Arc::clone(&config);
    let config_retx = Arc::clone(&config);
    let upstream_ch = upstream_channel.clone();
    let upstream_ch_for_down = upstream_channel.clone();
    let downstream_ch = downstream_channel.clone();
    let control_ch = send_control_channel.clone();
    let control_ch_retx = send_control_channel.clone();

    // Upstream task: read TCP → fragment → encrypt → send DATA frames.
    let upstream_handle = tokio::spawn(upstream_task(
        tcp_read,
        transport_up,
        mgr_up,
        config_up,
        session_id_up,
        upstream_ch,
        control_ch,
        payload_budget,
        session_key.data_key,
    ));

    // Downstream task: poll downstream channel → decrypt → reassemble → write TCP.
    let downstream_handle = tokio::spawn(downstream_task(
        tcp_write,
        transport_down,
        mgr_down,
        config_down,
        session_id_down,
        downstream_ch,
        upstream_ch_for_down,
        session_key.data_key,
    ));

    // Retransmit timer task.
    let retransmit_handle = tokio::spawn(retransmit_task(
        transport_retx,
        mgr_retx,
        config_retx,
        session_id_retx,
        upstream_channel.clone(),
        control_ch_retx,
    ));

    // Wait for any task to finish (session end).
    tokio::select! {
        res = upstream_handle => {
            if let Err(e) = res {
                warn!(session_id = %session_id, error = %e, "upstream task panicked");
            }
        }
        res = downstream_handle => {
            if let Err(e) = res {
                warn!(session_id = %session_id, error = %e, "downstream task panicked");
            }
        }
        res = retransmit_handle => {
            if let Err(e) = res {
                warn!(session_id = %session_id, error = %e, "retransmit task panicked");
            }
        }
    }

    // Cleanup.
    info!(session_id = %session_id, "session ending, cleaning up");
    cleanup_session(&session_manager, &session_id).await;
    Ok(())
}

/// Upstream task: reads from local TCP, fragments, encrypts, and sends DATA frames.
async fn upstream_task(
    mut tcp_read: tokio::net::tcp::OwnedReadHalf,
    transport: Arc<DnsTransport>,
    session_manager: Arc<Mutex<SessionManager>>,
    config: Arc<SocksClientConfig>,
    session_id: SessionId,
    upstream_channel: String,
    control_channel: String,
    payload_budget: usize,
    data_key: [u8; 32],
) {
    let session_key = SessionKey {
        data_key,
        control_key: [0u8; 32], // not used for DATA encryption
    };
    let mut buf = vec![0u8; payload_budget];

    loop {
        // Check window before reading.
        {
            let mgr = session_manager.lock().await;
            if let Some(session) = mgr.sessions_ref().get(&session_id) {
                if session.retransmit_buf.is_window_full() {
                    drop(mgr);
                    tokio::time::sleep(config.poll_active).await;
                    continue;
                }
            } else {
                return; // session removed
            }
        }

        match tcp_read.read(&mut buf).await {
            Ok(0) => {
                // TCP connection closed by application — send FIN.
                info!(session_id = %session_id, "local TCP closed, sending FIN");
                send_fin(&transport, &control_channel, &config.client_id, &session_id, &config.psk).await;
                return;
            }
            Ok(n) => {
                let plaintext = &buf[..n];

                let mut mgr = session_manager.lock().await;
                if let Some(session) = mgr.get_session(&session_id) {
                    if session.state != SessionState::Established {
                        return;
                    }

                    let seq = session.tx_seq;
                    session.tx_seq += 1;

                    let ciphertext =
                        encrypt_data(&session_key, seq, Direction::Upstream, plaintext);

                    let frame = Frame {
                        session_id: session_id.clone(),
                        seq,
                        frame_type: FrameType::Data,
                        flags: FrameFlags::empty(),
                        payload: ciphertext,
                    };

                    let frame_bytes = encode_frame(&frame);

                    // Insert into retransmit buffer.
                    session.retransmit_buf.insert(seq, frame.clone());

                    drop(mgr);

                    if let Err(e) = transport
                        .send_frame(&upstream_channel, &config.client_id, &frame_bytes)
                        .await
                    {
                        warn!(session_id = %session_id, seq, error = %e, "failed to send DATA frame");
                    } else {
                        debug!(session_id = %session_id, seq, bytes = n, "sent DATA frame");
                    }
                } else {
                    return; // session removed
                }
            }
            Err(e) => {
                warn!(session_id = %session_id, error = %e, "TCP read error");
                send_rst(&transport, &control_channel, &config.client_id, &session_id, &config.psk).await;
                return;
            }
        }
    }
}

/// Downstream task: polls downstream channel, decrypts, reassembles, writes to TCP.
async fn downstream_task(
    mut tcp_write: tokio::net::tcp::OwnedWriteHalf,
    transport: Arc<DnsTransport>,
    session_manager: Arc<Mutex<SessionManager>>,
    config: Arc<SocksClientConfig>,
    session_id: SessionId,
    downstream_channel: String,
    upstream_channel: String,
    data_key: [u8; 32],
) {
    let session_key = SessionKey {
        data_key,
        control_key: [0u8; 32],
    };
    let mut idle_count: u32 = 0;

    loop {
        // Adaptive polling: use active interval when data is flowing, idle when not.
        let poll_interval = if idle_count > 5 {
            config.poll_idle
        } else {
            config.poll_active
        };
        tokio::time::sleep(poll_interval).await;

        // Check session is still alive.
        {
            let mgr = session_manager.lock().await;
            match mgr.sessions_ref().get(&session_id) {
                Some(session) => {
                    if session.state == SessionState::Closed
                        || session.state == SessionState::FinSent
                    {
                        return;
                    }
                }
                None => return,
            }
        }

        match transport.recv_frames(&downstream_channel).await {
            Ok(frames) if frames.is_empty() => {
                idle_count = idle_count.saturating_add(1);
            }
            Ok(frames) => {
                idle_count = 0;
                for data in frames {

                let frame = match decode_frame(&data) {
                    Ok(f) => f,
                    Err(e) => {
                        debug!(error = %e, "failed to decode downstream frame");
                        continue;
                    }
                };

                if frame.session_id != session_id {
                    debug!("downstream frame for different session, ignoring");
                    continue;
                }

                match frame.frame_type {
                    FrameType::Data => {
                        // Decrypt payload.
                        let plaintext = match decrypt_data(
                            &session_key,
                            frame.seq,
                            Direction::Downstream,
                            &frame.payload,
                        ) {
                            Ok(pt) => pt,
                            Err(e) => {
                                debug!(seq = frame.seq, error = %e, "decryption failed, discarding");
                                continue;
                            }
                        };

                        let mut mgr = session_manager.lock().await;
                        if let Some(session) = mgr.get_session(&session_id) {
                            let is_new = session.reassembly_buf.insert(frame.seq, plaintext);
                            if !is_new {
                                debug!(seq = frame.seq, "duplicate frame, discarding");
                                continue;
                            }

                            // Check overflow.
                            if session.reassembly_buf.is_overflowed() {
                                warn!(session_id = %session_id, "reassembly buffer overflow");
                                drop(mgr);
                                send_rst(
                                    &transport,
                                    &format!("ctl-{}", config.exit_node_id),
                                    &config.client_id,
                                    &session_id,
                                    &config.psk,
                                )
                                .await;
                                return;
                            }

                            // Drain contiguous data and write to TCP.
                            let contiguous = session.reassembly_buf.drain_contiguous();
                            let ack_seq = session.reassembly_buf.ack_seq();
                            drop(mgr);

                            if !contiguous.is_empty() {
                                if let Err(e) = tcp_write.write_all(&contiguous).await {
                                    warn!(session_id = %session_id, error = %e, "TCP write error");
                                    return;
                                }

                                // Send ACK on upstream channel (back to exit-node).
                                send_ack(
                                    &transport,
                                    &upstream_channel,
                                    &config.client_id,
                                    &session_id,
                                    ack_seq,
                                    &config.psk,
                                )
                                .await;
                            }
                        } else {
                            return;
                        }
                    }
                    FrameType::Ack => {
                        // Process ACK for upstream retransmit buffer.
                        if frame.payload.len() >= 4 {
                            let ack_seq = u32::from_be_bytes([
                                frame.payload[0],
                                frame.payload[1],
                                frame.payload[2],
                                frame.payload[3],
                            ]);
                            let mut mgr = session_manager.lock().await;
                            if let Some(session) = mgr.get_session(&session_id) {
                                let removed = session.retransmit_buf.acknowledge(ack_seq);
                                debug!(session_id = %session_id, ack_seq, removed, "ACK processed");
                            }
                        }
                    }
                    FrameType::Fin => {
                        info!(session_id = %session_id, "received FIN");
                        let mut mgr = session_manager.lock().await;
                        if let Some(session) = mgr.get_session(&session_id) {
                            // Drain any remaining data.
                            let remaining = session.reassembly_buf.drain_contiguous();
                            session.state = SessionState::Closed;
                            drop(mgr);
                            if !remaining.is_empty() {
                                tcp_write.write_all(&remaining).await.ok();
                            }
                        }
                        return;
                    }
                    FrameType::Rst => {
                        warn!(session_id = %session_id, "received RST");
                        let mut mgr = session_manager.lock().await;
                        if let Some(session) = mgr.get_session(&session_id) {
                            session.state = SessionState::Closed;
                        }
                        return;
                    }
                    _ => {
                        debug!(frame_type = ?frame.frame_type, "unexpected frame type on downstream");
                    }
                }
              } // end for data in frames
            }
            Err(e) => {
                debug!(error = %e, "transport error polling downstream");
                idle_count = idle_count.saturating_add(1);
            }
        }
    }
}

/// Retransmit timer task: checks RetransmitBuffer and retransmits past-RTO frames.
async fn retransmit_task(
    transport: Arc<DnsTransport>,
    session_manager: Arc<Mutex<SessionManager>>,
    config: Arc<SocksClientConfig>,
    session_id: SessionId,
    upstream_channel: String,
    control_channel: String,
) {
    loop {
        tokio::time::sleep(config.rto / 2).await;

        let mut mgr = session_manager.lock().await;
        let session = match mgr.get_session(&session_id) {
            Some(s) => s,
            None => return,
        };

        if session.state == SessionState::Closed {
            return;
        }

        // Check max retransmits exceeded.
        if let Some(seq) = session.retransmit_buf.has_exceeded_max_retransmits() {
            warn!(session_id = %session_id, seq, "max retransmissions exceeded");
            session.state = SessionState::Closed;
            drop(mgr);
            send_rst(&transport, &control_channel, &config.client_id, &session_id, &config.psk).await;
            return;
        }

        // Get frames needing retransmission.
        let now = Instant::now();
        let retransmittable: Vec<Frame> = session
            .retransmit_buf
            .get_retransmittable(now)
            .into_iter()
            .cloned()
            .collect();

        // Mark them as retransmitted.
        for frame in &retransmittable {
            session.retransmit_buf.mark_retransmitted(frame.seq, now);
        }

        drop(mgr);

        // Send retransmissions.
        for frame in retransmittable {
            let frame_bytes = encode_frame(&frame);
            debug!(session_id = %session_id, seq = frame.seq, "retransmitting DATA frame");
            if let Err(e) = transport
                .send_frame(&upstream_channel, &config.client_id, &frame_bytes)
                .await
            {
                warn!(session_id = %session_id, seq = frame.seq, error = %e, "retransmit send failed");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

/// Send a FIN frame on the control channel.
async fn send_fin(
    transport: &Arc<DnsTransport>,
    control_channel: &str,
    sender_id: &str,
    session_id: &SessionId,
    psk: &Psk,
) {
    let frame = Frame {
        session_id: session_id.clone(),
        seq: 0,
        frame_type: FrameType::Fin,
        flags: FrameFlags::empty(),
        payload: vec![],
    };
    let mut frame_bytes = encode_frame(&frame);
    let mac = compute_control_mac(psk, &frame_bytes);
    frame_bytes.extend_from_slice(&mac);

    if let Err(e) = transport
        .send_frame(control_channel, sender_id, &frame_bytes)
        .await
    {
        warn!(session_id = %session_id, error = %e, "failed to send FIN");
    }
}

/// Send a RST frame on the control channel.
async fn send_rst(
    transport: &Arc<DnsTransport>,
    control_channel: &str,
    sender_id: &str,
    session_id: &SessionId,
    psk: &Psk,
) {
    let frame = Frame {
        session_id: session_id.clone(),
        seq: 0,
        frame_type: FrameType::Rst,
        flags: FrameFlags::empty(),
        payload: vec![],
    };
    let mut frame_bytes = encode_frame(&frame);
    let mac = compute_control_mac(psk, &frame_bytes);
    frame_bytes.extend_from_slice(&mac);

    if let Err(e) = transport
        .send_frame(control_channel, sender_id, &frame_bytes)
        .await
    {
        warn!(session_id = %session_id, error = %e, "failed to send RST");
    }
}

/// Send an ACK frame.
async fn send_ack(
    transport: &Arc<DnsTransport>,
    channel: &str,
    sender_id: &str,
    session_id: &SessionId,
    ack_seq: u32,
    psk: &Psk,
) {
    let mut payload = Vec::with_capacity(4);
    payload.extend_from_slice(&ack_seq.to_be_bytes());

    let frame = Frame {
        session_id: session_id.clone(),
        seq: 0,
        frame_type: FrameType::Ack,
        flags: FrameFlags::empty(),
        payload,
    };
    let mut frame_bytes = encode_frame(&frame);
    let mac = compute_control_mac(psk, &frame_bytes);
    frame_bytes.extend_from_slice(&mac);

    if let Err(e) = transport
        .send_frame(channel, sender_id, &frame_bytes)
        .await
    {
        debug!(session_id = %session_id, ack_seq, error = %e, "failed to send ACK");
    }
}

/// Remove a session from the session manager.
async fn cleanup_session(session_manager: &Arc<Mutex<SessionManager>>, session_id: &SessionId) {
    let mut mgr = session_manager.lock().await;
    mgr.remove_session(session_id);
    debug!(session_id = %session_id, "session cleaned up");
}
