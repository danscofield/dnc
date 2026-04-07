use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use clap::Parser;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};

use dns_socks_proxy::config::{DeploymentMode, ExitNodeCli, ExitNodeConfig};
use dns_socks_proxy::guard::is_blocked;
use dns_socks_proxy::crypto::{
    compute_control_mac, decrypt_data, derive_session_key, encrypt_data, generate_keypair,
    verify_control_mac, Direction, Psk, SessionKey,
};
use dns_socks_proxy::frame::{
    decode_frame, decode_syn_payload, encode_frame, Frame, FrameFlags, FrameType, SessionId,
};
use dns_socks_proxy::session::{Session, SessionManager, SessionState};
use dns_socks_proxy::socks::{ConnectRequest, TargetAddr};
use dns_socks_proxy::transport::{
    compute_payload_budget, recv_frames_parallel, AdaptiveBackoff, DirectTransport, DnsTransport,
    TransportBackend,
};

/// Nonce length used in DNS queries.
const NONCE_LEN: usize = 4;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = ExitNodeCli::parse();
    let config = cli.into_config()?;

    info!(
        domain = %config.controlled_domain,
        node_id = %config.node_id,
        mode = ?config.mode,
        "exit-node starting"
    );

    // Initialize transport based on mode.
    // In embedded mode we keep the broker shutdown sender so we can signal broker
    // tasks during graceful shutdown.
    let mut broker_shutdown_tx: Option<tokio::sync::watch::Sender<bool>> = None;

    let transport: Arc<dyn TransportBackend> = match config.mode {
        DeploymentMode::Standalone => {
            let resolver = config
                .resolver_addr
                .expect("resolver required in standalone mode");
            Arc::new(
                DnsTransport::new(resolver, config.controlled_domain.clone())
                    .await?
                    .with_edns(!config.no_edns),
            )
        }
        DeploymentMode::Embedded => {
            // 1. Read and parse the Broker TOML config file.
            let broker_config_path = config
                .broker_config_path
                .as_ref()
                .expect("broker_config_path required in embedded mode");
            let toml_str = std::fs::read_to_string(broker_config_path).unwrap_or_else(|e| {
                error!(path = %broker_config_path.display(), error = %e, "failed to read broker config");
                std::process::exit(1);
            });
            let broker_config =
                dns_message_broker::config::parse_config(&toml_str).unwrap_or_else(|e| {
                    error!(error = %e, "failed to parse broker config");
                    std::process::exit(1);
                });

            // 2. Create the shared ChannelStore.
            let store = dns_message_broker::server::create_store(&broker_config);

            // 3. Create a shutdown watch channel for broker tasks.
            let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
            let shutdown_rx2 = shutdown_tx.subscribe();

            // 4. Start the Broker's DNS server loop in a spawned task.
            let server_config = broker_config.clone();
            let server_store = store.clone();
            tokio::spawn(async move {
                if let Err(e) =
                    dns_message_broker::server::run_server_loop(server_config, server_store, shutdown_rx)
                        .await
                {
                    error!(error = %e, "embedded broker server loop error");
                }
            });

            // 5. Start the Broker's expiry sweeper task.
            let _sweeper_handle = dns_message_broker::server::spawn_expiry_sweeper(
                store.clone(),
                broker_config.expiry_interval(),
                shutdown_rx2,
            );

            info!(
                broker_listen = %format!("{}:{}", broker_config.listen_addr, broker_config.listen_port),
                "embedded broker started"
            );

            // Keep shutdown_tx so we can signal broker tasks during graceful shutdown.
            broker_shutdown_tx = Some(shutdown_tx);

            // 6. Use DirectTransport wrapping the shared store.
            Arc::new(DirectTransport::new(store, config.node_id.clone())) as Arc<dyn TransportBackend>
        }
    };

    let control_channel = format!("ctl-{}", config.node_id);
    let session_manager = Arc::new(Mutex::new(SessionManager::new()));
    let shared_config = Arc::new(config);

    info!(control_channel = %control_channel, "polling for SYN frames");

    // Adaptive polling state for the control channel.
    let mut backoff = AdaptiveBackoff::new(shared_config.poll_active, shared_config.backoff_max);

    // Set up shutdown signal handling (SIGINT / SIGTERM).
    let shutdown_signal = async {
        let ctrl_c = tokio::signal::ctrl_c();

        #[cfg(unix)]
        {
            let mut sigterm =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                    .expect("failed to register SIGTERM handler");
            tokio::select! {
                _ = ctrl_c => {}
                _ = sigterm.recv() => {}
            }
        }

        #[cfg(not(unix))]
        {
            ctrl_c.await.ok();
        }
    };
    tokio::pin!(shutdown_signal);

    loop {
        tokio::select! {
            _ = &mut shutdown_signal => {
                break;
            }
            _ = tokio::time::sleep(backoff.current()) => {}
        }

        match transport.recv_frames(&control_channel, None).await {
            Ok((frames, _seq)) if !frames.is_empty() => {
                backoff.reset();

                for data in frames {
                // Need at least 16 bytes for MAC at the end.
                if data.len() < 16 {
                    debug!("control frame too short, ignoring");
                    continue;
                }
                let (frame_bytes, received_mac) = data.split_at(data.len() - 16);
                let mut mac_arr = [0u8; 16];
                mac_arr.copy_from_slice(received_mac);

                if !verify_control_mac(&shared_config.psk, frame_bytes, &mac_arr) {
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

                match frame.frame_type {
                    FrameType::Syn => {
                        let transport = Arc::clone(&transport);
                        let session_manager = Arc::clone(&session_manager);
                        let config = Arc::clone(&shared_config);
                        let ctl_ch = control_channel.clone();

                        tokio::spawn(async move {
                            if let Err(e) = handle_syn(
                                frame,
                                transport,
                                session_manager,
                                config,
                                ctl_ch,
                            )
                            .await
                            {
                                warn!(error = %e, "SYN handling failed");
                            }
                        });
                    }
                    FrameType::Fin => {
                        info!(session_id = %frame.session_id, "received FIN on control channel");
                        let mut mgr = session_manager.lock().await;
                        if let Some(session) = mgr.get_session(&frame.session_id) {
                            session.state = SessionState::Closed;
                        }
                        mgr.remove_session(&frame.session_id);
                    }
                    FrameType::Rst => {
                        warn!(session_id = %frame.session_id, "received RST on control channel");
                        let mut mgr = session_manager.lock().await;
                        if let Some(session) = mgr.get_session(&frame.session_id) {
                            session.state = SessionState::Closed;
                        }
                        mgr.remove_session(&frame.session_id);
                    }
                    _ => {
                        debug!(frame_type = ?frame.frame_type, "unexpected frame type on control channel");
                    }
                }
                } // end for data in frames
            }
            Ok(_) => {
                backoff.increase();
            }
            Err(e) => {
                debug!(error = %e, "transport error polling control channel");
                backoff.increase();
            }
        }
    }

    // --- Graceful shutdown ---
    info!("shutdown signal received");

    // Send FIN frames for all active sessions and remove them.
    let shutdown_deadline = tokio::time::Instant::now() + Duration::from_secs(10);

    {
        let mut mgr = session_manager.lock().await;
        let session_ids: Vec<SessionId> = mgr
            .sessions_ref()
            .keys()
            .cloned()
            .collect();

        let active_count = session_ids.len();
        info!(active_sessions = active_count, "sending FIN for all active sessions");

        for sid in &session_ids {
            info!(session_id = %sid, "sending FIN for session shutdown");
            send_fin(
                &transport,
                &control_channel,
                &shared_config.node_id,
                sid,
                &shared_config.psk,
            )
            .await;
        }

        // Remove all sessions.
        for sid in &session_ids {
            mgr.remove_session(sid);
        }
        info!("all sessions cleaned up");
    }

    // Signal embedded broker tasks to shut down (if in embedded mode).
    if let Some(tx) = broker_shutdown_tx.take() {
        info!("signaling embedded broker tasks to shut down");
        let _ = tx.send(true);
    }

    // Wait briefly for any in-flight work to settle, but respect the 10-second deadline.
    let remaining = shutdown_deadline.saturating_duration_since(tokio::time::Instant::now());
    if !remaining.is_zero() {
        tokio::time::sleep(std::cmp::min(remaining, Duration::from_millis(500))).await;
    }

    info!("exit-node shut down gracefully");
    Ok(())
}

/// Handle an incoming SYN frame: decode target, perform key exchange, connect to target,
/// and spawn session tasks.
async fn handle_syn(
    syn_frame: Frame,
    transport: Arc<dyn TransportBackend>,
    session_manager: Arc<Mutex<SessionManager>>,
    config: Arc<ExitNodeConfig>,
    control_channel: String,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let session_id = syn_frame.session_id.clone();
    info!(session_id = %session_id, "received SYN");

    // 1. Decode SYN payload: target address, port, client X25519 pubkey, client_id.
    let (target_addr, target_port, client_pubkey_bytes, client_id) =
        decode_syn_payload(&syn_frame.payload)?;

    // Derive the client's control channel for sending responses.
    let client_control_channel = if client_id.is_empty() {
        // Fallback: respond on the same control channel we received from.
        warn!(session_id = %session_id, "SYN has no client_id, falling back to control_channel");
        control_channel.clone()
    } else {
        info!(session_id = %session_id, client_id = %client_id, "extracted client_id from SYN");
        format!("ctl-{}", client_id)
    };

    let target_str = match &target_addr {
        TargetAddr::Ipv4(ip) => format!(
            "{}.{}.{}.{}:{}",
            ip[0], ip[1], ip[2], ip[3], target_port
        ),
        TargetAddr::Ipv6(ip) => {
            let addr = std::net::Ipv6Addr::from(*ip);
            format!("[{}]:{}", addr, target_port)
        }
        TargetAddr::Domain(d) => format!("{}:{}", d, target_port),
    };
    info!(session_id = %session_id, target = %target_str, "SYN target");

    // 2. Generate exit node X25519 keypair and compute shared secret.
    let (exit_secret, exit_pubkey) = generate_keypair();
    let client_public = x25519_dalek::PublicKey::from(client_pubkey_bytes);
    let shared_secret = exit_secret.diffie_hellman(&client_public);

    // 3. Derive session key.
    let session_key = derive_session_key(shared_secret.as_bytes(), &config.psk)?;

    // 4. Attempt TCP connection to target within connect_timeout.
    let target_socket_addr = resolve_target(&target_addr, target_port).await?;

    // --- Private network guard ---
    if is_blocked(target_socket_addr.ip(), &config.blocked_networks) {
        warn!(session_id = %session_id, addr = %target_socket_addr, "blocked by private network guard");
        send_rst(
            &transport,
            &client_control_channel,
            &config.node_id,
            &session_id,
            &config.psk,
        )
        .await;
        return Ok(());
    }

    let tcp_stream = match tokio::time::timeout(
        config.connect_timeout,
        TcpStream::connect(target_socket_addr),
    )
    .await
    {
        Ok(Ok(stream)) => {
            info!(session_id = %session_id, target = %target_str, "TCP connected to target");
            stream
        }
        Ok(Err(e)) => {
            warn!(session_id = %session_id, target = %target_str, error = %e, "TCP connect failed");
            send_rst(
                &transport,
                &client_control_channel,
                &config.node_id,
                &session_id,
                &config.psk,
            )
            .await;
            return Ok(());
        }
        Err(_) => {
            warn!(session_id = %session_id, target = %target_str, "TCP connect timed out");
            send_rst(
                &transport,
                &client_control_channel,
                &config.node_id,
                &session_id,
                &config.psk,
            )
            .await;
            return Ok(());
        }
    };

    // 5. Send SYN-ACK with exit node pubkey + MAC.
    let syn_ack_frame = Frame {
        session_id: session_id.clone(),
        seq: 0,
        frame_type: FrameType::SynAck,
        flags: FrameFlags::empty(),
        payload: exit_pubkey.as_bytes().to_vec(),
    };
    let mut syn_ack_bytes = encode_frame(&syn_ack_frame);
    let mac = compute_control_mac(&config.psk, &syn_ack_bytes);
    syn_ack_bytes.extend_from_slice(&mac);

    transport
        .send_frame(&client_control_channel, &config.node_id, &syn_ack_bytes)
        .await?;
    info!(session_id = %session_id, channel = %client_control_channel, "SYN-ACK sent");

    // 6. Create session in session manager with the client's session_id.
    let upstream_channel = format!("u-{}", session_id.as_str());
    let downstream_channel = format!("d-{}", session_id.as_str());

    {
        let mut mgr = session_manager.lock().await;
        let session = Session {
            id: session_id.clone(),
            state: SessionState::Established,
            target: ConnectRequest {
                target_addr,
                target_port,
            },
            upstream_channel: upstream_channel.clone(),
            downstream_channel: downstream_channel.clone(),
            tx_seq: 0,
            rx_next: 0,
            session_key: Some(SessionKey {
                data_key: session_key.data_key,
                control_key: session_key.control_key,
            }),
            retransmit_buf: dns_socks_proxy::reliability::RetransmitBuffer::new(
                config.window_size,
                config.max_retransmits,
                config.rto,
            ),
            reassembly_buf: dns_socks_proxy::reliability::ReassemblyBuffer::new(32),
        };
        mgr.insert_session(session_id.clone(), session);
    }

    // 7. Compute payload budget.
    let payload_budget = compute_payload_budget(
        config.controlled_domain.len(),
        config.node_id.len(),
        downstream_channel.len(),
        NONCE_LEN,
    );
    if payload_budget == 0 {
        error!("payload budget is zero — domain/channel names too long");
        send_rst(
            &transport,
            &client_control_channel,
            &config.node_id,
            &session_id,
            &config.psk,
        )
        .await;
        cleanup_session(&session_manager, &session_id).await;
        return Ok(());
    }
    debug!(payload_budget, "computed payload budget");

    // 8. Split TCP stream and run bidirectional data flow.
    let (tcp_read, tcp_write) = tcp_stream.into_split();

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
    let downstream_ch = downstream_channel.clone();
    let control_ch = client_control_channel.clone();
    let control_ch_retx = client_control_channel.clone();

    // Upstream task (exit node perspective): poll upstream channel → decrypt → write to target TCP.
    let upstream_handle = tokio::spawn(upstream_task(
        tcp_write,
        transport_up,
        mgr_up,
        config_up,
        session_id_up,
        upstream_ch,
        downstream_ch.clone(),
        session_key.data_key,
    ));

    // Downstream task (exit node perspective): read target TCP → encrypt → send DATA on downstream channel.
    let downstream_handle = tokio::spawn(downstream_task(
        tcp_read,
        transport_down,
        mgr_down,
        config_down,
        session_id_down,
        downstream_ch,
        control_ch,
        payload_budget,
        session_key.data_key,
    ));

    // Retransmit timer task.
    let retransmit_handle = tokio::spawn(retransmit_task(
        transport_retx,
        mgr_retx,
        config_retx,
        session_id_retx,
        downstream_channel.clone(),
        control_ch_retx,
    ));

    // Wait for any task to finish.
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

    info!(session_id = %session_id, "session ending, cleaning up");
    cleanup_session(&session_manager, &session_id).await;
    Ok(())
}

/// Upstream task (exit node): polls upstream channel for DATA frames from the client,
/// decrypts them, reassembles, and writes to the target TCP socket.
///
/// Uses adaptive backoff + status query + parallel fetch (same pattern as
/// socks-client's downstream_task).
async fn upstream_task(
    mut tcp_write: tokio::net::tcp::OwnedWriteHalf,
    transport: Arc<dyn TransportBackend>,
    session_manager: Arc<Mutex<SessionManager>>,
    config: Arc<ExitNodeConfig>,
    session_id: SessionId,
    upstream_channel: String,
    downstream_channel: String,
    data_key: [u8; 32],
) {
    let session_key = SessionKey {
        data_key,
        control_key: [0u8; 32],
    };
    let mut backoff = AdaptiveBackoff::new(config.poll_active, config.backoff_max);
    let query_timeout = Duration::from_secs(2);
    // Track the highest store sequence seen from broker responses.
    let mut max_store_seq: Option<u64> = None;

    loop {
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

        // Use the highest store sequence we've seen + 1 as the cursor.
        let cursor = max_store_seq.map(|s| s + 1);

        // Phase 1: Query status to determine queue depth.
        let frames_result = match transport.query_status(&upstream_channel).await {
            Ok(0) => {
                // No data available — increase backoff and sleep.
                backoff.increase();
                tokio::time::sleep(backoff.current()).await;
                continue;
            }
            Ok(depth) => {
                // Data available — reset backoff and fire parallel queries.
                backoff.reset();
                let count = depth.min(config.max_parallel_queries);
                match config.resolver_addr {
                    Some(resolver_addr) => {
                        let (parallel_frames, seq) = recv_frames_parallel(
                            resolver_addr,
                            &config.controlled_domain,
                            &upstream_channel,
                            count,
                            query_timeout,
                            !config.no_edns,
                            cursor,
                        )
                        .await;
                        if let Some(s) = seq {
                            max_store_seq = Some(max_store_seq.map_or(s, |m| m.max(s)));
                        }
                        Ok(parallel_frames)
                    }
                    None => {
                        match transport.recv_frames(&upstream_channel, cursor).await {
                            Ok((frames, seq)) => {
                                if let Some(s) = seq {
                                    max_store_seq = Some(max_store_seq.map_or(s, |m| m.max(s)));
                                }
                                Ok(frames)
                            }
                            Err(e) => Err(e),
                        }
                    }
                }
            }
            Err(e) => {
                debug!(error = %e, "status query failed, falling back to single recv_frames");
                match transport.recv_frames(&upstream_channel, cursor).await {
                    Ok((frames, seq)) => {
                        if let Some(s) = seq {
                            max_store_seq = Some(max_store_seq.map_or(s, |m| m.max(s)));
                        }
                        Ok(frames)
                    }
                    Err(e2) => Err(e2),
                }
            }
        };

        // Phase 2: Process received frames through the decryption/reassembly/ACK pipeline.
        match frames_result {
            Ok(frames) if frames.is_empty() => {
                // No frames received — increase backoff and sleep.
                backoff.increase();
                tokio::time::sleep(backoff.current()).await;
            }
            Ok(frames) => {
                // Data received — reset backoff; will immediately re-poll (no sleep).
                backoff.reset();
                debug!(session_id = %session_id, count = frames.len(), "upstream poll: got frames");
                for data in frames {

                let frame = match decode_frame(&data) {
                    Ok(f) => f,
                    Err(e) => {
                        debug!(error = %e, "failed to decode upstream frame");
                        continue;
                    }
                };

                if frame.session_id != session_id {
                    debug!("upstream frame for different session, ignoring");
                    continue;
                }

                match frame.frame_type {
                    FrameType::Data => {
                        // Decrypt payload. Client sends with Direction::Upstream,
                        // so we decrypt with Direction::Upstream.
                        let plaintext = match decrypt_data(
                            &session_key,
                            frame.seq,
                            Direction::Upstream,
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

                            if session.reassembly_buf.is_overflowed() {
                                warn!(session_id = %session_id, "reassembly buffer overflow");
                                drop(mgr);
                                send_rst(
                                    &transport,
                                    &format!("ctl-{}", config.node_id),
                                    &config.node_id,
                                    &session_id,
                                    &config.psk,
                                )
                                .await;
                                return;
                            }

                            let contiguous = session.reassembly_buf.drain_contiguous();
                            let ack_seq = session.reassembly_buf.ack_seq();
                            drop(mgr);

                            if !contiguous.is_empty() {
                                if let Err(e) = tcp_write.write_all(&contiguous).await {
                                    warn!(session_id = %session_id, error = %e, "TCP write to target error");
                                    return;
                                }

                                // Send ACK back on the downstream channel (to client).
                                send_ack(
                                    &transport,
                                    &downstream_channel,
                                    &config.node_id,
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
                        // Process ACK for downstream retransmit buffer.
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
                        info!(session_id = %session_id, "received FIN on upstream");
                        let mut mgr = session_manager.lock().await;
                        if let Some(session) = mgr.get_session(&session_id) {
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
                        warn!(session_id = %session_id, "received RST on upstream");
                        let mut mgr = session_manager.lock().await;
                        if let Some(session) = mgr.get_session(&session_id) {
                            session.state = SessionState::Closed;
                        }
                        return;
                    }
                    _ => {
                        debug!(frame_type = ?frame.frame_type, "unexpected frame type on upstream");
                    }
                }
              } // end for data in frames
            }
            Err(e) => {
                debug!(error = %e, "transport error polling upstream");
                backoff.increase();
                tokio::time::sleep(backoff.current()).await;
            }
        }
    }
}

/// Downstream task (exit node): reads from target TCP, fragments, encrypts,
/// and sends DATA frames on the downstream channel.
async fn downstream_task(
    mut tcp_read: tokio::net::tcp::OwnedReadHalf,
    transport: Arc<dyn TransportBackend>,
    session_manager: Arc<Mutex<SessionManager>>,
    config: Arc<ExitNodeConfig>,
    session_id: SessionId,
    downstream_channel: String,
    control_channel: String,
    payload_budget: usize,
    data_key: [u8; 32],
) {
    let session_key = SessionKey {
        data_key,
        control_key: [0u8; 32],
    };
    let mut buf = vec![0u8; payload_budget];

    loop {
        // Check window before reading.
        {
            let mgr = session_manager.lock().await;
            if let Some(session) = mgr.sessions_ref().get(&session_id) {
                if session.state == SessionState::Closed {
                    return;
                }
                if session.retransmit_buf.is_window_full() {
                    drop(mgr);
                    tokio::time::sleep(config.poll_active).await;
                    continue;
                }
            } else {
                return;
            }
        }

        match tcp_read.read(&mut buf).await {
            Ok(0) => {
                // Target TCP closed — send FIN.
                info!(session_id = %session_id, "target TCP closed, sending FIN");
                send_fin(
                    &transport,
                    &control_channel,
                    &config.node_id,
                    &session_id,
                    &config.psk,
                )
                .await;
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

                    // Exit node sends downstream → encrypt with Direction::Downstream.
                    let ciphertext =
                        encrypt_data(&session_key, seq, Direction::Downstream, plaintext);

                    let frame = Frame {
                        session_id: session_id.clone(),
                        seq,
                        frame_type: FrameType::Data,
                        flags: FrameFlags::empty(),
                        payload: ciphertext,
                    };

                    let frame_bytes = encode_frame(&frame);

                    session.retransmit_buf.insert(seq, frame.clone());

                    drop(mgr);

                    if let Err(e) = transport
                        .send_frame(&downstream_channel, &config.node_id, &frame_bytes)
                        .await
                    {
                        warn!(session_id = %session_id, seq, error = %e, "failed to send DATA frame");
                    } else {
                        debug!(session_id = %session_id, seq, bytes = n, "sent DATA frame downstream");
                    }
                } else {
                    return;
                }
            }
            Err(e) => {
                warn!(session_id = %session_id, error = %e, "target TCP read error");
                send_rst(
                    &transport,
                    &control_channel,
                    &config.node_id,
                    &session_id,
                    &config.psk,
                )
                .await;
                return;
            }
        }
    }
}

/// Retransmit timer task: checks RetransmitBuffer and retransmits past-RTO frames.
async fn retransmit_task(
    transport: Arc<dyn TransportBackend>,
    session_manager: Arc<Mutex<SessionManager>>,
    config: Arc<ExitNodeConfig>,
    session_id: SessionId,
    downstream_channel: String,
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

        if let Some(seq) = session.retransmit_buf.has_exceeded_max_retransmits() {
            warn!(session_id = %session_id, seq, "max retransmissions exceeded");
            session.state = SessionState::Closed;
            drop(mgr);
            send_rst(
                &transport,
                &control_channel,
                &config.node_id,
                &session_id,
                &config.psk,
            )
            .await;
            return;
        }

        let now = Instant::now();
        let retransmittable: Vec<Frame> = session
            .retransmit_buf
            .get_retransmittable(now)
            .into_iter()
            .cloned()
            .collect();

        for frame in &retransmittable {
            session.retransmit_buf.mark_retransmitted(frame.seq, now);
        }

        drop(mgr);

        for frame in retransmittable {
            let frame_bytes = encode_frame(&frame);
            debug!(session_id = %session_id, seq = frame.seq, "retransmitting DATA frame");
            if let Err(e) = transport
                .send_frame(&downstream_channel, &config.node_id, &frame_bytes)
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

/// Resolve a TargetAddr to a SocketAddr for TCP connection.
async fn resolve_target(
    addr: &TargetAddr,
    port: u16,
) -> Result<SocketAddr, Box<dyn std::error::Error + Send + Sync>> {
    match addr {
        TargetAddr::Ipv4(ip) => {
            let addr = std::net::Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]);
            Ok(SocketAddr::new(std::net::IpAddr::V4(addr), port))
        }
        TargetAddr::Ipv6(ip) => {
            let addr = std::net::Ipv6Addr::from(*ip);
            Ok(SocketAddr::new(std::net::IpAddr::V6(addr), port))
        }
        TargetAddr::Domain(domain) => {
            // Use tokio's DNS resolution.
            let addr_str = format!("{}:{}", domain, port);
            let addrs: Vec<SocketAddr> = tokio::net::lookup_host(&addr_str).await?.collect();
            addrs
                .into_iter()
                .next()
                .ok_or_else(|| format!("DNS resolution failed for {}", domain).into())
        }
    }
}

/// Send a FIN frame on the control channel.
async fn send_fin(
    transport: &Arc<dyn TransportBackend>,
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
    transport: &Arc<dyn TransportBackend>,
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
    transport: &Arc<dyn TransportBackend>,
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
