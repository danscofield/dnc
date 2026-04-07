use std::sync::Arc;
use std::time::{Duration, Instant};

use clap::Parser;
use smoltcp::iface::SocketSet;
use smoltcp::wire::Ipv4Address;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tracing::{debug, error, info, warn};

use dns_socks_proxy::config::{RelaySocksCliArgs, RelaySocksConfig};
use dns_socks_proxy::crypto::{
    compute_control_mac, derive_session_key, generate_keypair, verify_control_mac, Psk,
    SessionKey,
};
use dns_socks_proxy::frame::SessionId;
use dns_socks_proxy::relay_transport::DedupRecvTransport;
use dns_socks_proxy::smol_device::{compute_mtu, VirtualDevice};
use dns_socks_proxy::smol_frame::{
    decode_init_ack_message, encode_init_message, encode_teardown_message, InitMessage,
    SMOL_MSG_INIT_ACK,
};
use dns_socks_proxy::smol_poll::{
    create_smol_interface, create_tcp_socket, run_session_poll_loop, PollDirection, SmolPollConfig,
};
use dns_socks_proxy::socks::{socks5_handshake, socks5_reply};
use dns_socks_proxy::transport::{
    compute_payload_budget, AdaptiveBackoff, DnsTransport, TransportBackend,
};

/// Nonce length used in DNS queries.
const NONCE_LEN: usize = 4;

// ---------------------------------------------------------------------------
// acquire_permit — concurrency limiter gate
// ---------------------------------------------------------------------------

async fn acquire_permit(
    semaphore: &Arc<Semaphore>,
    queue_timeout: Duration,
    peer_addr: std::net::SocketAddr,
) -> Option<OwnedSemaphorePermit> {
    match semaphore.clone().try_acquire_owned() {
        Ok(permit) => return Some(permit),
        Err(_) => {}
    }

    if queue_timeout == Duration::ZERO {
        warn!(%peer_addr, timeout_ms = 0u64, "connection dropped, queue timeout exceeded");
        return None;
    }

    info!(%peer_addr, "connection queued, all permits in use");
    let wait_start = Instant::now();

    match tokio::time::timeout(queue_timeout, semaphore.clone().acquire_owned()).await {
        Ok(Ok(permit)) => {
            info!(%peer_addr, wait_ms = wait_start.elapsed().as_millis() as u64, "queued connection dequeued");
            Some(permit)
        }
        Ok(Err(_)) => {
            warn!(%peer_addr, "semaphore closed unexpectedly");
            None
        }
        Err(_) => {
            warn!(%peer_addr, timeout_ms = queue_timeout.as_millis() as u64, "connection dropped, queue timeout exceeded");
            None
        }
    }
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = RelaySocksCliArgs::parse();
    let config = cli.into_config()?;

    info!(
        listen = %format!("{}:{}", config.listen_addr, config.listen_port),
        domain = %config.controlled_domain,
        resolver = %config.resolver_addr,
        client_id = %config.client_id,
        "dnssocksrelay starting"
    );

    info!(
        max_concurrent_sessions = config.max_concurrent_sessions,
        queue_timeout_ms = config.queue_timeout.as_millis() as u64,
        "concurrency limiter configured"
    );

    let listen_addr = format!("{}:{}", config.listen_addr, config.listen_port);
    let listener = TcpListener::bind(&listen_addr).await?;
    info!("listening on {}", listen_addr);

    let shared_config = Arc::new(config);
    let semaphore = Arc::new(Semaphore::new(shared_config.max_concurrent_sessions));

    // --- Set up graceful shutdown signal handling ---
    let shutdown = tokio::signal::ctrl_c();
    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            _ = &mut shutdown => {
                info!("shutdown signal received");
                break;
            }
            result = listener.accept() => {
                let (stream, peer_addr) = result?;
                info!(%peer_addr, "accepted connection");

                let permit = acquire_permit(&semaphore, shared_config.queue_timeout, peer_addr).await;
                let permit = match permit {
                    Some(p) => p,
                    None => continue,
                };

                let config = Arc::clone(&shared_config);

                tokio::spawn(async move {
                    let _permit = permit; // held until task ends
                    if let Err(e) = handle_session(stream, config).await {
                        warn!(%peer_addr, error = %e, "session failed");
                    }
                });
            }
        }
    }

    info!("dnssocksrelay shut down gracefully");
    Ok(())
}

// ---------------------------------------------------------------------------
// handle_session — per-session logic (no shared control poller needed)
// ---------------------------------------------------------------------------

async fn handle_session(
    mut stream: TcpStream,
    config: Arc<RelaySocksConfig>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
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

    // 2. Generate session ID and compute unique sender_id.
    let session_id = SessionId::generate();
    let sender_id = format!("{}-{}", config.client_id, session_id);
    let upstream_channel = format!("u-{}", session_id);
    let downstream_channel = format!("d-{}", session_id);
    let send_control_channel = format!("ctl-{}", config.exit_node_id);
    let recv_control_channel = format!("ctl-{}", session_id);

    info!(session_id = %session_id, sender_id = %sender_id, "session created");

    // 3. Create a per-session DNS transport for sending.
    let transport = Arc::new(
        DnsTransport::new(config.resolver_addr, config.controlled_domain.clone())
            .await?
            .with_query_interval(config.query_interval)
            .with_edns(!config.no_edns),
    );

    // 4. Generate X25519 keypair and send Init message.
    let (secret, pubkey) = generate_keypair();
    let init_msg = InitMessage {
        session_id: session_id.clone(),
        target_addr: connect_req.target_addr.clone(),
        target_port: connect_req.target_port,
        pubkey: *pubkey.as_bytes(),
        client_id: config.client_id.clone(),
    };
    let init_bytes = encode_init_message(&init_msg);
    let mac = compute_control_mac(&config.psk, &init_bytes);
    let mut init_with_mac = init_bytes;
    init_with_mac.extend_from_slice(&mac);

    transport
        .send_frame(&send_control_channel, &sender_id, &init_with_mac)
        .await?;
    debug!(session_id = %session_id, "Init sent to {}", send_control_channel);

    // 5. Poll ctl-<session_id> via DnsTransport for InitAck (with timeout).
    let session_key: SessionKey = match poll_for_init_ack(
        &transport,
        &recv_control_channel,
        &config.psk,
        &session_id,
        secret,
        config.connect_timeout,
        config.poll_active,
        config.backoff_max,
    )
    .await
    {
        Ok(key) => key,
        Err(e) => {
            warn!(session_id = %session_id, error = %e, "InitAck failed");
            // Send SOCKS5 error reply: 0x04 = host unreachable.
            socks5_reply(&mut stream, 0x04).await.ok();
            return Ok(());
        }
    };

    info!(session_id = %session_id, "session established");

    // 6. Send SOCKS5 success reply.
    socks5_reply(&mut stream, 0x00).await?;

    // 7. Compute payload budget and MTU.
    let payload_budget = compute_payload_budget(
        config.controlled_domain.len(),
        sender_id.len(),
        upstream_channel.len(),
        NONCE_LEN,
    );
    if payload_budget == 0 {
        error!("payload budget is zero — domain/channel names too long");
        send_teardown(&transport, &send_control_channel, &sender_id, &session_id, &config.psk).await;
        return Ok(());
    }

    let mtu = compute_mtu(payload_budget);
    if mtu == 0 {
        error!("MTU is zero — payload budget too small");
        send_teardown(&transport, &send_control_channel, &sender_id, &session_id, &config.psk).await;
        return Ok(());
    }

    let mss = config.smol_tuning.mss.unwrap_or_else(|| mtu.saturating_sub(40));
    if mss == 0 {
        error!("MSS is zero — MTU too small for TCP");
        send_teardown(&transport, &send_control_channel, &sender_id, &session_id, &config.psk).await;
        return Ok(());
    }

    debug!(payload_budget, mtu, mss, "computed tunnel parameters");

    // 8. Create VirtualDevice + smoltcp Interface + TCP socket.
    let mut device = VirtualDevice::new(mtu);
    let mut iface = create_smol_interface(
        &mut device,
        std::net::Ipv4Addr::new(192, 168, 69, 1),
        std::net::Ipv4Addr::new(192, 168, 69, 2),
    );

    let tcp_socket = create_tcp_socket(&config.smol_tuning, mss);
    let mut socket_set = SocketSet::new(vec![]);
    let socket_handle = socket_set.add(tcp_socket);

    // Connect the smoltcp TCP socket to the exit node's virtual IP.
    {
        let socket = socket_set.get_mut::<smoltcp::socket::tcp::Socket>(socket_handle);
        let cx = iface.context();
        socket
            .connect(
                cx,
                (Ipv4Address::new(192, 168, 69, 2), 4321),
                49152, // ephemeral local port
            )
            .map_err(|e| format!("smoltcp connect failed: {e}"))?;
    }

    debug!(session_id = %session_id, "smoltcp TCP connect initiated");

    // 9. Create a separate recv transport (own UDP socket) with dedup wrapper.
    let raw_recv_transport = Arc::new(
        DnsTransport::new(config.resolver_addr, config.controlled_domain.clone())
            .await?
            .with_query_interval(config.query_interval)
            .with_edns(!config.no_edns),
    );
    let recv_transport: Arc<dyn TransportBackend> =
        Arc::new(DedupRecvTransport::new(raw_recv_transport));

    let (mut tcp_read, mut tcp_write) = stream.into_split();

    let poll_config = SmolPollConfig {
        poll_active: config.poll_active,
        poll_idle: config.poll_idle,
        backoff_max: config.backoff_max,
        query_interval: config.query_interval,
        no_edns: config.no_edns,
    };

    let mut tx_seq: u32 = 0;

    let result = run_session_poll_loop(
        &mut iface,
        &mut device,
        &mut socket_set,
        socket_handle,
        transport.clone() as Arc<dyn TransportBackend>,
        recv_transport,
        &session_id,
        &session_key,
        &upstream_channel,
        &downstream_channel,
        PollDirection::Client,
        &mut tcp_read,
        &mut tcp_write,
        &poll_config,
        &sender_id,
        &mut tx_seq,
    )
    .await;

    if let Err(e) = &result {
        warn!(session_id = %session_id, error = %e, "poll loop error");
    }

    // 10. Cleanup: send Teardown on control channel.
    info!(session_id = %session_id, "session ending, sending teardown");
    send_teardown(&transport, &send_control_channel, &sender_id, &session_id, &config.psk).await;

    Ok(())
}

// ---------------------------------------------------------------------------
// poll_for_init_ack — poll ctl-<session_id> for InitAck via DnsTransport
// ---------------------------------------------------------------------------

async fn poll_for_init_ack(
    transport: &Arc<DnsTransport>,
    recv_control_channel: &str,
    psk: &Psk,
    session_id: &SessionId,
    secret: x25519_dalek::EphemeralSecret,
    connect_timeout: Duration,
    poll_active: Duration,
    backoff_max: Duration,
) -> Result<SessionKey, Box<dyn std::error::Error + Send + Sync>> {
    let deadline = tokio::time::Instant::now() + connect_timeout;
    let mut backoff = AdaptiveBackoff::new(poll_active, backoff_max);

    loop {
        if tokio::time::Instant::now() >= deadline {
            return Err("InitAck timeout".into());
        }

        let remaining = deadline - tokio::time::Instant::now();
        let sleep_dur = backoff.current().min(remaining);

        match transport.recv_frame(recv_control_channel, None).await {
            Ok(Some(data)) => {
                // Need at least 16 bytes for MAC at the end.
                if data.len() < 16 {
                    debug!(len = data.len(), "control frame too short, continuing poll");
                    backoff.increase();
                    tokio::time::sleep(sleep_dur).await;
                    continue;
                }

                let (frame_bytes, received_mac) = data.split_at(data.len() - 16);
                let mut mac_arr = [0u8; 16];
                mac_arr.copy_from_slice(received_mac);

                if !verify_control_mac(psk, frame_bytes, &mac_arr) {
                    debug!("InitAck MAC verification failed, continuing poll");
                    backoff.increase();
                    tokio::time::sleep(sleep_dur).await;
                    continue;
                }

                // Check message type — only accept SMOL_MSG_INIT_ACK.
                if frame_bytes.is_empty() || frame_bytes[0] != SMOL_MSG_INIT_ACK {
                    debug!(
                        msg_type = frame_bytes.first().copied().unwrap_or(0),
                        "non-InitAck message on control channel, continuing poll"
                    );
                    backoff.increase();
                    tokio::time::sleep(sleep_dur).await;
                    continue;
                }

                let init_ack = decode_init_ack_message(frame_bytes)?;

                if init_ack.session_id != *session_id {
                    debug!(
                        session_id = %session_id,
                        "InitAck for different session, continuing poll"
                    );
                    backoff.increase();
                    tokio::time::sleep(sleep_dur).await;
                    continue;
                }

                // Derive session key from DH shared secret + PSK.
                let exit_public = x25519_dalek::PublicKey::from(init_ack.pubkey);
                let shared_secret = secret.diffie_hellman(&exit_public);
                let session_key = derive_session_key(shared_secret.as_bytes(), psk)?;

                return Ok(session_key);
            }
            Ok(None) => {
                backoff.increase();
            }
            Err(e) => {
                debug!(error = %e, "control poll transport error");
                backoff.increase();
            }
        }

        tokio::time::sleep(sleep_dur).await;
    }
}

// ---------------------------------------------------------------------------
// Helper: send Teardown message
// ---------------------------------------------------------------------------

async fn send_teardown(
    transport: &Arc<DnsTransport>,
    control_channel: &str,
    sender_id: &str,
    session_id: &SessionId,
    psk: &Psk,
) {
    let teardown_bytes = encode_teardown_message(session_id);
    let mac = compute_control_mac(psk, &teardown_bytes);
    let mut msg = teardown_bytes;
    msg.extend_from_slice(&mac);

    if let Err(e) = transport
        .send_frame(control_channel, sender_id, &msg)
        .await
    {
        warn!(session_id = %session_id, error = %e, "failed to send Teardown");
    }
}
