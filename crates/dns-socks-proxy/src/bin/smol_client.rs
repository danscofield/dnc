use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use clap::Parser;
use smoltcp::iface::SocketSet;
use smoltcp::wire::Ipv4Address;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tracing::{debug, error, info, warn};

use dns_socks_proxy::config::{SmolClientCli, SmolClientConfig};
use dns_socks_proxy::crypto::{
    compute_control_mac, derive_session_key, generate_keypair, Psk, SessionKey,
};
use dns_socks_proxy::frame::SessionId;
use dns_socks_proxy::smol_device::{compute_mtu, VirtualDevice};
use dns_socks_proxy::smol_frame::{
    decode_init_ack_message, encode_init_message, encode_teardown_message, InitMessage,
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
// ControlDispatcher — demultiplexes control channel frames by session_id
// ---------------------------------------------------------------------------

/// Routes incoming control-channel frames to the correct session by `SessionId`.
///
/// For smol frames, the session_id is extracted from bytes 1..9 of the raw
/// frame (byte 0 is msg_type).
pub struct ControlDispatcher {
    senders: std::sync::Mutex<HashMap<SessionId, tokio::sync::mpsc::Sender<Vec<u8>>>>,
}

impl ControlDispatcher {
    pub fn new() -> Self {
        Self {
            senders: std::sync::Mutex::new(HashMap::new()),
        }
    }

    pub fn register(&self, session_id: SessionId) -> tokio::sync::mpsc::Receiver<Vec<u8>> {
        let (tx, rx) = tokio::sync::mpsc::channel(32);
        self.senders.lock().unwrap().insert(session_id, tx);
        rx
    }

    pub fn deregister(&self, session_id: &SessionId) {
        self.senders.lock().unwrap().remove(session_id);
    }

    /// Dispatch raw frame bytes to the matching session.
    ///
    /// For smol frames, extracts session_id from bytes 1..9 (byte 0 is msg_type).
    pub fn dispatch(&self, frame_bytes: &[u8]) {
        if frame_bytes.len() < 9 {
            warn!(
                len = frame_bytes.len(),
                "control frame too short to extract session_id, discarding"
            );
            return;
        }

        let mut sid_bytes = [0u8; 8];
        sid_bytes.copy_from_slice(&frame_bytes[1..9]);
        let session_id = SessionId(sid_bytes);

        let senders = self.senders.lock().unwrap();
        if let Some(tx) = senders.get(&session_id) {
            match tx.try_send(frame_bytes.to_vec()) {
                Ok(()) => {}
                Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                    warn!(session_id = %session_id, "per-session control channel full, discarding frame");
                }
                Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                    warn!(session_id = %session_id, "per-session control channel closed, discarding frame");
                }
            }
        } else {
            warn!(
                session_id = %session_id,
                "no registered session for control frame, discarding"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// DispatcherGuard — RAII guard that deregisters on drop
// ---------------------------------------------------------------------------

struct DispatcherGuard {
    dispatcher: Arc<ControlDispatcher>,
    session_id: SessionId,
}

impl Drop for DispatcherGuard {
    fn drop(&mut self) {
        self.dispatcher.deregister(&self.session_id);
    }
}

// ---------------------------------------------------------------------------
// Control channel poller
// ---------------------------------------------------------------------------

fn spawn_control_poller(
    transport: Arc<DnsTransport>,
    dispatcher: Arc<ControlDispatcher>,
    recv_control_channel: String,
    psk: Psk,
    poll_active: Duration,
    backoff_max: Duration,
) {
    tokio::spawn(async move {
        let mut backoff = AdaptiveBackoff::new(poll_active, backoff_max);
        let mut cursor: Option<u64> = None;

        loop {
            match transport.recv_frames(&recv_control_channel, cursor).await {
                Ok((frames, new_cursor)) if !frames.is_empty() => {
                    if let Some(c) = new_cursor {
                        cursor = Some(c + 1);
                    }
                    for data in frames {
                        if data.len() < 16 {
                            debug!(len = data.len(), "control poller: frame too short, discarding");
                            continue;
                        }

                        let (frame_bytes, received_mac) = data.split_at(data.len() - 16);
                        let mut mac_arr = [0u8; 16];
                        mac_arr.copy_from_slice(received_mac);

                        if !dns_socks_proxy::crypto::verify_control_mac(
                            &psk,
                            frame_bytes,
                            &mac_arr,
                        ) {
                            debug!("control poller: MAC verification failed, discarding");
                            continue;
                        }

                        // Dispatch the full raw bytes (including MAC).
                        dispatcher.dispatch(&data);
                    }
                    backoff.reset();
                }
                Ok(_) => {
                    backoff.increase();
                }
                Err(e) => {
                    debug!(error = %e, "control poller: transport error");
                    backoff.increase();
                }
            }

            tokio::time::sleep(backoff.current()).await;
        }
    });
}

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

    let cli = SmolClientCli::parse();
    let config = cli.into_config()?;

    info!(
        listen = %format!("{}:{}", config.listen_addr, config.listen_port),
        domain = %config.controlled_domain,
        resolver = %config.resolver_addr,
        client_id = %config.client_id,
        "smol-client starting"
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

    let dispatcher = Arc::new(ControlDispatcher::new());

    let poller_transport = Arc::new(
        DnsTransport::new(
            shared_config.resolver_addr,
            shared_config.controlled_domain.clone(),
        )
        .await?
        .with_query_interval(shared_config.query_interval)
        .with_edns(!shared_config.no_edns),
    );

    let recv_control_channel = format!("ctl-{}", shared_config.client_id);

    spawn_control_poller(
        poller_transport,
        Arc::clone(&dispatcher),
        recv_control_channel,
        shared_config.psk.clone(),
        shared_config.poll_active,
        shared_config.backoff_max,
    );

    loop {
        let (stream, peer_addr) = listener.accept().await?;
        info!(%peer_addr, "accepted connection");

        let permit = acquire_permit(&semaphore, shared_config.queue_timeout, peer_addr).await;
        let permit = match permit {
            Some(p) => p,
            None => continue,
        };

        let config = Arc::clone(&shared_config);
        let dispatcher = Arc::clone(&dispatcher);

        tokio::spawn(async move {
            let _permit = permit; // held until task ends
            if let Err(e) = handle_smol_connection(stream, config, dispatcher).await {
                warn!(%peer_addr, error = %e, "session failed");
            }
        });
    }
}

// ---------------------------------------------------------------------------
// handle_smol_connection — per-session logic
// ---------------------------------------------------------------------------

async fn handle_smol_connection(
    mut stream: TcpStream,
    config: Arc<SmolClientConfig>,
    dispatcher: Arc<ControlDispatcher>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Create a per-session DNS transport.
    let transport = Arc::new(
        DnsTransport::new(config.resolver_addr, config.controlled_domain.clone())
            .await?
            .with_query_interval(config.query_interval)
            .with_edns(!config.no_edns),
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

    // 2. Generate session ID and channel names.
    let session_id = SessionId::generate();
    let upstream_channel = format!("u-{}", session_id);
    let downstream_channel = format!("d-{}", session_id);
    let send_control_channel = format!("ctl-{}", config.exit_node_id);

    info!(session_id = %session_id, "session created");

    // Register with the control dispatcher.
    let mut control_rx = dispatcher.register(session_id.clone());
    let _dispatcher_guard = DispatcherGuard {
        dispatcher: Arc::clone(&dispatcher),
        session_id: session_id.clone(),
    };

    // 3. Generate X25519 keypair and send Init message.
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
        .send_frame(&send_control_channel, &config.client_id, &init_with_mac)
        .await?;
    debug!(session_id = %session_id, "Init sent");

    // 4. Wait for InitAck via the per-session dispatcher channel.
    let connect_timeout = config.connect_timeout;
    let session_key: SessionKey;

    match tokio::time::timeout(connect_timeout, control_rx.recv()).await {
        Ok(Some(data)) => {
            if data.len() < 16 {
                warn!(session_id = %session_id, "control frame too short");
                return Ok(());
            }
            let (frame_bytes, received_mac) = data.split_at(data.len() - 16);
            let mut mac_arr = [0u8; 16];
            mac_arr.copy_from_slice(received_mac);

            // Defense-in-depth MAC verification.
            if !dns_socks_proxy::crypto::verify_control_mac(&config.psk, frame_bytes, &mac_arr) {
                debug!(session_id = %session_id, "InitAck MAC verification failed");
                return Ok(());
            }

            let init_ack = match decode_init_ack_message(frame_bytes) {
                Ok(ack) => ack,
                Err(e) => {
                    debug!(session_id = %session_id, error = %e, "failed to decode InitAck");
                    return Ok(());
                }
            };

            if init_ack.session_id != session_id {
                debug!(session_id = %session_id, "InitAck for different session");
                return Ok(());
            }

            // Derive session key from DH shared secret + PSK.
            let exit_public = x25519_dalek::PublicKey::from(init_ack.pubkey);
            let shared_secret = secret.diffie_hellman(&exit_public);
            session_key = derive_session_key(shared_secret.as_bytes(), &config.psk)?;

            info!(session_id = %session_id, "session established");
        }
        Ok(None) => {
            warn!(session_id = %session_id, "control channel closed during setup");
            return Ok(());
        }
        Err(_) => {
            warn!(session_id = %session_id, "InitAck timeout");
            socks5_reply(&mut stream, 0x04).await.ok();
            return Ok(());
        }
    }

    // 5. Send SOCKS5 success reply.
    socks5_reply(&mut stream, 0x00).await?;

    // 6. Compute payload budget and MTU.
    let payload_budget = compute_payload_budget(
        config.controlled_domain.len(),
        config.client_id.len(),
        upstream_channel.len(),
        NONCE_LEN,
    );
    if payload_budget == 0 {
        error!("payload budget is zero — domain/channel names too long");
        send_teardown(&transport, &send_control_channel, &config.client_id, &session_id, &config.psk).await;
        return Ok(());
    }

    let mtu = compute_mtu(payload_budget);
    if mtu == 0 {
        error!("MTU is zero — payload budget too small");
        send_teardown(&transport, &send_control_channel, &config.client_id, &session_id, &config.psk).await;
        return Ok(());
    }

    // Compute MSS: MTU - 40 (20 IPv4 + 20 TCP headers), or use override.
    let mss = config.smol_tuning.mss.unwrap_or_else(|| mtu.saturating_sub(40));
    if mss == 0 {
        error!("MSS is zero — MTU too small for TCP");
        send_teardown(&transport, &send_control_channel, &config.client_id, &session_id, &config.psk).await;
        return Ok(());
    }

    debug!(payload_budget, mtu, mss, "computed tunnel parameters");

    // 7. Create VirtualDevice + smoltcp Interface + TCP socket.
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

    // 8. Split SOCKS5 TCP stream and run the poll loop.
    // Create a separate transport for the recv task (own UDP socket to avoid
    // response cross-contamination between A queries and TXT queries).
    let recv_transport: std::sync::Arc<dyn dns_socks_proxy::transport::TransportBackend> = std::sync::Arc::new(
        DnsTransport::new(config.resolver_addr, config.controlled_domain.clone())
            .await?
            .with_query_interval(config.query_interval)
            .with_edns(!config.no_edns),
    );

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
        transport.clone() as std::sync::Arc<dyn dns_socks_proxy::transport::TransportBackend>,
        recv_transport,
        &session_id,
        &session_key,
        &upstream_channel,
        &downstream_channel,
        PollDirection::Client,
        &mut tcp_read,
        &mut tcp_write,
        &poll_config,
        &config.client_id,
        &mut tx_seq,
    )
    .await;

    if let Err(e) = &result {
        warn!(session_id = %session_id, error = %e, "poll loop error");
    }

    // 9. Cleanup: send Teardown on control channel.
    info!(session_id = %session_id, "session ending, sending teardown");
    send_teardown(&transport, &send_control_channel, &config.client_id, &session_id, &config.psk).await;

    // Dispatcher deregistration handled by _dispatcher_guard Drop.
    // Semaphore permit released when _permit is dropped by the caller.

    Ok(())
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
