use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use clap::Parser;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore};
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
use dns_socks_proxy::transport::{
    compute_payload_budget, AdaptiveBackoff, DnsTransport, TransportBackend,
};

/// Nonce length used in DNS queries.
const NONCE_LEN: usize = 4;

// ---------------------------------------------------------------------------
// ControlDispatcher — demultiplexes control channel frames to per-session mpsc channels
// ---------------------------------------------------------------------------

/// Routes incoming control-channel frames to the correct session by `SessionId`.
///
/// Internally holds a `HashMap<SessionId, mpsc::Sender<Vec<u8>>>` behind a
/// `std::sync::Mutex` (not tokio — critical sections are just HashMap lookups).
pub struct ControlDispatcher {
    senders: std::sync::Mutex<HashMap<SessionId, tokio::sync::mpsc::Sender<Vec<u8>>>>,
}

impl ControlDispatcher {
    /// Create an empty dispatcher with no registered sessions.
    pub fn new() -> Self {
        Self {
            senders: std::sync::Mutex::new(HashMap::new()),
        }
    }

    /// Register a session and return its dedicated receiver.
    ///
    /// Creates a `tokio::sync::mpsc` channel with buffer size 4, stores the
    /// `Sender` side keyed by `session_id`, and hands back the `Receiver`.
    pub fn register(&self, session_id: SessionId) -> tokio::sync::mpsc::Receiver<Vec<u8>> {
        let (tx, rx) = tokio::sync::mpsc::channel(32);
        self.senders.lock().unwrap().insert(session_id, tx);
        rx
    }

    /// Deregister a session, dropping its sender and closing the channel.
    pub fn deregister(&self, session_id: &SessionId) {
        self.senders.lock().unwrap().remove(session_id);
    }

    /// Dispatch raw frame bytes to the matching session.
    ///
    /// Extracts the `session_id` from the first 9 bytes of `frame_bytes`
    /// (byte 0 = session_id_len, always 8; bytes 1..9 = session_id).
    /// Sends the *full* raw bytes (including any trailing MAC) through the
    /// per-session mpsc sender.
    ///
    /// If the frame is too short, the session is unknown, or the channel is
    /// full, a warning is logged and the frame is discarded.
    pub fn dispatch(&self, frame_bytes: &[u8]) {
        if frame_bytes.len() < 9 {
            warn!(len = frame_bytes.len(), "control frame too short to extract session_id, discarding");
            return;
        }

        // byte 0 is session_id_len (always 8)
        let sid_len = frame_bytes[0] as usize;
        if sid_len != 8 || frame_bytes.len() < 1 + sid_len {
            warn!(sid_len, "unexpected session_id_len in control frame, discarding");
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
            warn!(session_id = %session_id, "no registered session for control frame, discarding");
        }
    }
}

// ---------------------------------------------------------------------------
// DispatcherGuard — RAII guard that deregisters on drop
// ---------------------------------------------------------------------------

/// RAII guard that calls `dispatcher.deregister(&session_id)` when dropped.
///
/// This guarantees deregistration in ALL exit paths — including `?` propagation,
/// early returns, and panics — without requiring manual `deregister` calls at
/// every return site.
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
// Control channel poller — single background task that polls ctl-<client_id>
// ---------------------------------------------------------------------------

/// Spawn a background task that continuously polls the control channel and
/// dispatches incoming frames to the correct per-session mpsc channel via
/// the [`ControlDispatcher`].
///
/// The task runs indefinitely (until the process exits). It uses
/// [`AdaptiveBackoff`] to avoid hammering the broker when no frames are
/// available, and resets the backoff whenever a frame is received.
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

        loop {
            match transport.recv_frames(&recv_control_channel, None).await {
                Ok((frames, _seq)) if !frames.is_empty() => {
                    for data in frames {
                        // Need at least 16 bytes for the trailing MAC.
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

                        // Dispatch the full raw bytes (including MAC) so that
                        // handle_connection can re-verify for defense-in-depth.
                        dispatcher.dispatch(&data);
                    }
                    backoff.reset();
                }
                Ok(_) => {
                    // Channel empty — increase backoff.
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

/// Attempt to acquire a semaphore permit for a new connection.
///
/// Three cases:
/// 1. Permit available immediately → return it.
/// 2. All permits in use, `queue_timeout > 0` → wait up to `queue_timeout`.
/// 3. All permits in use, `queue_timeout == 0` → reject immediately.
async fn acquire_permit(
    semaphore: &Arc<Semaphore>,
    queue_timeout: Duration,
    peer_addr: std::net::SocketAddr,
) -> Option<OwnedSemaphorePermit> {
    // Fast path: try to acquire without waiting.
    match semaphore.clone().try_acquire_owned() {
        Ok(permit) => return Some(permit),
        Err(_) => {
            // All permits in use — fall through to queuing logic.
        }
    }

    // Zero timeout means immediate rejection.
    if queue_timeout == Duration::ZERO {
        warn!(%peer_addr, timeout_ms = 0u64, "connection dropped, queue timeout exceeded");
        return None;
    }

    // Non-zero timeout: queue the connection and wait.
    info!(%peer_addr, "connection queued, all permits in use");
    let wait_start = Instant::now();

    match tokio::time::timeout(queue_timeout, semaphore.clone().acquire_owned()).await {
        Ok(Ok(permit)) => {
            info!(%peer_addr, wait_ms = wait_start.elapsed().as_millis() as u64, "queued connection dequeued");
            Some(permit)
        }
        Ok(Err(_)) => {
            // Semaphore closed — should never happen.
            warn!(%peer_addr, "semaphore closed unexpectedly");
            None
        }
        Err(_) => {
            // Timeout expired.
            warn!(%peer_addr, timeout_ms = queue_timeout.as_millis() as u64, "connection dropped, queue timeout exceeded");
            None
        }
    }
}

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

    info!(
        max_concurrent_sessions = config.max_concurrent_sessions,
        queue_timeout_ms = config.queue_timeout.as_millis() as u64,
        "concurrency limiter configured"
    );

    // Bind TCP listener.
    let listen_addr = format!("{}:{}", config.listen_addr, config.listen_port);
    let listener = TcpListener::bind(&listen_addr).await?;
    info!("listening on {}", listen_addr);

    // Initialize session manager.
    let session_manager = Arc::new(Mutex::new(SessionManager::new()));

    // Shared config values wrapped in Arc for spawned tasks.
    let shared_config = Arc::new(config);

    // Create the concurrency-limiting semaphore.
    let semaphore = Arc::new(Semaphore::new(shared_config.max_concurrent_sessions));

    // Create the control channel dispatcher (demuxes control frames to per-session channels).
    let dispatcher = Arc::new(ControlDispatcher::new());

    // Create a dedicated DnsTransport for the control channel poller.
    let poller_transport = Arc::new(
        DnsTransport::new(shared_config.resolver_addr, shared_config.controlled_domain.clone())
            .await?
            .with_query_interval(shared_config.query_interval)
            .with_edns(!shared_config.no_edns),
    );

    // Compute the receive control channel name.
    let recv_control_channel = format!("ctl-{}", shared_config.client_id);

    // Spawn the single background control channel poller.
    spawn_control_poller(
        poller_transport,
        Arc::clone(&dispatcher),
        recv_control_channel,
        shared_config.psk.clone(),
        shared_config.poll_active,
        shared_config.backoff_max,
    );

    // Accept loop.
    loop {
        let (stream, peer_addr) = listener.accept().await?;
        info!(%peer_addr, "accepted connection");

        let permit = acquire_permit(&semaphore, shared_config.queue_timeout, peer_addr).await;
        let permit = match permit {
            Some(p) => p,
            None => continue, // timed out or rejected; stream dropped (closed)
        };

        let session_manager = Arc::clone(&session_manager);
        let config = Arc::clone(&shared_config);
        let dispatcher = Arc::clone(&dispatcher);

        tokio::spawn(async move {
            let _permit = permit; // held until task ends
            if let Err(e) = handle_connection(stream, session_manager, config, dispatcher).await {
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
    dispatcher: Arc<ControlDispatcher>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Create a per-session DNS transport (own UDP socket to avoid response cross-contamination).
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
    info!(session_id = %session_id, "session created");

    // Register with the control dispatcher to receive routed control frames.
    // The DispatcherGuard guarantees deregistration on all exit paths (including
    // `?` propagation and panics) via its Drop impl.
    let mut control_rx = dispatcher.register(session_id.clone());
    let _dispatcher_guard = DispatcherGuard {
        dispatcher: Arc::clone(&dispatcher),
        session_id: session_id.clone(),
    };

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

    // 4. Wait for SYN-ACK via the per-session dispatcher channel.
    let connect_timeout = config.connect_timeout;
    let session_key: SessionKey;

    match tokio::time::timeout(connect_timeout, control_rx.recv()).await {
        Ok(Some(data)) => {
            // Process the received raw bytes (MAC + frame).
            // Need at least 16 bytes for MAC.
            if data.len() < 16 {
                warn!(session_id = %session_id, "control frame too short");
                cleanup_session(&session_manager, &session_id).await;
                return Ok(());
            }
            let (frame_bytes, received_mac) = data.split_at(data.len() - 16);
            let mut mac_arr = [0u8; 16];
            mac_arr.copy_from_slice(received_mac);

            // Defense-in-depth MAC verification (poller already verified).
            if !dns_socks_proxy::crypto::verify_control_mac(&config.psk, frame_bytes, &mac_arr) {
                debug!(session_id = %session_id, "control frame MAC verification failed");
                cleanup_session(&session_manager, &session_id).await;
                return Ok(());
            }

            let frame = match decode_frame(frame_bytes) {
                Ok(f) => f,
                Err(e) => {
                    debug!(session_id = %session_id, error = %e, "failed to decode control frame");
                    cleanup_session(&session_manager, &session_id).await;
                    return Ok(());
                }
            };

            // Session ID check (defense-in-depth — dispatcher already routed correctly).
            if frame.session_id != session_id {
                debug!(session_id = %session_id, "control frame for different session after dispatch");
                cleanup_session(&session_manager, &session_id).await;
                return Ok(());
            }

            match frame.frame_type {
                FrameType::SynAck => {
                    // Extract exit node pubkey (first 32 bytes of payload).
                    if frame.payload.len() < 32 {
                        warn!(session_id = %session_id, "SYN-ACK payload too short");
                        cleanup_session(&session_manager, &session_id).await;
                        return Ok(());
                    }
                    let mut exit_pubkey = [0u8; 32];
                    exit_pubkey.copy_from_slice(&frame.payload[..32]);
                    let exit_public = x25519_dalek::PublicKey::from(exit_pubkey);
                    let shared_secret = secret.diffie_hellman(&exit_public);
                    session_key = derive_session_key(shared_secret.as_bytes(), &config.psk)?;

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
                }
                FrameType::Rst => {
                    warn!(session_id = %session_id, "received RST during setup");
                    socks5_reply(&mut stream, 0x05).await.ok();
                    cleanup_session(&session_manager, &session_id).await;
                    return Ok(());
                }
                _ => {
                    debug!(session_id = %session_id, frame_type = ?frame.frame_type, "unexpected control frame type during setup");
                    cleanup_session(&session_manager, &session_id).await;
                    return Ok(());
                }
            }
        }
        Ok(None) => {
            // Channel closed (dispatcher shutdown).
            warn!(session_id = %session_id, "control channel closed during setup");
            cleanup_session(&session_manager, &session_id).await;
            return Ok(());
        }
        Err(_) => {
            // Timeout.
            warn!(session_id = %session_id, "SYN-ACK timeout");
            socks5_reply(&mut stream, 0x04).await.ok();
            cleanup_session(&session_manager, &session_id).await;
            return Ok(());
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

    // Cleanup — dispatcher deregistration is handled by _dispatcher_guard's Drop impl.
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
    let mut backoff = AdaptiveBackoff::new(config.poll_active, config.backoff_max);
    let _query_timeout = Duration::from_secs(2);
    // Track the highest store sequence seen from broker responses.
    // Used as cursor for replay advancement: tells the broker to prune
    // replay entries with sequence <= this value.
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
        // This tells the broker to prune replay entries we've already received.
        let cursor = max_store_seq.map(|s| s + 1);

        // Poll for downstream frames using the main transport (with EDNS0).
        let frames_result = match transport.recv_frames(&downstream_channel, cursor).await {
            Ok((frames, seq)) => {
                // Update max_store_seq from the broker's response.
                if let Some(s) = seq {
                    max_store_seq = Some(max_store_seq.map_or(s, |m| m.max(s)));
                }
                Ok(frames)
            }
            Err(e) => Err(e),
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
                backoff.increase();
                tokio::time::sleep(backoff.current()).await;
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


// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// Task 1 — Bug condition exploration test.
// Originally commented out because ControlDispatcher did not exist on unfixed code.
// Now re-enabled (Task 3.6) to verify the dispatch mechanism works correctly.

#[cfg(test)]
mod tests {
    use dns_socks_proxy::frame::{encode_frame, Frame, FrameFlags, FrameType, SessionId};
    use proptest::prelude::*;
    use tokio::sync::mpsc::error::TryRecvError;
    use super::ControlDispatcher;

    /// Generate a random valid 8-byte alphanumeric SessionId.
    fn arb_session_id() -> impl Strategy<Value = SessionId> {
        proptest::collection::vec(
            proptest::sample::select(
                b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
                    .iter()
                    .copied()
                    .collect::<Vec<u8>>(),
            ),
            8,
        )
        .prop_map(|bytes| {
            let mut arr = [0u8; 8];
            arr.copy_from_slice(&bytes);
            SessionId(arr)
        })
    }

    /// Generate a set of N unique session IDs (2..=10).
    fn arb_unique_session_ids() -> impl Strategy<Value = Vec<SessionId>> {
        proptest::collection::hash_set(arb_session_id(), 2..=10)
            .prop_map(|set| set.into_iter().collect::<Vec<_>>())
    }

    // **Validates: Requirements 1.2**
    //
    // Property 1: Bug Condition — Control frame dispatch to correct session.
    //
    // For any set of N registered sessions (N >= 2) and a control frame whose
    // session_id matches session K, the ControlDispatcher SHALL deliver that
    // frame's raw bytes to session K's mpsc receiver and to no other session's
    // receiver.
    proptest! {
        #[test]
        fn control_frame_dispatched_only_to_target_session(
            session_ids in arb_unique_session_ids(),
            target_idx_seed in any::<usize>(),
            payload in proptest::collection::vec(any::<u8>(), 0..128),
        ) {
            let dispatcher = ControlDispatcher::new();

            // Register all sessions and collect their receivers.
            let mut receivers: Vec<(SessionId, tokio::sync::mpsc::Receiver<Vec<u8>>)> = Vec::new();
            for sid in &session_ids {
                let rx = dispatcher.register(sid.clone());
                receivers.push((sid.clone(), rx));
            }

            // Pick a target session.
            let target_idx = target_idx_seed % session_ids.len();
            let target_sid = session_ids[target_idx].clone();

            // Build a frame for the target session and encode it.
            let frame = Frame {
                session_id: target_sid.clone(),
                seq: 0,
                frame_type: FrameType::SynAck,
                flags: FrameFlags::empty(),
                payload: payload.clone(),
            };
            let frame_bytes = encode_frame(&frame);

            // Dispatch the frame.
            dispatcher.dispatch(&frame_bytes);

            // Assert: only the target session's receiver gets the frame.
            for (sid, rx) in &mut receivers {
                if *sid == target_sid {
                    match rx.try_recv() {
                        Ok(received) => {
                            prop_assert_eq!(&received, &frame_bytes);
                        }
                        Err(TryRecvError::Empty) => {
                            return Err(proptest::test_runner::TestCaseError::fail(
                                format!("target session {} did not receive the frame", sid),
                            ));
                        }
                        Err(TryRecvError::Disconnected) => {
                            return Err(proptest::test_runner::TestCaseError::fail(
                                format!("target session {} channel disconnected", sid),
                            ));
                        }
                    }
                } else {
                    match rx.try_recv() {
                        Err(TryRecvError::Empty) => { /* expected — no cross-delivery */ }
                        Ok(_) => {
                            return Err(proptest::test_runner::TestCaseError::fail(
                                format!("non-target session {} received a frame (cross-delivery!)", sid),
                            ));
                        }
                        Err(TryRecvError::Disconnected) => {
                            return Err(proptest::test_runner::TestCaseError::fail(
                                format!("non-target session {} channel disconnected", sid),
                            ));
                        }
                    }
                }
            }
        }
    }
}


// ---------------------------------------------------------------------------
// Preservation property tests (Task 2)
// ---------------------------------------------------------------------------
// These tests verify frame decode/encode behaviors that MUST be preserved
// after the ControlDispatcher fix. They run on UNFIXED code and must PASS.

#[cfg(test)]
mod preservation_tests {
    use dns_socks_proxy::frame::{
        decode_frame, encode_frame, Frame, FrameFlags, FrameType, SessionId,
    };
    use proptest::prelude::*;

    /// Generate a random valid 8-byte alphanumeric SessionId.
    fn arb_session_id() -> impl Strategy<Value = SessionId> {
        proptest::collection::vec(
            proptest::sample::select(
                b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
                    .iter()
                    .copied()
                    .collect::<Vec<u8>>(),
            ),
            8,
        )
        .prop_map(|bytes| {
            let mut arr = [0u8; 8];
            arr.copy_from_slice(&bytes);
            SessionId(arr)
        })
    }

    /// Generate a random valid FrameType.
    fn arb_frame_type() -> impl Strategy<Value = FrameType> {
        prop_oneof![
            Just(FrameType::Data),
            Just(FrameType::Ack),
            Just(FrameType::Syn),
            Just(FrameType::SynAck),
            Just(FrameType::Fin),
            Just(FrameType::Rst),
        ]
    }

    // **Validates: Requirements 3.1, 3.2**
    //
    // Property 2a: Frame decode preserves session_id.
    // For any valid encoded frame, `decode_frame` extracts the correct session_id.
    // This is the dispatch key the new ControlDispatcher code will use.
    proptest! {
        #[test]
        fn frame_decode_preserves_session_id(
            session_id in arb_session_id(),
            seq in any::<u32>(),
            frame_type in arb_frame_type(),
            flags in any::<u8>(),
            payload in proptest::collection::vec(any::<u8>(), 0..128),
        ) {
            let frame = Frame {
                session_id: session_id.clone(),
                seq,
                frame_type,
                flags: FrameFlags(flags),
                payload,
            };
            let encoded = encode_frame(&frame);
            let decoded = decode_frame(&encoded).unwrap();
            prop_assert_eq!(decoded.session_id, session_id);
        }
    }

    // **Validates: Requirements 3.1, 3.2, 3.3, 3.4, 3.5**
    //
    // Property 2b: Frame encode/decode round-trip preserves all fields.
    // For any valid frame with random session_id, seq, frame_type, flags, and
    // payload, encode then decode produces an identical frame.
    proptest! {
        #[test]
        fn frame_encode_decode_round_trip_preserves_all_fields(
            session_id in arb_session_id(),
            seq in any::<u32>(),
            frame_type in arb_frame_type(),
            flags in any::<u8>(),
            payload in proptest::collection::vec(any::<u8>(), 0..256),
        ) {
            let original = Frame {
                session_id: session_id.clone(),
                seq,
                frame_type,
                flags: FrameFlags(flags),
                payload: payload.clone(),
            };
            let encoded = encode_frame(&original);
            let decoded = decode_frame(&encoded).unwrap();
            prop_assert_eq!(&decoded.session_id, &original.session_id);
            prop_assert_eq!(decoded.seq, original.seq);
            prop_assert_eq!(decoded.frame_type, original.frame_type);
            prop_assert_eq!(&decoded.flags, &original.flags);
            prop_assert_eq!(&decoded.payload, &original.payload);
        }
    }

    // **Validates: Requirements 3.1, 3.2**
    //
    // Property 2c: decode_frame correctly extracts session_id from first 9 bytes.
    // For any valid frame, the session_id in bytes 1..9 of the encoded output
    // matches the original session_id, confirming the wire format the dispatcher
    // will rely on.
    proptest! {
        #[test]
        fn decode_frame_extracts_session_id_from_first_9_bytes(
            session_id in arb_session_id(),
            seq in any::<u32>(),
            frame_type in arb_frame_type(),
            payload in proptest::collection::vec(any::<u8>(), 0..64),
        ) {
            let frame = Frame {
                session_id: session_id.clone(),
                seq,
                frame_type,
                flags: FrameFlags::empty(),
                payload,
            };
            let encoded = encode_frame(&frame);

            // Verify wire format: byte 0 is session_id_len (always 8),
            // bytes 1..9 are the raw session_id bytes.
            prop_assert_eq!(encoded[0], 8u8);
            prop_assert_eq!(&encoded[1..9], &session_id.0[..]);

            // And decode_frame agrees.
            let decoded = decode_frame(&encoded).unwrap();
            prop_assert_eq!(&decoded.session_id.0[..], &encoded[1..9]);
        }
    }
}
