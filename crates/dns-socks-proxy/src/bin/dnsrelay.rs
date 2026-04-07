use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use smoltcp::iface::SocketSet;
use tokio::net::{TcpStream, UdpSocket};
use tracing::{debug, error, info, warn};

use dns_message_broker::dns::parse_dns_query;
use dns_message_broker::relay_handler::{handle_relay_query, RelayConfig as HandlerRelayConfig};
use dns_message_broker::relay_store::{RelayStore, SharedRelayStore};
use dns_message_broker::store::RealClock;

use dns_socks_proxy::config::RelayCliArgs;
use dns_socks_proxy::crypto::{
    compute_control_mac, derive_session_key, generate_keypair, verify_control_mac, Psk,
};
use dns_socks_proxy::frame::SessionId;
use dns_socks_proxy::guard::is_blocked;
use dns_socks_proxy::relay_transport::RelayTransport;
use dns_socks_proxy::smol_device::{compute_mtu, VirtualDevice};
use dns_socks_proxy::smol_frame::{decode_init_message, encode_init_ack_message, encode_teardown_message, InitAckMessage, SMOL_MSG_INIT};
use dns_socks_proxy::smol_poll::{
    create_smol_interface, create_tcp_socket, run_session_poll_loop, PollDirection, SmolPollConfig,
};
use dns_socks_proxy::socks::TargetAddr;
use dns_socks_proxy::transport::{compute_payload_budget, AdaptiveBackoff};

use hickory_proto::op::ResponseCode;
use hickory_proto::rr::{Name, RecordType};

/// Nonce length used in DNS queries.
const NONCE_LEN: usize = 4;

/// Maximum UDP DNS message size.
const MAX_UDP_SIZE: usize = 4096;

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

    let cli = RelayCliArgs::parse();
    let config = cli.into_config()?;

    info!(
        domain = %config.controlled_domain,
        node_id = %config.node_id,
        listen = %config.listen_addr,
        "dnsrelay starting"
    );

    // Create the shared RelayStore.
    let store: SharedRelayStore = Arc::new(RelayStore::new(config.message_ttl, RealClock));

    // Bind UDP socket for DNS listener.
    let socket = UdpSocket::bind(config.listen_addr).await.map_err(|e| {
        error!("failed to bind UDP socket to {}: {}", config.listen_addr, e);
        e
    })?;
    info!("DNS relay listening on {}", config.listen_addr);

    let shared_config = Arc::new(config);

    // Build the handler config.
    let handler_config = HandlerRelayConfig {
        controlled_domain: shared_config.controlled_domain.clone(),
        ..Default::default()
    };

    // --- Spawn expiry sweeper task ---
    let sweeper_store = store.clone();
    let expiry_interval = shared_config.expiry_interval;
    let sweeper_handle = tokio::spawn(async move {
        let mut ticker = tokio::time::interval(expiry_interval);
        // Consume the first immediate tick.
        ticker.tick().await;
        loop {
            ticker.tick().await;
            sweeper_store.sweep_expired();
            debug!("expiry sweep completed");
        }
    });

    // --- Spawn control channel poller task ---
    let control_channel = format!("ctl-{}", shared_config.node_id);
    let ctl_store = store.clone();
    let ctl_config = Arc::clone(&shared_config);
    let ctl_data_store = store.clone();

    let control_handle = tokio::spawn(async move {
        let mut backoff = AdaptiveBackoff::new(ctl_config.poll_active, ctl_config.poll_idle);
        // Deduplication: track last-seen sequence per sender_id to avoid re-processing.
        let mut last_seen: HashMap<String, u64> = HashMap::new();

        loop {
            tokio::time::sleep(backoff.current()).await;

            let slots = ctl_store.read(&control_channel);
            if slots.is_empty() {
                backoff.increase();
                continue;
            }

            let mut found_new = false;
            for slot in &slots {
                let prev_seq = last_seen.get(&slot.sender_id).copied().unwrap_or(0);
                if slot.sequence <= prev_seq {
                    continue; // Already processed.
                }
                last_seen.insert(slot.sender_id.clone(), slot.sequence);
                found_new = true;

                let data = &slot.payload;

                // Need at least 16 bytes for MAC at the end.
                if data.len() < 16 {
                    debug!(len = data.len(), "control frame too short, discarding");
                    continue;
                }

                let (frame_bytes, received_mac) = data.split_at(data.len() - 16);
                let mut mac_arr = [0u8; 16];
                mac_arr.copy_from_slice(received_mac);

                if !verify_control_mac(&ctl_config.psk, frame_bytes, &mac_arr) {
                    debug!("control frame MAC verification failed, discarding");
                    continue;
                }

                // Check message type byte — only handle SMOL_MSG_INIT.
                if frame_bytes.is_empty() || frame_bytes[0] != SMOL_MSG_INIT {
                    debug!(
                        msg_type = frame_bytes.first().copied().unwrap_or(0),
                        "non-Init message on control channel, ignoring"
                    );
                    continue;
                }

                let config = Arc::clone(&ctl_config);
                let session_store = ctl_data_store.clone();
                let frame_data = data.to_vec();

                tokio::spawn(async move {
                    if let Err(e) = handle_init(frame_data, session_store, config).await {
                        warn!(error = %e, "Init handling failed");
                    }
                });
            }

            if found_new {
                backoff.reset();
            } else {
                backoff.increase();
            }
        }
    });

    // --- Set up graceful shutdown signal handling ---
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

    // --- DNS listener loop ---
    let mut buf = [0u8; MAX_UDP_SIZE];

    loop {
        tokio::select! {
            _ = &mut shutdown_signal => {
                break;
            }
            result = socket.recv_from(&mut buf) => {
                let (len, src) = match result {
                    Ok(v) => v,
                    Err(e) => {
                        warn!("failed to receive UDP packet: {}", e);
                        continue;
                    }
                };

                let packet = &buf[..len];
                let response_bytes = process_dns_packet(packet, &handler_config, &store);

                if let Err(e) = socket.send_to(&response_bytes, src).await {
                    warn!("failed to send response to {}: {}", src, e);
                }
            }
        }
    }

    // --- Graceful shutdown ---
    info!("shutdown signal received");
    sweeper_handle.abort();
    control_handle.abort();
    tokio::time::sleep(Duration::from_millis(500)).await;
    info!("dnsrelay shut down gracefully");
    Ok(())
}

// ---------------------------------------------------------------------------
// DNS packet processing
// ---------------------------------------------------------------------------

/// Process a single DNS packet: parse, route via relay handler, produce response.
fn process_dns_packet(
    packet: &[u8],
    config: &HandlerRelayConfig,
    store: &RelayStore<RealClock>,
) -> Vec<u8> {
    match parse_dns_query(packet) {
        Ok(query) => handle_relay_query(&query, config, store),
        Err(_) => {
            // Malformed packet → FORMERR
            let dummy_name = Name::root();
            dns_message_broker::dns::build_response(
                0,
                &dummy_name,
                RecordType::A,
                ResponseCode::FormErr,
                vec![],
            )
            .unwrap_or_default()
        }
    }
}


// ---------------------------------------------------------------------------
// handle_init — per-session logic
// ---------------------------------------------------------------------------

async fn handle_init(
    raw_data: Vec<u8>,
    store: SharedRelayStore,
    config: Arc<dns_socks_proxy::config::RelayConfig>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // 1. Split frame_bytes and MAC, decode Init message.
    let (frame_bytes, _received_mac) = raw_data.split_at(raw_data.len() - 16);
    // MAC already verified by the caller.

    let init_msg = decode_init_message(frame_bytes)?;
    let session_id = init_msg.session_id.clone();

    info!(
        session_id = %session_id,
        client_id = %init_msg.client_id,
        target_port = init_msg.target_port,
        "received Init"
    );

    // 2. Generate X25519 keypair and derive SessionKey.
    let (exit_secret, exit_pubkey) = generate_keypair();
    let client_public = x25519_dalek::PublicKey::from(init_msg.pubkey);
    let shared_secret = exit_secret.diffie_hellman(&client_public);
    let session_key = derive_session_key(shared_secret.as_bytes(), &config.psk)?;

    // 3. Resolve target address.
    let target_socket_addr = resolve_target(&init_msg.target_addr, init_msg.target_port).await?;

    // 4. Check private network guard.
    if is_blocked(target_socket_addr.ip(), &config.blocked_networks) {
        warn!(
            session_id = %session_id,
            addr = %target_socket_addr,
            "blocked by private network guard"
        );
        return Ok(());
    }

    // 5. TCP connect to real target with timeout.
    let tcp_stream = match tokio::time::timeout(
        config.connect_timeout,
        TcpStream::connect(target_socket_addr),
    )
    .await
    {
        Ok(Ok(stream)) => {
            info!(
                session_id = %session_id,
                target = %target_socket_addr,
                "TCP connected to target"
            );
            stream
        }
        Ok(Err(e)) => {
            warn!(
                session_id = %session_id,
                target = %target_socket_addr,
                error = %e,
                "TCP connect failed"
            );
            return Ok(());
        }
        Err(_) => {
            warn!(
                session_id = %session_id,
                target = %target_socket_addr,
                "TCP connect timed out"
            );
            return Ok(());
        }
    };

    // 6. Send InitAck on per-session control channel via RelayStore.
    let session_control_channel = format!("ctl-{}", session_id);
    let init_ack = InitAckMessage {
        session_id: session_id.clone(),
        pubkey: *exit_pubkey.as_bytes(),
    };
    let init_ack_bytes = encode_init_ack_message(&init_ack);
    let mac = compute_control_mac(&config.psk, &init_ack_bytes);
    let mut ack_with_mac = init_ack_bytes;
    ack_with_mac.extend_from_slice(&mac);

    // Write InitAck directly to the RelayStore (not via transport).
    store.write(&session_control_channel, &config.node_id, ack_with_mac);
    info!(
        session_id = %session_id,
        channel = %session_control_channel,
        "InitAck written to RelayStore"
    );

    // 7. Compute payload budget and MTU.
    let upstream_channel = format!("u-{}", session_id);
    let downstream_channel = format!("d-{}", session_id);

    let payload_budget = compute_payload_budget(
        config.controlled_domain.len(),
        config.node_id.len(),
        downstream_channel.len(),
        NONCE_LEN,
    );
    if payload_budget == 0 {
        error!("payload budget is zero — domain/channel names too long");
        send_teardown(&store, &session_control_channel, &config.node_id, &session_id, &config.psk);
        return Ok(());
    }

    let mtu = compute_mtu(payload_budget);
    if mtu == 0 {
        error!("MTU is zero — payload budget too small");
        send_teardown(&store, &session_control_channel, &config.node_id, &session_id, &config.psk);
        return Ok(());
    }

    let mss = config.smol_tuning.mss.unwrap_or_else(|| mtu.saturating_sub(40));
    if mss == 0 {
        error!("MSS is zero — MTU too small for TCP");
        send_teardown(&store, &session_control_channel, &config.node_id, &session_id, &config.psk);
        return Ok(());
    }

    debug!(payload_budget, mtu, mss, "computed tunnel parameters");

    // 8. Create VirtualDevice + smoltcp Interface + TCP listener socket.
    let mut device = VirtualDevice::new(mtu);
    let mut iface = create_smol_interface(
        &mut device,
        std::net::Ipv4Addr::new(192, 168, 69, 2),
        std::net::Ipv4Addr::new(192, 168, 69, 1),
    );

    let tcp_socket = create_tcp_socket(&config.smol_tuning, mss);
    let mut socket_set = SocketSet::new(vec![]);
    let socket_handle = socket_set.add(tcp_socket);

    // Listen on 192.168.69.2:4321.
    {
        let socket = socket_set.get_mut::<smoltcp::socket::tcp::Socket>(socket_handle);
        socket
            .listen(smoltcp::wire::IpListenEndpoint {
                addr: Some(smoltcp::wire::IpAddress::Ipv4(smoltcp::wire::Ipv4Address::new(
                    192, 168, 69, 2,
                ))),
                port: 4321,
            })
            .map_err(|e| format!("smoltcp listen failed: {e}"))?;
    }

    debug!(session_id = %session_id, "smoltcp TCP listening on 192.168.69.2:4321");

    // 9. Create RelayTransport for this session and run the poll loop.
    let relay_transport: Arc<dyn dns_socks_proxy::transport::TransportBackend> =
        Arc::new(RelayTransport::new(store.clone(), config.node_id.clone()));

    let (mut tcp_read, mut tcp_write) = tcp_stream.into_split();

    let poll_config = SmolPollConfig {
        poll_active: config.poll_active,
        poll_idle: config.poll_idle,
        backoff_max: config.poll_idle,
        query_interval: Duration::ZERO,
        no_edns: false,
    };

    let mut tx_seq: u32 = 0;

    let result = run_session_poll_loop(
        &mut iface,
        &mut device,
        &mut socket_set,
        socket_handle,
        relay_transport.clone(),
        relay_transport.clone(),
        &session_id,
        &session_key,
        &upstream_channel,
        &downstream_channel,
        PollDirection::Exit,
        &mut tcp_read,
        &mut tcp_write,
        &poll_config,
        &config.node_id,
        &mut tx_seq,
    )
    .await;

    if let Err(e) = &result {
        warn!(session_id = %session_id, error = %e, "poll loop error");
    }

    // 10. Cleanup: send Teardown on per-session control channel, close real TCP.
    info!(session_id = %session_id, "session ending, sending teardown");
    send_teardown(
        &store,
        &session_control_channel,
        &config.node_id,
        &session_id,
        &config.psk,
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// Helper: resolve target address
// ---------------------------------------------------------------------------

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
            let addr_str = format!("{}:{}", domain, port);
            let addrs: Vec<SocketAddr> = tokio::net::lookup_host(&addr_str).await?.collect();
            addrs
                .into_iter()
                .next()
                .ok_or_else(|| format!("DNS resolution failed for {}", domain).into())
        }
    }
}

// ---------------------------------------------------------------------------
// Helper: send Teardown message via RelayStore
// ---------------------------------------------------------------------------

fn send_teardown(
    store: &SharedRelayStore,
    control_channel: &str,
    sender_id: &str,
    session_id: &SessionId,
    psk: &Psk,
) {
    let teardown_bytes = encode_teardown_message(session_id);
    let mac = compute_control_mac(psk, &teardown_bytes);
    let mut msg = teardown_bytes;
    msg.extend_from_slice(&mac);

    store.write(control_channel, sender_id, msg);
}
