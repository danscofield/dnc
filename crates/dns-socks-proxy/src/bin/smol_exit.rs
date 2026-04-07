use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use smoltcp::iface::SocketSet;
use tokio::net::TcpStream;
use tracing::{debug, error, info, warn};

use dns_socks_proxy::config::{DeploymentMode, SmolExitCli, SmolExitConfig};
use dns_socks_proxy::crypto::{
    compute_control_mac, derive_session_key, generate_keypair, verify_control_mac, Psk,
};
use dns_socks_proxy::frame::SessionId;
use dns_socks_proxy::guard::is_blocked;
use dns_socks_proxy::smol_device::{compute_mtu, VirtualDevice};
use dns_socks_proxy::smol_frame::{
    decode_init_message, encode_init_ack_message, encode_teardown_message, InitAckMessage,
    SMOL_MSG_INIT,
};
use dns_socks_proxy::smol_poll::{
    create_smol_interface, create_tcp_socket, run_session_poll_loop, PollDirection, SmolPollConfig,
};
use dns_socks_proxy::socks::TargetAddr;
use dns_socks_proxy::transport::{
    compute_payload_budget, AdaptiveBackoff, DirectTransport, DnsTransport, TransportBackend,
};

/// Nonce length used in DNS queries.
const NONCE_LEN: usize = 4;

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

    let cli = SmolExitCli::parse();
    let config = cli.into_config()?;

    info!(
        domain = %config.controlled_domain,
        node_id = %config.node_id,
        mode = ?config.mode,
        "smol-exit starting"
    );

    // Initialize transport based on mode.
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

            let store = dns_message_broker::server::create_store(&broker_config);

            let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
            let shutdown_rx2 = shutdown_tx.subscribe();

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

            let _sweeper_handle = dns_message_broker::server::spawn_expiry_sweeper(
                store.clone(),
                broker_config.expiry_interval(),
                shutdown_rx2,
            );

            info!(
                broker_listen = %format!("{}:{}", broker_config.listen_addr, broker_config.listen_port),
                "embedded broker started"
            );

            broker_shutdown_tx = Some(shutdown_tx);

            Arc::new(DirectTransport::new(store, config.node_id.clone())) as Arc<dyn TransportBackend>
        }
    };

    let control_channel = format!("ctl-{}", config.node_id);
    let shared_config = Arc::new(config);

    info!(control_channel = %control_channel, "polling for Init messages");

    let mut backoff = AdaptiveBackoff::new(shared_config.poll_active, shared_config.backoff_max);
    let mut control_cursor: Option<u64> = None;

    // Set up graceful shutdown signal handling (SIGINT / SIGTERM).
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

        match transport.recv_frames(&control_channel, control_cursor).await {
            Ok((frames, new_cursor)) if !frames.is_empty() => {
                if let Some(c) = new_cursor {
                    control_cursor = Some(c + 1);
                }
                backoff.reset();

                for data in frames {
                    // Need at least 16 bytes for MAC at the end.
                    if data.len() < 16 {
                        debug!(len = data.len(), "control frame too short, discarding");
                        continue;
                    }

                    let (frame_bytes, received_mac) = data.split_at(data.len() - 16);
                    let mut mac_arr = [0u8; 16];
                    mac_arr.copy_from_slice(received_mac);

                    if !verify_control_mac(&shared_config.psk, frame_bytes, &mac_arr) {
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

                    let transport = Arc::clone(&transport);
                    let config = Arc::clone(&shared_config);
                    let frame_data = data.to_vec();

                    tokio::spawn(async move {
                        if let Err(e) = handle_init(frame_data, transport, config).await {
                            warn!(error = %e, "Init handling failed");
                        }
                    });
                }
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

    // Signal embedded broker tasks to shut down (if in embedded mode).
    if let Some(tx) = broker_shutdown_tx.take() {
        info!("signaling embedded broker tasks to shut down");
        let _ = tx.send(true);
    }

    tokio::time::sleep(Duration::from_millis(500)).await;

    info!("smol-exit shut down gracefully");
    Ok(())
}


// ---------------------------------------------------------------------------
// handle_init — per-session logic
// ---------------------------------------------------------------------------

async fn handle_init(
    raw_data: Vec<u8>,
    transport: Arc<dyn TransportBackend>,
    config: Arc<SmolExitConfig>,
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

    // 6. Send InitAck on client's control channel (with MAC).
    let client_control_channel = format!("ctl-{}", init_msg.client_id);
    let init_ack = InitAckMessage {
        session_id: session_id.clone(),
        pubkey: *exit_pubkey.as_bytes(),
    };
    let init_ack_bytes = encode_init_ack_message(&init_ack);
    let mac = compute_control_mac(&config.psk, &init_ack_bytes);
    let mut ack_with_mac = init_ack_bytes;
    ack_with_mac.extend_from_slice(&mac);

    transport
        .send_frame(&client_control_channel, &config.node_id, &ack_with_mac)
        .await?;
    info!(
        session_id = %session_id,
        channel = %client_control_channel,
        "InitAck sent"
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
        send_teardown(&transport, &client_control_channel, &config.node_id, &session_id, &config.psk).await;
        return Ok(());
    }

    let mtu = compute_mtu(payload_budget);
    if mtu == 0 {
        error!("MTU is zero — payload budget too small");
        send_teardown(&transport, &client_control_channel, &config.node_id, &session_id, &config.psk).await;
        return Ok(());
    }

    let mss = config.smol_tuning.mss.unwrap_or_else(|| mtu.saturating_sub(40));
    if mss == 0 {
        error!("MSS is zero — MTU too small for TCP");
        send_teardown(&transport, &client_control_channel, &config.node_id, &session_id, &config.psk).await;
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

    // 9. Split real TcpStream and run the poll loop.
    let (mut tcp_read, mut tcp_write) = tcp_stream.into_split();

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
        transport.clone(),
        transport.clone(),
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

    // 10. Cleanup: send Teardown on control channel, close real TCP.
    info!(session_id = %session_id, "session ending, sending teardown");
    send_teardown(
        &transport,
        &client_control_channel,
        &config.node_id,
        &session_id,
        &config.psk,
    )
    .await;

    // tcp_stream halves are dropped here, closing the real TCP connection.
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
// Helper: send Teardown message
// ---------------------------------------------------------------------------

async fn send_teardown(
    transport: &Arc<dyn TransportBackend>,
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
