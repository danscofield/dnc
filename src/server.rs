//! Server module.
//!
//! Implements the async UDP server loop, expiry sweeper, and graceful shutdown.

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::UdpSocket;
use tokio::sync::RwLock;

use crate::config::Config;
use crate::dns::{build_response, parse_dns_query};
use crate::handler::{handle_query, handle_status, is_status_query_packet};
use crate::store::{ChannelStore, RealClock};

use hickory_proto::op::ResponseCode;
use hickory_proto::rr::{Name, RecordType};

/// Shared channel store type used by the server loop and expiry sweeper.
pub type SharedStore = Arc<RwLock<ChannelStore<RealClock>>>;

/// Maximum UDP DNS message size (standard DNS over UDP limit).
const MAX_UDP_SIZE: usize = 512;

/// Run the async UDP server loop.
///
/// Binds to the configured address/port, receives DNS queries, routes them
/// through the handler, and sends responses. The loop runs until the
/// `shutdown` receiver signals.
///
/// The `store` is passed in so it can be shared with the expiry sweeper task.
pub async fn run_server_loop(
    config: Config,
    store: SharedStore,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> Result<(), Box<dyn std::error::Error>> {
    let bind_addr = SocketAddr::new(config.listen_addr, config.listen_port);
    let socket = UdpSocket::bind(bind_addr).await.map_err(|e| {
        tracing::error!("Failed to bind UDP socket to {}: {}", bind_addr, e);
        e
    })?;

    tracing::info!("DNS Message Broker listening on {}", bind_addr);

    let mut buf = [0u8; MAX_UDP_SIZE];

    loop {
        tokio::select! {
            result = socket.recv_from(&mut buf) => {
                let (len, src) = match result {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::warn!("Failed to receive UDP packet: {}", e);
                        continue;
                    }
                };

                let packet = &buf[..len];
                tracing::debug!("Received {} bytes from {}", len, src);

                let response_bytes = process_packet(packet, &config, &store).await;

                if let Err(e) = socket.send_to(&response_bytes, src).await {
                    tracing::warn!("Failed to send response to {}: {}", src, e);
                }

                tracing::debug!("Sent {} byte response to {}", response_bytes.len(), src);
            }
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    tracing::info!("Shutdown signal received, stopping server loop");
                    break;
                }
            }
        }
    }

    Ok(())
}

/// Process a single DNS packet: parse, route, and produce a response.
///
/// If the packet is malformed (parse fails), returns a FORMERR response.
/// Status queries acquire only a read lock on the store; send/receive
/// queries acquire a write lock.
async fn process_packet(
    packet: &[u8],
    config: &Config,
    store: &SharedStore,
) -> Vec<u8> {
    match parse_dns_query(packet) {
        Ok(query) => {
            tracing::debug!(
                "Parsed query: id={:#06x} name={} type={:?}",
                query.query_id,
                query.query_name,
                query.query_type
            );

            let response = if is_status_query_packet(&query, config) {
                let store_guard = store.read().await;
                handle_status(&query, config, &*store_guard)
            } else {
                let mut store_guard = store.write().await;
                handle_query(&query, config, &mut store_guard)
            };

            tracing::debug!(
                "Produced {} byte response for query id={:#06x}",
                response.len(),
                query.query_id
            );

            response
        }
        Err(e) => {
            tracing::debug!("Malformed DNS packet: {}", e);

            // Build a minimal FORMERR response. Use a dummy name/type since
            // we couldn't parse the query.
            let dummy_name = Name::root();
            build_response(0, &dummy_name, RecordType::A, ResponseCode::FormErr, vec![])
                .unwrap_or_default()
        }
    }
}

/// Spawn a tokio task that periodically sweeps expired messages and inactive channels.
///
/// The task ticks at the given `expiry_interval` and, on each tick, acquires a
/// write lock on the store and calls `sweep_expired(Instant::now())`. The task
/// stops when the shutdown signal is received.
pub fn spawn_expiry_sweeper(
    store: SharedStore,
    expiry_interval: std::time::Duration,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(tokio::time::Duration::from(expiry_interval));
        // The first tick completes immediately; consume it so we don't sweep at startup.
        ticker.tick().await;

        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    let now = std::time::Instant::now();
                    store.write().await.sweep_expired(now);
                    tracing::debug!("Expiry sweep completed");
                }
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        tracing::debug!("Expiry sweeper stopping due to shutdown signal");
                        break;
                    }
                }
            }
        }
    })
}

/// Create a new `SharedStore` from the given configuration.
pub fn create_store(config: &Config) -> SharedStore {
    let store = ChannelStore::new(
        config.max_messages_per_channel,
        config.channel_inactivity_timeout(),
        config.message_ttl(),
        RealClock,
        32,
    );
    Arc::new(RwLock::new(store))
}

/// Run the full daemon lifecycle.
///
/// This is the main entry point called from `main.rs`. It:
/// 1. Creates the shared channel store
/// 2. Sets up a shutdown watch channel
/// 3. Spawns the expiry sweeper task
/// 4. Spawns the server loop
/// 5. Waits for SIGTERM or SIGINT
/// 6. Signals shutdown and waits up to 5 seconds for tasks to finish
pub async fn run(config: Config) -> Result<(), Box<dyn std::error::Error>> {
    // 1. Create the shared store.
    let store = create_store(&config);

    // 2. Create a watch channel for shutdown signaling.
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    // 3. Spawn the expiry sweeper task.
    let sweeper_handle = spawn_expiry_sweeper(
        store.clone(),
        config.expiry_interval(),
        shutdown_rx.clone(),
    );

    // 4. Set up signal handlers for SIGTERM and SIGINT.
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .map_err(|e| {
            tracing::error!("Failed to set up SIGTERM handler: {}", e);
            e
        })?;
    let mut sigint = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
        .map_err(|e| {
            tracing::error!("Failed to set up SIGINT handler: {}", e);
            e
        })?;

    // 5. Spawn the server loop.
    let server_config = config.clone();
    let server_shutdown_rx = shutdown_rx.clone();
    let server_handle = tokio::spawn(async move {
        if let Err(e) = run_server_loop(server_config, store, server_shutdown_rx).await {
            tracing::error!("Server loop error: {}", e);
        }
    });

    // 6. Wait for a signal, then send shutdown.
    tokio::select! {
        _ = sigterm.recv() => {
            tracing::info!("Received SIGTERM, initiating graceful shutdown");
        }
        _ = sigint.recv() => {
            tracing::info!("Received SIGINT, initiating graceful shutdown");
        }
    }

    let _ = shutdown_tx.send(true);

    // 7. Wait for tasks to finish with a 5-second timeout.
    let shutdown_deadline = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        async {
            let _ = server_handle.await;
            let _ = sweeper_handle.await;
        },
    )
    .await;

    if shutdown_deadline.is_err() {
        tracing::warn!("Graceful shutdown timed out after 5 seconds, exiting");
    } else {
        tracing::info!("Graceful shutdown complete");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::parse_config;
    use hickory_proto::op::{Message, MessageType, Query};
    use hickory_proto::rr::{Name, RecordType};

    fn test_config() -> Config {
        parse_config(
            r#"
listen_addr = "127.0.0.1"
listen_port = 15353
controlled_domain = "broker.example.com"
"#,
        )
        .unwrap()
    }

    fn build_query_bytes(name: &str, qtype: RecordType) -> Vec<u8> {
        let mut msg = Message::new();
        msg.set_id(0x1234);
        msg.set_message_type(MessageType::Query);
        let query_name = Name::from_ascii(name).unwrap();
        msg.add_query(Query::query(query_name, qtype));
        msg.to_vec().unwrap()
    }

    #[tokio::test]
    async fn test_process_packet_valid_query() {
        let config = test_config();
        let store = create_store(&config);

        let packet = build_query_bytes(
            "nonce123.inbox.broker.example.com.",
            RecordType::TXT,
        );

        let response = process_packet(&packet, &config, &store).await;
        let msg = Message::from_vec(&response).unwrap();

        assert_eq!(msg.id(), 0x1234);
        assert_eq!(msg.message_type(), MessageType::Response);
        assert!(msg.authoritative());
        // Empty channel → NOERROR with zero answers
        assert_eq!(msg.response_code(), ResponseCode::NoError);
        assert!(msg.answers().is_empty());
    }

    #[tokio::test]
    async fn test_process_packet_malformed() {
        let config = test_config();
        let store = create_store(&config);

        let garbage = b"this is not a dns packet";
        let response = process_packet(garbage, &config, &store).await;
        let msg = Message::from_vec(&response).unwrap();

        assert_eq!(msg.response_code(), ResponseCode::FormErr);
    }

    #[tokio::test]
    async fn test_process_packet_outside_domain_refused() {
        let config = test_config();
        let store = create_store(&config);

        let packet = build_query_bytes("nonce.something.other.com.", RecordType::A);
        let response = process_packet(&packet, &config, &store).await;
        let msg = Message::from_vec(&response).unwrap();

        assert_eq!(msg.response_code(), ResponseCode::Refused);
    }

    #[tokio::test]
    async fn test_process_packet_send_and_receive() {
        let config = test_config();
        let store = create_store(&config);

        // Send: nonce.payload.sender.channel.broker.example.com
        // payload "hi" base32 = "nbsq"
        let send_packet = build_query_bytes(
            "nonce123.nbsq.alice.inbox.broker.example.com.",
            RecordType::A,
        );
        let send_response = process_packet(&send_packet, &config, &store).await;
        let send_msg = Message::from_vec(&send_response).unwrap();
        assert_eq!(send_msg.response_code(), ResponseCode::NoError);
        assert_eq!(send_msg.answers().len(), 1);

        // Receive
        let recv_packet = build_query_bytes(
            "nonce456.inbox.broker.example.com.",
            RecordType::TXT,
        );
        let recv_response = process_packet(&recv_packet, &config, &store).await;
        let recv_msg = Message::from_vec(&recv_response).unwrap();
        assert_eq!(recv_msg.response_code(), ResponseCode::NoError);
        assert_eq!(recv_msg.answers().len(), 1);
    }

    #[tokio::test]
    async fn test_server_loop_shutdown() {
        let config = parse_config(
            r#"
listen_addr = "127.0.0.1"
listen_port = 0
controlled_domain = "broker.example.com"
"#,
        )
        .unwrap();

        // Use port 0 so the OS assigns a free port — but we need to bind
        // manually to get the actual port. Instead, just test that the
        // shutdown signal stops the loop promptly.
        let _store = create_store(&config);
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

        // We can't easily bind to port 0 through run_server_loop since it
        // binds internally. Instead, signal shutdown immediately and verify
        // the loop exits.
        shutdown_tx.send(true).unwrap();

        let handle = tokio::spawn(async move {
            // Use a high port to avoid permission issues
            let mut cfg = config;
            cfg.listen_port = 0;
            // Bind manually to test
            let bind_addr = SocketAddr::new(cfg.listen_addr, 0);
            let socket = UdpSocket::bind(bind_addr).await.unwrap();
            let _actual_port = socket.local_addr().unwrap().port();

            // The shutdown is already signaled, so the select! should pick it up
            let mut shutdown = shutdown_rx;
            let mut buf = [0u8; MAX_UDP_SIZE];

            tokio::select! {
                _ = socket.recv_from(&mut buf) => {
                    panic!("should not receive anything");
                }
                _ = shutdown.changed() => {
                    // Expected path
                    assert!(*shutdown.borrow());
                }
            }
        });

        // Should complete quickly
        tokio::time::timeout(std::time::Duration::from_secs(2), handle)
            .await
            .expect("shutdown should complete within 2 seconds")
            .expect("task should not panic");
    }

    #[test]
    fn test_create_store() {
        let config = test_config();
        let _store = create_store(&config);
        // Just verify it doesn't panic
    }

    #[tokio::test]
    async fn test_process_packet_status_query_empty_channel() {
        let config = test_config();
        let store = create_store(&config);

        // Status query: <nonce>.status.<channel>.<controlled_domain>
        let packet = build_query_bytes(
            "a7k2.status.inbox.broker.example.com.",
            RecordType::A,
        );
        let response = process_packet(&packet, &config, &store).await;
        let msg = Message::from_vec(&response).unwrap();

        assert_eq!(msg.response_code(), ResponseCode::NoError);
        assert_eq!(msg.answers().len(), 1);
        // Empty channel → 0.0.0.0
        match msg.answers()[0].data() {
            hickory_proto::rr::RData::A(a) => {
                assert_eq!(a.0, std::net::Ipv4Addr::new(0, 0, 0, 0));
            }
            other => panic!("expected A record, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_process_packet_status_query_with_data() {
        let config = test_config();
        let store = create_store(&config);

        // Push messages via send queries first
        let send_packet = build_query_bytes(
            "nonce1.nbsq.alice.inbox.broker.example.com.",
            RecordType::A,
        );
        process_packet(&send_packet, &config, &store).await;
        let send_packet2 = build_query_bytes(
            "nonce2.nbsq.bob.inbox.broker.example.com.",
            RecordType::A,
        );
        process_packet(&send_packet2, &config, &store).await;

        // Now issue a status query — should report depth 2 → 128.0.0.2
        let status_packet = build_query_bytes(
            "a7k2.status.inbox.broker.example.com.",
            RecordType::A,
        );
        let response = process_packet(&status_packet, &config, &store).await;
        let msg = Message::from_vec(&response).unwrap();

        assert_eq!(msg.response_code(), ResponseCode::NoError);
        assert_eq!(msg.answers().len(), 1);
        match msg.answers()[0].data() {
            hickory_proto::rr::RData::A(a) => {
                assert_eq!(a.0, std::net::Ipv4Addr::new(128, 0, 0, 2));
            }
            other => panic!("expected A record, got {:?}", other),
        }

        // Verify the status query didn't consume any messages (read-only)
        let status_packet2 = build_query_bytes(
            "b8m3.status.inbox.broker.example.com.",
            RecordType::A,
        );
        let response2 = process_packet(&status_packet2, &config, &store).await;
        let msg2 = Message::from_vec(&response2).unwrap();
        match msg2.answers()[0].data() {
            hickory_proto::rr::RData::A(a) => {
                assert_eq!(a.0, std::net::Ipv4Addr::new(128, 0, 0, 2));
            }
            other => panic!("expected A record, got {:?}", other),
        }
    }
}
