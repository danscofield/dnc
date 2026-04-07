//! Full relay-path integration test.
//!
//! Wires up the complete path in-process:
//!   smoltcp → encrypt → RelayTransport → RelayStore → RelayTransport → decrypt → smoltcp
//!
//! Two smoltcp stacks (client + server) with asymmetric MTUs talk through
//! VirtualDevices, encrypted IP packets, and an in-process RelayStore.
//! No external DNS, no network, no real TCP connections.

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use smoltcp::iface::SocketSet;
use smoltcp::socket::tcp;
use smoltcp::wire::{IpAddress, IpEndpoint};

use dns_message_broker::relay_store::RelayStore;
use dns_message_broker::store::RealClock;

use dns_socks_proxy::config::SmolTuningConfig;
use dns_socks_proxy::crypto::{derive_session_key, generate_keypair, Psk};
use dns_socks_proxy::frame::SessionId;
use dns_socks_proxy::relay_transport::RelayTransport;
use dns_socks_proxy::smol_device::VirtualDevice;
use dns_socks_proxy::smol_poll::{
    create_smol_interface, create_tcp_socket, run_session_poll_loop, PollDirection, SmolPollConfig,
};
use dns_socks_proxy::transport::TransportBackend;

#[tokio::test]
async fn full_relay_path_round_trip() {
    // --- 1. Shared RelayStore (in-process, no DNS) ---
    let store = Arc::new(RelayStore::new(Duration::from_secs(600), RealClock));

    // --- 2. Two RelayTransport instances ---
    let client_transport: Arc<dyn TransportBackend> =
        Arc::new(RelayTransport::new(store.clone(), "client1".to_string()));
    let server_transport: Arc<dyn TransportBackend> =
        Arc::new(RelayTransport::new(store.clone(), "server1".to_string()));

    // --- 3. X25519 keypairs + shared SessionKey ---
    let psk = Psk::from_bytes(vec![0xAB; 32]).unwrap();
    let (client_secret, client_public) = generate_keypair();
    let (server_secret, server_public) = generate_keypair();

    let client_shared = client_secret.diffie_hellman(&server_public);
    let server_shared = server_secret.diffie_hellman(&client_public);
    assert_eq!(client_shared.as_bytes(), server_shared.as_bytes());

    let session_key = derive_session_key(client_shared.as_bytes(), &psk).unwrap();
    // Derive a second copy for the server side (same key material).
    let server_session_key =
        derive_session_key(server_shared.as_bytes(), &psk).unwrap();

    let session_id = SessionId(*b"test0001");

    // --- 4. VirtualDevice + smoltcp Interface pairs ---
    let client_ip: Ipv4Addr = "192.168.69.1".parse().unwrap();
    let server_ip: Ipv4Addr = "192.168.69.2".parse().unwrap();

    let client_mtu: usize = 72;
    let client_mss: usize = 32;
    let server_mtu: usize = 77;
    let server_mss: usize = 37;

    let server_port: u16 = 4321;
    let client_port: u16 = 49152;

    let client_tuning = SmolTuningConfig {
        window_segments: 4,
        ..SmolTuningConfig::default()
    };
    let server_tuning = SmolTuningConfig {
        window_segments: 4,
        ..SmolTuningConfig::default()
    };

    let mut client_dev = VirtualDevice::new(client_mtu);
    let mut server_dev = VirtualDevice::new(server_mtu);

    let mut client_iface = create_smol_interface(&mut client_dev, client_ip, server_ip);
    let mut server_iface = create_smol_interface(&mut server_dev, server_ip, client_ip);

    // --- 5. Create sockets ---
    let client_socket = create_tcp_socket(&client_tuning, client_mss);
    let server_socket = create_tcp_socket(&server_tuning, server_mss);

    let mut client_sockets = SocketSet::new(vec![]);
    let mut server_sockets = SocketSet::new(vec![]);

    let client_handle = client_sockets.add(client_socket);
    let server_handle = server_sockets.add(server_socket);

    // --- 6. Server listens, client connects ---
    {
        let srv = server_sockets.get_mut::<tcp::Socket>(server_handle);
        srv.listen(IpEndpoint::new(
            IpAddress::from(smoltcp::wire::Ipv4Address::from(server_ip)),
            server_port,
        ))
        .expect("server listen failed");
    }
    {
        let cli = client_sockets.get_mut::<tcp::Socket>(client_handle);
        cli.connect(
            &mut client_iface.context(),
            IpEndpoint::new(
                IpAddress::from(smoltcp::wire::Ipv4Address::from(server_ip)),
                server_port,
            ),
            IpEndpoint::new(
                IpAddress::from(smoltcp::wire::Ipv4Address::from(client_ip)),
                client_port,
            ),
        )
        .expect("client connect failed");
    }

    // --- 7. Poll config (fast iteration) ---

    // --- 8. Duplex streams ---
    // Client side: we write the request and read the response from client_user_*.
    let (client_user_stream, client_poll_stream) = tokio::io::duplex(1024);
    let (mut client_user_read, mut client_user_write) = tokio::io::split(client_user_stream);
    let (client_poll_read, client_poll_write) = tokio::io::split(client_poll_stream);

    // Server side: mock TCP server writes response, poll loop uses the other end.
    let (server_user_stream, server_poll_stream) = tokio::io::duplex(1024);
    let (mut server_user_read, mut server_user_write) = tokio::io::split(server_user_stream);
    let (server_poll_read, server_poll_write) = tokio::io::split(server_poll_stream);

    let http_request = b"GET / HTTP/1.0\r\n\r\n";
    let http_response = b"HTTP/1.0 200 OK\r\n\r\nHello";

    // --- 9. Spawn client poll loop ---
    let client_transport_send = client_transport.clone();
    let client_transport_recv = client_transport.clone();
    let client_session_id = session_id.clone();
    let client_poll_cfg = SmolPollConfig {
        poll_active: Duration::from_millis(10),
        poll_idle: Duration::from_millis(50),
        backoff_max: Duration::from_millis(50),
        query_interval: Duration::ZERO,
        no_edns: false,
    };

    let client_task = tokio::spawn(async move {
        let mut poll_read = client_poll_read;
        let mut poll_write = client_poll_write;
        let mut tx_seq: u32 = 0;
        run_session_poll_loop(
            &mut client_iface,
            &mut client_dev,
            &mut client_sockets,
            client_handle,
            client_transport_send,
            client_transport_recv,
            &client_session_id,
            &session_key,
            "u-test",
            "d-test",
            PollDirection::Client,
            &mut poll_read,
            &mut poll_write,
            &client_poll_cfg,
            "client1",
            &mut tx_seq,
        )
        .await
    });

    // --- 10. Spawn server poll loop ---
    let server_transport_send = server_transport.clone();
    let server_transport_recv = server_transport.clone();
    let server_session_id = SessionId(*b"test0001");
    let server_poll_cfg = SmolPollConfig {
        poll_active: Duration::from_millis(10),
        poll_idle: Duration::from_millis(50),
        backoff_max: Duration::from_millis(50),
        query_interval: Duration::ZERO,
        no_edns: false,
    };

    let server_task = tokio::spawn(async move {
        let mut poll_read = server_poll_read;
        let mut poll_write = server_poll_write;
        let mut tx_seq: u32 = 0;
        run_session_poll_loop(
            &mut server_iface,
            &mut server_dev,
            &mut server_sockets,
            server_handle,
            server_transport_send,
            server_transport_recv,
            &server_session_id,
            &server_session_key,
            "u-test",
            "d-test",
            PollDirection::Exit,
            &mut poll_read,
            &mut poll_write,
            &server_poll_cfg,
            "server1",
            &mut tx_seq,
        )
        .await
    });

    // --- 11. Mock TCP server: read request, write response, close ---
    let mock_server = tokio::spawn(async move {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut buf = vec![0u8; 1024];
        let mut total = 0;
        // Read until we see the full HTTP request (ends with \r\n\r\n).
        loop {
            let n = server_user_read.read(&mut buf[total..]).await.unwrap();
            if n == 0 {
                break;
            }
            total += n;
            if total >= 4 && &buf[total - 4..total] == b"\r\n\r\n" {
                break;
            }
        }
        assert_eq!(&buf[..total], http_request);
        server_user_write.write_all(http_response).await.unwrap();
        // Shutdown to signal EOF.
        server_user_write.shutdown().await.unwrap();
    });

    // --- 12. Client: write request, read expected number of response bytes ---
    let expected_response = http_response.to_vec();
    let expected_len = expected_response.len();
    let client_io = tokio::spawn(async move {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        client_user_write.write_all(http_request).await.unwrap();
        client_user_write.shutdown().await.unwrap();

        // Read exactly the expected number of bytes (don't wait for EOF which
        // requires a full FIN exchange through the relay).
        let mut response = vec![0u8; expected_len];
        let mut total = 0;
        while total < expected_len {
            let n = client_user_read.read(&mut response[total..]).await.unwrap();
            if n == 0 {
                break;
            }
            total += n;
        }
        response[..total].to_vec()
    });

    // --- 13. Wait with timeout ---
    let result = tokio::time::timeout(Duration::from_secs(10), async {
        let response = client_io.await.expect("client IO task panicked");
        mock_server.await.expect("mock server task panicked");
        response
    })
    .await;

    // Abort poll loops (they run indefinitely until the socket closes).
    client_task.abort();
    server_task.abort();

    let response = result.expect("test timed out after 10 seconds");
    assert_eq!(
        String::from_utf8_lossy(&response),
        "HTTP/1.0 200 OK\r\n\r\nHello",
        "client did not receive the expected HTTP response"
    );
}

// ---------------------------------------------------------------------------
// DnsSimTransport — simulates the DNS TXT encode/decode path without UDP
// ---------------------------------------------------------------------------

use async_trait::async_trait;
use hickory_proto::op::Message;
use hickory_proto::rr::RData;
use rand::Rng;

use dns_message_broker::dns::parse_dns_query;
use dns_message_broker::encoding::decode_envelope;
use dns_message_broker::relay_handler::{handle_relay_query, RelayConfig as HandlerRelayConfig};
use dns_message_broker::relay_store::SharedRelayStore;

use dns_socks_proxy::relay_transport::DedupRecvTransport;
use dns_socks_proxy::transport::{DnsTransport, TransportError};

/// Simulates the DNS TXT encode/decode path in-process.
///
/// - `send_frame`: writes to RelayStore directly (like RelayTransport)
/// - `recv_frames`: builds a DNS TXT query, parses it through the relay handler,
///   then decodes the TXT response envelopes — exercising the full wire format
///   round-trip without any network.
/// - `query_status`: reads store directly
struct DnsSimTransport {
    store: SharedRelayStore,
    sender_id: String,
    handler_config: HandlerRelayConfig,
    controlled_domain: String,
}

impl DnsSimTransport {
    fn new(store: SharedRelayStore, sender_id: String) -> Self {
        let controlled_domain = "relay.test.com".to_string();
        let handler_config = HandlerRelayConfig {
            controlled_domain: controlled_domain.clone(),
            ..HandlerRelayConfig::default()
        };
        Self {
            store,
            sender_id,
            handler_config,
            controlled_domain,
        }
    }

    /// Generate a random 4-char lowercase alphanumeric nonce.
    fn generate_nonce() -> String {
        let mut rng = rand::thread_rng();
        (0..4)
            .map(|_| {
                let idx = rng.gen_range(0..36);
                if idx < 10 {
                    (b'0' + idx) as char
                } else {
                    (b'a' + idx - 10) as char
                }
            })
            .collect()
    }
}

#[async_trait]
impl TransportBackend for DnsSimTransport {
    async fn send_frame(
        &self,
        channel: &str,
        _sender_id: &str,
        frame_bytes: &[u8],
    ) -> Result<(), TransportError> {
        self.store.write(channel, &self.sender_id, frame_bytes.to_vec());
        Ok(())
    }

    async fn recv_frames(
        &self,
        channel: &str,
        cursor: Option<u64>,
    ) -> Result<(Vec<Vec<u8>>, Option<u64>), TransportError> {
        // 1. Build a DNS TXT query name: <nonce>.<channel>.<domain>.
        // Include cursor suffix in nonce so the relay handler can filter.
        let nonce = match cursor {
            Some(c) => format!("{}-c{}", Self::generate_nonce(), c),
            None => Self::generate_nonce(),
        };
        let full_name = format!("{}.{}.{}.", nonce, channel, self.controlled_domain);
        let query_name = hickory_proto::rr::Name::from_ascii(&full_name)
            .map_err(|e| TransportError::DnsProtocol(format!("invalid DNS name: {e}")))?;

        // 2. Build a DNS query message (with EDNS0 1232)
        let query_bytes =
            DnsTransport::build_dns_query(&query_name, hickory_proto::rr::RecordType::TXT, true)?;

        // 3. Parse it with parse_dns_query (broker side)
        let dns_msg = parse_dns_query(&query_bytes)
            .map_err(|e| TransportError::DnsProtocol(format!("parse_dns_query failed: {e}")))?;

        // 4. Call handle_relay_query to get the DNS response bytes
        let response_bytes = handle_relay_query(&dns_msg, &self.handler_config, &*self.store);

        // 5. Parse the response with hickory_proto
        let response = Message::from_vec(&response_bytes)
            .map_err(|e| TransportError::DnsProtocol(format!("response parse failed: {e}")))?;

        if response.answers().is_empty() {
            return Ok((vec![], None));
        }

        // 6. Extract TXT records, decode envelopes
        let mut frames = Vec::new();
        let mut max_seq: Option<u64> = None;
        let mut received_seqs = Vec::new();

        for answer in response.answers() {
            if let Some(RData::TXT(txt)) = answer.data().into() {
                let text: String = txt
                    .iter()
                    .map(|b| String::from_utf8_lossy(b).to_string())
                    .collect::<Vec<_>>()
                    .join("");

                match decode_envelope(&text) {
                    Ok(parts) => {
                        max_seq =
                            Some(max_seq.map_or(parts.sequence, |m: u64| m.max(parts.sequence)));
                        received_seqs.push(parts.sequence);
                        frames.push(parts.payload);
                    }
                    Err(e) => {
                        return Err(TransportError::EnvelopeDecode(format!(
                            "decode_envelope failed: {e}"
                        )));
                    }
                }
            }
        }

        // Ack received sequences so the relay stops re-delivering them.
        if !received_seqs.is_empty() {
            self.store.ack_sequences(channel, &received_seqs);
        }

        Ok((frames, max_seq))
    }

    async fn query_status(&self, channel: &str) -> Result<usize, TransportError> {
        Ok(self.store.slot_count(channel))
    }

    async fn recv_manifest(&self, channel: &str) -> Result<Vec<(u64, usize)>, TransportError> {
        // 1. Build manifest query: m<nonce>.<channel>.<domain>.
        let nonce = format!("m{}", Self::generate_nonce());
        let full_name = format!("{}.{}.{}.", nonce, channel, self.controlled_domain);
        let query_name = hickory_proto::rr::Name::from_ascii(&full_name)
            .map_err(|e| TransportError::DnsProtocol(format!("invalid DNS name: {e}")))?;

        // 2. Build DNS query with EDNS0
        let query_bytes =
            DnsTransport::build_dns_query(&query_name, hickory_proto::rr::RecordType::TXT, true)?;

        // 3. Parse through relay handler
        let dns_msg = parse_dns_query(&query_bytes)
            .map_err(|e| TransportError::DnsProtocol(format!("parse_dns_query failed: {e}")))?;
        let response_bytes = handle_relay_query(&dns_msg, &self.handler_config, &*self.store);

        // 4. Parse response
        let response = Message::from_vec(&response_bytes)
            .map_err(|e| TransportError::DnsProtocol(format!("response parse failed: {e}")))?;

        if response.answers().is_empty() {
            return Ok(vec![]);
        }

        // 5. Parse comma-separated "seq_id,payload_len" entries from TXT records
        let mut entries = Vec::new();
        for answer in response.answers() {
            if let Some(RData::TXT(txt)) = answer.data().into() {
                let text: String = txt
                    .iter()
                    .map(|b| String::from_utf8_lossy(b).to_string())
                    .collect::<Vec<_>>()
                    .join("");

                let tokens: Vec<&str> = text.split(',').collect();
                let mut i = 0;
                while i + 1 < tokens.len() {
                    if let (Ok(seq_id), Ok(payload_len)) = (
                        tokens[i].trim().parse::<u64>(),
                        tokens[i + 1].trim().parse::<usize>(),
                    ) {
                        entries.push((seq_id, payload_len));
                    }
                    i += 2;
                }
            }
        }
        Ok(entries)
    }

    async fn recv_fetch(
        &self,
        channel: &str,
        seq_ids: &[u64],
    ) -> Result<(Vec<Vec<u8>>, Option<u64>), TransportError> {
        // 1. Build fetch query: f<nonce>.<seq1>-<seq2>-<seq3>.<channel>.<domain>.
        let nonce = format!("f{}", Self::generate_nonce());
        let seq_label = seq_ids
            .iter()
            .map(|id| id.to_string())
            .collect::<Vec<_>>()
            .join("-");
        let full_name = format!(
            "{}.{}.{}.{}.",
            nonce, seq_label, channel, self.controlled_domain
        );
        let query_name = hickory_proto::rr::Name::from_ascii(&full_name)
            .map_err(|e| TransportError::DnsProtocol(format!("invalid DNS name: {e}")))?;

        // 2. Build DNS query with EDNS0
        let query_bytes =
            DnsTransport::build_dns_query(&query_name, hickory_proto::rr::RecordType::TXT, true)?;

        // 3. Parse through relay handler
        let dns_msg = parse_dns_query(&query_bytes)
            .map_err(|e| TransportError::DnsProtocol(format!("parse_dns_query failed: {e}")))?;
        let response_bytes = handle_relay_query(&dns_msg, &self.handler_config, &*self.store);

        // 4. Parse response, decode envelopes
        let response = Message::from_vec(&response_bytes)
            .map_err(|e| TransportError::DnsProtocol(format!("response parse failed: {e}")))?;

        if response.answers().is_empty() {
            return Ok((vec![], None));
        }

        let mut frames = Vec::new();
        let mut max_seq: Option<u64> = None;
        let mut received_seqs = Vec::new();

        for answer in response.answers() {
            if let Some(RData::TXT(txt)) = answer.data().into() {
                let text: String = txt
                    .iter()
                    .map(|b| String::from_utf8_lossy(b).to_string())
                    .collect::<Vec<_>>()
                    .join("");

                match decode_envelope(&text) {
                    Ok(parts) => {
                        max_seq =
                            Some(max_seq.map_or(parts.sequence, |m: u64| m.max(parts.sequence)));
                        received_seqs.push(parts.sequence);
                        frames.push(parts.payload);
                    }
                    Err(e) => {
                        return Err(TransportError::EnvelopeDecode(format!(
                            "decode_envelope failed: {e}"
                        )));
                    }
                }
            }
        }

        // Ack received sequences so the relay stops re-delivering them.
        if !received_seqs.is_empty() {
            self.store.ack_sequences(channel, &received_seqs);
        }

        Ok((frames, max_seq))
    }
}

#[tokio::test]
async fn full_relay_path_dns_sim_round_trip() {
    // --- 1. Shared RelayStore (in-process, no DNS) ---
    let store = Arc::new(RelayStore::new(Duration::from_secs(600), RealClock));

    // --- 2. Transports ---
    // Client SEND: RelayTransport (writes to store directly, like the real A query path)
    let client_send_transport: Arc<dyn TransportBackend> =
        Arc::new(RelayTransport::new(store.clone(), "client1".to_string()));
    // Client RECV: DnsSimTransport wrapped in DedupRecvTransport (exercises TXT encode/decode)
    let dns_sim = Arc::new(DnsSimTransport::new(store.clone(), "client1".to_string()));
    let client_recv_transport: Arc<dyn TransportBackend> =
        Arc::new(DedupRecvTransport::new(dns_sim));
    // Server: RelayTransport for both directions (reads/writes store directly)
    let server_transport: Arc<dyn TransportBackend> =
        Arc::new(RelayTransport::new(store.clone(), "server1".to_string()));

    // --- 3. X25519 keypairs + shared SessionKey ---
    let psk = Psk::from_bytes(vec![0xAB; 32]).unwrap();
    let (client_secret, client_public) = generate_keypair();
    let (server_secret, server_public) = generate_keypair();

    let client_shared = client_secret.diffie_hellman(&server_public);
    let server_shared = server_secret.diffie_hellman(&client_public);
    assert_eq!(client_shared.as_bytes(), server_shared.as_bytes());

    let session_key = derive_session_key(client_shared.as_bytes(), &psk).unwrap();
    let server_session_key = derive_session_key(server_shared.as_bytes(), &psk).unwrap();

    let session_id = SessionId(*b"test0001");

    // --- 4. VirtualDevice + smoltcp Interface pairs ---
    let client_ip: Ipv4Addr = "192.168.69.1".parse().unwrap();
    let server_ip: Ipv4Addr = "192.168.69.2".parse().unwrap();

    let client_mtu: usize = 72;
    let client_mss: usize = 32;
    let server_mtu: usize = 77;
    let server_mss: usize = 37;

    let server_port: u16 = 4321;
    let client_port: u16 = 49152;

    let client_tuning = SmolTuningConfig {
        window_segments: 4,
        ..SmolTuningConfig::default()
    };
    let server_tuning = SmolTuningConfig {
        window_segments: 4,
        ..SmolTuningConfig::default()
    };

    let mut client_dev = VirtualDevice::new(client_mtu);
    let mut server_dev = VirtualDevice::new(server_mtu);

    let mut client_iface = create_smol_interface(&mut client_dev, client_ip, server_ip);
    let mut server_iface = create_smol_interface(&mut server_dev, server_ip, client_ip);

    // --- 5. Create sockets ---
    let client_socket = create_tcp_socket(&client_tuning, client_mss);
    let server_socket = create_tcp_socket(&server_tuning, server_mss);

    let mut client_sockets = SocketSet::new(vec![]);
    let mut server_sockets = SocketSet::new(vec![]);

    let client_handle = client_sockets.add(client_socket);
    let server_handle = server_sockets.add(server_socket);

    // --- 6. Server listens, client connects ---
    {
        let srv = server_sockets.get_mut::<tcp::Socket>(server_handle);
        srv.listen(IpEndpoint::new(
            IpAddress::from(smoltcp::wire::Ipv4Address::from(server_ip)),
            server_port,
        ))
        .expect("server listen failed");
    }
    {
        let cli = client_sockets.get_mut::<tcp::Socket>(client_handle);
        cli.connect(
            &mut client_iface.context(),
            IpEndpoint::new(
                IpAddress::from(smoltcp::wire::Ipv4Address::from(server_ip)),
                server_port,
            ),
            IpEndpoint::new(
                IpAddress::from(smoltcp::wire::Ipv4Address::from(client_ip)),
                client_port,
            ),
        )
        .expect("client connect failed");
    }

    // --- 7. Duplex streams ---
    let (client_user_stream, client_poll_stream) = tokio::io::duplex(1024);
    let (mut client_user_read, mut client_user_write) = tokio::io::split(client_user_stream);
    let (client_poll_read, client_poll_write) = tokio::io::split(client_poll_stream);

    let (server_user_stream, server_poll_stream) = tokio::io::duplex(1024);
    let (mut server_user_read, mut server_user_write) = tokio::io::split(server_user_stream);
    let (server_poll_read, server_poll_write) = tokio::io::split(server_poll_stream);

    let http_request = b"GET / HTTP/1.0\r\n\r\n";
    let http_response = b"HTTP/1.0 200 OK\r\n\r\nHello";

    // --- 8. Spawn client poll loop (send=RelayTransport, recv=DnsSimTransport) ---
    let client_session_id = session_id.clone();
    let client_poll_cfg = SmolPollConfig {
        poll_active: Duration::from_millis(10),
        poll_idle: Duration::from_millis(50),
        backoff_max: Duration::from_millis(50),
        query_interval: Duration::ZERO,
        no_edns: false,
    };

    let client_task = tokio::spawn(async move {
        let mut poll_read = client_poll_read;
        let mut poll_write = client_poll_write;
        let mut tx_seq: u32 = 0;
        run_session_poll_loop(
            &mut client_iface,
            &mut client_dev,
            &mut client_sockets,
            client_handle,
            client_send_transport,
            client_recv_transport,
            &client_session_id,
            &session_key,
            "u-test",
            "d-test",
            PollDirection::Client,
            &mut poll_read,
            &mut poll_write,
            &client_poll_cfg,
            "client1",
            &mut tx_seq,
        )
        .await
    });

    // --- 9. Spawn server poll loop (both directions use RelayTransport) ---
    let server_transport_send = server_transport.clone();
    let server_transport_recv = server_transport.clone();
    let server_session_id = SessionId(*b"test0001");
    let server_poll_cfg = SmolPollConfig {
        poll_active: Duration::from_millis(10),
        poll_idle: Duration::from_millis(50),
        backoff_max: Duration::from_millis(50),
        query_interval: Duration::ZERO,
        no_edns: false,
    };

    let server_task = tokio::spawn(async move {
        let mut poll_read = server_poll_read;
        let mut poll_write = server_poll_write;
        let mut tx_seq: u32 = 0;
        run_session_poll_loop(
            &mut server_iface,
            &mut server_dev,
            &mut server_sockets,
            server_handle,
            server_transport_send,
            server_transport_recv,
            &server_session_id,
            &server_session_key,
            "u-test",
            "d-test",
            PollDirection::Exit,
            &mut poll_read,
            &mut poll_write,
            &server_poll_cfg,
            "server1",
            &mut tx_seq,
        )
        .await
    });

    // --- 10. Mock TCP server: read request, write response, close ---
    let mock_server = tokio::spawn(async move {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut buf = vec![0u8; 1024];
        let mut total = 0;
        loop {
            let n = server_user_read.read(&mut buf[total..]).await.unwrap();
            if n == 0 {
                break;
            }
            total += n;
            if total >= 4 && &buf[total - 4..total] == b"\r\n\r\n" {
                break;
            }
        }
        assert_eq!(&buf[..total], http_request);
        server_user_write.write_all(http_response).await.unwrap();
        server_user_write.shutdown().await.unwrap();
    });

    // --- 11. Client: write request, read expected number of response bytes ---
    let expected_response = http_response.to_vec();
    let expected_len = expected_response.len();
    let client_io = tokio::spawn(async move {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        client_user_write.write_all(http_request).await.unwrap();
        client_user_write.shutdown().await.unwrap();

        let mut response = vec![0u8; expected_len];
        let mut total = 0;
        while total < expected_len {
            let n = client_user_read.read(&mut response[total..]).await.unwrap();
            if n == 0 {
                break;
            }
            total += n;
        }
        response[..total].to_vec()
    });

    // --- 12. Wait with timeout ---
    let result = tokio::time::timeout(Duration::from_secs(10), async {
        let response = client_io.await.expect("client IO task panicked");
        mock_server.await.expect("mock server task panicked");
        response
    })
    .await;

    client_task.abort();
    server_task.abort();

    let response = result.expect("test timed out after 10 seconds");
    assert_eq!(
        String::from_utf8_lossy(&response),
        "HTTP/1.0 200 OK\r\n\r\nHello",
        "client did not receive the expected HTTP response via DNS sim path"
    );
}


#[tokio::test]
async fn full_relay_path_udp_loopback() {
    // --- 1. Shared RelayStore ---
    let store: SharedRelayStore = Arc::new(RelayStore::new(Duration::from_secs(600), RealClock));

    // --- 2. Bind a real UDP socket for the DNS listener ---
    let listener_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let listener_addr = listener_socket.local_addr().unwrap();

    // --- 3. Spawn DNS listener task ---
    let handler_config = HandlerRelayConfig {
        controlled_domain: "relay.test.com".to_string(),
        ..HandlerRelayConfig::default()
    };
    let store_for_listener = store.clone();
    let listener_task = tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        loop {
            let (len, src) = match listener_socket.recv_from(&mut buf).await {
                Ok(v) => v,
                Err(_) => break,
            };
            let packet = &buf[..len];
            let response = match parse_dns_query(packet) {
                Ok(query) => handle_relay_query(&query, &handler_config, &*store_for_listener),
                Err(_) => continue,
            };
            let _ = listener_socket.send_to(&response, src).await;
        }
    });

    // --- 4. Client transports: real DnsTransport over UDP loopback ---
    let client_send_transport: Arc<dyn dns_socks_proxy::transport::TransportBackend> = Arc::new(
        DnsTransport::new(listener_addr, "relay.test.com".to_string())
            .await
            .unwrap()
            .with_query_timeout(Duration::from_millis(500)),
    );
    let client_recv_inner: Arc<dyn dns_socks_proxy::transport::TransportBackend> = Arc::new(
        DnsTransport::new(listener_addr, "relay.test.com".to_string())
            .await
            .unwrap()
            .with_query_timeout(Duration::from_millis(500))
            .with_edns(true),
    );
    let client_recv_transport: Arc<dyn dns_socks_proxy::transport::TransportBackend> =
        Arc::new(DedupRecvTransport::new(client_recv_inner));

    // --- 5. Server transports: RelayTransport (in-process, same as working tests) ---
    let server_transport: Arc<dyn dns_socks_proxy::transport::TransportBackend> =
        Arc::new(RelayTransport::new(store.clone(), "server1".to_string()));

    // --- 6. X25519 keypairs + shared SessionKey ---
    let psk = Psk::from_bytes(vec![0xAB; 32]).unwrap();
    let (client_secret, client_public) = generate_keypair();
    let (server_secret, server_public) = generate_keypair();

    let client_shared = client_secret.diffie_hellman(&server_public);
    let server_shared = server_secret.diffie_hellman(&client_public);
    assert_eq!(client_shared.as_bytes(), server_shared.as_bytes());

    let session_key = derive_session_key(client_shared.as_bytes(), &psk).unwrap();
    let server_session_key = derive_session_key(server_shared.as_bytes(), &psk).unwrap();

    let session_id = SessionId(*b"test0001");

    // --- 7. VirtualDevice + smoltcp Interface pairs ---
    let client_ip: Ipv4Addr = "192.168.69.1".parse().unwrap();
    let server_ip: Ipv4Addr = "192.168.69.2".parse().unwrap();

    let client_mtu: usize = 72;
    let client_mss: usize = 32;
    let server_mtu: usize = 77;
    let server_mss: usize = 37;

    let server_port: u16 = 4321;
    let client_port: u16 = 49152;

    let client_tuning = SmolTuningConfig {
        window_segments: 4,
        ..SmolTuningConfig::default()
    };
    let server_tuning = SmolTuningConfig {
        window_segments: 4,
        ..SmolTuningConfig::default()
    };

    let mut client_dev = VirtualDevice::new(client_mtu);
    let mut server_dev = VirtualDevice::new(server_mtu);

    let mut client_iface = create_smol_interface(&mut client_dev, client_ip, server_ip);
    let mut server_iface = create_smol_interface(&mut server_dev, server_ip, client_ip);

    // --- 8. Create sockets ---
    let client_socket = create_tcp_socket(&client_tuning, client_mss);
    let server_socket = create_tcp_socket(&server_tuning, server_mss);

    let mut client_sockets = SocketSet::new(vec![]);
    let mut server_sockets = SocketSet::new(vec![]);

    let client_handle = client_sockets.add(client_socket);
    let server_handle = server_sockets.add(server_socket);

    // --- 9. Server listens, client connects ---
    {
        let srv = server_sockets.get_mut::<tcp::Socket>(server_handle);
        srv.listen(IpEndpoint::new(
            IpAddress::from(smoltcp::wire::Ipv4Address::from(server_ip)),
            server_port,
        ))
        .expect("server listen failed");
    }
    {
        let cli = client_sockets.get_mut::<tcp::Socket>(client_handle);
        cli.connect(
            &mut client_iface.context(),
            IpEndpoint::new(
                IpAddress::from(smoltcp::wire::Ipv4Address::from(server_ip)),
                server_port,
            ),
            IpEndpoint::new(
                IpAddress::from(smoltcp::wire::Ipv4Address::from(client_ip)),
                client_port,
            ),
        )
        .expect("client connect failed");
    }

    // --- 10. Duplex streams ---
    let (client_user_stream, client_poll_stream) = tokio::io::duplex(1024);
    let (mut client_user_read, mut client_user_write) = tokio::io::split(client_user_stream);
    let (client_poll_read, client_poll_write) = tokio::io::split(client_poll_stream);

    let (server_user_stream, server_poll_stream) = tokio::io::duplex(1024);
    let (mut server_user_read, mut server_user_write) = tokio::io::split(server_user_stream);
    let (server_poll_read, server_poll_write) = tokio::io::split(server_poll_stream);

    let http_request = b"GET / HTTP/1.0\r\n\r\n";
    let http_response = b"HTTP/1.0 200 OK\r\n\r\nHello";

    // --- 11. Spawn client poll loop (send=DnsTransport, recv=DnsTransport+Dedup) ---
    let client_session_id = session_id.clone();
    let client_poll_cfg = SmolPollConfig {
        poll_active: Duration::from_millis(10),
        poll_idle: Duration::from_millis(50),
        backoff_max: Duration::from_millis(50),
        query_interval: Duration::ZERO,
        no_edns: false,
    };

    let client_task = tokio::spawn(async move {
        let mut poll_read = client_poll_read;
        let mut poll_write = client_poll_write;
        let mut tx_seq: u32 = 0;
        run_session_poll_loop(
            &mut client_iface,
            &mut client_dev,
            &mut client_sockets,
            client_handle,
            client_send_transport,
            client_recv_transport,
            &client_session_id,
            &session_key,
            "u-test",
            "d-test",
            PollDirection::Client,
            &mut poll_read,
            &mut poll_write,
            &client_poll_cfg,
            "client1",
            &mut tx_seq,
        )
        .await
    });

    // --- 12. Spawn server poll loop (both directions use RelayTransport) ---
    let server_transport_send = server_transport.clone();
    let server_transport_recv = server_transport.clone();
    let server_session_id = SessionId(*b"test0001");
    let server_poll_cfg = SmolPollConfig {
        poll_active: Duration::from_millis(10),
        poll_idle: Duration::from_millis(50),
        backoff_max: Duration::from_millis(50),
        query_interval: Duration::ZERO,
        no_edns: false,
    };

    let server_task = tokio::spawn(async move {
        let mut poll_read = server_poll_read;
        let mut poll_write = server_poll_write;
        let mut tx_seq: u32 = 0;
        run_session_poll_loop(
            &mut server_iface,
            &mut server_dev,
            &mut server_sockets,
            server_handle,
            server_transport_send,
            server_transport_recv,
            &server_session_id,
            &server_session_key,
            "u-test",
            "d-test",
            PollDirection::Exit,
            &mut poll_read,
            &mut poll_write,
            &server_poll_cfg,
            "server1",
            &mut tx_seq,
        )
        .await
    });

    // --- 13. Mock TCP server: read request, write response, close ---
    let mock_server = tokio::spawn(async move {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut buf = vec![0u8; 1024];
        let mut total = 0;
        loop {
            let n = server_user_read.read(&mut buf[total..]).await.unwrap();
            if n == 0 {
                break;
            }
            total += n;
            if total >= 4 && &buf[total - 4..total] == b"\r\n\r\n" {
                break;
            }
        }
        assert_eq!(&buf[..total], http_request);
        server_user_write.write_all(http_response).await.unwrap();
        server_user_write.shutdown().await.unwrap();
    });

    // --- 14. Client: write request, read expected number of response bytes ---
    let expected_response = http_response.to_vec();
    let expected_len = expected_response.len();
    let client_io = tokio::spawn(async move {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        client_user_write.write_all(http_request).await.unwrap();
        client_user_write.shutdown().await.unwrap();

        let mut response = vec![0u8; expected_len];
        let mut total = 0;
        while total < expected_len {
            let n = client_user_read.read(&mut response[total..]).await.unwrap();
            if n == 0 {
                break;
            }
            total += n;
        }
        response[..total].to_vec()
    });

    // --- 15. Wait with timeout ---
    let result = tokio::time::timeout(Duration::from_secs(15), async {
        let response = client_io.await.expect("client IO task panicked");
        mock_server.await.expect("mock server task panicked");
        response
    })
    .await;

    // Abort all background tasks.
    client_task.abort();
    server_task.abort();
    listener_task.abort();

    let response = result.expect("test timed out after 15 seconds");
    assert_eq!(
        String::from_utf8_lossy(&response),
        "HTTP/1.0 200 OK\r\n\r\nHello",
        "client did not receive the expected HTTP response via UDP loopback path"
    );
}


/// Reproduces the stale slot accumulation bug.
///
/// Uses `DnsSimTransport` for the client's recv path (TXT response path) with
/// a 512-byte payload at MTU 72/77. At MSS 32, that's ~16 data segments, each
/// creating a unique sender slot in the RelayStore. The TXT response returns
/// ALL accumulated unique-sender slots on every poll — including stale ones
/// that smoltcp already processed — causing the connection to stall or corrupt.
#[tokio::test]
async fn dns_sim_path_stale_slots() {
    // --- 1. Shared RelayStore ---
    let store = Arc::new(RelayStore::new(Duration::from_secs(600), RealClock));

    // --- 2. Transports ---
    let client_send_transport: Arc<dyn TransportBackend> =
        Arc::new(RelayTransport::new(store.clone(), "client1".to_string()));
    let client_recv_transport: Arc<dyn TransportBackend> =
        Arc::new(DnsSimTransport::new(store.clone(), "client1".to_string()));
    let server_transport: Arc<dyn TransportBackend> =
        Arc::new(RelayTransport::new(store.clone(), "server1".to_string()));

    // --- 3. X25519 keypairs + shared SessionKey ---
    let psk = Psk::from_bytes(vec![0xAB; 32]).unwrap();
    let (client_secret, client_public) = generate_keypair();
    let (server_secret, server_public) = generate_keypair();
    let client_shared = client_secret.diffie_hellman(&server_public);
    let server_shared = server_secret.diffie_hellman(&client_public);
    assert_eq!(client_shared.as_bytes(), server_shared.as_bytes());
    let session_key = derive_session_key(client_shared.as_bytes(), &psk).unwrap();
    let server_session_key = derive_session_key(server_shared.as_bytes(), &psk).unwrap();
    let session_id = SessionId(*b"test0001");

    // --- 4. VirtualDevice + smoltcp Interface pairs ---
    let client_ip: Ipv4Addr = "192.168.69.1".parse().unwrap();
    let server_ip: Ipv4Addr = "192.168.69.2".parse().unwrap();
    let client_mtu: usize = 72;
    let client_mss: usize = 32;
    let server_mtu: usize = 77;
    let server_mss: usize = 37;
    let server_port: u16 = 4321;
    let client_port: u16 = 49152;

    let mut client_dev = VirtualDevice::new(client_mtu);
    let mut server_dev = VirtualDevice::new(server_mtu);
    let mut client_iface = create_smol_interface(&mut client_dev, client_ip, server_ip);
    let mut server_iface = create_smol_interface(&mut server_dev, server_ip, client_ip);

    // --- 5. Create sockets with 60s timeout for large payloads ---
    let cli_buf = (client_mss * 4).max(384);
    let mut client_socket = smoltcp::socket::tcp::Socket::new(
        smoltcp::socket::tcp::SocketBuffer::new(vec![0u8; cli_buf]),
        smoltcp::socket::tcp::SocketBuffer::new(vec![0u8; cli_buf]),
    );
    client_socket.set_timeout(Some(smoltcp::time::Duration::from_secs(60)));
    client_socket.set_nagle_enabled(false);

    let srv_buf = (server_mss * 4).max(384);
    let mut server_socket = smoltcp::socket::tcp::Socket::new(
        smoltcp::socket::tcp::SocketBuffer::new(vec![0u8; srv_buf]),
        smoltcp::socket::tcp::SocketBuffer::new(vec![0u8; srv_buf]),
    );
    server_socket.set_timeout(Some(smoltcp::time::Duration::from_secs(60)));
    server_socket.set_nagle_enabled(false);

    let mut client_sockets = SocketSet::new(vec![]);
    let mut server_sockets = SocketSet::new(vec![]);

    let client_handle = client_sockets.add(client_socket);
    let server_handle = server_sockets.add(server_socket);

    // --- 6. Server listens, client connects ---
    {
        let srv = server_sockets.get_mut::<tcp::Socket>(server_handle);
        srv.listen(IpEndpoint::new(
            IpAddress::from(smoltcp::wire::Ipv4Address::from(server_ip)),
            server_port,
        ))
        .expect("server listen failed");
    }
    {
        let cli = client_sockets.get_mut::<tcp::Socket>(client_handle);
        cli.connect(
            &mut client_iface.context(),
            IpEndpoint::new(
                IpAddress::from(smoltcp::wire::Ipv4Address::from(server_ip)),
                server_port,
            ),
            IpEndpoint::new(
                IpAddress::from(smoltcp::wire::Ipv4Address::from(client_ip)),
                client_port,
            ),
        )
        .expect("client connect failed");
    }

    // --- 7. Duplex streams (sized for 512-byte payloads) ---
    let payload_size: usize = 512;
    let (client_user_stream, client_poll_stream) = tokio::io::duplex(payload_size + 256);
    let (mut client_user_read, mut client_user_write) = tokio::io::split(client_user_stream);
    let (client_poll_read, client_poll_write) = tokio::io::split(client_poll_stream);

    let (server_user_stream, server_poll_stream) = tokio::io::duplex(payload_size + 256);
    let (mut server_user_read, mut server_user_write) = tokio::io::split(server_user_stream);
    let (server_poll_read, server_poll_write) = tokio::io::split(server_poll_stream);

    // Deterministic 512-byte payloads.
    let request_payload: Vec<u8> = (0..payload_size).map(|i| (i % 251) as u8).collect();
    let response_payload: Vec<u8> = (0..payload_size).map(|i| ((i + 37) % 251) as u8).collect();

    // --- 8. Spawn client poll loop (send=RelayTransport, recv=DnsSimTransport) ---
    let client_session_id = session_id.clone();
    let client_poll_cfg = SmolPollConfig {
        poll_active: Duration::from_millis(10),
        poll_idle: Duration::from_millis(50),
        backoff_max: Duration::from_millis(50),
        query_interval: Duration::ZERO,
        no_edns: false,
    };

    let client_task = tokio::spawn(async move {
        let mut poll_read = client_poll_read;
        let mut poll_write = client_poll_write;
        let mut tx_seq: u32 = 0;
        run_session_poll_loop(
            &mut client_iface,
            &mut client_dev,
            &mut client_sockets,
            client_handle,
            client_send_transport,
            client_recv_transport,
            &client_session_id,
            &session_key,
            "u-test",
            "d-test",
            PollDirection::Client,
            &mut poll_read,
            &mut poll_write,
            &client_poll_cfg,
            "client1",
            &mut tx_seq,
        )
        .await
    });

    // --- 9. Spawn server poll loop (both directions use RelayTransport) ---
    let server_transport_send = server_transport.clone();
    let server_transport_recv = server_transport.clone();
    let server_session_id = SessionId(*b"test0001");
    let server_poll_cfg = SmolPollConfig {
        poll_active: Duration::from_millis(10),
        poll_idle: Duration::from_millis(50),
        backoff_max: Duration::from_millis(50),
        query_interval: Duration::ZERO,
        no_edns: false,
    };

    let server_task = tokio::spawn(async move {
        let mut poll_read = server_poll_read;
        let mut poll_write = server_poll_write;
        let mut tx_seq: u32 = 0;
        run_session_poll_loop(
            &mut server_iface,
            &mut server_dev,
            &mut server_sockets,
            server_handle,
            server_transport_send,
            server_transport_recv,
            &server_session_id,
            &server_session_key,
            "u-test",
            "d-test",
            PollDirection::Exit,
            &mut poll_read,
            &mut poll_write,
            &server_poll_cfg,
            "server1",
            &mut tx_seq,
        )
        .await
    });

    // --- 10. Mock TCP server: read request, write response, close ---
    let request_expected = request_payload.clone();
    let response_to_send = response_payload.clone();
    let mock_server = tokio::spawn(async move {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut buf = vec![0u8; payload_size + 256];
        let mut total = 0;
        let expected_len = request_expected.len();
        while total < expected_len {
            let n = server_user_read.read(&mut buf[total..]).await.unwrap();
            if n == 0 {
                break;
            }
            total += n;
        }
        assert_eq!(&buf[..total], &request_expected[..], "server received wrong request data");
        server_user_write.write_all(&response_to_send).await.unwrap();
        server_user_write.shutdown().await.unwrap();
    });

    // --- 11. Client: write request, read response ---
    let request_to_send = request_payload.clone();
    let expected_response = response_payload.clone();
    let expected_len = expected_response.len();
    let client_io = tokio::spawn(async move {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        client_user_write.write_all(&request_to_send).await.unwrap();
        client_user_write.shutdown().await.unwrap();

        let mut response = vec![0u8; expected_len];
        let mut total = 0;
        while total < expected_len {
            let n = client_user_read.read(&mut response[total..]).await.unwrap();
            if n == 0 {
                break;
            }
            total += n;
        }
        response[..total].to_vec()
    });

    // --- 12. Wait with 10-second timeout ---
    let result = tokio::time::timeout(Duration::from_secs(5), async {
        let response = client_io.await.expect("client IO task panicked");
        mock_server.await.expect("mock server task panicked");
        response
    })
    .await;

    client_task.abort();
    server_task.abort();

    let response = result.expect(
        "test timed out after 5 seconds",
    );
    assert_eq!(
        response, expected_response,
        "client did not receive the expected 512-byte response via DNS sim path \
         (stale slots may have corrupted the TCP stream)",
    );
}


// ---------------------------------------------------------------------------
// LossyTransport — adds configurable latency AND packet loss
// ---------------------------------------------------------------------------

/// A `TransportBackend` wrapper that adds configurable latency and packet loss
/// to transport calls, simulating adverse real-world network conditions.
struct LossyTransport {
    inner: Arc<dyn TransportBackend>,
    latency: Duration,
    /// Probability of recv_frames returning empty (simulating packet loss).
    /// Value 0-100 representing percentage.
    loss_pct: u8,
}

#[async_trait]
impl TransportBackend for LossyTransport {
    async fn send_frame(
        &self,
        channel: &str,
        sender_id: &str,
        frame_bytes: &[u8],
    ) -> Result<(), TransportError> {
        // Sends add latency but NO loss — in the real system, DnsTransport
        // retries sends internally. Loss only applies to recv_frames (polls).
        tokio::time::sleep(self.latency).await;
        self.inner.send_frame(channel, sender_id, frame_bytes).await
    }

    async fn recv_frames(
        &self,
        channel: &str,
        cursor: Option<u64>,
    ) -> Result<(Vec<Vec<u8>>, Option<u64>), TransportError> {
        tokio::time::sleep(self.latency).await;
        // Simulate packet loss: return empty as if the DNS response was lost.
        if rand::thread_rng().gen_range(0..100) < self.loss_pct {
            return Ok((vec![], None));
        }
        self.inner.recv_frames(channel, cursor).await
    }

    async fn query_status(&self, channel: &str) -> Result<usize, TransportError> {
        self.inner.query_status(channel).await
    }
}

// ---------------------------------------------------------------------------
// run_relay_with_network_sim — helper for the proptest
// ---------------------------------------------------------------------------

async fn run_relay_with_network_sim(
    client_send_latency: Duration,
    client_recv_latency: Duration,
    server_latency: Duration,
    client_send_loss_pct: u8,
    client_recv_loss_pct: u8,
    server_loss_pct: u8,
    client_mtu: usize,
    server_mtu: usize,
    payload_size: usize,
) {
    // --- 1. Shared RelayStore (in-process, no DNS) ---
    let store = Arc::new(RelayStore::new(Duration::from_secs(600), RealClock));

    // --- 2. Two RelayTransport instances, wrapped in LossyTransport ---
    let client_send_transport: Arc<dyn TransportBackend> = Arc::new(LossyTransport {
        inner: Arc::new(RelayTransport::new(store.clone(), "client1".to_string())),
        latency: client_send_latency,
        loss_pct: client_send_loss_pct,
    });
    let client_recv_transport: Arc<dyn TransportBackend> = Arc::new(LossyTransport {
        inner: Arc::new(RelayTransport::new(store.clone(), "client1".to_string())),
        latency: client_recv_latency,
        loss_pct: client_recv_loss_pct,
    });
    let server_send_transport: Arc<dyn TransportBackend> = Arc::new(LossyTransport {
        inner: Arc::new(RelayTransport::new(store.clone(), "server1".to_string())),
        latency: server_latency,
        loss_pct: server_loss_pct,
    });
    let server_recv_transport: Arc<dyn TransportBackend> = Arc::new(LossyTransport {
        inner: Arc::new(RelayTransport::new(store.clone(), "server1".to_string())),
        latency: server_latency,
        loss_pct: server_loss_pct,
    });

    // --- 3. X25519 keypairs + shared SessionKey ---
    let psk = Psk::from_bytes(vec![0xAB; 32]).unwrap();
    let (client_secret, client_public) = generate_keypair();
    let (server_secret, server_public) = generate_keypair();

    let client_shared = client_secret.diffie_hellman(&server_public);
    let server_shared = server_secret.diffie_hellman(&client_public);

    let session_key = derive_session_key(client_shared.as_bytes(), &psk).unwrap();
    let server_session_key = derive_session_key(server_shared.as_bytes(), &psk).unwrap();

    let session_id = SessionId(*b"test0001");

    // --- 4. VirtualDevice + smoltcp Interface pairs (fuzzed MTUs) ---
    let client_ip: Ipv4Addr = "192.168.69.1".parse().unwrap();
    let server_ip: Ipv4Addr = "192.168.69.2".parse().unwrap();

    // MSS = MTU - 40 (20 IP + 20 TCP), minimum 1
    let client_mss = client_mtu.saturating_sub(40).max(1);
    let server_mss = server_mtu.saturating_sub(40).max(1);

    let server_port: u16 = 4321;
    let client_port: u16 = 49152;

    let mut client_dev = VirtualDevice::new(client_mtu);
    let mut server_dev = VirtualDevice::new(server_mtu);

    let mut client_iface = create_smol_interface(&mut client_dev, client_ip, server_ip);
    let mut server_iface = create_smol_interface(&mut server_dev, server_ip, client_ip);

    // --- 5. Create sockets with 6-second timeout ---
    let cli_buf_size = (client_mss * 4).max(384);
    let rx_buf = smoltcp::socket::tcp::SocketBuffer::new(vec![0u8; cli_buf_size]);
    let tx_buf = smoltcp::socket::tcp::SocketBuffer::new(vec![0u8; cli_buf_size]);
    let mut client_socket = smoltcp::socket::tcp::Socket::new(rx_buf, tx_buf);
    client_socket.set_timeout(Some(smoltcp::time::Duration::from_secs(6)));
    client_socket.set_nagle_enabled(false);

    let srv_buf_size = (server_mss * 4).max(384);
    let srv_rx_buf = smoltcp::socket::tcp::SocketBuffer::new(vec![0u8; srv_buf_size]);
    let srv_tx_buf = smoltcp::socket::tcp::SocketBuffer::new(vec![0u8; srv_buf_size]);
    let mut server_socket = smoltcp::socket::tcp::Socket::new(srv_rx_buf, srv_tx_buf);
    server_socket.set_timeout(Some(smoltcp::time::Duration::from_secs(6)));
    server_socket.set_nagle_enabled(false);

    let mut client_sockets = SocketSet::new(vec![]);
    let mut server_sockets = SocketSet::new(vec![]);

    let client_handle = client_sockets.add(client_socket);
    let server_handle = server_sockets.add(server_socket);

    // --- 6. Server listens, client connects ---
    {
        let srv = server_sockets.get_mut::<tcp::Socket>(server_handle);
        srv.listen(IpEndpoint::new(
            IpAddress::from(smoltcp::wire::Ipv4Address::from(server_ip)),
            server_port,
        ))
        .expect("server listen failed");
    }
    {
        let cli = client_sockets.get_mut::<tcp::Socket>(client_handle);
        cli.connect(
            &mut client_iface.context(),
            IpEndpoint::new(
                IpAddress::from(smoltcp::wire::Ipv4Address::from(server_ip)),
                server_port,
            ),
            IpEndpoint::new(
                IpAddress::from(smoltcp::wire::Ipv4Address::from(client_ip)),
                client_port,
            ),
        )
        .expect("client connect failed");
    }

    // --- 7. Duplex streams (sized for larger payloads) ---
    let (client_user_stream, client_poll_stream) = tokio::io::duplex(payload_size + 256);
    let (mut client_user_read, mut client_user_write) = tokio::io::split(client_user_stream);
    let (client_poll_read, client_poll_write) = tokio::io::split(client_poll_stream);

    let (server_user_stream, server_poll_stream) = tokio::io::duplex(payload_size + 256);
    let (mut server_user_read, mut server_user_write) = tokio::io::split(server_user_stream);
    let (server_poll_read, server_poll_write) = tokio::io::split(server_poll_stream);

    // Generate deterministic request/response payloads of the specified size.
    let request_payload: Vec<u8> = (0..payload_size).map(|i| (i % 251) as u8).collect();
    let response_payload: Vec<u8> = (0..payload_size).map(|i| ((i + 37) % 251) as u8).collect();

    // --- 8. Spawn client poll loop ---
    let client_session_id = session_id.clone();
    let client_poll_cfg = SmolPollConfig {
        poll_active: Duration::from_millis(50),
        poll_idle: Duration::from_millis(200),
        backoff_max: Duration::from_millis(200),
        query_interval: Duration::ZERO,
        no_edns: false,
    };

    let client_task = tokio::spawn(async move {
        let mut poll_read = client_poll_read;
        let mut poll_write = client_poll_write;
        let mut tx_seq: u32 = 0;
        run_session_poll_loop(
            &mut client_iface,
            &mut client_dev,
            &mut client_sockets,
            client_handle,
            client_send_transport,
            client_recv_transport,
            &client_session_id,
            &session_key,
            "u-test",
            "d-test",
            PollDirection::Client,
            &mut poll_read,
            &mut poll_write,
            &client_poll_cfg,
            "client1",
            &mut tx_seq,
        )
        .await
    });

    // --- 9. Spawn server poll loop ---
    let server_session_id = SessionId(*b"test0001");
    let server_poll_cfg = SmolPollConfig {
        poll_active: Duration::from_millis(50),
        poll_idle: Duration::from_millis(200),
        backoff_max: Duration::from_millis(200),
        query_interval: Duration::ZERO,
        no_edns: false,
    };

    let server_task = tokio::spawn(async move {
        let mut poll_read = server_poll_read;
        let mut poll_write = server_poll_write;
        let mut tx_seq: u32 = 0;
        run_session_poll_loop(
            &mut server_iface,
            &mut server_dev,
            &mut server_sockets,
            server_handle,
            server_send_transport,
            server_recv_transport,
            &server_session_id,
            &server_session_key,
            "u-test",
            "d-test",
            PollDirection::Exit,
            &mut poll_read,
            &mut poll_write,
            &server_poll_cfg,
            "server1",
            &mut tx_seq,
        )
        .await
    });

    // --- 10. Mock TCP server: read request, write response, close ---
    let request_expected = request_payload.clone();
    let response_to_send = response_payload.clone();
    let mock_server = tokio::spawn(async move {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut buf = vec![0u8; payload_size + 256];
        let mut total = 0;
        let expected_len = request_expected.len();
        while total < expected_len {
            let n = server_user_read.read(&mut buf[total..]).await.unwrap();
            if n == 0 {
                break;
            }
            total += n;
        }
        assert_eq!(&buf[..total], &request_expected[..], "server received wrong request data");
        server_user_write.write_all(&response_to_send).await.unwrap();
        server_user_write.shutdown().await.unwrap();
    });

    // --- 11. Client: write request, read response ---
    let request_to_send = request_payload.clone();
    let expected_response = response_payload.clone();
    let expected_len = expected_response.len();
    let client_io = tokio::spawn(async move {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        client_user_write.write_all(&request_to_send).await.unwrap();
        client_user_write.shutdown().await.unwrap();

        let mut response = vec![0u8; expected_len];
        let mut total = 0;
        while total < expected_len {
            let n = client_user_read.read(&mut response[total..]).await.unwrap();
            if n == 0 {
                break;
            }
            total += n;
        }
        response[..total].to_vec()
    });

    // --- 12. Wait with 30-second timeout ---
    let result = tokio::time::timeout(Duration::from_secs(30), async {
        let response = client_io.await.expect("client IO task panicked");
        mock_server.await.expect("mock server task panicked");
        response
    })
    .await;

    client_task.abort();
    server_task.abort();

    let response = result.expect("test timed out after 30 seconds");
    assert_eq!(
        response,
        expected_response,
        "client did not receive the expected response ({} bytes) under adverse conditions",
        expected_response.len(),
    );
}

// ---------------------------------------------------------------------------
// Property-based test: relay path survives adverse network conditions
// ---------------------------------------------------------------------------

use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10))]
    #[test]
    fn relay_path_survives_adverse_network(
        client_recv_latency_ms in 0u64..=100,
        client_send_latency_ms in 0u64..=50,
        server_latency_ms in 0u64..=30,
        client_send_loss_pct in 0u8..=0,
        client_recv_loss_pct in 0u8..=15,
        server_loss_pct in 0u8..=10,
        // MTU range: 60 (bare minimum for IP+TCP) to 120 (typical DNS tunnel)
        client_mtu in 60usize..=120,
        server_mtu in 60usize..=120,
        // Payload: 64 to 512 bytes — enough to require many segments at small MTUs
        payload_size in 64usize..=512,
    ) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            run_relay_with_network_sim(
                Duration::from_millis(client_send_latency_ms),
                Duration::from_millis(client_recv_latency_ms),
                Duration::from_millis(server_latency_ms),
                client_send_loss_pct,
                client_recv_loss_pct,
                server_loss_pct,
                client_mtu,
                server_mtu,
                payload_size,
            ).await;
        });
    }
}
