# Requirements Document

## Introduction

This feature builds a SOCKS5 proxy system that tunnels TCP traffic over DNS using the existing DNS Message Broker as its transport layer. The system consists of two cooperating binaries:

1. **SOCKS Client** — runs on a workstation, exposes a standard SOCKS5 interface on localhost. Applications (browsers, curl, etc.) connect to it as a normal SOCKS5 proxy. Instead of making TCP connections directly, the SOCKS Client fragments outbound TCP data into small datagrams, encodes them as DNS messages, and sends them through the Broker to the Exit Node. Inbound data arrives the same way in reverse.

2. **Exit Node** — runs alongside (or near) the Broker. It polls the Broker for inbound datagrams from the SOCKS Client, reassembles them, makes the actual TCP connections to target hosts on behalf of the client, and sends response data back through the Broker.

The Broker itself is unchanged — it remains a simple per-channel FIFO datagram store. All complexity around fragmentation, reassembly, ordering, reliability, and session management lives in the SOCKS Client and Exit Node.

### Key Constraints

- The Broker transports atomic datagrams of ~80–131 raw bytes each (depending on label lengths). TCP streams must be chunked to fit.
- DNS is inherently unreliable and high-latency. The tunnel protocol must handle packet loss, reordering, and duplication.
- The Broker's FIFO queues are per-channel with a configurable cap (default 100 messages). Flow control is needed to avoid overrunning the queue.
- Multiple concurrent SOCKS connections must be multiplexed over the DNS channel without interference.

### Scope Boundaries

- Only the SOCKS5 CONNECT command is in scope. BIND and UDP ASSOCIATE are out of scope.
- Authentication is limited to SOCKS5 NO AUTHENTICATION REQUIRED. Username/password auth is out of scope.
- The Broker is not modified by this feature. The SOCKS Client and Exit Node are new, separate binaries that use the Broker as a library dependency (for encoding utilities) and communicate with it over DNS.
- Tunnel payload encryption is in scope using a PSK-authenticated key exchange (X25519 Diffie-Hellman) to derive per-session symmetric keys (ChaCha20-Poly1305). Certificate-based PKI and multi-party key distribution are out of scope.

## Glossary

- **SOCKS_Client**: The proxy binary that runs on the user's workstation, accepts SOCKS5 connections on localhost, and tunnels traffic over DNS through the Broker.
- **Exit_Node**: The binary that runs near the Broker, receives tunneled requests from the SOCKS_Client via DNS channels, makes actual TCP connections to target hosts, and returns responses over DNS.
- **Broker**: The existing DNS Message Broker daemon that stores and forwards datagrams in per-channel FIFO queues (unchanged by this feature).
- **Session**: A logical bidirectional TCP tunnel between the SOCKS_Client and Exit_Node corresponding to a single SOCKS5 CONNECT request. Each Session has a unique Session_ID.
- **Session_ID**: A short unique identifier (fitting within a DNS label, max 16 alphanumeric characters) assigned by the SOCKS_Client to distinguish concurrent tunneled connections.
- **Upstream_Channel**: The Broker channel used to send data from the SOCKS_Client to the Exit_Node. Named by convention using the Session_ID (e.g., `s-<session_id>-up`).
- **Downstream_Channel**: The Broker channel used to send data from the Exit_Node back to the SOCKS_Client. Named by convention using the Session_ID (e.g., `s-<session_id>-dn`).
- **Control_Channel**: A well-known Broker channel used for session setup and teardown messages between the SOCKS_Client and Exit_Node (e.g., `ctl-<client_id>`).
- **Frame**: A tunnel-layer datagram sent through the Broker. Each Frame contains a header (Session_ID, sequence number, frame type, flags) and a payload chunk. Frames are the unit of fragmentation.
- **Sequence_Number**: A per-session, per-direction monotonically increasing integer included in each Frame to enable ordering and duplicate detection.
- **Frame_Type**: An enumeration indicating the purpose of a Frame: DATA (payload chunk), ACK (acknowledgment), SYN (session open request), SYN-ACK (session open confirmation), FIN (session close), RST (session abort).
- **Reassembly_Buffer**: A per-session buffer in the SOCKS_Client and Exit_Node that collects received DATA Frames, reorders them by Sequence_Number, and delivers contiguous payload bytes to the TCP socket.
- **Controlled_Domain**: The DNS zone for which the Broker is authoritative (inherited from the Broker configuration).
- **Client_ID**: A short identifier for the SOCKS_Client instance, used as the sender_id when communicating with the Broker.
- **Payload_Budget**: The maximum raw bytes available per DNS message for Frame data, determined by the Broker's Payload Budget formula minus the Frame header overhead.
- **PSK**: Pre-Shared Key — a secret known to both the SOCKS_Client and Exit_Node, configured out-of-band. Used to authenticate the Diffie-Hellman key exchange during session setup.
- **Session_Key**: A symmetric encryption key derived per-session from an X25519 Diffie-Hellman exchange authenticated by the PSK. Used with ChaCha20-Poly1305 to encrypt and authenticate all DATA Frame payloads within a Session.
- **Nonce_Counter**: A per-session, per-direction monotonically increasing counter used as the nonce for ChaCha20-Poly1305 encryption. Tied to the Sequence_Number to prevent nonce reuse.
- **Transport_Backend**: An abstraction over how the Exit_Node communicates with the Broker. In DNS mode, it sends/receives DNS queries over UDP. In embedded mode, it calls the Broker's ChannelStore directly via in-process function calls, bypassing DNS serialization entirely.
- **Embedded_Mode**: A deployment mode where the Exit_Node runs the Broker's DNS server and ChannelStore in the same process, accessing the store directly for its own operations while still serving external DNS queries from SOCKS_Clients.
- **Standalone_Mode**: A deployment mode where the Exit_Node communicates with a separate Broker process over DNS, identical to how the SOCKS_Client communicates.

## Requirements

### Requirement 1: SOCKS5 Proxy Interface

**User Story:** As a user, I want the SOCKS_Client to expose a standard SOCKS5 proxy on localhost, so that I can configure any SOCKS5-capable application to tunnel traffic through DNS.

#### Acceptance Criteria

1. THE SOCKS_Client SHALL listen for TCP connections on a configurable local address and port (default: `127.0.0.1:1080`).
2. WHEN a client application connects, THE SOCKS_Client SHALL perform the SOCKS5 handshake as defined in RFC 1928, supporting the NO AUTHENTICATION REQUIRED method (method `0x00`).
3. WHEN a SOCKS5 CONNECT request is received, THE SOCKS_Client SHALL extract the target host (IPv4, IPv6, or domain name) and target port from the request.
4. WHEN a SOCKS5 CONNECT request specifies a command other than CONNECT (`0x01`), THE SOCKS_Client SHALL respond with a "Command not supported" reply (`0x07`) and close the connection.
5. IF the SOCKS5 handshake is malformed or uses an unsupported protocol version, THEN THE SOCKS_Client SHALL close the TCP connection.
6. WHEN a SOCKS5 CONNECT request is accepted, THE SOCKS_Client SHALL respond with a success reply (`0x00`) after the Exit_Node confirms the session is established.
7. IF the Exit_Node reports that the target host is unreachable, THEN THE SOCKS_Client SHALL respond with the appropriate SOCKS5 error reply code and close the connection.

### Requirement 2: Session Management

**User Story:** As a user, I want to open multiple concurrent connections through the proxy, so that I can browse normally with multiple tabs or applications.

#### Acceptance Criteria

1. WHEN a new SOCKS5 CONNECT request is accepted, THE SOCKS_Client SHALL generate a unique Session_ID for the connection.
2. THE SOCKS_Client SHALL send a SYN Frame on the Control_Channel containing the Session_ID, target host, and target port.
3. WHEN the Exit_Node receives a SYN Frame, THE Exit_Node SHALL attempt a TCP connection to the specified target host and port.
4. WHEN the Exit_Node successfully connects to the target, THE Exit_Node SHALL send a SYN-ACK Frame on the Control_Channel containing the Session_ID.
5. IF the Exit_Node fails to connect to the target within a configurable timeout (default: 10 seconds), THEN THE Exit_Node SHALL send a RST Frame on the Control_Channel containing the Session_ID and an error reason.
6. WHEN either side wants to close a session, THE closing side SHALL send a FIN Frame on the Control_Channel containing the Session_ID.
7. WHEN a FIN Frame is received, THE receiving side SHALL flush any remaining buffered data, close the associated TCP socket, and release session resources.
8. WHEN a RST Frame is received, THE receiving side SHALL immediately close the associated TCP socket and release session resources without flushing.
9. THE SOCKS_Client SHALL support at least 64 concurrent Sessions.
10. THE SOCKS_Client SHALL clean up Session resources (channels, buffers, sequence counters) when a Session ends, whether by FIN, RST, or local TCP socket closure.

### Requirement 3: Frame Protocol

**User Story:** As a developer, I want a well-defined frame format for tunnel datagrams, so that the SOCKS_Client and Exit_Node can reliably exchange data over the Broker's small-datagram transport.

#### Acceptance Criteria

1. THE Frame format SHALL consist of a fixed-size binary header followed by a variable-length payload.
2. THE Frame header SHALL contain the following fields: Session_ID (variable, length-prefixed), Sequence_Number (4 bytes, big-endian u32), Frame_Type (1 byte), and Flags (1 byte).
3. THE Frame_Type field SHALL support the following values: DATA (`0x01`), ACK (`0x02`), SYN (`0x03`), SYN-ACK (`0x04`), FIN (`0x05`), RST (`0x06`).
4. THE Frame payload for DATA Frames SHALL contain a chunk of the TCP stream being tunneled, sized to fit within the Payload_Budget after accounting for the Frame header.
5. THE Frame payload for SYN Frames SHALL contain the target address type (1 byte: `0x01` IPv4, `0x03` domain, `0x04` IPv6), the target address, and the target port (2 bytes, big-endian).
6. THE Frame_Encoder SHALL serialize Frame structs into byte sequences suitable for sending through the Broker.
7. THE Frame_Decoder SHALL deserialize byte sequences received from the Broker back into Frame structs.
8. FOR ALL valid Frame structs, encoding then decoding SHALL produce an equivalent Frame struct (round-trip property).

### Requirement 4: Reliable Ordered Delivery

**User Story:** As a user, I want my TCP connections to work correctly even though DNS is unreliable, so that web pages load completely and data transfers are not corrupted.

#### Acceptance Criteria

1. THE sender (SOCKS_Client or Exit_Node) SHALL assign a monotonically increasing Sequence_Number to each DATA Frame within a Session and direction.
2. THE receiver SHALL maintain a Reassembly_Buffer that reorders received DATA Frames by Sequence_Number and delivers contiguous payload bytes to the local TCP socket in order.
3. WHEN the receiver delivers data from the Reassembly_Buffer, THE receiver SHALL send an ACK Frame containing the highest contiguous Sequence_Number received.
4. WHEN the sender does not receive an ACK for a sent DATA Frame within a configurable retransmission timeout (default: 2 seconds), THE sender SHALL retransmit the unacknowledged Frame.
5. THE sender SHALL retain sent DATA Frames in a retransmission buffer until they are acknowledged.
6. WHEN the receiver receives a DATA Frame with a Sequence_Number that has already been delivered or is already in the Reassembly_Buffer, THE receiver SHALL discard the duplicate Frame silently.
7. THE sender SHALL limit the number of unacknowledged in-flight Frames to a configurable window size (default: 8) to provide flow control and avoid overrunning the Broker's channel queue.
8. IF the sender's retransmission count for a single Frame exceeds a configurable maximum (default: 10), THEN THE sender SHALL abort the Session by sending a RST Frame.

### Requirement 5: DNS Transport Integration

**User Story:** As a developer, I want the SOCKS_Client and Exit_Node to communicate through the existing Broker using DNS queries, so that the tunnel works over any network that allows DNS.

#### Acceptance Criteria

1. THE SOCKS_Client SHALL send Frames to the Broker by encoding them as DNS A query payloads using the Broker's existing send query format (`<nonce>.<base32_payload_labels>.<sender_id>.<channel>.<Controlled_Domain>`).
2. THE SOCKS_Client SHALL receive Frames from the Broker by issuing DNS TXT queries for the appropriate Downstream_Channel and decoding the Envelope response.
3. THE Exit_Node SHALL send Frames to the Broker by encoding them as DNS A query payloads to the appropriate Downstream_Channel.
4. THE Exit_Node SHALL receive Frames from the Broker by issuing DNS TXT queries for the appropriate Upstream_Channel and decoding the Envelope response.
5. THE SOCKS_Client and Exit_Node SHALL poll their respective receive channels using an adaptive polling strategy: short intervals (configurable, default: 50ms) when a Session is active and data is flowing, backing off to a longer interval (configurable, default: 500ms) when idle.
6. THE SOCKS_Client and Exit_Node SHALL use the Broker's base32 encoding and envelope decoding functions from the existing library.
7. THE SOCKS_Client SHALL compute the effective Payload_Budget per Frame by subtracting the Frame header size from the Broker's available payload bytes for the given Sender_ID, channel name, and Controlled_Domain lengths.

### Requirement 6: Fragmentation and Reassembly

**User Story:** As a user, I want to transfer data of any size through the proxy, even though each DNS message can only carry ~100 bytes, so that normal web browsing and file downloads work.

#### Acceptance Criteria

1. WHEN the SOCKS_Client reads data from a local TCP socket, THE SOCKS_Client SHALL split the data into chunks that fit within the Payload_Budget and send each chunk as a separate DATA Frame with sequential Sequence_Numbers.
2. WHEN the Exit_Node reads data from a target TCP socket, THE Exit_Node SHALL split the data into chunks that fit within the Payload_Budget and send each chunk as a separate DATA Frame with sequential Sequence_Numbers.
3. THE Reassembly_Buffer SHALL deliver payload bytes to the local TCP socket only when contiguous Sequence_Numbers are available starting from the next expected sequence number.
4. THE Reassembly_Buffer SHALL buffer out-of-order Frames up to a configurable maximum buffer size (default: 32 Frames) to handle reordering.
5. IF the Reassembly_Buffer exceeds the maximum buffer size, THEN THE receiver SHALL abort the Session by sending a RST Frame.

### Requirement 7: SOCKS_Client Configuration

**User Story:** As an operator, I want to configure the SOCKS_Client through command-line arguments or a configuration file, so that I can adapt it to my deployment.

#### Acceptance Criteria

1. THE SOCKS_Client SHALL accept configuration via command-line arguments.
2. THE SOCKS_Client SHALL accept the following configuration parameters: listen address, listen port, Controlled_Domain, DNS resolver address, Client_ID, PSK (or path to PSK file), retransmission timeout, max retransmissions, window size, and poll intervals.
3. WHEN a configuration parameter is omitted, THE SOCKS_Client SHALL use a documented default value.
4. THE SOCKS_Client SHALL accept a `--resolver` argument specifying the DNS resolver (or direct Broker) address to use for sending and receiving DNS queries.
5. IF the SOCKS_Client fails to bind to the configured listen address and port, THEN THE SOCKS_Client SHALL log an error and exit with a non-zero exit code.

### Requirement 8: Exit_Node Configuration and Lifecycle

**User Story:** As an operator, I want to run the Exit_Node as a long-lived process that handles tunnel requests, so that the SOCKS proxy has a stable server-side endpoint.

#### Acceptance Criteria

1. THE Exit_Node SHALL accept configuration via command-line arguments.
2. THE Exit_Node SHALL accept the following configuration parameters: Controlled_Domain, DNS resolver address (or direct Broker address), Node_ID (used as sender_id), PSK (or path to PSK file), mode (embedded or standalone), Broker config file path (embedded mode only), retransmission timeout, max retransmissions, window size, poll intervals, and connection timeout.
3. WHEN a configuration parameter is omitted, THE Exit_Node SHALL use a documented default value.
4. THE Exit_Node SHALL poll the Control_Channel for incoming SYN Frames and create new Sessions in response.
5. WHEN the Exit_Node receives a SIGTERM or SIGINT signal, THE Exit_Node SHALL send FIN Frames for all active Sessions and shut down gracefully within 10 seconds.
6. WHILE the Exit_Node is running, THE Exit_Node SHALL log session lifecycle events (open, close, error) at info log level and frame-level activity at debug log level.

### Requirement 9: Channel Naming Convention

**User Story:** As a developer, I want a deterministic channel naming scheme, so that the SOCKS_Client and Exit_Node can find each other's channels without out-of-band coordination.

#### Acceptance Criteria

1. THE SOCKS_Client and Exit_Node SHALL use the following channel naming convention: Upstream_Channel is `u-<session_id>`, Downstream_Channel is `d-<session_id>`, and Control_Channel is `ctl-<client_id>`.
2. THE Session_ID SHALL be a random alphanumeric string of exactly 8 characters, generated by the SOCKS_Client.
3. THE channel names SHALL fit within a single DNS label (max 63 characters).
4. THE SOCKS_Client SHALL include the Client_ID in SYN Frames so the Exit_Node knows which Control_Channel to use for responses.

### Requirement 10: Error Handling and Resilience

**User Story:** As a user, I want the proxy to handle network errors gracefully, so that one failed connection does not crash the entire proxy.

#### Acceptance Criteria

1. IF a DNS query to the Broker times out, THEN THE SOCKS_Client or Exit_Node SHALL retry the query up to 3 times before treating the Frame as lost.
2. IF the Broker responds with a channel-full error IP, THEN THE sender SHALL back off for a configurable duration (default: 500ms) before retrying.
3. IF the local TCP socket for a Session is closed by the application or target, THEN THE corresponding side SHALL send a FIN Frame and clean up the Session.
4. IF the SOCKS_Client or Exit_Node encounters an unrecoverable error on a Session, THEN THE affected side SHALL send a RST Frame and clean up the Session without affecting other active Sessions.
5. THE SOCKS_Client SHALL continue accepting new SOCKS5 connections even when individual Sessions fail.

### Requirement 11: Frame Encoding Round-Trip

**User Story:** As a developer, I want to verify that frame serialization is correct, so that data is not corrupted in transit.

#### Acceptance Criteria

1. THE Frame_Encoder SHALL serialize a Frame struct into a compact binary representation.
2. THE Frame_Decoder SHALL deserialize a binary representation back into a Frame struct.
3. FOR ALL valid Frame structs, encoding then decoding SHALL produce an equivalent Frame struct (round-trip property).
4. IF the Frame_Decoder receives a byte sequence that is too short or contains an invalid Frame_Type, THEN THE Frame_Decoder SHALL return a descriptive error.

### Requirement 12: Tunnel Encryption

**User Story:** As a user, I want all tunneled data to be encrypted, so that observers of the DNS traffic (resolvers, network operators) cannot read the content of my connections.

#### Acceptance Criteria

1. THE SOCKS_Client and Exit_Node SHALL share a Pre-Shared Key (PSK) configured via command-line argument or configuration file.
2. DURING session setup, THE SOCKS_Client SHALL include an X25519 ephemeral public key in the SYN Frame payload (after the target address).
3. WHEN the Exit_Node receives a SYN Frame, THE Exit_Node SHALL generate its own X25519 ephemeral key pair, compute the shared secret via X25519 Diffie-Hellman, and include its ephemeral public key in the SYN-ACK Frame payload.
4. BOTH sides SHALL derive the Session_Key by computing HKDF-SHA256 over the concatenation of the X25519 shared secret and the PSK, using a fixed info string (e.g., `"dns-socks-v1"`).
5. THE sender SHALL encrypt each DATA Frame payload using ChaCha20-Poly1305 with the Session_Key and a nonce derived from the Sequence_Number and direction (upstream/downstream) to guarantee nonce uniqueness.
6. THE receiver SHALL decrypt each DATA Frame payload using ChaCha20-Poly1305 with the Session_Key and the corresponding nonce derived from the Frame's Sequence_Number and direction.
7. IF decryption fails (authentication tag mismatch), THEN THE receiver SHALL discard the Frame silently and log the event at debug level.
8. THE encryption overhead (16-byte Poly1305 authentication tag) SHALL be accounted for when computing the effective Payload_Budget for DATA Frames.
9. SYN, SYN-ACK, FIN, RST, and ACK Frames SHALL be authenticated (but not encrypted) using HMAC-SHA256 with the PSK, appending a truncated 16-byte MAC to the Frame payload.
10. IF MAC verification fails on a control Frame, THEN THE receiver SHALL discard the Frame silently and log the event at debug level.
11. THE PSK SHALL be at least 32 bytes (256 bits) and THE SOCKS_Client and Exit_Node SHALL reject shorter keys at startup with a descriptive error.

### Requirement 13: Embedded Broker Mode

**User Story:** As an operator, I want the option to run the Exit_Node and Broker as a single process, so that I can eliminate DNS serialization overhead on the server side and improve throughput.

#### Acceptance Criteria

1. THE Exit_Node SHALL support two deployment modes: Standalone_Mode and Embedded_Mode, selectable via a `--mode` command-line argument (default: `standalone`).
2. IN Standalone_Mode, THE Exit_Node SHALL communicate with the Broker over DNS queries, identical to how the SOCKS_Client communicates.
3. IN Embedded_Mode, THE Exit_Node SHALL initialize the Broker's ChannelStore in-process and access it directly via function calls for push, pop, and sweep operations, bypassing DNS serialization and UDP round-trips.
4. IN Embedded_Mode, THE Exit_Node SHALL also run the Broker's DNS server loop to serve external DNS queries from SOCKS_Clients, sharing the same ChannelStore.
5. IN Embedded_Mode, THE Exit_Node SHALL accept a `--broker-config` argument specifying the path to the Broker's TOML configuration file (for listen address, port, controlled domain, and store parameters).
6. THE Exit_Node's tunnel logic (session management, frame protocol, encryption, reliability) SHALL be identical in both modes — only the transport layer differs.
7. THE Exit_Node SHALL expose a Transport_Backend trait (or equivalent abstraction) with send_frame and recv_frame operations, with separate implementations for DNS-based transport and direct ChannelStore access.
8. IN Embedded_Mode, THE Exit_Node SHALL run the Broker's expiry sweeper task to clean up expired messages and inactive channels.
