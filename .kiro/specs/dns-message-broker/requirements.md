# Requirements Document

## Introduction

This feature implements a DNS daemon that acts as a lightweight message broker, enabling clients to exchange small datagrams with each other purely through DNS queries and responses. The system exploits DNS recursion: clients only need to reach their local DNS resolver, which recursively resolves queries to an authoritative DNS server under the operator's control. The authoritative server stores and forwards messages encoded in DNS records, effectively turning the DNS infrastructure into a covert, UDP-like datagram transport.

### Scope Boundaries

**Fragmentation**: Message fragmentation and reassembly is explicitly out of scope for the Broker. The Broker deals in single, atomic datagrams — what fits in one DNS query constitutes one Message. If a higher-level protocol requires messages larger than the available payload budget, fragmentation and reassembly is a client-layer concern.

### Future Considerations

**CNAME Response Channel**: CNAME records could serve as an additional data channel in the response direction, encoding payload in the CNAME target domain name (up to 253 bytes). This is deferred to a future version due to complexity around CNAME chasing behavior in recursive resolvers, which may cause intermediate resolvers to follow the CNAME rather than return it directly to the Client.

## Glossary

- **Broker**: The authoritative DNS server daemon that receives, stores, and serves messages encoded as DNS records for a controlled domain.
- **Client**: A program that sends and receives messages by issuing DNS queries to its local resolver, which recursively reaches the Broker.
- **Channel**: A logical named mailbox identified by a subdomain label under the controlled domain. Messages are sent to and retrieved from Channels.
- **Message**: A small payload that a Client sends to a Channel, encoded within DNS record data. The maximum raw payload size depends on the lengths of the Sender_ID, Channel name, Nonce_Label, and Controlled_Domain, and is typically in the range of 80–120 bytes. See the Payload Budget formula below.
- **Envelope**: The DNS-level encoding of a Message, including metadata such as sender identifier, sequence number, and timestamp, packed into one or more DNS TXT records.
- **Sender_ID**: A short, unique identifier (up to 63 bytes) chosen by a Client to identify itself as the author of a Message.
- **Controlled_Domain**: The DNS zone (e.g., `broker.example.com`) for which the Broker is authoritative and can dynamically create and serve records.
- **Local_Resolver**: The recursive DNS resolver that a Client queries; it handles recursion to reach the Broker transparently.
- **TTL**: Time-To-Live value on DNS records, used to control caching behavior of intermediate resolvers.
- **Nonce_Label**: A random, unique DNS label prepended to a query name to make each query globally unique from the perspective of resolvers, defeating DNS response caching.

## Payload Budget

DNS domain names are limited to 253 characters total, and each label within a domain name is limited to 63 characters. The send query format is `<nonce>.<base32_payload>.<sender_id>.<channel>.<Controlled_Domain>`, so the space available for the base32-encoded payload is constrained by the other components.

**Formula:**

```
available_base32_chars = 253 - len(Controlled_Domain) - len(Nonce_Label) - len(Sender_ID) - len(Channel) - 4 (dots between components)
max_raw_payload_bytes = floor(available_base32_chars * 5 / 8)
```

**Example calculation** (typical values):

| Component         | Example Value        | Length |
|--------------------|----------------------|--------|
| Controlled_Domain | `broker.example.com` | 18     |
| Nonce_Label       | `a1b2c3d4`           | 8      |
| Sender_ID         | `alice`              | 5      |
| Channel           | `inbox`              | 5      |
| Dots (4)          |                      | 4      |
| **Total overhead** |                     | **40** |
| Available for base32 payload | 253 - 40 | **213 chars** |

Since the base32-encoded payload may need to span multiple labels (each max 63 characters), additional dot separators are required between payload labels. With 213 available characters split across labels: `floor(213 / 63) = 3` extra dots, leaving ~210 base32 characters, yielding `floor(210 * 5 / 8)` = **131 raw bytes**.

With longer Sender_IDs or Channel names, the available payload shrinks accordingly. Client developers MUST compute the available budget dynamically based on their actual component lengths.

## Requirements

### Requirement 1: Authoritative DNS Server

**User Story:** As an operator, I want the Broker to serve as an authoritative DNS server for the Controlled_Domain, so that DNS queries for subdomains under it are answered by the Broker.

#### Acceptance Criteria

1. THE Broker SHALL listen for DNS queries on UDP port 53 (configurable).
2. WHEN a DNS query is received for a name under the Controlled_Domain, THE Broker SHALL respond with an authoritative answer.
3. WHEN a DNS query is received for a name outside the Controlled_Domain, THE Broker SHALL respond with a REFUSED rcode.
4. THE Broker SHALL respond to DNS queries conforming to RFC 1035 message format.
5. IF the Broker receives a malformed DNS query, THEN THE Broker SHALL respond with a FORMERR rcode.

### Requirement 2: Send a Message

**User Story:** As a Client, I want to send a small message to a Channel by issuing a DNS query, so that another Client can later retrieve it.

#### Acceptance Criteria

1. WHEN a Client issues a DNS query encoding a Message payload, Sender_ID, and target Channel name as a subdomain of the Controlled_Domain, THE Broker SHALL store the Message in the target Channel.
2. THE Broker SHALL encode the send operation as a specially structured subdomain query using A or AAAA record types, where labels encode the Sender_ID, payload, and Channel.
3. WHEN a Message is successfully stored, THE Broker SHALL respond with a DNS answer containing a predefined acknowledgment IP address (e.g., `1.2.3.4` for success).
4. IF the encoded Message exceeds the maximum payload size as determined by the Payload Budget formula for the given Sender_ID, Channel, Nonce_Label, and Controlled_Domain lengths, THEN THE Broker SHALL respond with a predefined error IP address (e.g., `1.2.3.5` for payload too large).
5. THE Broker SHALL associate a monotonically increasing sequence number and a timestamp with each stored Message.

### Requirement 3: Receive Messages

**User Story:** As a Client, I want to retrieve messages from a Channel by issuing a DNS query, so that I can read messages sent to me.

#### Acceptance Criteria

1. WHEN a Client issues a DNS TXT query for a Channel subdomain under the Controlled_Domain, THE Broker SHALL respond with the oldest undelivered Message in that Channel as a TXT record.
2. THE Broker SHALL encode each returned Message as an Envelope in the TXT record, containing the Sender_ID, sequence number, timestamp, and payload.
3. WHEN no undelivered Messages exist in the queried Channel, THE Broker SHALL respond with an empty answer section (NOERROR with zero answer records).
4. WHEN a Message is returned to a Client, THE Broker SHALL mark that Message as delivered.
5. THE Broker SHALL set the TTL on Message TXT records to 0 to discourage caching by intermediate resolvers (see Requirement 9 for additional cache mitigation via Nonce_Labels).

### Requirement 4: Channel Management

**User Story:** As an operator, I want Channels to be created on demand and cleaned up automatically, so that the Broker requires no manual channel administration.

#### Acceptance Criteria

1. WHEN a Message is sent to a Channel that does not yet exist, THE Broker SHALL create the Channel automatically.
2. THE Broker SHALL delete a Channel and all its Messages after a configurable inactivity timeout (default: 1 hour) with no new sends or receives.
3. THE Broker SHALL enforce a configurable maximum number of pending Messages per Channel (default: 100).
4. IF a Client sends a Message to a Channel that has reached the maximum pending Message count, THEN THE Broker SHALL respond with a predefined error IP address (e.g., `1.2.3.6` for channel full).

### Requirement 5: Message Encoding and Decoding

**User Story:** As a Client developer, I want a well-defined encoding scheme for packing messages into DNS queries and unpacking them from DNS responses, so that I can implement a Client in any language.

#### Acceptance Criteria

1. THE Client SHALL encode the send operation as a DNS A query where the queried name follows the pattern: `<nonce>.<base32_payload_labels>.<sender_id>.<channel>.<Controlled_Domain>`, where `<nonce>` is a Nonce_Label and `<base32_payload_labels>` is the base32-encoded payload split across one or more labels of at most 63 characters each.
2. THE Client SHALL use base32 encoding (RFC 4648, lowercase, no padding) for the Message payload to ensure DNS label safety, splitting the encoded payload into labels of at most 63 characters each.
3. THE Client SHALL decode received Envelopes from TXT record data using a defined delimiter-separated format: `<sender_id>|<sequence_number>|<timestamp_epoch_seconds>|<base32_payload>`.
4. THE Broker SHALL parse incoming send queries by stripping the leading Nonce_Label, then identifying the Sender_ID and Channel labels by their known positions relative to the Controlled_Domain, and concatenating all remaining intermediate labels as the base32-encoded payload.
5. IF the Broker cannot parse a query into valid Message components, THEN THE Broker SHALL respond with a NXDOMAIN rcode.
6. FOR ALL valid Messages, encoding a Message into a DNS query, sending it to the Broker, retrieving it via a TXT query, and decoding the Envelope SHALL produce a payload identical to the original Message (round-trip property).

### Requirement 6: Daemon Lifecycle

**User Story:** As an operator, I want the Broker to run as a long-lived daemon with clean startup and shutdown behavior, so that I can deploy it reliably.

#### Acceptance Criteria

1. THE Broker SHALL read configuration from a file path specified as a command-line argument.
2. WHEN the Broker starts, THE Broker SHALL bind to the configured UDP port and begin serving DNS queries.
3. WHEN the Broker receives a SIGTERM or SIGINT signal, THE Broker SHALL stop accepting new queries and shut down gracefully within 5 seconds.
4. WHILE the Broker is running, THE Broker SHALL log each received query and sent response at debug log level.
5. IF the Broker fails to bind to the configured port, THEN THE Broker SHALL log an error message and exit with a non-zero exit code.

### Requirement 7: Configuration

**User Story:** As an operator, I want to configure the Broker's behavior through a configuration file, so that I can tune it for my deployment.

#### Acceptance Criteria

1. THE Broker SHALL support a configuration file in TOML format.
2. THE Broker SHALL accept the following configuration parameters: listen address, listen port, Controlled_Domain, channel inactivity timeout, maximum messages per channel, log level, and acknowledgment/error IP addresses.
3. WHEN a configuration parameter is omitted, THE Broker SHALL use a documented default value.
4. IF the configuration file is missing or contains invalid syntax, THEN THE Broker SHALL log a descriptive error and exit with a non-zero exit code.
5. THE Broker SHALL parse the TOML configuration file into an internal Configuration object.
6. THE Configuration_Printer SHALL format Configuration objects back into valid TOML configuration files.
7. FOR ALL valid Configuration objects, parsing then printing then parsing SHALL produce an equivalent Configuration object (round-trip property).

### Requirement 8: Message Expiry

**User Story:** As an operator, I want messages to expire after a configurable duration, so that the Broker does not accumulate stale data indefinitely.

#### Acceptance Criteria

1. THE Broker SHALL associate an expiry time with each stored Message, calculated as the storage timestamp plus a configurable message TTL (default: 10 minutes).
2. WHEN the current time exceeds a Message's expiry time, THE Broker SHALL remove the Message from its Channel.
3. THE Broker SHALL perform expiry checks at a regular interval (configurable, default: 30 seconds).

### Requirement 9: DNS Cache Mitigation

**User Story:** As a Client developer, I want DNS caching to be mitigated at every layer, so that message delivery is correct and Clients always receive fresh responses from the Broker.

#### Acceptance Criteria

1. THE Broker SHALL set the TTL on all DNS responses to 0 to discourage caching by intermediate resolvers.
2. THE Client SHALL prepend a Nonce_Label to every DNS query name, making each query globally unique from the perspective of any resolver cache.
3. THE Client SHALL generate each Nonce_Label as a random alphanumeric string of at least 8 characters.
4. WHEN the Broker receives a query with a Nonce_Label as the first label, THE Broker SHALL strip the Nonce_Label before parsing the remaining query name.
5. THE Client SHALL include a Nonce_Label on both send queries (A record) and receive queries (TXT record), so that no repeated query name risks a cached response.
6. WHEN a Client issues a TXT query to receive Messages, THE Client SHALL use the pattern: `<nonce>.<channel>.<Controlled_Domain>`, where `<nonce>` is a Nonce_Label.
7. THE Broker SHALL identify the Nonce_Label by its position as the leftmost label and distinguish it from payload or Channel labels by the defined query structure.
