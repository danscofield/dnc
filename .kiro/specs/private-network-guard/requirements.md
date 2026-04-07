# Requirements Document

## Introduction

The exit node opens outbound TCP connections on behalf of tunnel clients. Without a guard, a client can target RFC 1918, loopback, and link-local addresses to reach internal services (SSRF). This feature adds a pure-function CIDR check between `resolve_target` and `TcpStream::connect` in `handle_syn`, blocking private addresses by default.

## Glossary

- **Exit_Node**: The `exit-node` binary (`crates/dns-socks-proxy/src/bin/exit_node.rs`).
- **Guard**: A pure function `is_blocked(addr: IpAddr, blocked_cidrs: &[IpNet]) -> bool` that returns true when the address falls within any blocked CIDR range.
- **Default_Blocked_Ranges**: RFC 1918 (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16), loopback (127.0.0.0/8, ::1/128), link-local (169.254.0.0/16, fe80::/10), unique local (fc00::/7), unspecified (0.0.0.0/8, ::/128), and cloud IMDS (fd00:ec2::254/128 — the EC2 instance metadata service IPv6 endpoint).
- **Allow_Private_Networks_Flag**: `--allow-private-networks` CLI flag or `allow_private_networks = true` in TOML; disables the Default_Blocked_Ranges.
- **Disallow_Network_Flag**: `--disallow-network <CIDR>` repeatable CLI flag or `disallow_networks = ["CIDR", ...]` in TOML; adds additional CIDR blocks on top of (or independent of) the defaults.

## Requirements

### Requirement 1: Pure CIDR classification function

**User Story:** As a developer, I want address classification isolated in a pure function, so that it can be property-tested independently of networking.

#### Acceptance Criteria

1. THE Guard SHALL accept an `IpAddr` and a slice of CIDR ranges and return a boolean indicating whether the address is blocked.
2. FOR ALL addresses within any provided CIDR range, THE Guard SHALL return true (blocked).
3. FOR ALL addresses outside every provided CIDR range, THE Guard SHALL return false (allowed).
4. FOR ALL CIDR ranges, classifying an address then re-classifying the same address SHALL produce the same result (idempotence).

### Requirement 2: Guard insertion at TCP connect point

**User Story:** As an exit node operator, I want the guard checked after DNS resolution but before TCP connect, so that no TCP SYN packet is sent to a blocked address.

#### Acceptance Criteria

1. WHEN `resolve_target` produces a Resolved_IP, THE Exit_Node SHALL pass the Resolved_IP and the active blocked-CIDR list to the Guard before calling `TcpStream::connect`.
2. WHEN the Guard returns true (blocked), THE Exit_Node SHALL send a RST frame to the client, log a warning containing the session ID and blocked address, and skip the TCP connect entirely.
3. WHEN the Guard returns false (allowed), THE Exit_Node SHALL proceed with `TcpStream::connect` as normal.

### Requirement 3: Default blocked ranges and opt-out

**User Story:** As an exit node operator, I want private/loopback/link-local ranges blocked by default with no extra flags, so that new deployments are secure out of the box, and I want an opt-out for trusted environments.

#### Acceptance Criteria

1. THE Exit_Node SHALL block Default_Blocked_Ranges when neither Allow_Private_Networks_Flag nor any Disallow_Network_Flag is provided.
2. WHEN Allow_Private_Networks_Flag is present, THE Exit_Node SHALL remove the Default_Blocked_Ranges from the active blocked list.
3. WHEN Allow_Private_Networks_Flag is present, THE Exit_Node SHALL log an informational message at startup indicating that default private-network blocking is disabled.

### Requirement 4: Custom additional CIDR blocks

**User Story:** As an exit node operator, I want to block additional CIDR ranges beyond the defaults, so that I can restrict access to specific subnets in my environment.

#### Acceptance Criteria

1. WHEN one or more Disallow_Network_Flag values are provided, THE Exit_Node SHALL add those CIDR ranges to the active blocked list.
2. WHEN both Default_Blocked_Ranges and Disallow_Network_Flag ranges are active, THE Guard SHALL block addresses matching either set.
3. WHEN Allow_Private_Networks_Flag is present alongside Disallow_Network_Flag values, THE Exit_Node SHALL block only the custom CIDR ranges (defaults removed, custom retained).
4. IF a Disallow_Network_Flag value is not a valid CIDR notation, THEN THE Exit_Node SHALL exit with a configuration error at startup.
