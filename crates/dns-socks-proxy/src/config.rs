// Configuration: CLI parsing for socks-client and exit-node.

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;

use clap::{Parser, ValueEnum};

use ipnet::IpNet;
use tracing::info;

use crate::crypto::Psk;
use crate::guard::default_blocked_ranges;

/// Errors arising from configuration parsing and validation.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("PSK too short: got {got} bytes, need at least 32")]
    PskTooShort { got: usize },

    #[error("failed to read PSK file: {0}")]
    PskFileError(#[from] std::io::Error),

    #[error("invalid hex in --psk value: {0}")]
    PskHexError(String),

    #[error("--broker-config is required when mode is embedded")]
    BrokerConfigRequired,

    #[error("--resolver is required when mode is standalone")]
    ResolverRequired,

    #[error("exactly one of --psk or --psk-file must be provided")]
    PskNotProvided,

    #[error("--max-concurrent-sessions must be >= 1, got {got}")]
    InvalidMaxConcurrentSessions { got: usize },

    #[error("PSK validation failed: {0}")]
    PskValidation(#[from] crate::crypto::CryptoError),

    #[error("invalid CIDR in --disallow-network: {value}: {source}")]
    InvalidCidr { value: String, source: ipnet::AddrParseError },
}

/// Deployment mode for the exit-node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum DeploymentMode {
    /// Communicate with a separate Broker process over DNS.
    Standalone,
    /// Run the Broker in-process, accessing ChannelStore directly.
    Embedded,
}

// ---------------------------------------------------------------------------
// SOCKS Client
// ---------------------------------------------------------------------------

/// CLI arguments for the socks-client binary.
#[derive(Parser, Debug)]
#[command(name = "dns-socksd-fifo", version, about = "SOCKS5 proxy client that tunnels TCP traffic over DNS")]
pub struct SocksClientCli {
    /// Local listen address (default: 127.0.0.1).
    #[arg(long, default_value = "127.0.0.1")]
    pub listen_addr: IpAddr,

    /// Local listen port (default: 1080).
    #[arg(long, default_value_t = 1080)]
    pub listen_port: u16,

    /// Controlled DNS domain (e.g. "tunnel.example.com").
    #[arg(long)]
    pub domain: String,

    /// DNS resolver (or direct Broker) address, e.g. "127.0.0.1:5353".
    #[arg(long)]
    pub resolver: SocketAddr,

    /// Client identifier used as sender_id in DNS queries.
    #[arg(long)]
    pub client_id: String,

    /// Exit node identifier. Determines the control channel (`ctl-<exit_node_id>`)
    /// that the client sends SYN frames to and polls for SYN-ACK responses.
    /// Must match the `--node-id` configured on the exit-node.
    #[arg(long)]
    pub exit_node_id: String,

    /// Pre-shared key as a hex-encoded string.
    #[arg(long, group = "psk_source")]
    pub psk: Option<String>,

    /// Path to a file containing the raw PSK bytes.
    #[arg(long, group = "psk_source")]
    pub psk_file: Option<PathBuf>,

    /// Retransmission timeout in milliseconds (default: 2000).
    #[arg(long, default_value_t = 2000)]
    pub rto_ms: u64,

    /// Maximum retransmissions before session abort (default: 10).
    #[arg(long, default_value_t = 10)]
    pub max_retransmits: usize,

    /// Sliding window size (default: 8).
    #[arg(long, default_value_t = 8)]
    pub window_size: usize,

    /// Active poll interval in milliseconds (default: 50).
    #[arg(long, default_value_t = 50)]
    pub poll_active_ms: u64,

    /// Idle poll interval in milliseconds (default: 500).
    #[arg(long, default_value_t = 500)]
    pub poll_idle_ms: u64,

    /// Session setup timeout in milliseconds (default: 30000).
    #[arg(long, default_value_t = 30000)]
    pub connect_timeout_ms: u64,

    /// Maximum number of parallel TXT data queries per poll cycle (default: 8).
    #[arg(long, default_value_t = 8)]
    pub max_parallel_queries: usize,

    /// Maximum backoff interval in milliseconds (default: value of poll_idle_ms).
    #[arg(long)]
    pub backoff_max_ms: Option<u64>,

    /// Maximum number of concurrent active sessions (default: 8).
    #[arg(long, default_value_t = 8)]
    pub max_concurrent_sessions: usize,

    /// Queue timeout in milliseconds for waiting connections (default: 30000).
    /// Set to 0 to reject immediately when all permits are in use.
    #[arg(long, default_value_t = 30000)]
    pub queue_timeout_ms: u64,

    /// Minimum interval between DNS queries in milliseconds (default: 0 = no throttle).
    /// Helps avoid rate limiting by recursive resolvers.
    #[arg(long, default_value_t = 0)]
    pub query_interval_ms: u64,

    /// Disable EDNS0 OPT record on TXT queries (reduces response size for
    /// compatibility with recursive resolvers that truncate large UDP responses).
    #[arg(long)]
    pub no_edns: bool,
}

/// Validated configuration for the socks-client binary.
pub struct SocksClientConfig {
    /// Local listen address (default: 127.0.0.1).
    pub listen_addr: IpAddr,
    /// Local listen port (default: 1080).
    pub listen_port: u16,
    /// Controlled DNS domain.
    pub controlled_domain: String,
    /// DNS resolver address.
    pub resolver_addr: SocketAddr,
    /// Client identifier.
    pub client_id: String,
    /// Exit node identifier (determines the control channel).
    pub exit_node_id: String,
    /// Pre-shared key (≥ 32 bytes).
    pub psk: Psk,
    /// Retransmission timeout (default: 2s).
    pub rto: Duration,
    /// Maximum retransmissions (default: 10).
    pub max_retransmits: usize,
    /// Sliding window size (default: 8).
    pub window_size: usize,
    /// Active poll interval (default: 50ms).
    pub poll_active: Duration,
    /// Idle poll interval (default: 500ms).
    pub poll_idle: Duration,
    /// Session setup timeout (default: 30s).
    pub connect_timeout: Duration,
    /// Maximum number of parallel TXT data queries per poll cycle (default: 8).
    pub max_parallel_queries: usize,
    /// Maximum backoff interval (defaults to poll_idle).
    pub backoff_max: Duration,
    /// Maximum number of concurrent active sessions.
    pub max_concurrent_sessions: usize,
    /// Queue timeout for waiting connections.
    pub queue_timeout: Duration,
    /// Minimum interval between DNS queries (rate limiting).
    pub query_interval: Duration,
    /// Whether to disable EDNS0 on TXT queries.
    pub no_edns: bool,
}

impl SocksClientCli {
    /// Parse CLI arguments and validate into a `SocksClientConfig`.
    pub fn into_config(self) -> Result<SocksClientConfig, ConfigError> {
        if self.max_concurrent_sessions < 1 {
            return Err(ConfigError::InvalidMaxConcurrentSessions {
                got: self.max_concurrent_sessions,
            });
        }

        let psk = resolve_psk(self.psk.as_deref(), self.psk_file.as_deref())?;
        let poll_idle = Duration::from_millis(self.poll_idle_ms);
        let backoff_max = match self.backoff_max_ms {
            Some(ms) => Duration::from_millis(ms),
            None => poll_idle,
        };

        Ok(SocksClientConfig {
            listen_addr: self.listen_addr,
            listen_port: self.listen_port,
            controlled_domain: self.domain,
            resolver_addr: self.resolver,
            client_id: self.client_id,
            exit_node_id: self.exit_node_id,
            psk,
            rto: Duration::from_millis(self.rto_ms),
            max_retransmits: self.max_retransmits,
            window_size: self.window_size,
            poll_active: Duration::from_millis(self.poll_active_ms),
            poll_idle,
            connect_timeout: Duration::from_millis(self.connect_timeout_ms),
            max_parallel_queries: self.max_parallel_queries.max(1),
            backoff_max,
            max_concurrent_sessions: self.max_concurrent_sessions,
            queue_timeout: Duration::from_millis(self.queue_timeout_ms),
            query_interval: Duration::from_millis(self.query_interval_ms),
            no_edns: self.no_edns,
        })
    }
}

// ---------------------------------------------------------------------------
// Exit Node
// ---------------------------------------------------------------------------

/// CLI arguments for the exit-node binary.
#[derive(Parser, Debug)]
#[command(name = "dns-exit-fifo", version, about = "Exit node that terminates DNS-tunneled TCP connections")]
pub struct ExitNodeCli {
    /// Controlled DNS domain (e.g. "tunnel.example.com").
    #[arg(long)]
    pub domain: String,

    /// DNS resolver address. Required in standalone mode.
    #[arg(long)]
    pub resolver: Option<SocketAddr>,

    /// Node identifier used as sender_id.
    #[arg(long)]
    pub node_id: String,

    /// Pre-shared key as a hex-encoded string.
    #[arg(long, group = "psk_source")]
    pub psk: Option<String>,

    /// Path to a file containing the raw PSK bytes.
    #[arg(long, group = "psk_source")]
    pub psk_file: Option<PathBuf>,

    /// Deployment mode: standalone or embedded (default: standalone).
    #[arg(long, value_enum, default_value_t = DeploymentMode::Standalone)]
    pub mode: DeploymentMode,

    /// Path to Broker TOML config file. Required in embedded mode.
    #[arg(long)]
    pub broker_config: Option<PathBuf>,

    /// Retransmission timeout in milliseconds (default: 2000).
    #[arg(long, default_value_t = 2000)]
    pub rto_ms: u64,

    /// Maximum retransmissions before session abort (default: 10).
    #[arg(long, default_value_t = 10)]
    pub max_retransmits: usize,

    /// Sliding window size (default: 8).
    #[arg(long, default_value_t = 8)]
    pub window_size: usize,

    /// Active poll interval in milliseconds (default: 50).
    #[arg(long, default_value_t = 50)]
    pub poll_active_ms: u64,

    /// Idle poll interval in milliseconds (default: 500).
    #[arg(long, default_value_t = 500)]
    pub poll_idle_ms: u64,

    /// TCP connect timeout in milliseconds (default: 10000).
    #[arg(long, default_value_t = 10000)]
    pub connect_timeout_ms: u64,

    /// Maximum number of parallel TXT data queries per poll cycle (default: 8).
    #[arg(long, default_value_t = 8)]
    pub max_parallel_queries: usize,

    /// Maximum backoff interval in milliseconds (default: value of poll_idle_ms).
    #[arg(long)]
    pub backoff_max_ms: Option<u64>,

    /// Disable EDNS0 OPT record on TXT queries (reduces response size for
    /// compatibility with recursive resolvers that truncate large UDP responses).
    #[arg(long)]
    pub no_edns: bool,

    /// Disable default private-network blocking (allows RFC 1918, loopback, etc.).
    #[arg(long)]
    pub allow_private_networks: bool,

    /// Additional CIDR ranges to block (repeatable).
    #[arg(long = "disallow-network", value_name = "CIDR")]
    pub disallow_networks: Vec<String>,
}

/// Validated configuration for the exit-node binary.
pub struct ExitNodeConfig {
    /// Controlled DNS domain.
    pub controlled_domain: String,
    /// DNS resolver address (required in standalone mode).
    pub resolver_addr: Option<SocketAddr>,
    /// Node identifier.
    pub node_id: String,
    /// Pre-shared key (≥ 32 bytes).
    pub psk: Psk,
    /// Deployment mode.
    pub mode: DeploymentMode,
    /// Path to Broker TOML config (required in embedded mode).
    pub broker_config_path: Option<PathBuf>,
    /// Retransmission timeout (default: 2s).
    pub rto: Duration,
    /// Maximum retransmissions (default: 10).
    pub max_retransmits: usize,
    /// Sliding window size (default: 8).
    pub window_size: usize,
    /// Active poll interval (default: 50ms).
    pub poll_active: Duration,
    /// Idle poll interval (default: 500ms).
    pub poll_idle: Duration,
    /// TCP connect timeout (default: 10s).
    pub connect_timeout: Duration,
    /// Maximum number of parallel TXT data queries per poll cycle (default: 8).
    pub max_parallel_queries: usize,
    /// Maximum backoff interval (defaults to poll_idle).
    pub backoff_max: Duration,
    /// Whether to disable EDNS0 on TXT queries.
    pub no_edns: bool,
    /// Active blocked CIDR ranges (computed from defaults + CLI flags).
    pub blocked_networks: Vec<IpNet>,
}

impl ExitNodeCli {
    /// Parse CLI arguments and validate into an `ExitNodeConfig`.
    pub fn into_config(self) -> Result<ExitNodeConfig, ConfigError> {
        let psk = resolve_psk(self.psk.as_deref(), self.psk_file.as_deref())?;

        // Mode-specific validation.
        match self.mode {
            DeploymentMode::Embedded => {
                if self.broker_config.is_none() {
                    return Err(ConfigError::BrokerConfigRequired);
                }
            }
            DeploymentMode::Standalone => {
                if self.resolver.is_none() {
                    return Err(ConfigError::ResolverRequired);
                }
            }
        }

        let poll_idle = Duration::from_millis(self.poll_idle_ms);
        let backoff_max = match self.backoff_max_ms {
            Some(ms) => Duration::from_millis(ms),
            None => poll_idle,
        };

        let mut blocked = if self.allow_private_networks {
            info!("default private-network blocking disabled by --allow-private-networks");
            vec![]
        } else {
            default_blocked_ranges()
        };
        for cidr_str in &self.disallow_networks {
            let net: IpNet = cidr_str.parse().map_err(|e| ConfigError::InvalidCidr {
                value: cidr_str.clone(),
                source: e,
            })?;
            blocked.push(net);
        }

        Ok(ExitNodeConfig {
            controlled_domain: self.domain,
            resolver_addr: self.resolver,
            node_id: self.node_id,
            psk,
            mode: self.mode,
            broker_config_path: self.broker_config,
            rto: Duration::from_millis(self.rto_ms),
            max_retransmits: self.max_retransmits,
            window_size: self.window_size,
            poll_active: Duration::from_millis(self.poll_active_ms),
            poll_idle,
            connect_timeout: Duration::from_millis(self.connect_timeout_ms),
            max_parallel_queries: self.max_parallel_queries.max(1),
            backoff_max,
            no_edns: self.no_edns,
            blocked_networks: blocked,
        })
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Resolve a PSK from either a hex string (`--psk`) or a file path (`--psk-file`).
fn resolve_psk(
    hex_value: Option<&str>,
    file_path: Option<&std::path::Path>,
) -> Result<Psk, ConfigError> {
    match (hex_value, file_path) {
        (Some(hex), None) => {
            let bytes = decode_hex(hex).map_err(ConfigError::PskHexError)?;
            Ok(Psk::from_bytes(bytes)?)
        }
        (None, Some(path)) => Ok(Psk::from_file(path)?),
        (None, None) => Err(ConfigError::PskNotProvided),
        // clap's `group` prevents both being provided, but handle defensively.
        (Some(_), Some(_)) => Err(ConfigError::PskNotProvided),
    }
}

/// Decode a hex-encoded string into bytes.
fn decode_hex(s: &str) -> Result<Vec<u8>, String> {
    // Strip optional "0x" prefix.
    let s = s.strip_prefix("0x").unwrap_or(s);
    if s.len() % 2 != 0 {
        return Err(format!("odd-length hex string: {}", s.len()));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .map_err(|e| format!("invalid hex at position {i}: {e}"))
        })
        .collect()
}

// ---------------------------------------------------------------------------
// smoltcp Tuning
// ---------------------------------------------------------------------------

/// Tuning parameters for the smoltcp TCP stack.
pub struct SmolTuningConfig {
    /// Initial retransmission timeout (default: 3000ms).
    pub initial_rto: Duration,
    /// TCP window size in MSS multiples (default: 4).
    pub window_segments: usize,
    /// Override MSS; None = auto-compute from DNS payload budget.
    pub mss: Option<usize>,
}

impl Default for SmolTuningConfig {
    fn default() -> Self {
        Self {
            initial_rto: Duration::from_millis(3000),
            window_segments: 4,
            mss: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Smol Client
// ---------------------------------------------------------------------------

/// CLI arguments for the smol-client binary.
#[derive(Parser, Debug)]
#[command(name = "dns-socksd-smol-fifo", version, about = "SOCKS5 proxy client that tunnels TCP traffic over DNS using smoltcp")]
pub struct SmolClientCli {
    /// Local listen address (default: 127.0.0.1).
    #[arg(long, default_value = "127.0.0.1")]
    pub listen_addr: IpAddr,

    /// Local listen port (default: 1080).
    #[arg(long, default_value_t = 1080)]
    pub listen_port: u16,

    /// Controlled DNS domain (e.g. "tunnel.example.com").
    #[arg(long)]
    pub domain: String,

    /// DNS resolver (or direct Broker) address, e.g. "127.0.0.1:5353".
    #[arg(long)]
    pub resolver: SocketAddr,

    /// Client identifier used as sender_id in DNS queries.
    #[arg(long)]
    pub client_id: String,

    /// Exit node identifier. Determines the control channel (`ctl-<exit_node_id>`)
    /// that the client sends Init frames to and polls for InitAck responses.
    /// Must match the `--node-id` configured on the smol-exit.
    #[arg(long)]
    pub exit_node_id: String,

    /// Pre-shared key as a hex-encoded string.
    #[arg(long, group = "psk_source")]
    pub psk: Option<String>,

    /// Path to a file containing the raw PSK bytes.
    #[arg(long, group = "psk_source")]
    pub psk_file: Option<PathBuf>,

    /// Active poll interval in milliseconds (default: 50).
    #[arg(long, default_value_t = 50)]
    pub poll_active_ms: u64,

    /// Idle poll interval in milliseconds (default: 500).
    #[arg(long, default_value_t = 500)]
    pub poll_idle_ms: u64,

    /// Session setup timeout in milliseconds (default: 30000).
    #[arg(long, default_value_t = 30000)]
    pub connect_timeout_ms: u64,

    /// Maximum backoff interval in milliseconds (default: value of poll_idle_ms).
    #[arg(long)]
    pub backoff_max_ms: Option<u64>,

    /// Maximum number of concurrent active sessions (default: 8).
    #[arg(long, default_value_t = 8)]
    pub max_concurrent_sessions: usize,

    /// Queue timeout in milliseconds for waiting connections (default: 30000).
    /// Set to 0 to reject immediately when all permits are in use.
    #[arg(long, default_value_t = 30000)]
    pub queue_timeout_ms: u64,

    /// Minimum interval between DNS queries in milliseconds (default: 0 = no throttle).
    /// Helps avoid rate limiting by recursive resolvers.
    #[arg(long, default_value_t = 0)]
    pub query_interval_ms: u64,

    /// Disable EDNS0 OPT record on TXT queries.
    #[arg(long)]
    pub no_edns: bool,

    /// smoltcp initial RTO in milliseconds (default: 3000).
    #[arg(long, default_value_t = 3000)]
    pub smol_rto_ms: u64,

    /// smoltcp TCP window size in MSS multiples (default: 4).
    #[arg(long, default_value_t = 4)]
    pub smol_window_segments: usize,

    /// Override smoltcp MSS (default: auto-computed from DNS payload budget).
    #[arg(long)]
    pub smol_mss: Option<usize>,
}

/// Validated configuration for the smol-client binary.
pub struct SmolClientConfig {
    /// Local listen address.
    pub listen_addr: IpAddr,
    /// Local listen port.
    pub listen_port: u16,
    /// Controlled DNS domain.
    pub controlled_domain: String,
    /// DNS resolver address.
    pub resolver_addr: SocketAddr,
    /// Client identifier.
    pub client_id: String,
    /// Exit node identifier (determines the control channel).
    pub exit_node_id: String,
    /// Pre-shared key (≥ 32 bytes).
    pub psk: Psk,
    /// Active poll interval.
    pub poll_active: Duration,
    /// Idle poll interval.
    pub poll_idle: Duration,
    /// Session setup timeout.
    pub connect_timeout: Duration,
    /// Maximum backoff interval.
    pub backoff_max: Duration,
    /// Maximum number of concurrent active sessions.
    pub max_concurrent_sessions: usize,
    /// Queue timeout for waiting connections.
    pub queue_timeout: Duration,
    /// Minimum interval between DNS queries.
    pub query_interval: Duration,
    /// Whether to disable EDNS0 on TXT queries.
    pub no_edns: bool,
    /// smoltcp tuning parameters.
    pub smol_tuning: SmolTuningConfig,
}

impl SmolClientCli {
    /// Parse CLI arguments and validate into a `SmolClientConfig`.
    pub fn into_config(self) -> Result<SmolClientConfig, ConfigError> {
        if self.max_concurrent_sessions < 1 {
            return Err(ConfigError::InvalidMaxConcurrentSessions {
                got: self.max_concurrent_sessions,
            });
        }

        let psk = resolve_psk(self.psk.as_deref(), self.psk_file.as_deref())?;
        let poll_idle = Duration::from_millis(self.poll_idle_ms);
        let backoff_max = match self.backoff_max_ms {
            Some(ms) => Duration::from_millis(ms),
            None => poll_idle,
        };

        Ok(SmolClientConfig {
            listen_addr: self.listen_addr,
            listen_port: self.listen_port,
            controlled_domain: self.domain,
            resolver_addr: self.resolver,
            client_id: self.client_id,
            exit_node_id: self.exit_node_id,
            psk,
            poll_active: Duration::from_millis(self.poll_active_ms),
            poll_idle,
            connect_timeout: Duration::from_millis(self.connect_timeout_ms),
            backoff_max,
            max_concurrent_sessions: self.max_concurrent_sessions,
            queue_timeout: Duration::from_millis(self.queue_timeout_ms),
            query_interval: Duration::from_millis(self.query_interval_ms),
            no_edns: self.no_edns,
            smol_tuning: SmolTuningConfig {
                initial_rto: Duration::from_millis(self.smol_rto_ms),
                window_segments: self.smol_window_segments,
                mss: self.smol_mss,
            },
        })
    }
}

// ---------------------------------------------------------------------------
// Smol Exit
// ---------------------------------------------------------------------------

/// CLI arguments for the smol-exit binary.
#[derive(Parser, Debug)]
#[command(name = "dns-exit-smol-fifo", version, about = "Exit node that terminates DNS-tunneled TCP connections using smoltcp")]
pub struct SmolExitCli {
    /// Controlled DNS domain (e.g. "tunnel.example.com").
    #[arg(long)]
    pub domain: String,

    /// DNS resolver address. Required in standalone mode.
    #[arg(long)]
    pub resolver: Option<SocketAddr>,

    /// Node identifier used as sender_id.
    #[arg(long)]
    pub node_id: String,

    /// Pre-shared key as a hex-encoded string.
    #[arg(long, group = "psk_source")]
    pub psk: Option<String>,

    /// Path to a file containing the raw PSK bytes.
    #[arg(long, group = "psk_source")]
    pub psk_file: Option<PathBuf>,

    /// Deployment mode: standalone or embedded (default: standalone).
    #[arg(long, value_enum, default_value_t = DeploymentMode::Standalone)]
    pub mode: DeploymentMode,

    /// Path to Broker TOML config file. Required in embedded mode.
    #[arg(long)]
    pub broker_config: Option<PathBuf>,

    /// Active poll interval in milliseconds (default: 50).
    #[arg(long, default_value_t = 50)]
    pub poll_active_ms: u64,

    /// Idle poll interval in milliseconds (default: 500).
    #[arg(long, default_value_t = 500)]
    pub poll_idle_ms: u64,

    /// TCP connect timeout in milliseconds (default: 10000).
    #[arg(long, default_value_t = 10000)]
    pub connect_timeout_ms: u64,

    /// Maximum backoff interval in milliseconds (default: value of poll_idle_ms).
    #[arg(long)]
    pub backoff_max_ms: Option<u64>,

    /// Disable EDNS0 OPT record on TXT queries.
    #[arg(long)]
    pub no_edns: bool,

    /// Disable default private-network blocking (allows RFC 1918, loopback, etc.).
    #[arg(long)]
    pub allow_private_networks: bool,

    /// Additional CIDR ranges to block (repeatable).
    #[arg(long = "disallow-network", value_name = "CIDR")]
    pub disallow_networks: Vec<String>,

    /// Minimum interval between DNS queries in milliseconds (default: 0 = no throttle).
    #[arg(long, default_value_t = 0)]
    pub query_interval_ms: u64,

    /// smoltcp initial RTO in milliseconds (default: 3000).
    #[arg(long, default_value_t = 3000)]
    pub smol_rto_ms: u64,

    /// smoltcp TCP window size in MSS multiples (default: 4).
    #[arg(long, default_value_t = 4)]
    pub smol_window_segments: usize,

    /// Override smoltcp MSS (default: auto-computed from DNS payload budget).
    #[arg(long)]
    pub smol_mss: Option<usize>,
}

/// Validated configuration for the smol-exit binary.
pub struct SmolExitConfig {
    /// Controlled DNS domain.
    pub controlled_domain: String,
    /// DNS resolver address (required in standalone mode).
    pub resolver_addr: Option<SocketAddr>,
    /// Node identifier.
    pub node_id: String,
    /// Pre-shared key (≥ 32 bytes).
    pub psk: Psk,
    /// Deployment mode.
    pub mode: DeploymentMode,
    /// Path to Broker TOML config (required in embedded mode).
    pub broker_config_path: Option<PathBuf>,
    /// Active poll interval.
    pub poll_active: Duration,
    /// Idle poll interval.
    pub poll_idle: Duration,
    /// TCP connect timeout.
    pub connect_timeout: Duration,
    /// Maximum backoff interval.
    pub backoff_max: Duration,
    /// Whether to disable EDNS0 on TXT queries.
    pub no_edns: bool,
    /// Active blocked CIDR ranges.
    pub blocked_networks: Vec<IpNet>,
    /// Minimum interval between DNS queries.
    pub query_interval: Duration,
    /// smoltcp tuning parameters.
    pub smol_tuning: SmolTuningConfig,
}

impl SmolExitCli {
    /// Parse CLI arguments and validate into a `SmolExitConfig`.
    pub fn into_config(self) -> Result<SmolExitConfig, ConfigError> {
        let psk = resolve_psk(self.psk.as_deref(), self.psk_file.as_deref())?;

        // Mode-specific validation.
        match self.mode {
            DeploymentMode::Embedded => {
                if self.broker_config.is_none() {
                    return Err(ConfigError::BrokerConfigRequired);
                }
            }
            DeploymentMode::Standalone => {
                if self.resolver.is_none() {
                    return Err(ConfigError::ResolverRequired);
                }
            }
        }

        let poll_idle = Duration::from_millis(self.poll_idle_ms);
        let backoff_max = match self.backoff_max_ms {
            Some(ms) => Duration::from_millis(ms),
            None => poll_idle,
        };

        let mut blocked = if self.allow_private_networks {
            info!("default private-network blocking disabled by --allow-private-networks");
            vec![]
        } else {
            default_blocked_ranges()
        };
        for cidr_str in &self.disallow_networks {
            let net: IpNet = cidr_str.parse().map_err(|e| ConfigError::InvalidCidr {
                value: cidr_str.clone(),
                source: e,
            })?;
            blocked.push(net);
        }

        Ok(SmolExitConfig {
            controlled_domain: self.domain,
            resolver_addr: self.resolver,
            node_id: self.node_id,
            psk,
            mode: self.mode,
            broker_config_path: self.broker_config,
            poll_active: Duration::from_millis(self.poll_active_ms),
            poll_idle,
            connect_timeout: Duration::from_millis(self.connect_timeout_ms),
            backoff_max,
            no_edns: self.no_edns,
            blocked_networks: blocked,
            query_interval: Duration::from_millis(self.query_interval_ms),
            smol_tuning: SmolTuningConfig {
                initial_rto: Duration::from_millis(self.smol_rto_ms),
                window_segments: self.smol_window_segments,
                mss: self.smol_mss,
            },
        })
    }
}

// ---------------------------------------------------------------------------
// Relay (dnsrelay)
// ---------------------------------------------------------------------------

/// CLI arguments for the dnsrelay binary.
#[derive(Parser, Debug)]
#[command(name = "dns-exit-smol-rb", version, about = "DNS relay server with integrated smoltcp exit node")]
pub struct RelayCliArgs {
    /// Controlled DNS domain (e.g. "tunnel.example.com").
    #[arg(long)]
    pub domain: String,

    /// UDP bind address (default: 0.0.0.0:53).
    #[arg(long, default_value = "0.0.0.0:53")]
    pub listen: SocketAddr,

    /// Node identifier used as sender_id.
    #[arg(long)]
    pub node_id: String,

    /// Pre-shared key as a hex-encoded string.
    #[arg(long, group = "psk_source")]
    pub psk: Option<String>,

    /// Path to a file containing the raw PSK bytes.
    #[arg(long, group = "psk_source")]
    pub psk_file: Option<PathBuf>,

    /// Packet slot expiry TTL in seconds (default: 600).
    #[arg(long, default_value_t = 600)]
    pub message_ttl_secs: u64,

    /// Expiry sweep interval in seconds (default: 30).
    #[arg(long, default_value_t = 30)]
    pub expiry_interval_secs: u64,

    /// TCP connect timeout in milliseconds (default: 10000).
    #[arg(long, default_value_t = 10000)]
    pub connect_timeout_ms: u64,

    /// Active poll interval in milliseconds (default: 50).
    #[arg(long, default_value_t = 50)]
    pub poll_active_ms: u64,

    /// Idle poll interval in milliseconds (default: 500).
    #[arg(long, default_value_t = 500)]
    pub poll_idle_ms: u64,

    /// smoltcp initial RTO in milliseconds (default: 3000).
    #[arg(long, default_value_t = 3000)]
    pub smol_rto_ms: u64,

    /// smoltcp TCP window size in MSS multiples (default: 4).
    #[arg(long, default_value_t = 4)]
    pub smol_window_segments: usize,

    /// Override smoltcp MSS (default: auto-computed from DNS payload budget).
    #[arg(long)]
    pub smol_mss: Option<usize>,

    /// Disable default private-network blocking (allows RFC 1918, loopback, etc.).
    #[arg(long)]
    pub allow_private_networks: bool,

    /// Additional CIDR ranges to block (repeatable).
    #[arg(long = "disallow-network", value_name = "CIDR")]
    pub disallow_networks: Vec<String>,
}

/// Validated configuration for the dnsrelay binary.
pub struct RelayConfig {
    /// Controlled DNS domain.
    pub controlled_domain: String,
    /// UDP bind address.
    pub listen_addr: SocketAddr,
    /// Node identifier.
    pub node_id: String,
    /// Pre-shared key (≥ 32 bytes).
    pub psk: Psk,
    /// Packet slot expiry TTL.
    pub message_ttl: Duration,
    /// Expiry sweep interval.
    pub expiry_interval: Duration,
    /// TCP connect timeout.
    pub connect_timeout: Duration,
    /// Active poll interval.
    pub poll_active: Duration,
    /// Idle poll interval.
    pub poll_idle: Duration,
    /// smoltcp tuning parameters.
    pub smol_tuning: SmolTuningConfig,
    /// Active blocked CIDR ranges.
    pub blocked_networks: Vec<IpNet>,
}

impl RelayCliArgs {
    /// Parse CLI arguments and validate into a `RelayConfig`.
    pub fn into_config(self) -> Result<RelayConfig, ConfigError> {
        let psk = resolve_psk(self.psk.as_deref(), self.psk_file.as_deref())?;

        let mut blocked = if self.allow_private_networks {
            info!("default private-network blocking disabled by --allow-private-networks");
            vec![]
        } else {
            default_blocked_ranges()
        };
        for cidr_str in &self.disallow_networks {
            let net: IpNet = cidr_str.parse().map_err(|e| ConfigError::InvalidCidr {
                value: cidr_str.clone(),
                source: e,
            })?;
            blocked.push(net);
        }

        Ok(RelayConfig {
            controlled_domain: self.domain,
            listen_addr: self.listen,
            node_id: self.node_id,
            psk,
            message_ttl: Duration::from_secs(self.message_ttl_secs),
            expiry_interval: Duration::from_secs(self.expiry_interval_secs),
            connect_timeout: Duration::from_millis(self.connect_timeout_ms),
            poll_active: Duration::from_millis(self.poll_active_ms),
            poll_idle: Duration::from_millis(self.poll_idle_ms),
            smol_tuning: SmolTuningConfig {
                initial_rto: Duration::from_millis(self.smol_rto_ms),
                window_segments: self.smol_window_segments,
                mss: self.smol_mss,
            },
            blocked_networks: blocked,
        })
    }
}

// ---------------------------------------------------------------------------
// Relay SOCKS (dnssocksrelay)
// ---------------------------------------------------------------------------

/// CLI arguments for the dnssocksrelay binary.
#[derive(Parser, Debug)]
#[command(name = "dns-socksd-smol-rb", version, about = "SOCKS5 proxy client that tunnels TCP traffic through a dns-exit-smol-rb instance")]
pub struct RelaySocksCliArgs {
    /// Controlled DNS domain (e.g. "tunnel.example.com").
    #[arg(long)]
    pub domain: String,

    /// DNS resolver (dnsrelay) address, e.g. "127.0.0.1:53".
    #[arg(long)]
    pub resolver: SocketAddr,

    /// Client identifier used as sender_id prefix.
    #[arg(long)]
    pub client_id: String,

    /// Exit node identifier (dnsrelay's node-id).
    #[arg(long)]
    pub exit_node_id: String,

    /// Pre-shared key as a hex-encoded string.
    #[arg(long, group = "psk_source")]
    pub psk: Option<String>,

    /// Path to a file containing the raw PSK bytes.
    #[arg(long, group = "psk_source")]
    pub psk_file: Option<PathBuf>,

    /// Local listen address (default: 127.0.0.1).
    #[arg(long, default_value = "127.0.0.1")]
    pub listen_addr: IpAddr,

    /// Local listen port (default: 1080).
    #[arg(long, default_value_t = 1080)]
    pub listen_port: u16,

    /// Session setup timeout in milliseconds (default: 30000).
    #[arg(long, default_value_t = 30000)]
    pub connect_timeout_ms: u64,

    /// Active poll interval in milliseconds (default: 50).
    #[arg(long, default_value_t = 50)]
    pub poll_active_ms: u64,

    /// Idle poll interval in milliseconds (default: 500).
    #[arg(long, default_value_t = 500)]
    pub poll_idle_ms: u64,

    /// Maximum backoff interval in milliseconds (default: value of poll_idle_ms).
    #[arg(long)]
    pub backoff_max_ms: Option<u64>,

    /// smoltcp initial RTO in milliseconds (default: 3000).
    #[arg(long, default_value_t = 3000)]
    pub smol_rto_ms: u64,

    /// smoltcp TCP window size in MSS multiples (default: 4).
    #[arg(long, default_value_t = 4)]
    pub smol_window_segments: usize,

    /// Override smoltcp MSS (default: auto-computed from DNS payload budget).
    #[arg(long)]
    pub smol_mss: Option<usize>,

    /// Disable EDNS0 OPT record on TXT queries.
    #[arg(long)]
    pub no_edns: bool,

    /// Minimum interval between DNS queries in milliseconds (default: 0 = no throttle).
    #[arg(long, default_value_t = 0)]
    pub query_interval_ms: u64,

    /// Maximum number of concurrent active sessions (default: 8).
    #[arg(long, default_value_t = 8)]
    pub max_concurrent_sessions: usize,

    /// Queue timeout in milliseconds for waiting connections (default: 30000).
    #[arg(long, default_value_t = 30000)]
    pub queue_timeout_ms: u64,
}

/// Validated configuration for the dnssocksrelay binary.
pub struct RelaySocksConfig {
    /// Controlled DNS domain.
    pub controlled_domain: String,
    /// DNS resolver (dnsrelay) address.
    pub resolver_addr: SocketAddr,
    /// Client identifier.
    pub client_id: String,
    /// Exit node identifier.
    pub exit_node_id: String,
    /// Pre-shared key (≥ 32 bytes).
    pub psk: Psk,
    /// Local listen address.
    pub listen_addr: IpAddr,
    /// Local listen port.
    pub listen_port: u16,
    /// Session setup timeout.
    pub connect_timeout: Duration,
    /// Active poll interval.
    pub poll_active: Duration,
    /// Idle poll interval.
    pub poll_idle: Duration,
    /// Maximum backoff interval.
    pub backoff_max: Duration,
    /// smoltcp tuning parameters.
    pub smol_tuning: SmolTuningConfig,
    /// Whether to disable EDNS0 on TXT queries.
    pub no_edns: bool,
    /// Minimum interval between DNS queries.
    pub query_interval: Duration,
    /// Maximum number of concurrent active sessions.
    pub max_concurrent_sessions: usize,
    /// Queue timeout for waiting connections.
    pub queue_timeout: Duration,
}

impl RelaySocksCliArgs {
    /// Parse CLI arguments and validate into a `RelaySocksConfig`.
    pub fn into_config(self) -> Result<RelaySocksConfig, ConfigError> {
        if self.max_concurrent_sessions < 1 {
            return Err(ConfigError::InvalidMaxConcurrentSessions {
                got: self.max_concurrent_sessions,
            });
        }

        let psk = resolve_psk(self.psk.as_deref(), self.psk_file.as_deref())?;
        let poll_idle = Duration::from_millis(self.poll_idle_ms);
        let backoff_max = match self.backoff_max_ms {
            Some(ms) => Duration::from_millis(ms),
            None => poll_idle,
        };

        Ok(RelaySocksConfig {
            controlled_domain: self.domain,
            resolver_addr: self.resolver,
            client_id: self.client_id,
            exit_node_id: self.exit_node_id,
            psk,
            listen_addr: self.listen_addr,
            listen_port: self.listen_port,
            connect_timeout: Duration::from_millis(self.connect_timeout_ms),
            poll_active: Duration::from_millis(self.poll_active_ms),
            poll_idle,
            backoff_max,
            smol_tuning: SmolTuningConfig {
                initial_rto: Duration::from_millis(self.smol_rto_ms),
                window_segments: self.smol_window_segments,
                mss: self.smol_mss,
            },
            no_edns: self.no_edns,
            query_interval: Duration::from_millis(self.query_interval_ms),
            max_concurrent_sessions: self.max_concurrent_sessions,
            queue_timeout: Duration::from_millis(self.queue_timeout_ms),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- decode_hex ---

    #[test]
    fn decode_hex_valid() {
        assert_eq!(decode_hex("deadbeef").unwrap(), vec![0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn decode_hex_with_0x_prefix() {
        assert_eq!(decode_hex("0xCAFE").unwrap(), vec![0xca, 0xfe]);
    }

    #[test]
    fn decode_hex_odd_length() {
        assert!(decode_hex("abc").is_err());
    }

    #[test]
    fn decode_hex_invalid_chars() {
        assert!(decode_hex("zzzz").is_err());
    }

    // --- PSK resolution ---

    #[test]
    fn resolve_psk_from_hex() {
        let hex = "aa".repeat(32); // 32 bytes
        let psk = resolve_psk(Some(&hex), None).unwrap();
        assert_eq!(psk.as_bytes().len(), 32);
    }

    #[test]
    fn resolve_psk_hex_too_short() {
        let hex = "aa".repeat(16); // 16 bytes < 32
        let result = resolve_psk(Some(&hex), None);
        assert!(result.is_err());
    }

    #[test]
    fn resolve_psk_none_provided() {
        let result = resolve_psk(None, None);
        assert!(matches!(result, Err(ConfigError::PskNotProvided)));
    }

    #[test]
    fn resolve_psk_from_file() {
        // Write a temp file with 32 bytes.
        let dir = std::env::temp_dir().join("dns-socks-proxy-test-psk");
        std::fs::write(&dir, vec![0x42u8; 32]).unwrap();
        let psk = resolve_psk(None, Some(&dir)).unwrap();
        assert_eq!(psk.as_bytes().len(), 32);
        let _ = std::fs::remove_file(&dir);
    }

    #[test]
    fn resolve_psk_file_not_found() {
        let result = resolve_psk(None, Some(std::path::Path::new("/nonexistent/psk")));
        assert!(result.is_err());
    }

    // --- SocksClientCli::into_config ---

    fn base_socks_cli() -> SocksClientCli {
        SocksClientCli {
            listen_addr: "127.0.0.1".parse().unwrap(),
            listen_port: 1080,
            domain: "tunnel.example.com".into(),
            resolver: "127.0.0.1:5353".parse().unwrap(),
            client_id: "myclient".into(),
            exit_node_id: "mynode".into(),
            psk: Some("aa".repeat(32)),
            psk_file: None,
            rto_ms: 2000,
            max_retransmits: 10,
            window_size: 8,
            poll_active_ms: 50,
            poll_idle_ms: 500,
            connect_timeout_ms: 30000,
            max_parallel_queries: 8,
            backoff_max_ms: None,
            max_concurrent_sessions: 8,
            queue_timeout_ms: 30000,
            query_interval_ms: 0,
            no_edns: false,
        }
    }

    #[test]
    fn socks_client_config_defaults() {
        let cfg = base_socks_cli().into_config().unwrap();
        assert_eq!(cfg.listen_addr, "127.0.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(cfg.listen_port, 1080);
        assert_eq!(cfg.controlled_domain, "tunnel.example.com");
        assert_eq!(cfg.rto, Duration::from_millis(2000));
        assert_eq!(cfg.max_retransmits, 10);
        assert_eq!(cfg.window_size, 8);
        assert_eq!(cfg.poll_active, Duration::from_millis(50));
        assert_eq!(cfg.poll_idle, Duration::from_millis(500));
    }

    #[test]
    fn socks_client_config_no_psk() {
        let mut cli = base_socks_cli();
        cli.psk = None;
        cli.psk_file = None;
        assert!(cli.into_config().is_err());
    }

    // --- ExitNodeCli::into_config ---

    fn base_exit_cli() -> ExitNodeCli {
        ExitNodeCli {
            domain: "tunnel.example.com".into(),
            resolver: Some("127.0.0.1:5353".parse().unwrap()),
            node_id: "mynode".into(),
            psk: Some("bb".repeat(32)),
            psk_file: None,
            mode: DeploymentMode::Standalone,
            broker_config: None,
            rto_ms: 2000,
            max_retransmits: 10,
            window_size: 8,
            poll_active_ms: 50,
            poll_idle_ms: 500,
            connect_timeout_ms: 10000,
            max_parallel_queries: 8,
            backoff_max_ms: None,
            no_edns: false,
            allow_private_networks: false,
            disallow_networks: vec![],
        }
    }

    #[test]
    fn exit_node_config_standalone() {
        let cfg = base_exit_cli().into_config().unwrap();
        assert_eq!(cfg.mode, DeploymentMode::Standalone);
        assert!(cfg.resolver_addr.is_some());
        assert_eq!(cfg.connect_timeout, Duration::from_secs(10));
    }

    #[test]
    fn exit_node_standalone_requires_resolver() {
        let mut cli = base_exit_cli();
        cli.resolver = None;
        let result = cli.into_config();
        assert!(matches!(result, Err(ConfigError::ResolverRequired)));
    }

    #[test]
    fn exit_node_embedded_requires_broker_config() {
        let mut cli = base_exit_cli();
        cli.mode = DeploymentMode::Embedded;
        cli.resolver = None;
        cli.broker_config = None;
        let result = cli.into_config();
        assert!(matches!(result, Err(ConfigError::BrokerConfigRequired)));
    }

    #[test]
    fn exit_node_embedded_with_broker_config() {
        let mut cli = base_exit_cli();
        cli.mode = DeploymentMode::Embedded;
        cli.resolver = None;
        cli.broker_config = Some(PathBuf::from("/etc/broker.toml"));
        let cfg = cli.into_config().unwrap();
        assert_eq!(cfg.mode, DeploymentMode::Embedded);
        assert_eq!(
            cfg.broker_config_path,
            Some(PathBuf::from("/etc/broker.toml"))
        );
    }

    #[test]
    fn exit_node_config_no_psk() {
        let mut cli = base_exit_cli();
        cli.psk = None;
        cli.psk_file = None;
        assert!(cli.into_config().is_err());
    }

    // --- Concurrency config ---

    #[test]
    fn socks_client_concurrency_defaults() {
        let cfg = base_socks_cli().into_config().unwrap();
        assert_eq!(cfg.max_concurrent_sessions, 8);
        assert_eq!(cfg.queue_timeout, Duration::from_secs(30));
    }

    #[test]
    fn socks_client_zero_max_concurrent_sessions_rejected() {
        let mut cli = base_socks_cli();
        cli.max_concurrent_sessions = 0;
        let result = cli.into_config();
        assert!(matches!(
            result,
            Err(ConfigError::InvalidMaxConcurrentSessions { got: 0 })
        ));
    }

    #[test]
    fn socks_client_zero_queue_timeout_produces_duration_zero() {
        let mut cli = base_socks_cli();
        cli.queue_timeout_ms = 0;
        let cfg = cli.into_config().unwrap();
        assert_eq!(cfg.queue_timeout, Duration::ZERO);
    }

    // --- DeploymentMode ---

    #[test]
    fn deployment_mode_value_enum() {
        // Verify ValueEnum derives work by round-tripping through string.
        use clap::ValueEnum;
        let variants = DeploymentMode::value_variants();
        assert_eq!(variants.len(), 2);
        assert_eq!(
            DeploymentMode::from_str("standalone", true).unwrap(),
            DeploymentMode::Standalone
        );
        assert_eq!(
            DeploymentMode::from_str("embedded", true).unwrap(),
            DeploymentMode::Embedded
        );
    }

    // --- Guard config (blocked_networks) ---

    #[test]
    fn exit_node_default_blocked_networks() {
        let cfg = base_exit_cli().into_config().unwrap();
        assert_eq!(cfg.blocked_networks, default_blocked_ranges());
    }

    #[test]
    fn exit_node_allow_private_networks_empties_defaults() {
        let mut cli = base_exit_cli();
        cli.allow_private_networks = true;
        let cfg = cli.into_config().unwrap();
        assert!(cfg.blocked_networks.is_empty());
    }

    #[test]
    fn exit_node_disallow_network_adds_range() {
        let mut cli = base_exit_cli();
        cli.disallow_networks = vec!["203.0.113.0/24".into()];
        let cfg = cli.into_config().unwrap();
        let expected_extra: IpNet = "203.0.113.0/24".parse().unwrap();
        assert!(cfg.blocked_networks.contains(&expected_extra));
        // Should also contain the defaults
        assert_eq!(cfg.blocked_networks.len(), default_blocked_ranges().len() + 1);
    }

    #[test]
    fn exit_node_invalid_cidr_produces_error() {
        let mut cli = base_exit_cli();
        cli.disallow_networks = vec!["not-a-cidr".into()];
        let result = cli.into_config();
        assert!(matches!(result, Err(ConfigError::InvalidCidr { .. })));
    }

    #[test]
    fn exit_node_allow_private_with_custom_ranges() {
        let mut cli = base_exit_cli();
        cli.allow_private_networks = true;
        cli.disallow_networks = vec!["203.0.113.0/24".into()];
        let cfg = cli.into_config().unwrap();
        let expected: IpNet = "203.0.113.0/24".parse().unwrap();
        assert_eq!(cfg.blocked_networks, vec![expected]);
    }

    // --- SmolTuningConfig ---

    #[test]
    fn smol_tuning_config_defaults() {
        let cfg = SmolTuningConfig::default();
        assert_eq!(cfg.initial_rto, Duration::from_millis(3000));
        assert_eq!(cfg.window_segments, 4);
        assert_eq!(cfg.mss, None);
    }

    // --- SmolClientCli ---

    fn base_smol_client_cli() -> SmolClientCli {
        SmolClientCli {
            listen_addr: "127.0.0.1".parse().unwrap(),
            listen_port: 1080,
            domain: "tunnel.example.com".into(),
            resolver: "127.0.0.1:5353".parse().unwrap(),
            client_id: "myclient".into(),
            exit_node_id: "mynode".into(),
            psk: Some("aa".repeat(32)),
            psk_file: None,
            poll_active_ms: 50,
            poll_idle_ms: 500,
            connect_timeout_ms: 30000,
            backoff_max_ms: None,
            max_concurrent_sessions: 8,
            queue_timeout_ms: 30000,
            query_interval_ms: 0,
            no_edns: false,
            smol_rto_ms: 3000,
            smol_window_segments: 4,
            smol_mss: None,
        }
    }

    #[test]
    fn smol_client_config_defaults() {
        let cfg = base_smol_client_cli().into_config().unwrap();
        assert_eq!(cfg.listen_addr, "127.0.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(cfg.listen_port, 1080);
        assert_eq!(cfg.controlled_domain, "tunnel.example.com");
        assert_eq!(cfg.poll_active, Duration::from_millis(50));
        assert_eq!(cfg.poll_idle, Duration::from_millis(500));
        assert_eq!(cfg.connect_timeout, Duration::from_secs(30));
        assert_eq!(cfg.max_concurrent_sessions, 8);
        assert_eq!(cfg.smol_tuning.initial_rto, Duration::from_millis(3000));
        assert_eq!(cfg.smol_tuning.window_segments, 4);
        assert_eq!(cfg.smol_tuning.mss, None);
    }

    #[test]
    fn smol_client_config_custom_tuning() {
        let mut cli = base_smol_client_cli();
        cli.smol_rto_ms = 5000;
        cli.smol_window_segments = 8;
        cli.smol_mss = Some(100);
        let cfg = cli.into_config().unwrap();
        assert_eq!(cfg.smol_tuning.initial_rto, Duration::from_millis(5000));
        assert_eq!(cfg.smol_tuning.window_segments, 8);
        assert_eq!(cfg.smol_tuning.mss, Some(100));
    }

    #[test]
    fn smol_client_config_no_psk() {
        let mut cli = base_smol_client_cli();
        cli.psk = None;
        cli.psk_file = None;
        assert!(cli.into_config().is_err());
    }

    #[test]
    fn smol_client_zero_concurrent_sessions_rejected() {
        let mut cli = base_smol_client_cli();
        cli.max_concurrent_sessions = 0;
        let result = cli.into_config();
        assert!(matches!(
            result,
            Err(ConfigError::InvalidMaxConcurrentSessions { got: 0 })
        ));
    }

    #[test]
    fn smol_client_backoff_defaults_to_poll_idle() {
        let cfg = base_smol_client_cli().into_config().unwrap();
        assert_eq!(cfg.backoff_max, cfg.poll_idle);
    }

    #[test]
    fn smol_client_backoff_override() {
        let mut cli = base_smol_client_cli();
        cli.backoff_max_ms = Some(2000);
        let cfg = cli.into_config().unwrap();
        assert_eq!(cfg.backoff_max, Duration::from_millis(2000));
    }

    // --- SmolExitCli ---

    fn base_smol_exit_cli() -> SmolExitCli {
        SmolExitCli {
            domain: "tunnel.example.com".into(),
            resolver: Some("127.0.0.1:5353".parse().unwrap()),
            node_id: "mynode".into(),
            psk: Some("bb".repeat(32)),
            psk_file: None,
            mode: DeploymentMode::Standalone,
            broker_config: None,
            poll_active_ms: 50,
            poll_idle_ms: 500,
            connect_timeout_ms: 10000,
            backoff_max_ms: None,
            no_edns: false,
            allow_private_networks: false,
            disallow_networks: vec![],
            query_interval_ms: 0,
            smol_rto_ms: 3000,
            smol_window_segments: 4,
            smol_mss: None,
        }
    }

    #[test]
    fn smol_exit_config_standalone() {
        let cfg = base_smol_exit_cli().into_config().unwrap();
        assert_eq!(cfg.mode, DeploymentMode::Standalone);
        assert!(cfg.resolver_addr.is_some());
        assert_eq!(cfg.connect_timeout, Duration::from_secs(10));
        assert_eq!(cfg.smol_tuning.initial_rto, Duration::from_millis(3000));
        assert_eq!(cfg.smol_tuning.window_segments, 4);
        assert_eq!(cfg.smol_tuning.mss, None);
    }

    #[test]
    fn smol_exit_config_custom_tuning() {
        let mut cli = base_smol_exit_cli();
        cli.smol_rto_ms = 5000;
        cli.smol_window_segments = 8;
        cli.smol_mss = Some(100);
        let cfg = cli.into_config().unwrap();
        assert_eq!(cfg.smol_tuning.initial_rto, Duration::from_millis(5000));
        assert_eq!(cfg.smol_tuning.window_segments, 8);
        assert_eq!(cfg.smol_tuning.mss, Some(100));
    }

    #[test]
    fn smol_exit_standalone_requires_resolver() {
        let mut cli = base_smol_exit_cli();
        cli.resolver = None;
        let result = cli.into_config();
        assert!(matches!(result, Err(ConfigError::ResolverRequired)));
    }

    #[test]
    fn smol_exit_embedded_requires_broker_config() {
        let mut cli = base_smol_exit_cli();
        cli.mode = DeploymentMode::Embedded;
        cli.resolver = None;
        cli.broker_config = None;
        let result = cli.into_config();
        assert!(matches!(result, Err(ConfigError::BrokerConfigRequired)));
    }

    #[test]
    fn smol_exit_embedded_with_broker_config() {
        let mut cli = base_smol_exit_cli();
        cli.mode = DeploymentMode::Embedded;
        cli.resolver = None;
        cli.broker_config = Some(PathBuf::from("/etc/broker.toml"));
        let cfg = cli.into_config().unwrap();
        assert_eq!(cfg.mode, DeploymentMode::Embedded);
        assert_eq!(cfg.broker_config_path, Some(PathBuf::from("/etc/broker.toml")));
    }

    #[test]
    fn smol_exit_config_no_psk() {
        let mut cli = base_smol_exit_cli();
        cli.psk = None;
        cli.psk_file = None;
        assert!(cli.into_config().is_err());
    }

    #[test]
    fn smol_exit_default_blocked_networks() {
        let cfg = base_smol_exit_cli().into_config().unwrap();
        assert_eq!(cfg.blocked_networks, default_blocked_ranges());
    }

    #[test]
    fn smol_exit_allow_private_networks() {
        let mut cli = base_smol_exit_cli();
        cli.allow_private_networks = true;
        let cfg = cli.into_config().unwrap();
        assert!(cfg.blocked_networks.is_empty());
    }

    #[test]
    fn smol_exit_disallow_network_adds_range() {
        let mut cli = base_smol_exit_cli();
        cli.disallow_networks = vec!["203.0.113.0/24".into()];
        let cfg = cli.into_config().unwrap();
        let expected_extra: IpNet = "203.0.113.0/24".parse().unwrap();
        assert!(cfg.blocked_networks.contains(&expected_extra));
        assert_eq!(cfg.blocked_networks.len(), default_blocked_ranges().len() + 1);
    }

    #[test]
    fn smol_exit_invalid_cidr_produces_error() {
        let mut cli = base_smol_exit_cli();
        cli.disallow_networks = vec!["not-a-cidr".into()];
        let result = cli.into_config();
        assert!(matches!(result, Err(ConfigError::InvalidCidr { .. })));
    }

    #[test]
    fn smol_exit_backoff_defaults_to_poll_idle() {
        let cfg = base_smol_exit_cli().into_config().unwrap();
        assert_eq!(cfg.backoff_max, cfg.poll_idle);
    }

    #[test]
    fn smol_exit_query_interval() {
        let mut cli = base_smol_exit_cli();
        cli.query_interval_ms = 100;
        let cfg = cli.into_config().unwrap();
        assert_eq!(cfg.query_interval, Duration::from_millis(100));
    }

    // --- RelayCliArgs ---

    fn base_relay_cli() -> RelayCliArgs {
        RelayCliArgs {
            domain: "tunnel.example.com".into(),
            listen: "0.0.0.0:53".parse().unwrap(),
            node_id: "mynode".into(),
            psk: Some("bb".repeat(32)),
            psk_file: None,
            message_ttl_secs: 600,
            expiry_interval_secs: 30,
            connect_timeout_ms: 10000,
            poll_active_ms: 50,
            poll_idle_ms: 500,
            smol_rto_ms: 3000,
            smol_window_segments: 4,
            smol_mss: None,
            allow_private_networks: false,
            disallow_networks: vec![],
        }
    }

    #[test]
    fn relay_config_defaults() {
        let cfg = base_relay_cli().into_config().unwrap();
        assert_eq!(cfg.controlled_domain, "tunnel.example.com");
        assert_eq!(cfg.listen_addr, "0.0.0.0:53".parse::<SocketAddr>().unwrap());
        assert_eq!(cfg.node_id, "mynode");
        assert_eq!(cfg.message_ttl, Duration::from_secs(600));
        assert_eq!(cfg.expiry_interval, Duration::from_secs(30));
        assert_eq!(cfg.connect_timeout, Duration::from_secs(10));
        assert_eq!(cfg.poll_active, Duration::from_millis(50));
        assert_eq!(cfg.poll_idle, Duration::from_millis(500));
        assert_eq!(cfg.smol_tuning.initial_rto, Duration::from_millis(3000));
        assert_eq!(cfg.smol_tuning.window_segments, 4);
        assert_eq!(cfg.smol_tuning.mss, None);
    }

    #[test]
    fn relay_config_no_psk() {
        let mut cli = base_relay_cli();
        cli.psk = None;
        cli.psk_file = None;
        assert!(cli.into_config().is_err());
    }

    #[test]
    fn relay_config_default_blocked_networks() {
        let cfg = base_relay_cli().into_config().unwrap();
        assert_eq!(cfg.blocked_networks, default_blocked_ranges());
    }

    #[test]
    fn relay_config_allow_private_networks() {
        let mut cli = base_relay_cli();
        cli.allow_private_networks = true;
        let cfg = cli.into_config().unwrap();
        assert!(cfg.blocked_networks.is_empty());
    }

    #[test]
    fn relay_config_disallow_network_adds_range() {
        let mut cli = base_relay_cli();
        cli.disallow_networks = vec!["203.0.113.0/24".into()];
        let cfg = cli.into_config().unwrap();
        let expected_extra: IpNet = "203.0.113.0/24".parse().unwrap();
        assert!(cfg.blocked_networks.contains(&expected_extra));
        assert_eq!(cfg.blocked_networks.len(), default_blocked_ranges().len() + 1);
    }

    #[test]
    fn relay_config_invalid_cidr_produces_error() {
        let mut cli = base_relay_cli();
        cli.disallow_networks = vec!["not-a-cidr".into()];
        let result = cli.into_config();
        assert!(matches!(result, Err(ConfigError::InvalidCidr { .. })));
    }

    #[test]
    fn relay_config_custom_tuning() {
        let mut cli = base_relay_cli();
        cli.smol_rto_ms = 5000;
        cli.smol_window_segments = 8;
        cli.smol_mss = Some(100);
        let cfg = cli.into_config().unwrap();
        assert_eq!(cfg.smol_tuning.initial_rto, Duration::from_millis(5000));
        assert_eq!(cfg.smol_tuning.window_segments, 8);
        assert_eq!(cfg.smol_tuning.mss, Some(100));
    }

    // --- RelaySocksCliArgs ---

    fn base_relay_socks_cli() -> RelaySocksCliArgs {
        RelaySocksCliArgs {
            domain: "tunnel.example.com".into(),
            resolver: "127.0.0.1:53".parse().unwrap(),
            client_id: "myclient".into(),
            exit_node_id: "mynode".into(),
            psk: Some("aa".repeat(32)),
            psk_file: None,
            listen_addr: "127.0.0.1".parse().unwrap(),
            listen_port: 1080,
            connect_timeout_ms: 30000,
            poll_active_ms: 50,
            poll_idle_ms: 500,
            backoff_max_ms: None,
            smol_rto_ms: 3000,
            smol_window_segments: 4,
            smol_mss: None,
            no_edns: false,
            query_interval_ms: 0,
            max_concurrent_sessions: 8,
            queue_timeout_ms: 30000,
        }
    }

    #[test]
    fn relay_socks_config_defaults() {
        let cfg = base_relay_socks_cli().into_config().unwrap();
        assert_eq!(cfg.controlled_domain, "tunnel.example.com");
        assert_eq!(cfg.resolver_addr, "127.0.0.1:53".parse::<SocketAddr>().unwrap());
        assert_eq!(cfg.client_id, "myclient");
        assert_eq!(cfg.exit_node_id, "mynode");
        assert_eq!(cfg.listen_addr, "127.0.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(cfg.listen_port, 1080);
        assert_eq!(cfg.connect_timeout, Duration::from_secs(30));
        assert_eq!(cfg.poll_active, Duration::from_millis(50));
        assert_eq!(cfg.poll_idle, Duration::from_millis(500));
        assert_eq!(cfg.max_concurrent_sessions, 8);
        assert_eq!(cfg.queue_timeout, Duration::from_secs(30));
        assert_eq!(cfg.smol_tuning.initial_rto, Duration::from_millis(3000));
        assert_eq!(cfg.smol_tuning.window_segments, 4);
        assert_eq!(cfg.smol_tuning.mss, None);
        assert!(!cfg.no_edns);
        assert_eq!(cfg.query_interval, Duration::ZERO);
    }

    #[test]
    fn relay_socks_config_no_psk() {
        let mut cli = base_relay_socks_cli();
        cli.psk = None;
        cli.psk_file = None;
        assert!(cli.into_config().is_err());
    }

    #[test]
    fn relay_socks_zero_concurrent_sessions_rejected() {
        let mut cli = base_relay_socks_cli();
        cli.max_concurrent_sessions = 0;
        let result = cli.into_config();
        assert!(matches!(
            result,
            Err(ConfigError::InvalidMaxConcurrentSessions { got: 0 })
        ));
    }

    #[test]
    fn relay_socks_backoff_defaults_to_poll_idle() {
        let cfg = base_relay_socks_cli().into_config().unwrap();
        assert_eq!(cfg.backoff_max, cfg.poll_idle);
    }

    #[test]
    fn relay_socks_backoff_override() {
        let mut cli = base_relay_socks_cli();
        cli.backoff_max_ms = Some(2000);
        let cfg = cli.into_config().unwrap();
        assert_eq!(cfg.backoff_max, Duration::from_millis(2000));
    }

    #[test]
    fn relay_socks_custom_tuning() {
        let mut cli = base_relay_socks_cli();
        cli.smol_rto_ms = 5000;
        cli.smol_window_segments = 8;
        cli.smol_mss = Some(100);
        let cfg = cli.into_config().unwrap();
        assert_eq!(cfg.smol_tuning.initial_rto, Duration::from_millis(5000));
        assert_eq!(cfg.smol_tuning.window_segments, 8);
        assert_eq!(cfg.smol_tuning.mss, Some(100));
    }
}
