// Configuration: CLI parsing for socks-client and exit-node.

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;

use clap::{Parser, ValueEnum};

use crate::crypto::Psk;

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

    #[error("PSK validation failed: {0}")]
    PskValidation(#[from] crate::crypto::CryptoError),
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
#[command(name = "socks-client", version, about = "SOCKS5 proxy client that tunnels TCP traffic over DNS")]
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
}

impl SocksClientCli {
    /// Parse CLI arguments and validate into a `SocksClientConfig`.
    pub fn into_config(self) -> Result<SocksClientConfig, ConfigError> {
        let psk = resolve_psk(self.psk.as_deref(), self.psk_file.as_deref())?;

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
            poll_idle: Duration::from_millis(self.poll_idle_ms),
            connect_timeout: Duration::from_millis(self.connect_timeout_ms),
        })
    }
}

// ---------------------------------------------------------------------------
// Exit Node
// ---------------------------------------------------------------------------

/// CLI arguments for the exit-node binary.
#[derive(Parser, Debug)]
#[command(name = "exit-node", version, about = "Exit node that terminates DNS-tunneled TCP connections")]
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
            poll_idle: Duration::from_millis(self.poll_idle_ms),
            connect_timeout: Duration::from_millis(self.connect_timeout_ms),
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
}
