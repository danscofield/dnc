//! Configuration module for the DNS Message Broker.
//!
//! Handles parsing TOML configuration files and providing default values.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::error::ConfigError;

/// Default listen address.
/// Uses IPv6 unspecified (`::`) which accepts both IPv4 and IPv6 on dual-stack systems.
const DEFAULT_LISTEN_ADDR: IpAddr = IpAddr::V6(Ipv6Addr::UNSPECIFIED);
/// Default listen port.
const DEFAULT_LISTEN_PORT: u16 = 53;
/// Default channel inactivity timeout in seconds (1 hour).
const DEFAULT_CHANNEL_INACTIVITY_TIMEOUT_SECS: u64 = 3600;
/// Default max messages per channel.
const DEFAULT_MAX_MESSAGES_PER_CHANNEL: usize = 100;
/// Default message TTL in seconds (10 minutes).
const DEFAULT_MESSAGE_TTL_SECS: u64 = 600;
/// Default expiry sweep interval in seconds (30 seconds).
const DEFAULT_EXPIRY_INTERVAL_SECS: u64 = 30;
/// Default log level.
const DEFAULT_LOG_LEVEL: &str = "info";
/// Default acknowledgment IP.
const DEFAULT_ACK_IP: Ipv4Addr = Ipv4Addr::new(1, 2, 3, 4);
/// Default error IP for payload too large.
const DEFAULT_ERROR_PAYLOAD_TOO_LARGE_IP: Ipv4Addr = Ipv4Addr::new(1, 2, 3, 5);
/// Default error IP for channel full.
const DEFAULT_ERROR_CHANNEL_FULL_IP: Ipv4Addr = Ipv4Addr::new(1, 2, 3, 6);

/// Broker configuration with all fields resolved (defaults applied).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Config {
    /// Address to listen on.
    #[serde(default = "default_listen_addr")]
    pub listen_addr: IpAddr,
    /// UDP port to listen on.
    #[serde(default = "default_listen_port")]
    pub listen_port: u16,
    /// The controlled domain (required).
    pub controlled_domain: String,
    /// Channel inactivity timeout in seconds.
    #[serde(default = "default_channel_inactivity_timeout_secs")]
    pub channel_inactivity_timeout_secs: u64,
    /// Maximum messages per channel.
    #[serde(default = "default_max_messages_per_channel")]
    pub max_messages_per_channel: usize,
    /// Message TTL in seconds.
    #[serde(default = "default_message_ttl_secs")]
    pub message_ttl_secs: u64,
    /// Expiry sweep interval in seconds.
    #[serde(default = "default_expiry_interval_secs")]
    pub expiry_interval_secs: u64,
    /// Log level (e.g., "info", "debug", "trace").
    #[serde(default = "default_log_level")]
    pub log_level: String,
    /// Acknowledgment IP returned on successful send.
    #[serde(default = "default_ack_ip")]
    pub ack_ip: Ipv4Addr,
    /// Error IP returned when payload is too large.
    #[serde(default = "default_error_payload_too_large_ip")]
    pub error_payload_too_large_ip: Ipv4Addr,
    /// Error IP returned when channel is full.
    #[serde(default = "default_error_channel_full_ip")]
    pub error_channel_full_ip: Ipv4Addr,
}

// --- Serde default functions ---

fn default_listen_addr() -> IpAddr {
    DEFAULT_LISTEN_ADDR
}

fn default_listen_port() -> u16 {
    DEFAULT_LISTEN_PORT
}

fn default_channel_inactivity_timeout_secs() -> u64 {
    DEFAULT_CHANNEL_INACTIVITY_TIMEOUT_SECS
}

fn default_max_messages_per_channel() -> usize {
    DEFAULT_MAX_MESSAGES_PER_CHANNEL
}

fn default_message_ttl_secs() -> u64 {
    DEFAULT_MESSAGE_TTL_SECS
}

fn default_expiry_interval_secs() -> u64 {
    DEFAULT_EXPIRY_INTERVAL_SECS
}

fn default_log_level() -> String {
    DEFAULT_LOG_LEVEL.to_string()
}

fn default_ack_ip() -> Ipv4Addr {
    DEFAULT_ACK_IP
}

fn default_error_payload_too_large_ip() -> Ipv4Addr {
    DEFAULT_ERROR_PAYLOAD_TOO_LARGE_IP
}

fn default_error_channel_full_ip() -> Ipv4Addr {
    DEFAULT_ERROR_CHANNEL_FULL_IP
}

impl Config {
    /// Returns the channel inactivity timeout as a `Duration`.
    pub fn channel_inactivity_timeout(&self) -> Duration {
        Duration::from_secs(self.channel_inactivity_timeout_secs)
    }

    /// Returns the message TTL as a `Duration`.
    pub fn message_ttl(&self) -> Duration {
        Duration::from_secs(self.message_ttl_secs)
    }

    /// Returns the expiry sweep interval as a `Duration`.
    pub fn expiry_interval(&self) -> Duration {
        Duration::from_secs(self.expiry_interval_secs)
    }
}

/// Parse a TOML configuration string into a `Config`.
///
/// The `controlled_domain` field is required; all other fields have defaults.
/// Returns `ConfigError` if the TOML is invalid or `controlled_domain` is missing.
pub fn parse_config(toml_str: &str) -> Result<Config, ConfigError> {
    let config: Config =
        toml::from_str(toml_str).map_err(|e| ConfigError::ParseError(e.to_string()))?;

    if config.controlled_domain.is_empty() {
        return Err(ConfigError::MissingField(
            "controlled_domain".to_string(),
        ));
    }

    // Validate log_level is a recognized value.
    match config.log_level.to_lowercase().as_str() {
        "trace" | "debug" | "info" | "warn" | "error" | "off" => {}
        _ => {
            return Err(ConfigError::InvalidValue {
                field: "log_level".to_string(),
                reason: format!(
                    "unknown log level '{}', expected one of: trace, debug, info, warn, error, off",
                    config.log_level
                ),
            });
        }
    }

    Ok(config)
}

/// Format a `Config` as a valid TOML string that can be parsed back.
pub fn print_config(config: &Config) -> String {
    toml::to_string_pretty(config).expect("Config serialization should not fail")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_minimal_config() {
        let toml_str = r#"controlled_domain = "broker.example.com""#;
        let config = parse_config(toml_str).unwrap();
        assert_eq!(config.controlled_domain, "broker.example.com");
        assert_eq!(config.listen_addr, DEFAULT_LISTEN_ADDR);
        assert_eq!(config.listen_port, DEFAULT_LISTEN_PORT);
        assert_eq!(config.channel_inactivity_timeout_secs, DEFAULT_CHANNEL_INACTIVITY_TIMEOUT_SECS);
        assert_eq!(config.max_messages_per_channel, DEFAULT_MAX_MESSAGES_PER_CHANNEL);
        assert_eq!(config.message_ttl_secs, DEFAULT_MESSAGE_TTL_SECS);
        assert_eq!(config.expiry_interval_secs, DEFAULT_EXPIRY_INTERVAL_SECS);
        assert_eq!(config.log_level, DEFAULT_LOG_LEVEL);
        assert_eq!(config.ack_ip, DEFAULT_ACK_IP);
        assert_eq!(config.error_payload_too_large_ip, DEFAULT_ERROR_PAYLOAD_TOO_LARGE_IP);
        assert_eq!(config.error_channel_full_ip, DEFAULT_ERROR_CHANNEL_FULL_IP);
    }

    #[test]
    fn test_parse_full_config() {
        let toml_str = r#"
listen_addr = "127.0.0.1"
listen_port = 5353
controlled_domain = "test.example.com"
channel_inactivity_timeout_secs = 7200
max_messages_per_channel = 50
message_ttl_secs = 300
expiry_interval_secs = 15
log_level = "debug"
ack_ip = "10.0.0.1"
error_payload_too_large_ip = "10.0.0.2"
error_channel_full_ip = "10.0.0.3"
"#;
        let config = parse_config(toml_str).unwrap();
        assert_eq!(config.listen_addr, "127.0.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(config.listen_port, 5353);
        assert_eq!(config.controlled_domain, "test.example.com");
        assert_eq!(config.channel_inactivity_timeout_secs, 7200);
        assert_eq!(config.max_messages_per_channel, 50);
        assert_eq!(config.message_ttl_secs, 300);
        assert_eq!(config.expiry_interval_secs, 15);
        assert_eq!(config.log_level, "debug");
        assert_eq!(config.ack_ip, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(config.error_payload_too_large_ip, Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(config.error_channel_full_ip, Ipv4Addr::new(10, 0, 0, 3));
    }

    #[test]
    fn test_missing_controlled_domain() {
        let toml_str = r#"listen_port = 5353"#;
        let err = parse_config(toml_str).unwrap_err();
        assert!(matches!(err, ConfigError::ParseError(_)));
    }

    #[test]
    fn test_empty_controlled_domain() {
        let toml_str = r#"controlled_domain = """#;
        let err = parse_config(toml_str).unwrap_err();
        assert!(matches!(err, ConfigError::MissingField(_)));
    }

    #[test]
    fn test_invalid_toml() {
        let toml_str = "this is not valid toml {{{";
        let err = parse_config(toml_str).unwrap_err();
        assert!(matches!(err, ConfigError::ParseError(_)));
    }

    #[test]
    fn test_invalid_log_level() {
        let toml_str = r#"
controlled_domain = "broker.example.com"
log_level = "verbose"
"#;
        let err = parse_config(toml_str).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidValue { .. }));
    }

    #[test]
    fn test_print_config_roundtrip() {
        let toml_str = r#"controlled_domain = "broker.example.com""#;
        let config = parse_config(toml_str).unwrap();
        let printed = print_config(&config);
        let reparsed = parse_config(&printed).unwrap();
        assert_eq!(config, reparsed);
    }

    #[test]
    fn test_duration_helpers() {
        let toml_str = r#"
controlled_domain = "broker.example.com"
channel_inactivity_timeout_secs = 120
message_ttl_secs = 60
expiry_interval_secs = 10
"#;
        let config = parse_config(toml_str).unwrap();
        assert_eq!(config.channel_inactivity_timeout(), Duration::from_secs(120));
        assert_eq!(config.message_ttl(), Duration::from_secs(60));
        assert_eq!(config.expiry_interval(), Duration::from_secs(10));
    }
}
