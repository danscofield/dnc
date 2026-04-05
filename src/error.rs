use thiserror::Error;

/// Error type for configuration parsing and validation.
#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to parse TOML: {0}")]
    ParseError(String),

    #[error("missing required field: {0}")]
    MissingField(String),

    #[error("invalid value for field '{field}': {reason}")]
    InvalidValue { field: String, reason: String },
}

/// Error type for encoding/decoding operations.
#[derive(Debug, Error)]
pub enum DecodeError {
    #[error("base32 decode error: {0}")]
    Base32Error(String),

    #[error("invalid envelope format: {0}")]
    EnvelopeError(String),

    #[error("invalid query structure: {0}")]
    QueryError(String),
}

/// Error type for channel store operations.
#[derive(Debug, Error)]
pub enum StoreError {
    #[error("channel '{0}' is full")]
    ChannelFull(String),

    #[error("payload too large: {size} bytes exceeds budget of {budget} bytes")]
    PayloadTooLarge { size: usize, budget: usize },
}

/// Error type for DNS parsing and response building.
#[derive(Debug, Error)]
pub enum DnsError {
    #[error("malformed DNS packet: {0}")]
    MalformedPacket(String),

    #[error("unsupported query type: {0}")]
    UnsupportedQueryType(String),

    #[error("failed to build DNS response: {0}")]
    ResponseBuildError(String),
}
