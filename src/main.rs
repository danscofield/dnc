use std::path::PathBuf;
use std::process;

use clap::Parser;
use dns_message_broker::{config, server};
use tracing_subscriber::EnvFilter;

/// DNS Message Broker — an authoritative DNS server for lightweight datagram transport.
#[derive(Parser)]
#[command(name = "dns-fifo-broker", version, about)]
struct Cli {
    /// Path to the TOML configuration file.
    config: PathBuf,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    // Read the config file from disk.
    let toml_str = match std::fs::read_to_string(&cli.config) {
        Ok(s) => s,
        Err(e) => {
            // Set up minimal logging so the error is visible.
            tracing_subscriber::fmt()
                .with_env_filter(EnvFilter::new("error"))
                .init();
            tracing::error!("Failed to read config file {:?}: {}", cli.config, e);
            process::exit(1);
        }
    };

    // Parse the config.
    let config = match config::parse_config(&toml_str) {
        Ok(c) => c,
        Err(e) => {
            tracing_subscriber::fmt()
                .with_env_filter(EnvFilter::new("error"))
                .init();
            tracing::error!("Invalid configuration: {}", e);
            process::exit(1);
        }
    };

    // Initialize tracing with the configured log level.
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new(&config.log_level))
        .init();

    tracing::info!("Starting DNS Message Broker");

    // Run the server. On error (e.g. bind failure), log and exit non-zero.
    if let Err(e) = server::run(config).await {
        tracing::error!("Fatal error: {}", e);
        process::exit(1);
    }
}
