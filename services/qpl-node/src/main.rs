// SPDX-License-Identifier: MIT OR Apache-2.0

//! QPL Node — Decentralized operator for the QPL quantum-proof network.
//!
//! Each operator node:
//! - Exposes gRPC services (signing, proving, settlement, yield, RWA)
//! - Participates in threshold coordination with peer operators
//! - Collects per-operation fees from on-chain payments
//! - Reports health and metrics

mod config;
mod identity;
mod server;
mod state;
mod handlers;

use clap::Parser;
use tracing_subscriber::{fmt, EnvFilter};

/// QPL operator node
#[derive(Parser, Debug)]
#[command(name = "qpl-node", about = "QPL decentralized operator node")]
struct Cli {
    /// Path to node configuration file
    #[arg(short, long, default_value = "qpl-node.toml")]
    config: String,

    /// Override listen address
    #[arg(long)]
    listen: Option<String>,

    /// Override node name
    #[arg(long)]
    name: Option<String>,

    /// Generate a new operator identity and exit
    #[arg(long)]
    generate_identity: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_target(true)
        .init();

    let cli = Cli::parse();

    // Handle identity generation
    if cli.generate_identity {
        let id = identity::OperatorIdentity::generate()?;
        println!("Operator identity generated:");
        println!("  ID:         {}", id.operator_id());
        println!("  Public key: {} bytes", id.public_key().len());
        println!("\nSave the identity file and configure qpl-node.toml with the path.");
        return Ok(());
    }

    // Load configuration
    let mut node_config = config::NodeConfig::load(&cli.config)?;

    // Apply CLI overrides
    if let Some(ref listen) = cli.listen {
        node_config.listen_addr = listen.clone();
    }
    if let Some(ref name) = cli.name {
        node_config.name = name.clone();
    }

    tracing::info!(
        name = %node_config.name,
        listen = %node_config.listen_addr,
        "Starting QPL node"
    );

    // Load operator identity
    let identity = identity::OperatorIdentity::load_or_generate(&node_config.identity_path)?;
    tracing::info!(
        operator_id = %identity.operator_id(),
        "Operator identity loaded"
    );

    // Initialize node state
    let node_state = state::NodeState::new(identity.clone(), node_config.clone());

    // Start the gRPC server
    server::run(node_state).await?;

    Ok(())
}
