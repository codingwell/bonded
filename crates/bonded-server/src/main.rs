use std::path::PathBuf;

use bonded_core::config::{load_server_config, ServerConfig, DEFAULT_SERVER_CONFIG_PATH};
use clap::Parser;
use tracing::{info, warn};

#[derive(Debug, Parser)]
#[command(name = "bonded-server")]
struct Args {
    #[arg(long, env = "BONDED_CONFIG", default_value = DEFAULT_SERVER_CONFIG_PATH)]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    let cfg = match load_server_config(&args.config) {
        Ok(cfg) => cfg,
        Err(err) => {
            warn!(path = %args.config.display(), error = %err, "using default server config");
            ServerConfig::default()
        }
    };

    info!(bind = %cfg.server.bind, "bonded-server starting");

    // TODO: accept client connections, authenticate, and handle session frames.
    Ok(())
}
