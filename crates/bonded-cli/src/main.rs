use std::path::PathBuf;

use bonded_client::ClientRuntime;
use bonded_core::config::{load_client_config, ClientConfig, DEFAULT_CLIENT_CONFIG_PATH};
use clap::Parser;
use tracing::{info, warn};

#[derive(Debug, Parser)]
#[command(name = "bonded-cli")]
struct Args {
    #[arg(long, env = "BONDED_CLIENT_CONFIG", default_value = DEFAULT_CLIENT_CONFIG_PATH)]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    let cfg = match load_client_config(&args.config) {
        Ok(cfg) => cfg,
        Err(err) => {
            warn!(path = %args.config.display(), error = %err, "using default client config");
            ClientConfig::default()
        }
    };

    info!("bonded-cli starting");
    ClientRuntime::new(cfg).start().await
}
