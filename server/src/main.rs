use tracing::info;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    info!("bonded-server starting");

    // TODO: Initialize server
    // TODO: Accept client connections
    // TODO: Traffic aggregation logic
}
