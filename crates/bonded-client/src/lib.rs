use bonded_core::config::ClientConfig;
use tracing::info;

#[derive(Debug, Clone)]
pub struct ClientRuntime {
    pub config: ClientConfig,
}

impl ClientRuntime {
    pub fn new(config: ClientConfig) -> Self {
        Self { config }
    }

    pub async fn start(&self) -> anyhow::Result<()> {
        info!(
            device = %self.config.client.device_name,
            "bonded client runtime starting"
        );
        Ok(())
    }
}
