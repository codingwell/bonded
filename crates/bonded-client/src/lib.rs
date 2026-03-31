use bonded_core::config::ClientConfig;
use pnet_datalink::NetworkInterface;
use tracing::info;
#[cfg(target_os = "linux")]
use tun::Configuration;

#[derive(Debug, Clone)]
pub struct ClientRuntime {
    pub config: ClientConfig,
}

impl ClientRuntime {
    pub fn new(config: ClientConfig) -> Self {
        Self { config }
    }

    pub async fn start(&self) -> anyhow::Result<()> {
        let interfaces = enumerate_interfaces();
        info!(
            interfaces = interfaces.len(),
            "detected network interfaces for client runtime"
        );

        #[cfg(target_os = "linux")]
        {
            initialize_tun(&self.config.client.tun_name)?;
        }

        info!(
            device = %self.config.client.device_name,
            "bonded client runtime starting"
        );
        Ok(())
    }
}

pub fn enumerate_interfaces() -> Vec<NetworkInterface> {
    pnet_datalink::interfaces()
}

#[cfg(target_os = "linux")]
fn initialize_tun(tun_name: &str) -> anyhow::Result<()> {
    let mut config = Configuration::default();
    config.tun_name(tun_name).up();

    let _device = tun::create(&config)?;
    info!(tun_name = %tun_name, "linux TUN device initialized");
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn initialize_tun(_tun_name: &str) -> anyhow::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::enumerate_interfaces;

    #[test]
    fn interfaces_can_be_enumerated() {
        let interfaces = enumerate_interfaces();
        assert!(!interfaces.is_empty());
    }
}
