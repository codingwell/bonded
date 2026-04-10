use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use std::sync::Arc;
use thiserror::Error;

pub const DEFAULT_SERVER_CONFIG_PATH: &str = "/etc/bonded/server.toml";
pub const DEFAULT_AUTHORIZED_KEYS_PATH: &str = "/var/lib/bonded/authorized_keys.toml";
pub const DEFAULT_INVITE_TOKENS_PATH: &str = "/var/lib/bonded/invite_tokens.toml";

pub const DEFAULT_CLIENT_CONFIG_PATH: &str = "~/.config/bonded/client.toml";
pub const DEFAULT_CLIENT_PRIVATE_KEY_PATH: &str = "~/.local/share/bonded/device-key.pem";
pub const DEFAULT_CLIENT_PUBLIC_KEY_PATH: &str = "~/.local/share/bonded/device-key.pub";

/// Transport kind identifier for diagnostics
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportKind {
    NaiveTcp,
    WebSocketTls,
}

impl TransportKind {
    pub fn as_str(self) -> &'static str {
        match self {
            TransportKind::NaiveTcp => "NaiveTCP",
            TransportKind::WebSocketTls => "WebSocketTLS",
        }
    }
}

/// Callback called with a raw socket file-descriptor just before the socket
/// connects.  On Android this is used to call `VpnService.protect(fd)` so
/// that the tunnel session's own TCP connections bypass the VPN routing table
/// and avoid a routing loop.
#[derive(Clone)]
pub struct SocketProtectFn(pub Arc<dyn Fn(i32) -> bool + Send + Sync>);

impl std::fmt::Debug for SocketProtectFn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SocketProtectFn(..)")
    }
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to read config file: {0}")]
    Io(#[from] std::io::Error),
    #[error("failed to parse TOML config: {0}")]
    Toml(#[from] toml::de::Error),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    #[serde(default)]
    pub server: ServerSection,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            server: ServerSection::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ServerSection {
    pub bind: String,
    pub websocket_bind: String,
    pub status_bind: String,
    pub forwarding_mode: String,
    pub tun_name: String,
    pub tun_cidr: String,
    pub tun_mtu: u16,
    pub tun_egress_interface: String,
    pub websocket_tls_cert_file: String,
    pub websocket_tls_key_file: String,
    pub public_address: String,
    pub health_bind: String,
    pub upstream_tcp_target: String,
    pub log_level: String,
    pub authorized_keys_file: String,
    pub invite_tokens_file: String,
}

impl Default for ServerSection {
    fn default() -> Self {
        Self {
            bind: "0.0.0.0:8080".to_owned(),
            websocket_bind: "0.0.0.0:8443".to_owned(),
            status_bind: "0.0.0.0:8082".to_owned(),
            forwarding_mode: "proxy".to_owned(),
            tun_name: "bonded0".to_owned(),
            tun_cidr: "100.64.0.1/24".to_owned(),
            tun_mtu: 1400,
            tun_egress_interface: String::new(),
            websocket_tls_cert_file: String::new(),
            websocket_tls_key_file: String::new(),
            public_address: String::new(),
            health_bind: "0.0.0.0:8081".to_owned(),
            upstream_tcp_target: String::new(),
            log_level: "info".to_owned(),
            authorized_keys_file: DEFAULT_AUTHORIZED_KEYS_PATH.to_owned(),
            invite_tokens_file: DEFAULT_INVITE_TOKENS_PATH.to_owned(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    pub client: ClientSection,
    /// Not serialised – set at runtime on platforms that require socket
    /// protection (e.g. Android VPN services).
    #[serde(skip)]
    pub socket_protect: Option<SocketProtectFn>,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            client: ClientSection::default(),
            socket_protect: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientSection {
    pub device_name: String,
    pub tun_name: String,
    pub server_public_address: String,
    pub server_websocket_address: String,
    pub path_bind_addresses: Vec<String>,
    pub server_public_key: String,
    pub invite_token: String,
    pub preferred_protocols: Vec<String>,
    pub private_key_path: String,
    pub public_key_path: String,
}

impl Default for ClientSection {
    fn default() -> Self {
        Self {
            device_name: "linux-cli".to_owned(),
            tun_name: "bonded0".to_owned(),
            server_public_address: String::new(),
            server_websocket_address: String::new(),
            path_bind_addresses: Vec::new(),
            server_public_key: String::new(),
            invite_token: String::new(),
            preferred_protocols: vec!["naive_tcp".to_owned(), "wss".to_owned()],
            private_key_path: DEFAULT_CLIENT_PRIVATE_KEY_PATH.to_owned(),
            public_key_path: DEFAULT_CLIENT_PUBLIC_KEY_PATH.to_owned(),
        }
    }
}

pub fn load_server_config(path: &Path) -> Result<ServerConfig, ConfigError> {
    let data = fs::read_to_string(path)?;
    Ok(toml::from_str(&data)?)
}

pub fn load_client_config(path: &Path) -> Result<ClientConfig, ConfigError> {
    let data = fs::read_to_string(path)?;
    Ok(toml::from_str(&data)?)
}

#[cfg(test)]
mod tests {
    use super::ServerConfig;

    #[test]
    fn default_server_config_has_naive_tcp_protocol() {
        let cfg = ServerConfig::default();
        assert!(cfg.server.upstream_tcp_target.is_empty());
        assert_eq!(cfg.server.websocket_bind, "0.0.0.0:8443");
        assert_eq!(cfg.server.status_bind, "0.0.0.0:8082");
        assert_eq!(cfg.server.forwarding_mode, "proxy");
        assert_eq!(cfg.server.tun_name, "bonded0");
        assert_eq!(cfg.server.tun_cidr, "100.64.0.1/24");
        assert_eq!(cfg.server.tun_mtu, 1400);
        assert!(cfg.server.tun_egress_interface.is_empty());
        assert!(cfg.server.websocket_tls_cert_file.is_empty());
        assert!(cfg.server.websocket_tls_key_file.is_empty());
    }

    #[test]
    fn server_config_parses_with_missing_options_using_defaults() {
        let cfg: ServerConfig = toml::from_str(
            r#"
[server]
bind = "127.0.0.1:9000"
"#,
        )
        .expect("partial server config should parse");

        assert_eq!(cfg.server.bind, "127.0.0.1:9000");
        assert_eq!(cfg.server.websocket_bind, "0.0.0.0:8443");
        assert_eq!(cfg.server.status_bind, "0.0.0.0:8082");
        assert_eq!(cfg.server.forwarding_mode, "proxy");
        assert_eq!(cfg.server.tun_name, "bonded0");
        assert_eq!(cfg.server.tun_cidr, "100.64.0.1/24");
        assert_eq!(cfg.server.tun_mtu, 1400);
        assert!(cfg.server.tun_egress_interface.is_empty());
        assert_eq!(cfg.server.health_bind, "0.0.0.0:8081");
        assert_eq!(cfg.server.log_level, "info");
    }

    #[test]
    fn server_config_parses_without_server_section_using_defaults() {
        let cfg: ServerConfig = toml::from_str("").expect("empty config should parse");
        let defaults = ServerConfig::default();
        assert_eq!(cfg.server.bind, defaults.server.bind);
        assert_eq!(cfg.server.websocket_bind, defaults.server.websocket_bind);
        assert_eq!(cfg.server.status_bind, defaults.server.status_bind);
        assert_eq!(cfg.server.health_bind, defaults.server.health_bind);
    }
}
