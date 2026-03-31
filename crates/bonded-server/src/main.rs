use std::path::PathBuf;

use bonded_core::config::{load_server_config, ServerConfig, DEFAULT_SERVER_CONFIG_PATH};
use clap::Parser;
use tracing::{info, Level};

#[derive(Debug, Parser)]
#[command(name = "bonded-server")]
struct Args {
    #[arg(long, env = "BONDED_CONFIG", default_value = DEFAULT_SERVER_CONFIG_PATH)]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    let mut cfg = match load_server_config(&args.config) {
        Ok(cfg) => cfg,
        Err(err) => {
            eprintln!(
                "failed to load server config at {} ({err}); using defaults",
                args.config.display()
            );
            ServerConfig::default()
        }
    };

    apply_env_overrides(&mut cfg, |key| std::env::var(key).ok());
    init_tracing_from_level(&cfg.server.log_level);

    info!(bind = %cfg.server.bind, "bonded-server starting");

    // TODO: accept client connections, authenticate, and handle session frames.
    Ok(())
}

fn apply_env_overrides<F>(cfg: &mut ServerConfig, mut read_env: F)
where
    F: FnMut(&str) -> Option<String>,
{
    if let Some(bind) = read_env("BONDED_BIND") {
        cfg.server.bind = bind;
    }
    if let Some(public_address) =
        read_env("BONDED_PUBLIC_ADDRESS").or_else(|| read_env("PUBLIC_ADDRESS"))
    {
        cfg.server.public_address = public_address;
    }
    if let Some(health_bind) = read_env("BONDED_HEALTH_BIND") {
        cfg.server.health_bind = health_bind;
    }
    if let Some(log_level) = read_env("BONDED_LOG_LEVEL") {
        cfg.server.log_level = log_level;
    }
    if let Some(authorized_keys_file) = read_env("BONDED_AUTHORIZED_KEYS_FILE") {
        cfg.server.authorized_keys_file = authorized_keys_file;
    }
    if let Some(invite_tokens_file) = read_env("BONDED_INVITE_TOKENS_FILE") {
        cfg.server.invite_tokens_file = invite_tokens_file;
    }
    if let Some(protocols) = read_env("BONDED_SUPPORTED_PROTOCOLS") {
        let parsed: Vec<String> = protocols
            .split(',')
            .map(str::trim)
            .filter(|item| !item.is_empty())
            .map(ToOwned::to_owned)
            .collect();
        if !parsed.is_empty() {
            cfg.server.supported_protocols = parsed;
        }
    }
}

fn init_tracing_from_level(level: &str) {
    let parsed = match level.to_ascii_lowercase().as_str() {
        "trace" => Level::TRACE,
        "debug" => Level::DEBUG,
        "info" => Level::INFO,
        "warn" => Level::WARN,
        "error" => Level::ERROR,
        _ => Level::INFO,
    };

    tracing_subscriber::fmt().with_max_level(parsed).init();
}

#[cfg(test)]
mod tests {
    use super::apply_env_overrides;
    use bonded_core::config::ServerConfig;

    #[test]
    fn env_overrides_replace_server_fields() {
        let mut cfg = ServerConfig::default();
        let env = [
            ("BONDED_BIND", "127.0.0.1:9000"),
            ("BONDED_PUBLIC_ADDRESS", "bonded.example.com:9000"),
            ("BONDED_HEALTH_BIND", "127.0.0.1:9001"),
            ("BONDED_LOG_LEVEL", "debug"),
            ("BONDED_AUTHORIZED_KEYS_FILE", "/tmp/auth.toml"),
            ("BONDED_INVITE_TOKENS_FILE", "/tmp/tokens.toml"),
            ("BONDED_SUPPORTED_PROTOCOLS", "naive_tcp,wss,quic"),
        ];

        apply_env_overrides(&mut cfg, |key| {
            env.iter()
                .find(|(candidate, _)| *candidate == key)
                .map(|(_, value)| (*value).to_owned())
        });

        assert_eq!(cfg.server.bind, "127.0.0.1:9000");
        assert_eq!(cfg.server.public_address, "bonded.example.com:9000");
        assert_eq!(cfg.server.health_bind, "127.0.0.1:9001");
        assert_eq!(cfg.server.log_level, "debug");
        assert_eq!(cfg.server.authorized_keys_file, "/tmp/auth.toml");
        assert_eq!(cfg.server.invite_tokens_file, "/tmp/tokens.toml");
        assert_eq!(
            cfg.server.supported_protocols,
            vec!["naive_tcp", "wss", "quic"]
        );
    }

    #[test]
    fn public_address_alias_env_var_is_supported() {
        let mut cfg = ServerConfig::default();
        apply_env_overrides(&mut cfg, |key| {
            if key == "PUBLIC_ADDRESS" {
                return Some("legacy.example.com:8080".to_owned());
            }
            None
        });

        assert_eq!(cfg.server.public_address, "legacy.example.com:8080");
    }
}
