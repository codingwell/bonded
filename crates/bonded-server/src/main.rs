use std::path::PathBuf;

mod auth_handshake;
mod authorized_keys;
mod frame_forwarder;
mod health;
mod invite_tokens;
mod pairing_qr;
mod session_registry;

#[cfg(test)]
mod server_integration;

use auth_handshake::perform_auth_handshake;
use authorized_keys::{AuthorizedKeysStore, AuthorizedKeysWatcher};
use bonded_core::auth::DeviceKeypair;
use bonded_core::config::{load_server_config, ServerConfig, DEFAULT_SERVER_CONFIG_PATH};
use bonded_core::transport::{NaiveTcpTransport, Transport};
use clap::Parser;
use frame_forwarder::forward_frame;
use health::run_health_server;
use invite_tokens::ensure_startup_invite;
use pairing_qr::emit_pairing_qr;
use session_registry::SessionRegistry;
use tokio::net::TcpListener;
use tracing::{error, info, warn, Level};

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

    let authorized_keys = AuthorizedKeysStore::load(&cfg.server.authorized_keys_file)?;
    info!(
        path = %cfg.server.authorized_keys_file,
        devices = authorized_keys.device_count(),
        "authorized keys loaded"
    );
    let _authorized_keys_watcher = AuthorizedKeysWatcher::spawn(authorized_keys.clone())?;
    let invite = ensure_startup_invite(&cfg.server.invite_tokens_file)?;
    info!(
        path = %cfg.server.invite_tokens_file,
        token = %invite.token,
        "startup invite token ready"
    );
    let server_identity = DeviceKeypair::generate();
    let _ = emit_pairing_qr(
        &cfg.server.public_address,
        &invite,
        &server_identity.public_key_b64,
        &cfg.server.supported_protocols,
    );

    let health_bind = cfg.server.health_bind.clone();
    tokio::spawn(async move {
        if let Err(err) = run_health_server(&health_bind).await {
            error!(bind = %health_bind, error = %err, "health listener terminated");
        }
    });

    info!(bind = %cfg.server.bind, "bonded-server starting");
    run_server(
        &cfg.server.bind,
        &cfg.server.upstream_tcp_target,
        authorized_keys,
        SessionRegistry::default(),
    )
    .await
}

async fn run_server(
    bind: &str,
    upstream_tcp_target: &str,
    authorized_keys: AuthorizedKeysStore,
    sessions: SessionRegistry,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(bind).await?;
    info!(bind = %bind, "naive tcp listener bound");

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(value) => value,
            Err(err) => {
                error!(error = %err, "failed to accept incoming connection");
                continue;
            }
        };

        let authorized_keys = authorized_keys.clone();
        let sessions = sessions.clone();
        let upstream_tcp_target = upstream_tcp_target.to_owned();
        tokio::spawn(async move {
            match perform_auth_handshake(stream, authorized_keys).await {
                Ok((public_key, stream)) => {
                    let handle = sessions.register_client(public_key.clone());
                    info!(
                        peer = %peer,
                        public_key = %public_key,
                        session_id = handle.session_id,
                        active_sessions = sessions.active_sessions(),
                        "client authenticated"
                    );

                    let mut transport = NaiveTcpTransport::from_stream(stream);
                    loop {
                        match transport.recv().await {
                            Ok(frame) => {
                                let response = match forward_frame(
                                    frame,
                                    if upstream_tcp_target.is_empty() {
                                        None
                                    } else {
                                        Some(upstream_tcp_target.as_str())
                                    },
                                )
                                .await
                                {
                                    Ok(value) => value,
                                    Err(err) => {
                                        warn!(
                                            peer = %peer,
                                            public_key = %public_key,
                                            session_id = handle.session_id,
                                            error = %err,
                                            "failed to forward session frame"
                                        );
                                        continue;
                                    }
                                };

                                if let Err(err) = transport.send(response).await {
                                    warn!(
                                        peer = %peer,
                                        public_key = %public_key,
                                        session_id = handle.session_id,
                                        error = %err,
                                        "failed to return forwarded frame"
                                    );
                                    break;
                                }
                            }
                            Err(err) => {
                                info!(
                                    peer = %peer,
                                    public_key = %public_key,
                                    session_id = handle.session_id,
                                    error = %err,
                                    "client session ended"
                                );
                                break;
                            }
                        }
                    }

                    sessions.unregister_client(&public_key);
                }
                Err(err) => {
                    warn!(peer = %peer, error = %err, "client authentication failed");
                }
            }
        });
    }
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
    if let Some(upstream_tcp_target) = read_env("BONDED_UPSTREAM_TCP_TARGET") {
        cfg.server.upstream_tcp_target = upstream_tcp_target;
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
            ("BONDED_UPSTREAM_TCP_TARGET", "127.0.0.1:9100"),
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
        assert_eq!(cfg.server.upstream_tcp_target, "127.0.0.1:9100");
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
