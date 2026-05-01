use std::collections::HashMap;
use std::path::PathBuf;

mod auth_handshake;
mod authorized_keys;
mod health;
mod invite_tokens;
mod network_runtime;
mod pairing_qr;
mod session_registry;
mod smoltcp_forwarder;
mod status;
mod tun_bridge;
mod tunnel_pcap;

#[cfg(test)]
mod server_integration;

#[cfg(test)]
mod channel_tests {
    #[tokio::test]
    async fn test_channel_batch_drain_completes_before_blocking() {
        use tokio::sync::mpsc;

        let (tx, mut rx) = mpsc::unbounded_channel::<u32>();

        for i in 0..256u32 {
            tx.send(i).ok();
        }

        let mut drained = 0usize;
        loop {
            match rx.try_recv() {
                Ok(_) => drained += 1,
                Err(mpsc::error::TryRecvError::Empty) => break,
                Err(mpsc::error::TryRecvError::Disconnected) => break,
            }
        }

        assert_eq!(drained, 256, "all 256 items must drain before blocking");
    }
}

use auth_handshake::{perform_auth_handshake, perform_websocket_auth_handshake};
use authorized_keys::{AuthorizedKeysStore, AuthorizedKeysWatcher};
use bonded_core::auth::DeviceKeypair;
use bonded_core::config::{load_server_config, ServerConfig, DEFAULT_SERVER_CONFIG_PATH};
use bonded_core::session::{SessionFrame, SessionHeader, FLAG_PING, FLAG_PONG};
use bonded_core::transport::{NaiveTcpTransport, Transport};
use clap::Parser;
use health::run_health_server;
use invite_tokens::ensure_startup_invite;
use network_runtime::NetworkRuntime;
use pairing_qr::emit_pairing_qr;
use session_registry::SessionRegistry;
use smoltcp_forwarder::SmoltcpForwarder;
use status::run_status_server;
use std::io::BufReader;
use std::path::Path;
use std::sync::{Arc, RwLock};
use tokio::net::TcpListener;
use tokio::signal;
use tokio::sync::mpsc;
use tokio_rustls::TlsAcceptor;
use tracing::{error, info, warn, Level};
use tun_bridge::TunBridge;
use tunnel_pcap::TunnelPcapLogger;

type ForwarderRegistry = Arc<RwLock<HashMap<u64, Arc<SmoltcpForwarder>>>>;
const MAX_RESPONSE_DRAIN_PER_CYCLE: usize = 256;
const TUNNEL_PCAP_MAX_MB_ENV: &str = "BONDED_TUNNEL_PCAP_MAX_MB";

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
    let tunnel_pcap = TunnelPcapLogger::from_env(TUNNEL_PCAP_MAX_MB_ENV)?;
    ensure_server_state_files(&cfg)?;
    let mut network_runtime = match NetworkRuntime::setup(&cfg.server) {
        Ok(runtime) => runtime,
        Err(err) => {
            error!(
                forwarding_mode = %cfg.server.forwarding_mode,
                tun_name = %cfg.server.tun_name,
                tun_cidr = %cfg.server.tun_cidr,
                tun_mtu = cfg.server.tun_mtu,
                tun_egress_interface = %cfg.server.tun_egress_interface,
                error = %err,
                "failed to initialize network runtime"
            );
            return Err(err);
        }
    };
    let tun_bridge = if network_runtime.is_tun_mode() {
        let device = network_runtime.take_tun_device().ok_or_else(|| {
            anyhow::anyhow!("forwarding_mode=tun active but no TUN device was created")
        })?;
        info!(
            tun_name = %cfg.server.tun_name,
            tun_cidr = %cfg.server.tun_cidr,
            tun_mtu = cfg.server.tun_mtu,
            "TUN forwarding mode enabled"
        );
        Some(TunBridge::new(device))
    } else {
        None
    };

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
    );

    let health_bind = cfg.server.health_bind.clone();
    tokio::spawn(async move {
        if let Err(err) = run_health_server(&health_bind).await {
            error!(bind = %health_bind, error = %err, "health listener terminated");
        }
    });

    let sessions = SessionRegistry::default();
    let forwarders: ForwarderRegistry = Arc::new(RwLock::new(HashMap::new()));

    let status_bind = cfg.server.status_bind.clone();
    let status_sessions = sessions.clone();
    let status_forwarders = forwarders.clone();
    tokio::spawn(async move {
        if let Err(err) = run_status_server(&status_bind, status_sessions, status_forwarders).await
        {
            error!(bind = %status_bind, error = %err, "status listener terminated");
        }
    });

    info!(bind = %cfg.server.bind, "bonded-server starting");
    let websocket_bind = cfg.server.websocket_bind.clone();
    let websocket_upstream = cfg.server.upstream_tcp_target.clone();
    let websocket_invites = cfg.server.invite_tokens_file.clone();
    let websocket_sessions = sessions.clone();
    let websocket_forwarders = forwarders.clone();
    let websocket_keys = authorized_keys.clone();
    let websocket_tunnel_pcap = tunnel_pcap.clone();
    let websocket_tls_acceptor = load_websocket_tls_acceptor(
        &cfg.server.websocket_tls_cert_file,
        &cfg.server.websocket_tls_key_file,
    )?;
    if tun_bridge.is_none() {
        tokio::spawn(async move {
            if let Err(err) = run_websocket_server(
                &websocket_bind,
                &websocket_upstream,
                &websocket_invites,
                websocket_keys,
                websocket_sessions,
                websocket_forwarders,
                websocket_tls_acceptor,
                websocket_tunnel_pcap,
            )
            .await
            {
                error!(bind = %websocket_bind, error = %err, "websocket listener terminated");
            }
        });
    } else {
        warn!("forwarding_mode=tun currently supports naive-tcp transport only; websocket listener not started");
    }

    tokio::select! {
        result = run_server(
            &cfg.server.bind,
            &cfg.server.upstream_tcp_target,
            &cfg.server.invite_tokens_file,
            authorized_keys,
            sessions,
            forwarders,
            tun_bridge,
            tunnel_pcap,
        ) => result,
        signal_result = signal::ctrl_c() => {
            match signal_result {
                Ok(()) => {
                    info!("shutdown signal received, cleaning up network runtime");
                    Ok(())
                }
                Err(err) => Err(err.into()),
            }
        }
    }
}

fn ensure_server_state_files(cfg: &ServerConfig) -> anyhow::Result<()> {
    ensure_state_file(
        &cfg.server.authorized_keys_file,
        "devices = []\n",
        "authorized keys",
    )?;
    ensure_state_file(
        &cfg.server.invite_tokens_file,
        "tokens = []\n",
        "invite tokens",
    )?;

    Ok(())
}

fn ensure_state_file(path: &str, default_contents: &str, description: &str) -> anyhow::Result<()> {
    let path = Path::new(path);

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    if !path.exists() {
        std::fs::write(path, default_contents)?;
        info!(
            path = %path.display(),
            file = %description,
            "created missing server state file"
        );
    }

    Ok(())
}

async fn run_websocket_server(
    bind: &str,
    _upstream_tcp_target: &str,
    invite_tokens_file: &str,
    authorized_keys: AuthorizedKeysStore,
    sessions: SessionRegistry,
    forwarders: ForwarderRegistry,
    tls_acceptor: Option<TlsAcceptor>,
    tunnel_pcap: Option<Arc<TunnelPcapLogger>>,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(bind).await?;
    info!(bind = %bind, "websocket listener bound");

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(value) => value,
            Err(err) => {
                error!(error = %err, "failed to accept incoming websocket connection");
                continue;
            }
        };

        let authorized_keys = authorized_keys.clone();
        let sessions = sessions.clone();
        let forwarders = forwarders.clone();
        let invite_tokens_file = invite_tokens_file.to_owned();
        let tls_acceptor = tls_acceptor.clone();
        let tunnel_pcap = tunnel_pcap.clone();
        tokio::spawn(async move {
            let mut transport = match tls_acceptor {
                Some(acceptor) => {
                    match bonded_core::transport::WebSocketTlsTransport::accept_tls(
                        stream, acceptor,
                    )
                    .await
                    {
                        Ok(value) => value,
                        Err(err) => {
                            warn!(peer = %peer, error = %err, "wss upgrade failed");
                            return;
                        }
                    }
                }
                None => match bonded_core::transport::WebSocketTlsTransport::accept(stream).await {
                    Ok(value) => value,
                    Err(err) => {
                        warn!(peer = %peer, error = %err, "websocket upgrade failed");
                        return;
                    }
                },
            };

            match perform_websocket_auth_handshake(
                &mut transport,
                authorized_keys,
                std::path::Path::new(&invite_tokens_file),
            )
            .await
            {
                Ok(public_key) => {
                    let handle = sessions.register_client(public_key.clone());
                    info!(
                        peer = %peer,
                        public_key = %public_key,
                        session_id = handle.session_id,
                        active_sessions = sessions.active_sessions(),
                        "websocket client authenticated"
                    );

                    info!(
                        peer = %peer,
                        session_id = handle.session_id,
                        "starting websocket frame receive loop"
                    );
                    let (forward_tx, mut forward_rx) = mpsc::unbounded_channel();
                    let forwarder = Arc::new(SmoltcpForwarder::new(handle.session_id, forward_tx));
                    forwarders
                        .write()
                        .expect("forwarder registry lock should not be poisoned")
                        .insert(handle.session_id, forwarder.clone());

                    loop {
                        // Drain queued forwarded frames before blocking in select! so bursty
                        // response traffic is not serialized to one frame per scheduler turn.
                        for _ in 0..MAX_RESPONSE_DRAIN_PER_CYCLE {
                            let maybe_forwarded_frame = match forward_rx.try_recv() {
                                Ok(frame) => Some(frame),
                                Err(tokio::sync::mpsc::error::TryRecvError::Empty) => None,
                                Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                                    break;
                                }
                            };

                            let Some(forwarded_frame) = maybe_forwarded_frame else {
                                break;
                            };

                            maybe_log_tunnel_packet(&tunnel_pcap, &forwarded_frame.payload);
                            if let Err(err) = transport.send(forwarded_frame).await {
                                warn!(
                                    peer = %peer,
                                    public_key = %public_key,
                                    session_id = handle.session_id,
                                    error = %err,
                                    "failed to return drained websocket forwarded frame"
                                );
                                break;
                            }
                        }

                        tokio::select! {
                            maybe_forwarded_frame = forward_rx.recv() => {
                                let Some(forwarded_frame) = maybe_forwarded_frame else {
                                    warn!(
                                        peer = %peer,
                                        public_key = %public_key,
                                        session_id = handle.session_id,
                                        "websocket forwarder response queue closed"
                                    );
                                    break;
                                };

                                maybe_log_tunnel_packet(&tunnel_pcap, &forwarded_frame.payload);
                                if let Err(err) = transport.send(forwarded_frame).await {
                                    warn!(
                                        peer = %peer,
                                        public_key = %public_key,
                                        session_id = handle.session_id,
                                        error = %err,
                                        "failed to return websocket forwarded frame"
                                    );
                                    break;
                                }
                            }
                            recv_result = transport.recv() => {
                                match recv_result {
                                    Ok(frame) => {
                                        maybe_log_tunnel_packet(&tunnel_pcap, &frame.payload);
                                        // Respond to heartbeat pings without forwarding them.
                                        // Only treat ping-bit frames as control heartbeats when
                                        // they carry no payload; otherwise keep forwarding.
                                        if frame.header.flags & FLAG_PING != 0 && frame.payload.is_empty() {
                                            info!(
                                                peer = %peer,
                                                session_id = handle.session_id,
                                                sequence = frame.header.sequence,
                                                "websocket heartbeat ping received, sending pong"
                                            );
                                            let pong = SessionFrame {
                                                header: SessionHeader {
                                                    connection_id: frame.header.connection_id,
                                                    sequence: frame.header.sequence,
                                                    flags: FLAG_PONG,
                                                },
                                                payload: frame.payload,
                                            };
                                            if let Err(err) = transport.send(pong).await {
                                                warn!(
                                                    peer = %peer,
                                                    session_id = handle.session_id,
                                                    error = %err,
                                                    "failed to send websocket heartbeat pong"
                                                );
                                                break;
                                            }
                                            continue;
                                        }

                                        if frame.header.flags & FLAG_PING != 0 {
                                            warn!(
                                                peer = %peer,
                                                session_id = handle.session_id,
                                                sequence = frame.header.sequence,
                                                flags = frame.header.flags,
                                                payload_len = frame.payload.len(),
                                                "websocket frame has ping flag with payload; forwarding as data"
                                            );
                                        }

                                        forwarder.ingest_packet(frame);
                                    }
                                    Err(err) => {
                                        info!(
                                            peer = %peer,
                                            public_key = %public_key,
                                            session_id = handle.session_id,
                                            error = ?err,
                                            "websocket client session ended - recv error"
                                        );
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    forwarder.clear_session();
                    forwarders
                        .write()
                        .expect("forwarder registry lock should not be poisoned")
                        .remove(&handle.session_id);
                    sessions.unregister_client(&public_key);
                }
                Err(err) => {
                    warn!(peer = %peer, error = %err, "websocket client authentication failed");
                }
            }
        });
    }
}

fn load_websocket_tls_acceptor(
    cert_file: &str,
    key_file: &str,
) -> anyhow::Result<Option<TlsAcceptor>> {
    if cert_file.trim().is_empty() || key_file.trim().is_empty() {
        return Ok(None);
    }

    let cert_reader = std::fs::File::open(cert_file)?;
    let mut cert_reader = BufReader::new(cert_reader);
    let cert_chain: Vec<rustls::pki_types::CertificateDer<'static>> =
        rustls_pemfile::certs(&mut cert_reader).collect::<Result<Vec<_>, _>>()?;
    if cert_chain.is_empty() {
        anyhow::bail!("no certificates found in websocket tls cert file");
    }

    let key = load_private_key(key_file)?;
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)?;

    Ok(Some(TlsAcceptor::from(Arc::new(config))))
}

fn load_private_key(path: &str) -> anyhow::Result<rustls::pki_types::PrivateKeyDer<'static>> {
    let pkcs8_file = std::fs::File::open(path)?;
    let mut pkcs8_reader = BufReader::new(pkcs8_file);
    let mut pkcs8_keys: Vec<rustls::pki_types::PrivatePkcs8KeyDer<'static>> =
        rustls_pemfile::pkcs8_private_keys(&mut pkcs8_reader).collect::<Result<Vec<_>, _>>()?;
    if let Some(key) = pkcs8_keys.pop() {
        return Ok(rustls::pki_types::PrivateKeyDer::Pkcs8(key));
    }

    let rsa_file = std::fs::File::open(path)?;
    let mut rsa_reader = BufReader::new(rsa_file);
    let mut rsa_keys: Vec<rustls::pki_types::PrivatePkcs1KeyDer<'static>> =
        rustls_pemfile::rsa_private_keys(&mut rsa_reader).collect::<Result<Vec<_>, _>>()?;
    if let Some(key) = rsa_keys.pop() {
        return Ok(rustls::pki_types::PrivateKeyDer::Pkcs1(key));
    }

    anyhow::bail!("no supported private key found in websocket tls key file");
}

async fn run_server(
    bind: &str,
    _upstream_tcp_target: &str,
    invite_tokens_file: &str,
    authorized_keys: AuthorizedKeysStore,
    sessions: SessionRegistry,
    forwarders: ForwarderRegistry,
    tun_bridge: Option<TunBridge>,
    tunnel_pcap: Option<Arc<TunnelPcapLogger>>,
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
        let forwarders = forwarders.clone();
        let tun_bridge = tun_bridge.clone();
        let tunnel_pcap = tunnel_pcap.clone();
        let invite_tokens_file = invite_tokens_file.to_owned();
        tokio::spawn(async move {
            match perform_auth_handshake(
                stream,
                authorized_keys,
                std::path::Path::new(&invite_tokens_file),
            )
            .await
            {
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
                    info!(
                        peer = %peer,
                        session_id = handle.session_id,
                        "starting frame receive loop"
                    );
                    let use_tun_bridge = tun_bridge.is_some();
                    let (forward_tx, mut forward_rx) = mpsc::unbounded_channel();
                    let forwarder = if use_tun_bridge {
                        None
                    } else {
                        let value = Arc::new(SmoltcpForwarder::new(handle.session_id, forward_tx));
                        forwarders
                            .write()
                            .expect("forwarder registry lock should not be poisoned")
                            .insert(handle.session_id, value.clone());
                        Some(value)
                    };

                    let (tun_tx, mut tun_rx) = mpsc::unbounded_channel::<SessionFrame>();
                    if let Some(bridge) = &tun_bridge {
                        bridge.register_session(handle.session_id, tun_tx).await;
                    }
                    loop {
                        // Drain queued response frames before blocking in select! so bursty
                        // server->client traffic is not throttled by select scheduling.
                        for _ in 0..MAX_RESPONSE_DRAIN_PER_CYCLE {
                            let maybe_tun_frame = match tun_rx.try_recv() {
                                Ok(frame) => Some(frame),
                                Err(tokio::sync::mpsc::error::TryRecvError::Empty) => None,
                                Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                                    break;
                                }
                            };

                            let Some(tun_frame) = maybe_tun_frame else {
                                break;
                            };

                            maybe_log_tunnel_packet(&tunnel_pcap, &tun_frame.payload);
                            if let Err(err) = transport.send(tun_frame).await {
                                warn!(
                                    peer = %peer,
                                    public_key = %public_key,
                                    session_id = handle.session_id,
                                    error = %err,
                                    "failed to send drained TUN return packet to client"
                                );
                                break;
                            }
                        }

                        if !use_tun_bridge {
                            for _ in 0..MAX_RESPONSE_DRAIN_PER_CYCLE {
                                let maybe_forwarded_frame = match forward_rx.try_recv() {
                                    Ok(frame) => Some(frame),
                                    Err(tokio::sync::mpsc::error::TryRecvError::Empty) => None,
                                    Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                                        break;
                                    }
                                };

                                let Some(forwarded_frame) = maybe_forwarded_frame else {
                                    break;
                                };

                                maybe_log_tunnel_packet(&tunnel_pcap, &forwarded_frame.payload);
                                if let Err(err) = transport.send(forwarded_frame).await {
                                    warn!(
                                        peer = %peer,
                                        public_key = %public_key,
                                        session_id = handle.session_id,
                                        error = %err,
                                        "failed to return drained forwarded frame"
                                    );
                                    break;
                                }
                            }
                        }

                        tokio::select! {
                            maybe_tun_frame = tun_rx.recv() => {
                                let Some(tun_frame) = maybe_tun_frame else {
                                    break;
                                };

                                maybe_log_tunnel_packet(&tunnel_pcap, &tun_frame.payload);
                                if let Err(err) = transport.send(tun_frame).await {
                                    warn!(
                                        peer = %peer,
                                        public_key = %public_key,
                                        session_id = handle.session_id,
                                        error = %err,
                                        "failed to send TUN return packet to client"
                                    );
                                    break;
                                }
                            }
                            maybe_forwarded_frame = forward_rx.recv() => {
                                if use_tun_bridge {
                                    continue;
                                }
                                let Some(forwarded_frame) = maybe_forwarded_frame else {
                                    warn!(
                                        peer = %peer,
                                        public_key = %public_key,
                                        session_id = handle.session_id,
                                        "forward response queue closed"
                                    );
                                    break;
                                };

                                maybe_log_tunnel_packet(&tunnel_pcap, &forwarded_frame.payload);
                                if let Err(err) = transport.send(forwarded_frame).await {
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
                            recv_result = transport.recv() => {
                                match recv_result {
                                    Ok(frame) => {
                                        maybe_log_tunnel_packet(&tunnel_pcap, &frame.payload);
                                        // Respond to heartbeat pings without forwarding them.
                                        // Only treat ping-bit frames as control heartbeats when
                                        // they carry no payload; otherwise keep forwarding.
                                        if frame.header.flags & FLAG_PING != 0 && frame.payload.is_empty() {
                                            info!(
                                                peer = %peer,
                                                session_id = handle.session_id,
                                                sequence = frame.header.sequence,
                                                "heartbeat ping received, sending pong"
                                            );
                                            let pong = SessionFrame {
                                                header: SessionHeader {
                                                    connection_id: frame.header.connection_id,
                                                    sequence: frame.header.sequence,
                                                    flags: FLAG_PONG,
                                                },
                                                payload: frame.payload,
                                            };
                                            if let Err(err) = transport.send(pong).await {
                                                warn!(
                                                    peer = %peer,
                                                    session_id = handle.session_id,
                                                    error = %err,
                                                    "failed to send heartbeat pong"
                                                );
                                                break;
                                            }
                                            continue;
                                        }

                                        if frame.header.flags & FLAG_PING != 0 {
                                            warn!(
                                                peer = %peer,
                                                session_id = handle.session_id,
                                                sequence = frame.header.sequence,
                                                flags = frame.header.flags,
                                                payload_len = frame.payload.len(),
                                                "frame has ping flag with payload; forwarding as data"
                                            );
                                        }

                                        if let Some(bridge) = &tun_bridge {
                                            if let Err(err) = bridge.submit_client_frame(handle.session_id, frame) {
                                                warn!(
                                                    peer = %peer,
                                                    public_key = %public_key,
                                                    session_id = handle.session_id,
                                                    error = %err,
                                                    "failed to enqueue frame into TUN bridge"
                                                );
                                                break;
                                            }
                                            continue;
                                        }
                                        if let Some(f) = &forwarder {
                                            f.ingest_packet(frame);
                                        }
                                    }
                                    Err(err) => {
                                        info!(
                                            peer = %peer,
                                            public_key = %public_key,
                                            session_id = handle.session_id,
                                            error = ?err,
                                            "client session ended - recv error"
                                        );
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    if let Some(bridge) = &tun_bridge {
                        bridge.unregister_session(handle.session_id).await;
                    }
                    if let Some(f) = forwarder {
                        f.clear_session();
                        forwarders
                            .write()
                            .expect("forwarder registry lock should not be poisoned")
                            .remove(&handle.session_id);
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

fn maybe_log_tunnel_packet(tunnel_pcap: &Option<Arc<TunnelPcapLogger>>, payload: &[u8]) {
    if payload.is_empty() {
        return;
    }
    if let Some(writer) = tunnel_pcap {
        writer.log_packet(payload);
    }
}

#[cfg(test)]
fn is_ipv4_icmp_echo_frame(packet: &[u8]) -> bool {
    if packet.len() < 28 {
        return false;
    }

    let version = packet[0] >> 4;
    let ihl = (packet[0] & 0x0f) as usize;
    if version != 4 || ihl < 5 {
        return false;
    }

    let header_len = ihl * 4;
    if packet.len() < header_len + 8 {
        return false;
    }

    let total_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    if total_len < header_len + 8 || total_len > packet.len() {
        return false;
    }

    if packet[9] != 1 {
        return false;
    }

    let icmp_start = header_len;
    packet[icmp_start] == 8 && packet[icmp_start + 1] == 0
}

fn apply_env_overrides<F>(cfg: &mut ServerConfig, mut read_env: F)
where
    F: FnMut(&str) -> Option<String>,
{
    if let Some(bind) = read_env("BONDED_BIND") {
        cfg.server.bind = bind;
    }
    if let Some(websocket_bind) = read_env("BONDED_WEBSOCKET_BIND") {
        cfg.server.websocket_bind = websocket_bind;
    }
    if let Some(status_bind) = read_env("BONDED_STATUS_BIND") {
        cfg.server.status_bind = status_bind;
    }
    if let Some(forwarding_mode) = read_env("BONDED_FORWARDING_MODE") {
        cfg.server.forwarding_mode = forwarding_mode;
    }
    if let Some(tun_name) = read_env("BONDED_TUN_NAME") {
        cfg.server.tun_name = tun_name;
    }
    if let Some(tun_cidr) = read_env("BONDED_TUN_CIDR") {
        cfg.server.tun_cidr = tun_cidr;
    }
    if let Some(tun_mtu) = read_env("BONDED_TUN_MTU") {
        if let Ok(value) = tun_mtu.parse::<u16>() {
            cfg.server.tun_mtu = value;
        }
    }
    if let Some(tun_egress_interface) = read_env("BONDED_TUN_EGRESS_INTERFACE") {
        cfg.server.tun_egress_interface = tun_egress_interface;
    }
    if let Some(websocket_tls_cert_file) = read_env("BONDED_WEBSOCKET_TLS_CERT_FILE") {
        cfg.server.websocket_tls_cert_file = websocket_tls_cert_file;
    }
    if let Some(websocket_tls_key_file) = read_env("BONDED_WEBSOCKET_TLS_KEY_FILE") {
        cfg.server.websocket_tls_key_file = websocket_tls_key_file;
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
    use super::{apply_env_overrides, ensure_server_state_files, is_ipv4_icmp_echo_frame};
    use bonded_core::config::ServerConfig;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_state_path(name: &str) -> std::path::PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be valid")
            .as_nanos();
        std::env::temp_dir().join(format!("bonded-{name}-{stamp}"))
    }

    #[test]
    fn env_overrides_replace_server_fields() {
        let mut cfg = ServerConfig::default();
        let env = [
            ("BONDED_BIND", "127.0.0.1:9000"),
            ("BONDED_WEBSOCKET_BIND", "127.0.0.1:9443"),
            ("BONDED_STATUS_BIND", "127.0.0.1:9002"),
            ("BONDED_FORWARDING_MODE", "tun"),
            ("BONDED_TUN_NAME", "bondedtest0"),
            ("BONDED_TUN_CIDR", "100.65.0.1/24"),
            ("BONDED_TUN_MTU", "1380"),
            ("BONDED_TUN_EGRESS_INTERFACE", "eth0"),
            ("BONDED_WEBSOCKET_TLS_CERT_FILE", "/tmp/wss.crt"),
            ("BONDED_WEBSOCKET_TLS_KEY_FILE", "/tmp/wss.key"),
            ("BONDED_PUBLIC_ADDRESS", "bonded.example.com:9000"),
            ("BONDED_HEALTH_BIND", "127.0.0.1:9001"),
            ("BONDED_UPSTREAM_TCP_TARGET", "127.0.0.1:9100"),
            ("BONDED_LOG_LEVEL", "debug"),
            ("BONDED_AUTHORIZED_KEYS_FILE", "/tmp/auth.toml"),
            ("BONDED_INVITE_TOKENS_FILE", "/tmp/tokens.toml"),
        ];

        apply_env_overrides(&mut cfg, |key| {
            env.iter()
                .find(|(candidate, _)| *candidate == key)
                .map(|(_, value)| (*value).to_owned())
        });

        assert_eq!(cfg.server.bind, "127.0.0.1:9000");
        assert_eq!(cfg.server.websocket_bind, "127.0.0.1:9443");
        assert_eq!(cfg.server.status_bind, "127.0.0.1:9002");
        assert_eq!(cfg.server.forwarding_mode, "tun");
        assert_eq!(cfg.server.tun_name, "bondedtest0");
        assert_eq!(cfg.server.tun_cidr, "100.65.0.1/24");
        assert_eq!(cfg.server.tun_mtu, 1380);
        assert_eq!(cfg.server.tun_egress_interface, "eth0");
        assert_eq!(cfg.server.websocket_tls_cert_file, "/tmp/wss.crt");
        assert_eq!(cfg.server.websocket_tls_key_file, "/tmp/wss.key");
        assert_eq!(cfg.server.public_address, "bonded.example.com:9000");
        assert_eq!(cfg.server.health_bind, "127.0.0.1:9001");
        assert_eq!(cfg.server.upstream_tcp_target, "127.0.0.1:9100");
        assert_eq!(cfg.server.log_level, "debug");
        assert_eq!(cfg.server.authorized_keys_file, "/tmp/auth.toml");
        assert_eq!(cfg.server.invite_tokens_file, "/tmp/tokens.toml");
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

    #[test]
    fn startup_creates_missing_server_state_files() {
        let root = temp_state_path("state-files");
        let authorized = root.join("authorized_keys.toml");
        let invites = root.join("invite_tokens.toml");

        let mut cfg = ServerConfig::default();
        cfg.server.authorized_keys_file = authorized.display().to_string();
        cfg.server.invite_tokens_file = invites.display().to_string();

        ensure_server_state_files(&cfg).expect("state files should be created");

        assert!(authorized.exists());
        assert!(invites.exists());
        assert_eq!(
            fs::read_to_string(&authorized).expect("authorized keys should be readable"),
            "devices = []\n"
        );
        assert_eq!(
            fs::read_to_string(&invites).expect("invite tokens should be readable"),
            "tokens = []\n"
        );

        let _ = fs::remove_file(authorized);
        let _ = fs::remove_file(invites);
        let _ = fs::remove_dir(root);
    }

    #[test]
    fn detects_ipv4_icmp_echo_frames() {
        let packet = vec![
            0x45, 0x00, 0x00, 0x1c, // IPv4 header start + total length
            0x12, 0x34, 0x40, 0x00, // id + flags/fragment
            64, 1, 0, 0, // ttl + proto=icmp + checksum placeholder
            10, 8, 0, 2, // src ip
            1, 1, 1, 1, // dst ip
            8, 0, 0, 0, // ICMP echo request type/code/checksum
            0xab, 0xcd, 0x00, 0x01, // echo id + sequence
        ];

        assert!(is_ipv4_icmp_echo_frame(&packet));
    }

    #[test]
    fn rejects_non_icmp_echo_frames() {
        let tcp_packet = vec![
            0x45, 0x00, 0x00, 0x14, // IPv4 header total length only
            0x12, 0x34, 0x40, 0x00, // id + flags/fragment
            64, 6, 0, 0, // ttl + proto=tcp + checksum placeholder
            10, 8, 0, 2, // src ip
            1, 1, 1, 1, // dst ip
        ];

        assert!(!is_ipv4_icmp_echo_frame(&tcp_packet));
    }
}
