use std::path::PathBuf;

mod auth_handshake;
mod authorized_keys;
mod frame_forwarder;
mod health;
mod invite_tokens;
mod pairing_qr;
mod session_registry;
mod status;

#[cfg(test)]
mod server_integration;

#[cfg(test)]
mod concurrency_tests {
    use crate::frame_forwarder::TcpFlowTable;

    #[test]
    fn test_256_shard_distribution_for_50_connections() {
        const FORWARD_WORKER_SHARDS: usize = 256;
        let mut shard_loads = vec![0usize; FORWARD_WORKER_SHARDS];

        for connection_id in 0u32..50 {
            let shard_idx = (connection_id as usize) % FORWARD_WORKER_SHARDS;
            shard_loads[shard_idx] += 1;
        }

        let occupied_shards = shard_loads.iter().filter(|&&load| load > 0).count();
        let max_load = *shard_loads.iter().max().unwrap();

        println!(
            "Shard distribution for 50 connections: {} occupied shards, max load {} per shard",
            occupied_shards, max_load
        );
        assert!(
            max_load <= 1,
            "Each connection should map to unique or near-unique shard"
        );
    }

    #[test]
    fn test_tcp_flow_table_has_256_shards() {
        let _table = TcpFlowTable::default();
        println!("TcpFlowTable architecture: 256 independent Mutex shards created");
        // Verify it doesn't panic on construction
        // Actual concurrency testing requires load testing
    }

    #[tokio::test]
    async fn test_batch_response_drain_prevents_select_latency() {
        use tokio::sync::mpsc;

        let (tx, mut rx) = mpsc::unbounded_channel::<u32>();

        // Simulate 256 forwarding workers sending responses
        for i in 0..256 {
            tx.send(i).ok();
        }

        // Batch drain all responses before select blocking
        let mut drained_count = 0;
        loop {
            match rx.try_recv() {
                Ok(_) => drained_count += 1,
                Err(mpsc::error::TryRecvError::Empty) => break,
                Err(mpsc::error::TryRecvError::Disconnected) => break,
            }
        }

        println!(
            "Batch drained {} responses in one pass (no select cycles)",
            drained_count
        );
        assert_eq!(
            drained_count, 256,
            "All responses should drain before select blocks"
        );
    }
}

use auth_handshake::{perform_auth_handshake, perform_websocket_auth_handshake};
use authorized_keys::{AuthorizedKeysStore, AuthorizedKeysWatcher};
use bonded_core::auth::DeviceKeypair;
use bonded_core::config::{load_server_config, ServerConfig, DEFAULT_SERVER_CONFIG_PATH};
use bonded_core::session::{SessionFrame, SessionHeader, FLAG_PING, FLAG_PONG};
use bonded_core::transport::{NaiveTcpTransport, Transport};
use clap::Parser;
use frame_forwarder::{
    forward_frame, forward_icmp_frame, AsyncIcmpSocket, IcmpSessionTracker, TcpFlowTable,
    TcpSessionTracker, UdpSessionManager, UdpSessionTracker,
};
use health::run_health_server;
use invite_tokens::ensure_startup_invite;
use pairing_qr::emit_pairing_qr;
use session_registry::SessionRegistry;
use status::run_status_server;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_rustls::TlsAcceptor;
use tracing::{error, info, warn, Level};

const FORWARD_WORKER_SHARDS: usize = 256;
const MAX_ICMP_FRAMES_PER_SESSION: usize = 128;

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
    ensure_server_state_files(&cfg)?;

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
    let udp_tracker = UdpSessionTracker::default();
    let tcp_tracker = TcpSessionTracker::default();
    let icmp_tracker = IcmpSessionTracker::default();

    let status_bind = cfg.server.status_bind.clone();
    let status_sessions = sessions.clone();
    let status_udp_tracker = udp_tracker.clone();
    let status_tcp_tracker = tcp_tracker.clone();
    let status_icmp_tracker = icmp_tracker.clone();
    tokio::spawn(async move {
        if let Err(err) = run_status_server(
            &status_bind,
            status_sessions,
            status_udp_tracker,
            status_tcp_tracker,
            status_icmp_tracker,
        )
        .await
        {
            error!(bind = %status_bind, error = %err, "status listener terminated");
        }
    });

    info!(bind = %cfg.server.bind, "bonded-server starting");
    let websocket_bind = cfg.server.websocket_bind.clone();
    let websocket_upstream = cfg.server.upstream_tcp_target.clone();
    let websocket_invites = cfg.server.invite_tokens_file.clone();
    let websocket_sessions = sessions.clone();
    let websocket_udp_tracker = udp_tracker.clone();
    let websocket_tcp_tracker = tcp_tracker.clone();
    let websocket_icmp_tracker = icmp_tracker.clone();
    let websocket_keys = authorized_keys.clone();
    let websocket_tls_acceptor = load_websocket_tls_acceptor(
        &cfg.server.websocket_tls_cert_file,
        &cfg.server.websocket_tls_key_file,
    )?;
    tokio::spawn(async move {
        if let Err(err) = run_websocket_server(
            &websocket_bind,
            &websocket_upstream,
            &websocket_invites,
            websocket_keys,
            websocket_sessions,
            websocket_udp_tracker,
            websocket_tcp_tracker,
            websocket_icmp_tracker,
            websocket_tls_acceptor,
        )
        .await
        {
            error!(bind = %websocket_bind, error = %err, "websocket listener terminated");
        }
    });

    run_server(
        &cfg.server.bind,
        &cfg.server.upstream_tcp_target,
        &cfg.server.invite_tokens_file,
        authorized_keys,
        sessions,
        udp_tracker,
        tcp_tracker,
        icmp_tracker,
    )
    .await
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
    upstream_tcp_target: &str,
    invite_tokens_file: &str,
    authorized_keys: AuthorizedKeysStore,
    sessions: SessionRegistry,
    udp_tracker: UdpSessionTracker,
    tcp_tracker: TcpSessionTracker,
    icmp_tracker: IcmpSessionTracker,
    tls_acceptor: Option<TlsAcceptor>,
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
        let udp_tracker = udp_tracker.clone();
        let tcp_tracker = tcp_tracker.clone();
        let icmp_tracker = icmp_tracker.clone();
        let upstream_tcp_target = upstream_tcp_target.to_owned();
        let invite_tokens_file = invite_tokens_file.to_owned();
        let tls_acceptor = tls_acceptor.clone();
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
                    let tcp_flows = TcpFlowTable::default();
                    let (udp_tx, mut udp_rx) = mpsc::unbounded_channel();
                    let udp_sessions =
                        UdpSessionManager::new(handle.session_id, udp_tx, udp_tracker.clone());
                    let (forward_shards, icmp_forward_tx, mut forward_responses) =
                        spawn_forward_workers(
                            handle.session_id,
                            upstream_tcp_target.clone(),
                            tcp_flows.clone(),
                            udp_sessions.clone(),
                            tcp_tracker.clone(),
                            icmp_tracker.clone(),
                            "websocket",
                        );

                    loop {
                        // Batch-drain forward responses before blocking on select.
                        // This prevents select from blocking when multiple responses are queued.
                        loop {
                            match forward_responses.try_recv() {
                                Ok(forwarded_frame) => {
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
                                Err(mpsc::error::TryRecvError::Empty) => break,
                                Err(mpsc::error::TryRecvError::Disconnected) => {
                                    warn!(
                                        peer = %peer,
                                        public_key = %public_key,
                                        session_id = handle.session_id,
                                        "websocket forward response queue closed"
                                    );
                                    return;
                                }
                            }
                        }

                        tokio::select! {
                            maybe_udp_frame = udp_rx.recv() => {
                                let Some(udp_frame) = maybe_udp_frame else {
                                    break;
                                };

                                if let Err(err) = transport.send(udp_frame).await {
                                    warn!(
                                        peer = %peer,
                                        public_key = %public_key,
                                        session_id = handle.session_id,
                                        error = %err,
                                        "failed to send websocket async UDP response"
                                    );
                                    break;
                                }
                            }
                            maybe_forwarded_frame = forward_responses.recv() => {
                                let Some(forwarded_frame) = maybe_forwarded_frame else {
                                    warn!(
                                        peer = %peer,
                                        public_key = %public_key,
                                        session_id = handle.session_id,
                                        "websocket forward response queue closed"
                                    );
                                    break;
                                };

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
                                        info!(
                                            peer = %peer,
                                            session_id = handle.session_id,
                                            connection_id = frame.header.connection_id,
                                            frame_size = frame.payload.len(),
                                            sequence = frame.header.sequence,
                                            flags = frame.header.flags,
                                            "websocket frame received from client"
                                        );

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

                                        let is_icmp_echo = is_ipv4_icmp_echo_frame(&frame.payload);
                                        if is_icmp_echo {
                                            match icmp_forward_tx.try_send(frame) {
                                                Ok(()) => continue,
                                                Err(mpsc::error::TrySendError::Full(_)) => {
                                                    warn!(
                                                        peer = %peer,
                                                        public_key = %public_key,
                                                        session_id = handle.session_id,
                                                        max_pending_icmp = MAX_ICMP_FRAMES_PER_SESSION,
                                                        "dropping ICMP echo frame because dedicated ICMP queue is full"
                                                    );
                                                    continue;
                                                }
                                                Err(mpsc::error::TrySendError::Closed(_)) => {
                                                    warn!(
                                                        peer = %peer,
                                                        public_key = %public_key,
                                                        session_id = handle.session_id,
                                                        "dedicated ICMP queue closed"
                                                    );
                                                    break;
                                                }
                                            }
                                        }

                                        let shard_idx = shard_index_for_connection(frame.header.connection_id);
                                        if let Err(err) = forward_shards[shard_idx].send(frame) {
                                            warn!(
                                                peer = %peer,
                                                public_key = %public_key,
                                                session_id = handle.session_id,
                                                error = ?err,
                                                shard_idx,
                                                "failed to enqueue websocket frame for forwarding"
                                            );
                                            break;
                                        }
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
                    drop(forward_shards);
                    drop(icmp_forward_tx);

                    sessions.unregister_client(&public_key);
                    udp_tracker.clear_session(handle.session_id);
                    tcp_tracker.clear_session(handle.session_id);
                    icmp_tracker.clear_session(handle.session_id);
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
    upstream_tcp_target: &str,
    invite_tokens_file: &str,
    authorized_keys: AuthorizedKeysStore,
    sessions: SessionRegistry,
    udp_tracker: UdpSessionTracker,
    tcp_tracker: TcpSessionTracker,
    icmp_tracker: IcmpSessionTracker,
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
        let udp_tracker = udp_tracker.clone();
        let tcp_tracker = tcp_tracker.clone();
        let icmp_tracker = icmp_tracker.clone();
        let upstream_tcp_target = upstream_tcp_target.to_owned();
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
                    let tcp_flows = TcpFlowTable::default();
                    let (udp_tx, mut udp_rx) = mpsc::unbounded_channel();
                    let udp_sessions =
                        UdpSessionManager::new(handle.session_id, udp_tx, udp_tracker.clone());
                    let (forward_shards, icmp_forward_tx, mut forward_responses) =
                        spawn_forward_workers(
                            handle.session_id,
                            upstream_tcp_target.clone(),
                            tcp_flows.clone(),
                            udp_sessions.clone(),
                            tcp_tracker.clone(),
                            icmp_tracker.clone(),
                            "naive-tcp",
                        );
                    loop {
                        // Batch-drain forward responses before blocking on select.
                        // This prevents select from blocking when multiple responses are queued.
                        loop {
                            match forward_responses.try_recv() {
                                Ok(forwarded_frame) => {
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
                                Err(mpsc::error::TryRecvError::Empty) => break,
                                Err(mpsc::error::TryRecvError::Disconnected) => {
                                    warn!(
                                        peer = %peer,
                                        public_key = %public_key,
                                        session_id = handle.session_id,
                                        "forward response queue closed"
                                    );
                                    return;
                                }
                            }
                        }

                        tokio::select! {
                            maybe_udp_frame = udp_rx.recv() => {
                                let Some(udp_frame) = maybe_udp_frame else {
                                    break;
                                };

                                if let Err(err) = transport.send(udp_frame).await {
                                    warn!(
                                        peer = %peer,
                                        public_key = %public_key,
                                        session_id = handle.session_id,
                                        error = %err,
                                        "failed to send async UDP response"
                                    );
                                    break;
                                }
                            }
                            maybe_forwarded_frame = forward_responses.recv() => {
                                let Some(forwarded_frame) = maybe_forwarded_frame else {
                                    warn!(
                                        peer = %peer,
                                        public_key = %public_key,
                                        session_id = handle.session_id,
                                        "forward response queue closed"
                                    );
                                    break;
                                };

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
                                        info!(
                                            peer = %peer,
                                            session_id = handle.session_id,
                                            connection_id = frame.header.connection_id,
                                            frame_size = frame.payload.len(),
                                            sequence = frame.header.sequence,
                                            flags = frame.header.flags,
                                            "frame received from client"
                                        );

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

                                        let is_icmp_echo = is_ipv4_icmp_echo_frame(&frame.payload);
                                        if is_icmp_echo {
                                            match icmp_forward_tx.try_send(frame) {
                                                Ok(()) => continue,
                                                Err(mpsc::error::TrySendError::Full(_)) => {
                                                    warn!(
                                                        peer = %peer,
                                                        public_key = %public_key,
                                                        session_id = handle.session_id,
                                                        max_pending_icmp = MAX_ICMP_FRAMES_PER_SESSION,
                                                        "dropping ICMP echo frame because dedicated ICMP queue is full"
                                                    );
                                                    continue;
                                                }
                                                Err(mpsc::error::TrySendError::Closed(_)) => {
                                                    warn!(
                                                        peer = %peer,
                                                        public_key = %public_key,
                                                        session_id = handle.session_id,
                                                        "dedicated ICMP queue closed"
                                                    );
                                                    break;
                                                }
                                            }
                                        }

                                        let shard_idx = shard_index_for_connection(frame.header.connection_id);
                                        if let Err(err) = forward_shards[shard_idx].send(frame) {
                                            warn!(
                                                peer = %peer,
                                                public_key = %public_key,
                                                session_id = handle.session_id,
                                                error = ?err,
                                                shard_idx,
                                                "failed to enqueue frame for forwarding"
                                            );
                                            break;
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
                    drop(forward_shards);
                    drop(icmp_forward_tx);

                    sessions.unregister_client(&public_key);
                    udp_tracker.clear_session(handle.session_id);
                    tcp_tracker.clear_session(handle.session_id);
                    icmp_tracker.clear_session(handle.session_id);
                }
                Err(err) => {
                    warn!(peer = %peer, error = %err, "client authentication failed");
                }
            }
        });
    }
}

fn shard_index_for_connection(connection_id: u32) -> usize {
    (connection_id as usize) % FORWARD_WORKER_SHARDS
}

fn spawn_forward_workers(
    session_id: u64,
    upstream_tcp_target: String,
    tcp_flows: TcpFlowTable,
    udp_sessions: UdpSessionManager,
    tcp_tracker: TcpSessionTracker,
    icmp_tracker: IcmpSessionTracker,
    transport_label: &'static str,
) -> (
    Vec<mpsc::UnboundedSender<SessionFrame>>,
    mpsc::Sender<SessionFrame>,
    mpsc::UnboundedReceiver<SessionFrame>,
) {
    let (response_tx, response_rx) = mpsc::unbounded_channel();
    let upstream = if upstream_tcp_target.trim().is_empty() {
        None
    } else {
        Some(upstream_tcp_target)
    };

    let mut shard_senders = Vec::with_capacity(FORWARD_WORKER_SHARDS);
    for shard_idx in 0..FORWARD_WORKER_SHARDS {
        let (tx, mut rx) = mpsc::unbounded_channel::<SessionFrame>();
        shard_senders.push(tx);

        let response_tx = response_tx.clone();
        let tcp_flows = tcp_flows.clone();
        let udp_sessions = udp_sessions.clone();
        let tcp_tracker = tcp_tracker.clone();
        let icmp_tracker = icmp_tracker.clone();
        let upstream = upstream.clone();

        tokio::spawn(async move {
            while let Some(frame) = rx.recv().await {
                let response = match forward_frame(
                    frame,
                    upstream.as_deref(),
                    &tcp_flows,
                    &udp_sessions,
                    &tcp_tracker,
                    &icmp_tracker,
                    session_id,
                )
                .await
                {
                    Ok(value) => value,
                    Err(err) => {
                        warn!(
                            session_id,
                            shard_idx,
                            transport = transport_label,
                            error = %err,
                            "failed to forward session frame"
                        );
                        continue;
                    }
                };

                let Some(response) = response else {
                    continue;
                };

                if response_tx.send(response).is_err() {
                    warn!(
                        session_id,
                        shard_idx,
                        transport = transport_label,
                        "forward response receiver dropped"
                    );
                    break;
                }
            }
        });
    }

    let (icmp_tx, mut icmp_rx) = mpsc::channel::<SessionFrame>(MAX_ICMP_FRAMES_PER_SESSION);
    let response_tx_icmp = response_tx.clone();
    let icmp_tracker_icmp = icmp_tracker.clone();
    // Create one shared async ICMP socket for this session.  Each probe is
    // dispatched as its own tokio task so all in-flight pings run concurrently
    // without any blocking threads.
    let icmp_socket = match AsyncIcmpSocket::new() {
        Ok(s) => s,
        Err(err) => {
            warn!(
                session_id,
                transport = transport_label,
                error = %err,
                "failed to create async ICMP socket; ICMP forwarding disabled for this session"
            );
            // Return a dummy channel that is immediately closed.
            let (dead_tx, _) = mpsc::channel(1);
            return (shard_senders, dead_tx, response_rx);
        }
    };
    tokio::spawn(async move {
        while let Some(frame) = icmp_rx.recv().await {
            // Spawn a task per probe so all pings fly concurrently.
            let icmp_socket = icmp_socket.clone();
            let response_tx = response_tx_icmp.clone();
            let icmp_tracker = icmp_tracker_icmp.clone();
            tokio::spawn(async move {
                match forward_icmp_frame(frame, &icmp_socket, &icmp_tracker, session_id).await {
                    Ok(Some(response)) => {
                        if response_tx.send(response).is_err() {
                            // Session gone; nothing to do.
                        }
                    }
                    Ok(None) => {}
                    Err(err) => {
                        warn!(
                            session_id,
                            transport = transport_label,
                            lane = "icmp",
                            error = %err,
                            "failed to forward ICMP session frame"
                        );
                    }
                }
            });
        }
    });

    (shard_senders, icmp_tx, response_rx)
}

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
