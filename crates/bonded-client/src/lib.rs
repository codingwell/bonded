use anyhow::Context;
use bonded_core::auth::{sign_auth_challenge, DeviceKeypair};
use bonded_core::config::ClientConfig;
#[cfg(target_os = "linux")]
use bonded_core::session::SessionState;
use bonded_core::transport::{
    NaiveTcpTransport, QuicTransport, Transport, WebSocketTlsTransport, WireGuardTransport,
};
#[cfg(target_os = "linux")]
use bytes::Bytes;
use pnet_datalink::NetworkInterface;
use rustls::pki_types::ServerName;
use serde::Deserialize;
use serde_json::json;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{lookup_host, TcpSocket, TcpStream};
#[cfg(target_os = "linux")]
use tokio::select;
use tokio::time::{timeout, Duration};
use tokio_rustls::TlsConnector;
use tokio_tungstenite::client_async_tls_with_config;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::Connector;
use tracing::{debug, info, warn};
#[cfg(target_os = "linux")]
use tun::Configuration;

pub mod cert_proof;

#[cfg(test)]
mod client_integration;

pub enum ClientTransport {
    NaiveTcp(NaiveTcpTransport),
    WebSocket(Box<WebSocketTlsTransport>),
    Quic(Box<QuicTransport>),
    WireGuard(Box<WireGuardTransport>),
}

impl ClientTransport {
    pub async fn send(&mut self, frame: bonded_core::session::SessionFrame) -> anyhow::Result<()> {
        match self {
            ClientTransport::NaiveTcp(inner) => inner.send(frame).await,
            ClientTransport::WebSocket(inner) => inner.send(frame).await,
            ClientTransport::Quic(inner) => inner.send(frame).await,
            ClientTransport::WireGuard(inner) => inner.send(frame).await,
        }
    }

    pub async fn recv(&mut self) -> anyhow::Result<bonded_core::session::SessionFrame> {
        match self {
            ClientTransport::NaiveTcp(inner) => inner.recv().await,
            ClientTransport::WebSocket(inner) => inner.recv().await,
            ClientTransport::Quic(inner) => inner.recv().await,
            ClientTransport::WireGuard(inner) => inner.recv().await,
        }
    }

    pub async fn close(&mut self) -> anyhow::Result<()> {
        match self {
            ClientTransport::NaiveTcp(inner) => inner.close().await,
            ClientTransport::WebSocket(inner) => inner.close().await,
            ClientTransport::Quic(inner) => inner.close().await,
            ClientTransport::WireGuard(inner) => inner.close().await,
        }
    }
}

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

        let max_paths = interfaces.len().clamp(1, 2);
        let transports = establish_transport_paths(&self.config, max_paths).await?;
        info!(
            paths = transports.len(),
            "authenticated transport paths established"
        );

        #[cfg(target_os = "linux")]
        {
            run_linux_packet_loop(&self.config.client.tun_name, transports).await?;
        }

        #[cfg(not(target_os = "linux"))]
        {
            let _ = transports;
        }

        info!(
            device = %self.config.client.device_name,
            "bonded client runtime starting"
        );
        Ok(())
    }
}

pub async fn establish_transport_paths(
    config: &ClientConfig,
    count: usize,
) -> anyhow::Result<Vec<ClientTransport>> {
    let protocols = if config.client.preferred_protocols.is_empty() {
        vec!["naive_tcp".to_owned()]
    } else {
        config.client.preferred_protocols.clone()
    };

    let target = count.max(1);
    let mut paths = Vec::with_capacity(target);
    for path_index in 0..target {
        let mut attempt_errors: Vec<String> = Vec::new();

        let bind_address = config
            .client
            .path_bind_addresses
            .get(path_index)
            .map(String::as_str);

        let mut connected: Option<ClientTransport> = None;
        for protocol in rotated_protocols(&protocols, path_index) {
            let attempt = match (protocol.as_str(), bind_address) {
                ("naive_tcp", Some(bind)) => timeout(
                    PATH_ESTABLISH_TIMEOUT,
                    establish_naive_tcp_session_with_bind(config, bind),
                )
                .await
                .map_err(anyhow::Error::from)
                .and_then(|result| result)
                .map(NaiveTcpTransport::from_stream)
                .map(ClientTransport::NaiveTcp),
                ("naive_tcp", None) => {
                    timeout(PATH_ESTABLISH_TIMEOUT, establish_naive_tcp_session(config))
                        .await
                        .map_err(anyhow::Error::from)
                        .and_then(|result| result)
                        .map(NaiveTcpTransport::from_stream)
                        .map(ClientTransport::NaiveTcp)
                }
                ("wss" | "websocket_tls", Some(bind)) => timeout(
                    PATH_ESTABLISH_TIMEOUT,
                    establish_websocket_session_with_bind(config, bind),
                )
                .await
                .map_err(anyhow::Error::from)
                .and_then(|result| result)
                .map(|transport| ClientTransport::WebSocket(Box::new(transport))),
                ("wss" | "websocket_tls", None) => {
                    timeout(PATH_ESTABLISH_TIMEOUT, establish_websocket_session(config))
                        .await
                        .map_err(anyhow::Error::from)
                        .and_then(|result| result)
                        .map(|transport| ClientTransport::WebSocket(Box::new(transport)))
                }
                ("h3" | "quic", _bind) => {
                    timeout(PATH_ESTABLISH_TIMEOUT, establish_quic_session(config))
                        .await
                        .map_err(anyhow::Error::from)
                        .and_then(|result| result)
                        .map(|transport| ClientTransport::Quic(Box::new(transport)))
                }
                ("wireguard" | "wg", _bind) => {
                    timeout(PATH_ESTABLISH_TIMEOUT, establish_wireguard_session(config))
                        .await
                        .map_err(anyhow::Error::from)
                        .and_then(|result| result)
                        .map(|transport| ClientTransport::WireGuard(Box::new(transport)))
                }
                _ => continue,
            };

            match attempt {
                Ok(path) => {
                    connected = Some(path);
                    break;
                }
                Err(err) => {
                    let bind_context = bind_address
                        .map(|bind| format!(", bind_address={bind}"))
                        .unwrap_or_default();
                    attempt_errors.push(format!(
                        "protocol={protocol}, path_index={path_index}{bind_context}: {:#}",
                        err
                    ));
                }
            }
        }

        let Some(path) = connected else {
            let reason = if attempt_errors.is_empty() {
                "no matching protocols configured".to_owned()
            } else {
                attempt_errors.join(" | ")
            };
            if path_index == 0 {
                anyhow::bail!(
                    "failed to establish path {path_index} with configured protocols: {reason}"
                );
            }

            warn!(
                path_index,
                requested_paths = target,
                established_paths = paths.len(),
                reason = %reason,
                "failed to establish additional path; continuing with available paths"
            );
            break;
        };
        paths.push(path);
    }

    Ok(paths)
}

const PATH_ESTABLISH_TIMEOUT: Duration = Duration::from_secs(8);

fn rotated_protocols(protocols: &[String], start: usize) -> Vec<String> {
    if protocols.is_empty() {
        return Vec::new();
    }

    let len = protocols.len();
    (0..len)
        .map(|offset| protocols[(start + offset) % len].clone())
        .collect()
}

#[derive(Debug, Deserialize)]
struct ServerChallenge {
    challenge_b64: String,
}

#[derive(Debug, Deserialize)]
struct ServerAuthResult {
    status: String,
}

#[derive(Debug, Deserialize)]
pub struct PairingPayload {
    pub server_public_address: String,
    pub invite_token: String,
    pub server_public_key: String,
}

#[derive(Clone, Copy, Debug)]
enum BootstrapScheme {
    Http,
    Https,
}

#[derive(Debug, Deserialize)]
struct WireGuardCapabilitiesResponse {
    wireguard: Option<WireGuardCapability>,
}

#[derive(Debug, Deserialize)]
struct WireGuardCapability {
    endpoint: String,
    #[serde(default)]
    server_public_key: String,
}

#[derive(Debug, Deserialize)]
struct WireGuardProvisionResponse {
    #[serde(default)]
    server_wg_public_key: String,
    #[allow(dead_code)]
    #[serde(default)]
    peer_ip: String,
}

#[derive(Debug)]
struct WireGuardBootstrapInfo {
    endpoint: String,
    server_public_key: String,
}

pub async fn establish_naive_tcp_session(config: &ClientConfig) -> anyhow::Result<TcpStream> {
    if config.client.server_public_address.trim().is_empty() {
        anyhow::bail!("server_public_address is required for NaiveTCP connection");
    }

    let dial_address = if config.client.server_resolved_address.trim().is_empty() {
        config.client.server_public_address.as_str()
    } else {
        config.client.server_resolved_address.as_str()
    };
    let server_addr = resolve_server_address(dial_address, None).await?;
    let socket = match server_addr {
        SocketAddr::V4(_) => TcpSocket::new_v4()?,
        SocketAddr::V6(_) => TcpSocket::new_v6()?,
    };
    socket.bind(local_wildcard_bind_addr_for(server_addr))?;
    #[cfg(unix)]
    if let Some(protect) = &config.socket_protect {
        use std::os::unix::io::AsRawFd;
        let fd = socket.as_raw_fd();
        debug!("protecting NaiveTCP socket fd={}", fd);
        if !protect.0(fd) {
            warn!("failed to protect NaiveTCP socket fd={}", fd);
            anyhow::bail!("failed to protect NaiveTCP socket from VPN capture");
        }
        debug!("successfully protected NaiveTCP socket fd={}", fd);
    }
    #[cfg(not(unix))]
    if config.socket_protect.is_some() {
        debug!("socket protect callback configured but platform is not Unix");
    }
    let stream = socket.connect(server_addr).await?;
    authenticate_naive_tcp_stream(config, stream).await
}

pub async fn establish_naive_tcp_session_with_bind(
    config: &ClientConfig,
    bind_address: &str,
) -> anyhow::Result<TcpStream> {
    if config.client.server_public_address.trim().is_empty() {
        anyhow::bail!("server_public_address is required for NaiveTCP connection");
    }

    let bind_ip = parse_bind_ip(bind_address)?;
    let dial_address = if config.client.server_resolved_address.trim().is_empty() {
        config.client.server_public_address.as_str()
    } else {
        config.client.server_resolved_address.as_str()
    };
    let server_address = resolve_server_address(dial_address, Some(bind_ip)).await?;
    let socket = match bind_ip {
        IpAddr::V4(_) => TcpSocket::new_v4()?,
        IpAddr::V6(_) => TcpSocket::new_v6()?,
    };
    socket.bind(SocketAddr::new(bind_ip, 0))?;
    #[cfg(unix)]
    if let Some(protect) = &config.socket_protect {
        use std::os::unix::io::AsRawFd;
        let fd = socket.as_raw_fd();
        debug!(
            "protecting NaiveTCP bind-aware socket fd={} bind_ip={}",
            fd, bind_ip
        );
        if !protect.0(fd) {
            warn!("failed to protect NaiveTCP bind-aware socket fd={}", fd);
            anyhow::bail!("failed to protect bind-aware NaiveTCP socket from VPN capture");
        }
        debug!(
            "successfully protected NaiveTCP bind-aware socket fd={}",
            fd
        );
    }
    #[cfg(not(unix))]
    if config.socket_protect.is_some() {
        debug!("socket protect callback configured but platform is not Unix");
    }
    let stream = socket.connect(server_address).await?;
    authenticate_naive_tcp_stream(config, stream).await
}

pub async fn authenticate_naive_tcp_stream(
    config: &ClientConfig,
    stream: TcpStream,
) -> anyhow::Result<TcpStream> {
    let keypair = load_or_create_device_keypair(
        &expand_home_path(&config.client.private_key_path),
        &expand_home_path(&config.client.public_key_path),
    )?;

    perform_auth_handshake(stream, &keypair, &config.client.invite_token).await
}

pub async fn establish_naive_tcp_sessions(
    config: &ClientConfig,
    count: usize,
) -> anyhow::Result<Vec<TcpStream>> {
    let target = count.max(1);
    let mut streams = Vec::with_capacity(target);
    for _ in 0..target {
        streams.push(establish_naive_tcp_session(config).await?);
    }
    Ok(streams)
}

async fn establish_websocket_session(
    config: &ClientConfig,
) -> anyhow::Result<WebSocketTlsTransport> {
    if config.client.server_public_address.trim().is_empty() {
        anyhow::bail!("server_public_address is required for websocket connection");
    }

    let keypair = load_or_create_device_keypair(
        &expand_home_path(&config.client.private_key_path),
        &expand_home_path(&config.client.public_key_path),
    )?;

    let address = &config.client.server_public_address;
    let websocket_address = if config.client.server_websocket_address.trim().is_empty() {
        address
    } else {
        &config.client.server_websocket_address
    };
    let websocket_url =
        if websocket_address.starts_with("ws://") || websocket_address.starts_with("wss://") {
            websocket_address.clone()
        } else {
            format!("wss://{websocket_address}")
        };

    let request = websocket_url.as_str().into_client_request()?;
    let uri = request.uri().clone();
    let host = uri
        .host()
        .ok_or_else(|| anyhow::anyhow!("websocket URL is missing host: {websocket_url}"))?
        .to_owned();
    let scheme = uri.scheme_str().unwrap_or("wss").to_owned();
    let default_port = if scheme.eq_ignore_ascii_case("wss") {
        443
    } else {
        80
    };
    let port = uri.port_u16().unwrap_or(default_port);
    let endpoint = format!("{scheme}://{host}:{port}");
    let dial_address = if config.client.server_resolved_address.trim().is_empty() {
        format!("{host}:{port}")
    } else {
        config.client.server_resolved_address.clone()
    };

    let server_addr = resolve_server_address(&dial_address, None).await?;
    let socket = match server_addr {
        SocketAddr::V4(_) => TcpSocket::new_v4()?,
        SocketAddr::V6(_) => TcpSocket::new_v6()?,
    };
    socket.bind(local_wildcard_bind_addr_for(server_addr))?;
    #[cfg(unix)]
    if let Some(protect) = &config.socket_protect {
        use std::os::unix::io::AsRawFd;
        let fd = socket.as_raw_fd();
        debug!(
            "protecting WebSocket socket fd={} target={}://{}:{}",
            fd, scheme, host, port
        );
        if !protect.0(fd) {
            warn!("FAILED to protect WebSocket socket fd={}", fd);
            anyhow::bail!("failed to protect WebSocket socket from VPN capture");
        }
        debug!("successfully protected WebSocket socket fd={}", fd);
    }
    #[cfg(not(unix))]
    if config.socket_protect.is_some() {
        debug!("socket protect callback configured but platform is not Unix");
    }

    let connector = resolve_wss_tls_connector(
        &scheme,
        &host,
        port,
        config,
        (!config.client.server_resolved_address.trim().is_empty())
            .then_some(config.client.server_resolved_address.as_str()),
    )
    .await
    .with_context(|| format!("failed to resolve WSS TLS connector for {scheme}://{host}:{port}"))?;

    let stream = socket
        .connect(server_addr)
        .await
        .with_context(|| format!("failed to connect websocket TCP socket to {server_addr}"))?;
    let (ws_stream, _response) = client_async_tls_with_config(request, stream, None, connector)
        .await
        .with_context(|| format!("websocket TLS/upgrade failed for {endpoint}"))?;

    let mut transport = WebSocketTlsTransport::from_client_stream(ws_stream);
    perform_websocket_auth_handshake(&mut transport, &keypair, &config.client.invite_token)
        .await
        .with_context(|| format!("websocket auth handshake failed for {host}:{port}"))?;
    Ok(transport)
}

async fn establish_websocket_session_with_bind(
    config: &ClientConfig,
    bind_address: &str,
) -> anyhow::Result<WebSocketTlsTransport> {
    if config.client.server_public_address.trim().is_empty() {
        anyhow::bail!("server_public_address is required for websocket connection");
    }

    let bind_ip = parse_bind_ip(bind_address)?;
    let keypair = load_or_create_device_keypair(
        &expand_home_path(&config.client.private_key_path),
        &expand_home_path(&config.client.public_key_path),
    )?;

    let address = &config.client.server_public_address;
    let websocket_address = if config.client.server_websocket_address.trim().is_empty() {
        address
    } else {
        &config.client.server_websocket_address
    };
    let websocket_url =
        if websocket_address.starts_with("ws://") || websocket_address.starts_with("wss://") {
            websocket_address.clone()
        } else {
            format!("wss://{websocket_address}")
        };

    let request = websocket_url.as_str().into_client_request()?;
    let uri = request.uri().clone();
    let host = uri
        .host()
        .ok_or_else(|| anyhow::anyhow!("websocket URL is missing host: {websocket_url}"))?
        .to_owned();
    let scheme = uri.scheme_str().unwrap_or("wss").to_owned();
    let default_port = if scheme.eq_ignore_ascii_case("wss") {
        443
    } else {
        80
    };
    let port = uri.port_u16().unwrap_or(default_port);
    let endpoint = format!("{scheme}://{host}:{port}");
    let dial_address = if config.client.server_resolved_address.trim().is_empty() {
        format!("{host}:{port}")
    } else {
        config.client.server_resolved_address.clone()
    };

    let server_addr = resolve_server_address(&dial_address, Some(bind_ip)).await?;
    let socket = match bind_ip {
        IpAddr::V4(_) => TcpSocket::new_v4()?,
        IpAddr::V6(_) => TcpSocket::new_v6()?,
    };
    socket.bind(SocketAddr::new(bind_ip, 0))?;
    #[cfg(unix)]
    if let Some(protect) = &config.socket_protect {
        use std::os::unix::io::AsRawFd;
        let fd = socket.as_raw_fd();
        debug!(
            "protecting WebSocket bind-aware socket fd={} bind_ip={} target={}://{}:{}",
            fd, bind_ip, scheme, host, port
        );
        if !protect.0(fd) {
            warn!("FAILED to protect WebSocket bind-aware socket fd={}", fd);
            anyhow::bail!("failed to protect bind-aware WebSocket socket from VPN capture");
        }
        debug!(
            "successfully protected WebSocket bind-aware socket fd={}",
            fd
        );
    }
    #[cfg(not(unix))]
    if config.socket_protect.is_some() {
        debug!("socket protect callback configured but platform is not Unix");
    }

    let connector = resolve_wss_tls_connector(
        &scheme,
        &host,
        port,
        config,
        (!config.client.server_resolved_address.trim().is_empty())
            .then_some(config.client.server_resolved_address.as_str()),
    )
    .await
    .with_context(|| format!("failed to resolve WSS TLS connector for {scheme}://{host}:{port}"))?;

    let stream = socket.connect(server_addr).await.with_context(|| {
        format!("failed to connect websocket TCP socket to {server_addr} from bind {bind_ip}")
    })?;
    let (ws_stream, _response) = client_async_tls_with_config(request, stream, None, connector)
        .await
        .with_context(|| {
            format!("websocket TLS/upgrade failed for {endpoint} from bind {bind_ip}")
        })?;

    let mut transport = WebSocketTlsTransport::from_client_stream(ws_stream);
    perform_websocket_auth_handshake(&mut transport, &keypair, &config.client.invite_token)
        .await
        .with_context(|| {
            format!("websocket auth handshake failed for {host}:{port} from bind {bind_ip}")
        })?;
    Ok(transport)
}

/// Establish a QUIC (HTTP/3) transport session with the bonded server.
///
/// The server address is resolved from `config.client.server_websocket_address`
/// or `config.client.server_public_address`.  TLS is pinned using the same
/// cert-proof mechanism as WSS: if `tls_cert_fingerprint` is already stored it
/// is used directly; otherwise `fetch_and_verify_cert_proof` is called.
async fn establish_quic_session(config: &ClientConfig) -> anyhow::Result<QuicTransport> {
    let address = &config.client.server_public_address;
    let ws_addr = &config.client.server_websocket_address;
    let quic_address = if ws_addr.trim().is_empty() {
        address
    } else {
        ws_addr
    };

    // Strip any URL scheme prefix — QUIC connects directly to host:port.
    let quic_host_port = quic_address
        .trim_start_matches("wss://")
        .trim_start_matches("ws://")
        .trim_start_matches("h3://");

    // Split host and port.
    let (host, port) = if let Some(pos) = quic_host_port.rfind(':') {
        let port_str = &quic_host_port[pos + 1..];
        if let Ok(port) = port_str.parse::<u16>() {
            (&quic_host_port[..pos], port)
        } else {
            (quic_host_port, 443u16)
        }
    } else {
        (quic_host_port, 443u16)
    };

    // Build rustls ClientConfig with cert pinning.
    let rustls_config = if !config.client.tls_cert_fingerprint.is_empty() {
        cert_proof::make_pinned_tls_config(&config.client.tls_cert_fingerprint)
    } else if !config.client.server_public_key.is_empty() {
        let fingerprint = cert_proof::fetch_and_verify_cert_proof(
            host,
            port,
            &config.client.server_public_key,
            config.socket_protect.as_ref(),
            None,
        )
        .await
        .map_err(|e| anyhow::anyhow!("QUIC cert-proof bootstrap failed for {host}:{port}: {e}"))?;
        info!(fingerprint = %fingerprint, "QUIC cert-proof verified");
        cert_proof::make_pinned_tls_config(&fingerprint)
    } else {
        anyhow::bail!(
            "QUIC transport requires tls_cert_fingerprint or server_public_key in client config"
        );
    };

    let quic_client_config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from((*rustls_config).clone())
            .map_err(|e| anyhow::anyhow!("QUIC crypto config error: {e}"))?,
    ));

    let mut endpoint = quinn::Endpoint::client("[::]:0".parse().unwrap())
        .map_err(|e| anyhow::anyhow!("failed to bind QUIC client endpoint: {e}"))?;
    endpoint.set_default_client_config(quic_client_config);

    let server_addr: SocketAddr = tokio::net::lookup_host(format!("{host}:{port}"))
        .await
        .map_err(|e| anyhow::anyhow!("failed to resolve QUIC server {host}:{port}: {e}"))?
        .next()
        .ok_or_else(|| anyhow::anyhow!("no addresses resolved for {host}:{port}"))?;

    debug!(peer = %server_addr, "connecting QUIC endpoint");
    let connection = endpoint
        .connect(server_addr, host)
        .map_err(|e| anyhow::anyhow!("QUIC connect error: {e}"))?
        .await
        .map_err(|e| anyhow::anyhow!("QUIC connection failed: {e}"))?;

    let mut transport = QuicTransport::from_client_connection(connection).await?;

    // Perform the same challenge-response auth handshake as over WSS.
    let keypair = load_or_create_device_keypair(
        &expand_home_path(&config.client.private_key_path),
        &expand_home_path(&config.client.public_key_path),
    )?;
    perform_quic_auth_handshake(&mut transport, &keypair, &config.client.invite_token).await?;
    Ok(transport)
}

/// Perform the challenge-response auth handshake over a QUIC transport.
async fn perform_quic_auth_handshake(
    transport: &mut QuicTransport,
    keypair: &DeviceKeypair,
    invite_token: &str,
) -> anyhow::Result<()> {
    // Send hello (same as WebSocket path).
    let hello = json!({
        "type": "hello",
        "public_key": keypair.public_key_b64,
        "invite_token": invite_token,
    });
    transport.send_text(&hello.to_string()).await?;

    // Receive challenge.
    let challenge_line = transport.recv_text().await?;
    let challenge: serde_json::Value = serde_json::from_str(challenge_line.trim())?;
    if challenge.get("type").and_then(|v| v.as_str()) == Some("error") {
        anyhow::bail!(
            "server rejected hello: {}",
            challenge
                .get("message")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown error")
        );
    }
    let challenge_b64 = challenge
        .get("challenge_b64")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("server sent invalid challenge: {challenge_line}"))?;

    // Sign and respond.
    let signature_b64 = sign_auth_challenge(keypair, challenge_b64)?;
    let response = json!({
        "type": "auth_response",
        "signature_b64": signature_b64,
    });
    transport.send_text(&response.to_string()).await?;

    // Receive result.
    let result_line = transport.recv_text().await?;
    let result: serde_json::Value = serde_json::from_str(result_line.trim())?;
    if result.get("status").and_then(|v| v.as_str()) != Some("ok") {
        anyhow::bail!(
            "QUIC auth failed: {}",
            result
                .get("message")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown error")
        );
    }
    Ok(())
}

/// Establish a WireGuard UDP transport session.
///
/// Generates a fresh client-side WireGuard keypair, resolves the server's WG
/// public key from config, and connects.  The session handshake is driven
/// lazily on the first `send()` call.
///
/// Config requirements:
/// - `server_public_address` or `server_websocket_address` — host:port for UDP
/// - `wireguard_server_public_key` — the server's X25519 public key (base64)
async fn establish_wireguard_session(config: &ClientConfig) -> anyhow::Result<WireGuardTransport> {
    use bonded_core::transport::WireGuardKeypair;

    let private_key_path = expand_home_path(&config.client.private_key_path);
    let public_key_path = expand_home_path(&config.client.public_key_path);
    let device_keypair = load_or_create_device_keypair(&private_key_path, &public_key_path)?;
    let local_keypair = WireGuardKeypair::generate();
    let bootstrap = bootstrap_wireguard_peer(
        config,
        &device_keypair.public_key_b64,
        &local_keypair.public_key_b64(),
    )
    .await?;
    let peer_public_key = decode_wireguard_public_key(&bootstrap.server_public_key)?;

    let server_addr: std::net::SocketAddr = tokio::net::lookup_host(&bootstrap.endpoint)
        .await
        .map_err(|e| {
            anyhow::anyhow!(
                "failed to resolve WireGuard server {}: {e}",
                bootstrap.endpoint
            )
        })?
        .next()
        .ok_or_else(|| anyhow::anyhow!("no addresses resolved for {}", bootstrap.endpoint))?;

    let transport = WireGuardTransport::new(
        local_keypair,
        peer_public_key,
        "[::]:0", // bind to any local UDP port
        server_addr,
        rand::random::<u32>(),
        #[cfg(unix)]
        config.socket_protect.as_ref(),
    )
    .await?;
    Ok(transport)
}

async fn bootstrap_wireguard_peer(
    config: &ClientConfig,
    device_public_key_b64: &str,
    wireguard_public_key_b64: &str,
) -> anyhow::Result<WireGuardBootstrapInfo> {
    let bootstrap_address = config.client.server_public_address.trim();
    if bootstrap_address.is_empty() {
        anyhow::bail!("server_public_address is required for WireGuard bootstrap");
    }

    let mut errors = Vec::new();
    for scheme in bootstrap_scheme_candidates(config) {
        let capabilities_raw = match request_bootstrap_json(
            config,
            scheme,
            bootstrap_address,
            "GET",
            "/v1/bootstrap/capabilities",
            None,
        )
        .await
        {
            Ok(body) => body,
            Err(err) => {
                errors.push(format!(
                    "scheme={scheme:?}: capabilities request failed: {err:#}"
                ));
                continue;
            }
        };

        let capabilities: WireGuardCapabilitiesResponse =
            serde_json::from_str(&capabilities_raw)
                .map_err(|e| anyhow::anyhow!("invalid WireGuard capabilities JSON: {e}"))?;
        let Some(wireguard) = capabilities.wireguard else {
            errors.push(format!(
                "scheme={scheme:?}: server did not advertise wireguard transport"
            ));
            continue;
        };

        let request_body = json!({
            "device_public_key": device_public_key_b64,
            "wg_public_key": wireguard_public_key_b64,
        })
        .to_string();
        let provision_raw = match request_bootstrap_json(
            config,
            scheme,
            bootstrap_address,
            "POST",
            "/v1/bootstrap/wireguard/peer",
            Some(&request_body),
        )
        .await
        {
            Ok(body) => body,
            Err(err) => {
                errors.push(format!(
                    "scheme={scheme:?}: peer provisioning failed: {err:#}"
                ));
                continue;
            }
        };

        let provision: WireGuardProvisionResponse = serde_json::from_str(&provision_raw)
            .map_err(|e| anyhow::anyhow!("invalid WireGuard provision JSON: {e}"))?;
        let server_public_key = if !provision.server_wg_public_key.is_empty() {
            provision.server_wg_public_key
        } else if !wireguard.server_public_key.is_empty() {
            wireguard.server_public_key
        } else {
            config.client.wireguard_server_public_key.clone()
        };

        if server_public_key.is_empty() {
            errors.push(format!(
                "scheme={scheme:?}: server did not provide a WireGuard public key"
            ));
            continue;
        }

        return Ok(WireGuardBootstrapInfo {
            endpoint: wireguard.endpoint,
            server_public_key,
        });
    }

    anyhow::bail!(
        "failed to bootstrap WireGuard transport via {}: {}",
        bootstrap_address,
        errors.join(" | ")
    )
}

fn bootstrap_scheme_candidates(config: &ClientConfig) -> Vec<BootstrapScheme> {
    let websocket_address = config
        .client
        .server_websocket_address
        .trim()
        .to_ascii_lowercase();
    if websocket_address.starts_with("ws://") {
        vec![BootstrapScheme::Http, BootstrapScheme::Https]
    } else if websocket_address.starts_with("wss://") {
        vec![BootstrapScheme::Https, BootstrapScheme::Http]
    } else {
        vec![BootstrapScheme::Https, BootstrapScheme::Http]
    }
}

async fn request_bootstrap_json(
    config: &ClientConfig,
    scheme: BootstrapScheme,
    address: &str,
    method: &str,
    path: &str,
    body: Option<&str>,
) -> anyhow::Result<String> {
    let (host, port) = split_host_port(address)?;
    match scheme {
        BootstrapScheme::Http => {
            request_bootstrap_json_http(config, &host, port, method, path, body).await
        }
        BootstrapScheme::Https => {
            request_bootstrap_json_https(config, &host, port, method, path, body).await
        }
    }
}

async fn request_bootstrap_json_http(
    config: &ClientConfig,
    host: &str,
    port: u16,
    method: &str,
    path: &str,
    body: Option<&str>,
) -> anyhow::Result<String> {
    let mut stream = connect_bootstrap_tcp(host, port, config.socket_protect.as_ref()).await?;
    let request = build_http_request(method, host, path, body);
    stream.write_all(request.as_bytes()).await?;
    stream.flush().await?;

    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).await?;
    extract_http_json_body(&raw)
}

async fn request_bootstrap_json_https(
    config: &ClientConfig,
    host: &str,
    port: u16,
    method: &str,
    path: &str,
    body: Option<&str>,
) -> anyhow::Result<String> {
    let tls_config = if !config.client.tls_cert_fingerprint.is_empty() {
        cert_proof::make_pinned_tls_config(&config.client.tls_cert_fingerprint)
    } else if !config.client.server_public_key.is_empty() {
        let fingerprint = cert_proof::fetch_and_verify_cert_proof(
            host,
            port,
            &config.client.server_public_key,
            config.socket_protect.as_ref(),
            None,
        )
        .await?;
        cert_proof::make_pinned_tls_config(&fingerprint)
    } else {
        anyhow::bail!(
            "HTTPS WireGuard bootstrap requires tls_cert_fingerprint or server_public_key"
        );
    };

    let tcp = connect_bootstrap_tcp(host, port, config.socket_protect.as_ref()).await?;
    let server_name = if let Ok(ip) = host.parse::<IpAddr>() {
        ServerName::IpAddress(ip.into())
    } else {
        ServerName::try_from(host.to_owned())
            .map_err(|_| anyhow::anyhow!("invalid TLS server name: {host}"))?
    };
    let connector = TlsConnector::from(tls_config);
    let mut tls = connector.connect(server_name, tcp).await?;

    let request = build_http_request(method, host, path, body);
    tls.write_all(request.as_bytes()).await?;
    tls.flush().await?;

    let mut raw = Vec::new();
    tls.read_to_end(&mut raw).await?;
    extract_http_json_body(&raw)
}

async fn connect_bootstrap_tcp(
    host: &str,
    port: u16,
    socket_protect: Option<&bonded_core::config::SocketProtectFn>,
) -> anyhow::Result<TcpStream> {
    let target = format!("{host}:{port}");
    let address = lookup_host(&target)
        .await
        .map_err(|e| anyhow::anyhow!("failed to resolve {target}: {e}"))?
        .next()
        .ok_or_else(|| anyhow::anyhow!("no addresses resolved for {target}"))?;
    let socket = match address {
        SocketAddr::V4(_) => TcpSocket::new_v4()?,
        SocketAddr::V6(_) => TcpSocket::new_v6()?,
    };
    #[cfg(unix)]
    if let Some(protect) = socket_protect {
        use std::os::unix::io::AsRawFd;
        let fd = socket.as_raw_fd();
        if !protect.0(fd) {
            anyhow::bail!("failed to protect bootstrap socket from VPN capture (fd={fd})");
        }
    }
    Ok(socket.connect(address).await?)
}

fn build_http_request(method: &str, host: &str, path: &str, body: Option<&str>) -> String {
    match body {
        Some(body) => format!(
            "{method} {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body,
        ),
        None => format!(
            "{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
        ),
    }
}

fn extract_http_json_body(raw: &[u8]) -> anyhow::Result<String> {
    let response = std::str::from_utf8(raw)
        .map_err(|_| anyhow::anyhow!("bootstrap response contained non-UTF8 bytes"))?;
    let (headers, body) = response
        .split_once("\r\n\r\n")
        .ok_or_else(|| anyhow::anyhow!("bootstrap response missing header terminator"))?;
    let status_line = headers
        .lines()
        .next()
        .ok_or_else(|| anyhow::anyhow!("bootstrap response missing status line"))?;
    if !status_line.contains(" 200 ") {
        anyhow::bail!("bootstrap request failed: {status_line}; body={body}");
    }
    Ok(body.trim().to_owned())
}

fn split_host_port(address: &str) -> anyhow::Result<(String, u16)> {
    if let Some(stripped) = address.strip_prefix('[') {
        let end = stripped
            .find(']')
            .ok_or_else(|| anyhow::anyhow!("invalid bracketed address: {address}"))?;
        let host = stripped[..end].to_owned();
        let port = stripped[end + 1..]
            .strip_prefix(':')
            .ok_or_else(|| anyhow::anyhow!("missing port in address: {address}"))?
            .parse::<u16>()?;
        return Ok((host, port));
    }

    let (host, port) = address
        .rsplit_once(':')
        .ok_or_else(|| anyhow::anyhow!("address must be host:port: {address}"))?;
    Ok((host.to_owned(), port.parse::<u16>()?))
}

fn decode_wireguard_public_key(
    public_key_b64: &str,
) -> anyhow::Result<boringtun::x25519::PublicKey> {
    use base64::Engine as _;

    let server_pub_bytes: Vec<u8> = base64::engine::general_purpose::STANDARD
        .decode(public_key_b64)
        .map_err(|e| anyhow::anyhow!("invalid wireguard_server_public_key base64: {e}"))?;
    if server_pub_bytes.len() != 32 {
        anyhow::bail!(
            "wireguard_server_public_key must be 32 bytes (got {})",
            server_pub_bytes.len()
        );
    }
    let mut peer_pub_bytes = [0u8; 32];
    peer_pub_bytes.copy_from_slice(&server_pub_bytes);
    Ok(boringtun::x25519::PublicKey::from(peer_pub_bytes))
}

/// Determine the TLS `Connector` to use for a `wss://` WebSocket connection.
///
/// * Plain (`ws://`) — returns `None` (no TLS).
/// * `wss://` with a pinned fingerprint already stored in config — returns a
///   `Connector::Rustls` that verifies the leaf cert matches that fingerprint.
/// * `wss://` with no stored fingerprint, but a server public key from pairing
///   — runs the cert-proof bootstrap, pins the fingerprint for this session,
///   and returns a `Connector::Rustls` that verifies it on the WS connect.
/// * `wss://` with neither fingerprint nor public key — returns `None` (falls
///   back to system CAs / webpki roots as compiled into tokio-tungstenite).
async fn resolve_wss_tls_connector(
    scheme: &str,
    host: &str,
    port: u16,
    config: &ClientConfig,
    dial_address: Option<&str>,
) -> anyhow::Result<Option<Connector>> {
    if !scheme.eq_ignore_ascii_case("wss") {
        return Ok(None);
    }

    // If we already have a pinned fingerprint, use it directly.
    if !config.client.tls_cert_fingerprint.is_empty() {
        debug!(
            "using pinned TLS cert fingerprint for WSS connection: {}",
            &config.client.tls_cert_fingerprint
        );
        let tls_config = cert_proof::make_pinned_tls_config(&config.client.tls_cert_fingerprint);
        return Ok(Some(Connector::Rustls(tls_config)));
    }

    // No stored fingerprint. If we have the server public key (from pairing),
    // run the cert-proof bootstrap to fetch and verify a fingerprint.
    if !config.client.server_public_key.is_empty() {
        info!(
            host,
            port, "no TLS cert fingerprint stored; running cert-proof bootstrap"
        );
        match cert_proof::fetch_and_verify_cert_proof(
            host,
            port,
            &config.client.server_public_key,
            config.socket_protect.as_ref(),
            dial_address,
        )
        .await
        {
            Ok(fingerprint) => {
                info!(
                    fingerprint = %fingerprint,
                    "cert-proof verified; pinning TLS cert fingerprint for this session"
                );
                // NOTE: the caller should persist `fingerprint` back to
                // config.client.tls_cert_fingerprint to avoid re-bootstrapping
                // on every connection.  We return the connector here; the
                // calling code in establish_transport_paths can do the persist.
                let tls_config = cert_proof::make_pinned_tls_config(&fingerprint);
                return Ok(Some(Connector::Rustls(tls_config)));
            }
            Err(err) => {
                warn!(
                    error = %err,
                    "cert-proof bootstrap failed; falling back to system CAs"
                );
                // Fall through to default connector.
            }
        }
    }

    // Fall back to the default TLS connector (webpki roots bundled in
    // tokio-tungstenite with the `rustls-tls-webpki-roots` feature).
    Ok(None)
}

fn parse_bind_ip(bind_address: &str) -> anyhow::Result<IpAddr> {
    if let Ok(ip) = bind_address.parse::<IpAddr>() {
        return Ok(ip);
    }

    if let Ok(socket_addr) = bind_address.parse::<SocketAddr>() {
        return Ok(socket_addr.ip());
    }

    anyhow::bail!("invalid bind address {bind_address}")
}

fn local_wildcard_bind_addr_for(remote: SocketAddr) -> SocketAddr {
    match remote {
        SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    }
}

async fn resolve_server_address(
    address: &str,
    bind_ip: Option<IpAddr>,
) -> anyhow::Result<SocketAddr> {
    let addresses: Vec<SocketAddr> = lookup_host(address).await?.collect();
    if addresses.is_empty() {
        anyhow::bail!("failed to resolve server address {address}");
    }

    if let Some(bind_ip) = bind_ip {
        if let Some(matched) = addresses
            .iter()
            .copied()
            .find(|candidate| candidate.is_ipv4() == bind_ip.is_ipv4())
        {
            return Ok(matched);
        }
    }

    Ok(addresses[0])
}

async fn perform_auth_handshake(
    mut stream: TcpStream,
    keypair: &DeviceKeypair,
    invite_token: &str,
) -> anyhow::Result<TcpStream> {
    let hello = json!({
        "public_key_b64": keypair.public_key_b64,
        "invite_token": invite_token,
    });
    stream.write_all(format!("{}\n", hello).as_bytes()).await?;

    let challenge_line = read_line_from_stream(&mut stream).await?;

    let challenge_value: serde_json::Value = serde_json::from_str(challenge_line.trim_end())
        .map_err(|e| anyhow::anyhow!("server sent invalid JSON: {e}"))?;
    if let Some(status) = challenge_value.get("status").and_then(|v| v.as_str()) {
        anyhow::bail!("server rejected authentication: status={status}");
    }
    let challenge: ServerChallenge = serde_json::from_value(challenge_value).map_err(|e| {
        anyhow::anyhow!("server sent unexpected JSON (expected challenge_b64): {e}")
    })?;
    let signature_b64 = sign_auth_challenge(keypair, &challenge.challenge_b64)?;

    let proof = json!({
        "signature_b64": signature_b64,
    });
    stream.write_all(format!("{}\n", proof).as_bytes()).await?;

    let result_line = read_line_from_stream(&mut stream).await?;

    let result: ServerAuthResult = serde_json::from_str(result_line.trim_end())?;
    if result.status != "ok" {
        anyhow::bail!(
            "server rejected authentication with status {}",
            result.status
        );
    }

    Ok(stream)
}

async fn read_line_from_stream(stream: &mut TcpStream) -> anyhow::Result<String> {
    const MAX_AUTH_LINE_BYTES: usize = 16 * 1024;
    let mut buf = Vec::with_capacity(256);
    loop {
        let byte = match stream.read_u8().await {
            Ok(value) => value,
            Err(err) if buf.is_empty() && err.kind() == std::io::ErrorKind::UnexpectedEof => {
                anyhow::bail!("server closed connection during auth handshake")
            }
            Err(err) => return Err(err.into()),
        };
        buf.push(byte);
        if byte == b'\n' {
            return Ok(String::from_utf8(buf)?);
        }
        if buf.len() >= MAX_AUTH_LINE_BYTES {
            anyhow::bail!("auth handshake line exceeded {MAX_AUTH_LINE_BYTES} bytes");
        }
    }
}

async fn perform_websocket_auth_handshake(
    transport: &mut WebSocketTlsTransport,
    keypair: &DeviceKeypair,
    invite_token: &str,
) -> anyhow::Result<()> {
    let hello = json!({
        "public_key_b64": keypair.public_key_b64,
        "invite_token": invite_token,
    });
    transport.send_text(&hello.to_string()).await?;

    let challenge_line = transport.recv_text().await?;
    let challenge_value: serde_json::Value = serde_json::from_str(challenge_line.trim_end())
        .map_err(|e| anyhow::anyhow!("server sent invalid JSON: {e}"))?;
    if let Some(status) = challenge_value.get("status").and_then(|v| v.as_str()) {
        anyhow::bail!("server rejected websocket authentication: status={status}");
    }
    let challenge: ServerChallenge = serde_json::from_value(challenge_value).map_err(|e| {
        anyhow::anyhow!("server sent unexpected JSON (expected challenge_b64): {e}")
    })?;
    let signature_b64 = sign_auth_challenge(keypair, &challenge.challenge_b64)?;

    let proof = json!({
        "signature_b64": signature_b64,
    });
    transport.send_text(&proof.to_string()).await?;

    let result_line = transport.recv_text().await?;
    let result: ServerAuthResult = serde_json::from_str(result_line.trim_end())?;
    if result.status != "ok" {
        anyhow::bail!(
            "server rejected websocket authentication with status {}",
            result.status
        );
    }

    Ok(())
}

fn load_or_create_device_keypair(
    private_key_path: &Path,
    public_key_path: &Path,
) -> anyhow::Result<DeviceKeypair> {
    if private_key_path.exists() {
        let private_key_b64 = fs::read_to_string(private_key_path)?.trim().to_owned();
        let keypair = DeviceKeypair::from_private_key_b64(&private_key_b64)?;

        if let Some(parent) = public_key_path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(public_key_path, format!("{}\n", keypair.public_key_b64))?;
        return Ok(keypair);
    }

    if let Some(parent) = private_key_path.parent() {
        fs::create_dir_all(parent)?;
    }
    if let Some(parent) = public_key_path.parent() {
        fs::create_dir_all(parent)?;
    }

    let keypair = DeviceKeypair::generate();
    fs::write(private_key_path, format!("{}\n", keypair.private_key_b64))?;
    fs::write(public_key_path, format!("{}\n", keypair.public_key_b64))?;
    Ok(keypair)
}

fn expand_home_path(path: &str) -> PathBuf {
    if let Some(rest) = path.strip_prefix("~/") {
        if let Ok(home) = std::env::var("HOME") {
            return PathBuf::from(home).join(rest);
        }
    }
    PathBuf::from(path)
}

pub fn apply_pairing_payload(config: &mut ClientConfig, payload_json: &str) -> anyhow::Result<()> {
    let payload: PairingPayload = serde_json::from_str(payload_json)?;
    config.client.server_public_address = payload.server_public_address;
    config.client.server_websocket_address = config.client.server_public_address.clone();
    config.client.server_public_key = payload.server_public_key;
    config.client.invite_token = payload.invite_token;
    Ok(())
}

pub fn enumerate_interfaces() -> Vec<NetworkInterface> {
    pnet_datalink::interfaces()
}

#[cfg(target_os = "linux")]
fn build_tun_config(tun_name: &str) -> Configuration {
    let mut config = Configuration::default();
    config.tun_name(tun_name).up();
    config
}

#[cfg(target_os = "linux")]
async fn run_linux_packet_loop(
    tun_name: &str,
    transports: Vec<ClientTransport>,
) -> anyhow::Result<()> {
    let config = build_tun_config(tun_name);
    let device = tun::create_as_async(&config)?;
    let mut transports = transports;
    let mut active_index = 0_usize;
    let mut state = SessionState::new(1);
    let mut tun_buf = vec![0_u8; 8192];

    loop {
        select! {
            tun_result = device.recv(&mut tun_buf) => {
                let read = tun_result?;
                if read == 0 {
                    continue;
                }

                let frame = state.create_outbound_frame(Bytes::copy_from_slice(&tun_buf[..read]), 0);
                match transports[active_index].send(frame).await {
                    Ok(()) => {}
                    Err(err) => {
                        if transports.len() == 1 {
                            return Err(err);
                        }

                        transports.remove(active_index);
                        if active_index >= transports.len() {
                            active_index = 0;
                        }
                        info!(active_path = active_index, remaining_paths = transports.len(), "switched active path after send failure");
                    }
                }
            }
            frame_result = transports[active_index].recv() => {
                match frame_result {
                    Ok(frame) => {
                        let ready = state.ingest_inbound(frame)?;
                        for packet in ready {
                            let _ = device.send(&packet.payload).await?;
                        }
                    }
                    Err(err) => {
                        if transports.len() == 1 {
                            return Err(err);
                        }

                        transports.remove(active_index);
                        if active_index >= transports.len() {
                            active_index = 0;
                        }
                        info!(active_path = active_index, remaining_paths = transports.len(), "switched active path after recv failure");
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{enumerate_interfaces, load_or_create_device_keypair};
    use bonded_core::auth::verify_auth_challenge;
    use bonded_core::auth::{create_auth_challenge, DeviceKeypair};
    use bonded_core::config::ClientConfig;
    use serde_json::json;
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::TcpListener;

    #[test]
    fn interfaces_can_be_enumerated() {
        let interfaces = enumerate_interfaces();
        assert!(!interfaces.is_empty());
    }

    fn temp_file_path(name: &str) -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be valid")
            .as_nanos();
        std::env::temp_dir().join(format!("bonded-client-{name}-{stamp}.txt"))
    }

    #[test]
    fn keypair_is_created_and_then_reloaded() {
        let private_path = temp_file_path("private");
        let public_path = temp_file_path("public");

        let first = load_or_create_device_keypair(&private_path, &public_path)
            .expect("keypair should be created");
        let second = load_or_create_device_keypair(&private_path, &public_path)
            .expect("keypair should be reloaded");

        assert_eq!(first.public_key_b64, second.public_key_b64);

        let _ = fs::remove_file(private_path);
        let _ = fs::remove_file(public_path);
    }

    #[tokio::test]
    async fn auth_handshake_flow_is_compatible_with_server_protocol() {
        let keypair = DeviceKeypair::generate();
        let server_keypair = keypair.clone();
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind");
        let addr = listener.local_addr().expect("addr should resolve");

        let server_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept should succeed");
            let (read_half, mut write_half) = stream.into_split();
            let mut reader = BufReader::new(read_half);

            let mut hello_line = String::new();
            reader
                .read_line(&mut hello_line)
                .await
                .expect("hello should be readable");
            let hello: serde_json::Value =
                serde_json::from_str(hello_line.trim_end()).expect("hello should parse");
            assert_eq!(
                hello["public_key_b64"].as_str().unwrap_or_default(),
                server_keypair.public_key_b64
            );

            let challenge_b64 = create_auth_challenge();
            let challenge = json!({ "challenge_b64": challenge_b64 });
            write_half
                .write_all(format!("{}\n", challenge).as_bytes())
                .await
                .expect("challenge should be written");

            let mut proof_line = String::new();
            reader
                .read_line(&mut proof_line)
                .await
                .expect("proof should be readable");
            let proof: serde_json::Value =
                serde_json::from_str(proof_line.trim_end()).expect("proof should parse");
            let signature_b64 = proof["signature_b64"]
                .as_str()
                .expect("signature should exist");

            verify_auth_challenge(
                &server_keypair.public_key_b64,
                &challenge_b64,
                signature_b64,
            )
            .expect("signature should verify");

            write_half
                .write_all(b"{\"status\":\"ok\"}\n")
                .await
                .expect("result should be written");
        });

        let stream = tokio::net::TcpStream::connect(addr)
            .await
            .expect("client should connect");
        super::perform_auth_handshake(stream, &keypair, "")
            .await
            .expect("auth handshake should succeed");

        server_task.await.expect("server task should join");
    }

    #[test]
    fn pairing_payload_updates_client_config() {
        let mut cfg = ClientConfig::default();
        let original_protocols = cfg.client.preferred_protocols.clone();
        let payload = r#"{
            "server_public_address": "bonded.example.com:8080",
            "invite_token": "token-abc",
            "server_public_key": "server-pub"
        }"#;

        super::apply_pairing_payload(&mut cfg, payload).expect("payload should apply");
        assert_eq!(cfg.client.server_public_address, "bonded.example.com:8080");
        assert_eq!(cfg.client.invite_token, "token-abc");
        assert_eq!(cfg.client.server_public_key, "server-pub");
        assert_eq!(cfg.client.preferred_protocols, original_protocols);
    }
}
