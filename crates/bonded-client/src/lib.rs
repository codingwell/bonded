use bonded_core::auth::{sign_auth_challenge, DeviceKeypair};
use bonded_core::config::ClientConfig;
#[cfg(target_os = "linux")]
use bonded_core::session::SessionState;
use bonded_core::transport::{NaiveTcpTransport, Transport, WebSocketTlsTransport};
#[cfg(target_os = "linux")]
use bytes::Bytes;
use pnet_datalink::NetworkInterface;
use serde::Deserialize;
use serde_json::json;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{lookup_host, TcpSocket, TcpStream};
#[cfg(target_os = "linux")]
use tokio::select;
use tokio::time::{timeout, Duration};
use tracing::{info, warn};
#[cfg(target_os = "linux")]
use tun::Configuration;

#[cfg(test)]
mod client_integration;

pub enum ClientTransport {
    NaiveTcp(NaiveTcpTransport),
    WebSocket(WebSocketTlsTransport),
}

impl ClientTransport {
    pub async fn send(&mut self, frame: bonded_core::session::SessionFrame) -> anyhow::Result<()> {
        match self {
            ClientTransport::NaiveTcp(inner) => inner.send(frame).await,
            ClientTransport::WebSocket(inner) => inner.send(frame).await,
        }
    }

    pub async fn recv(&mut self) -> anyhow::Result<bonded_core::session::SessionFrame> {
        match self {
            ClientTransport::NaiveTcp(inner) => inner.recv().await,
            ClientTransport::WebSocket(inner) => inner.recv().await,
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
        let mut last_err: Option<anyhow::Error> = None;

        if let Some(bind_address) = config.client.path_bind_addresses.get(path_index) {
            match timeout(
                PATH_ESTABLISH_TIMEOUT,
                establish_naive_tcp_session_with_bind(config, bind_address),
            )
            .await
            {
                Ok(Ok(stream)) => {
                    paths.push(ClientTransport::NaiveTcp(NaiveTcpTransport::from_stream(
                        stream,
                    )));
                    continue;
                }
                Ok(Err(err)) => {
                    last_err = Some(err);
                }
                Err(_) => {
                    last_err = Some(anyhow::anyhow!(
                        "timed out after {}s while establishing bind-aware NaiveTCP session",
                        PATH_ESTABLISH_TIMEOUT.as_secs()
                    ));
                }
            }
        }

        let mut connected: Option<ClientTransport> = None;
        for protocol in rotated_protocols(&protocols, path_index) {
            let attempt = match protocol.as_str() {
                "naive_tcp" => timeout(PATH_ESTABLISH_TIMEOUT, establish_naive_tcp_session(config))
                    .await
                    .map_err(anyhow::Error::from)
                    .and_then(|result| result)
                    .map(NaiveTcpTransport::from_stream)
                    .map(ClientTransport::NaiveTcp),
                "wss" | "websocket_tls" => {
                    timeout(PATH_ESTABLISH_TIMEOUT, establish_websocket_session(config))
                        .await
                        .map_err(anyhow::Error::from)
                        .and_then(|result| result)
                        .map(ClientTransport::WebSocket)
                }
                _ => continue,
            };

            match attempt {
                Ok(path) => {
                    connected = Some(path);
                    break;
                }
                Err(err) => {
                    last_err = Some(err);
                }
            }
        }

        let Some(path) = connected else {
            let reason = last_err
                .map(|err| err.to_string())
                .unwrap_or_else(|| "no matching protocols configured".to_owned());
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
    pub supported_protocols: Vec<String>,
}

pub async fn establish_naive_tcp_session(config: &ClientConfig) -> anyhow::Result<TcpStream> {
    if config.client.server_public_address.trim().is_empty() {
        anyhow::bail!("server_public_address is required for NaiveTCP connection");
    }

    let server_addr = resolve_server_address(&config.client.server_public_address, None).await?;
    let socket = match server_addr {
        SocketAddr::V4(_) => TcpSocket::new_v4()?,
        SocketAddr::V6(_) => TcpSocket::new_v6()?,
    };
    socket.bind(local_wildcard_bind_addr_for(server_addr))?;
    #[cfg(unix)]
    if let Some(protect) = &config.socket_protect {
        use std::os::unix::io::AsRawFd;
        if !protect.0(socket.as_raw_fd()) {
            anyhow::bail!("failed to protect NaiveTCP socket from VPN capture");
        }
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
    let server_address =
        resolve_server_address(&config.client.server_public_address, Some(bind_ip)).await?;
    let socket = match bind_ip {
        IpAddr::V4(_) => TcpSocket::new_v4()?,
        IpAddr::V6(_) => TcpSocket::new_v6()?,
    };
    socket.bind(SocketAddr::new(bind_ip, 0))?;
    #[cfg(unix)]
    if let Some(protect) = &config.socket_protect {
        use std::os::unix::io::AsRawFd;
        if !protect.0(socket.as_raw_fd()) {
            anyhow::bail!("failed to protect bind-aware NaiveTCP socket from VPN capture");
        }
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
            format!("ws://{websocket_address}")
        };

    let mut transport = WebSocketTlsTransport::connect(&websocket_url).await?;
    perform_websocket_auth_handshake(&mut transport, &keypair, &config.client.invite_token).await?;
    Ok(transport)
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
    stream
        .write_all(format!("{}\n", hello).as_bytes())
        .await?;

    let challenge_line = read_line_from_stream(&mut stream).await?;

    let challenge: ServerChallenge = serde_json::from_str(challenge_line.trim_end())?;
    let signature_b64 = sign_auth_challenge(keypair, &challenge.challenge_b64)?;

    let proof = json!({
        "signature_b64": signature_b64,
    });
    stream
        .write_all(format!("{}\n", proof).as_bytes())
        .await?;

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
    let challenge: ServerChallenge = serde_json::from_str(challenge_line.trim_end())?;
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
    if !payload.supported_protocols.is_empty() {
        config.client.preferred_protocols = payload.supported_protocols;
    }
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
        let payload = r#"{
            "server_public_address": "bonded.example.com:8080",
            "invite_token": "token-abc",
            "server_public_key": "server-pub",
            "supported_protocols": ["naive_tcp", "wss"]
        }"#;

        super::apply_pairing_payload(&mut cfg, payload).expect("payload should apply");
        assert_eq!(cfg.client.server_public_address, "bonded.example.com:8080");
        assert_eq!(cfg.client.invite_token, "token-abc");
        assert_eq!(cfg.client.server_public_key, "server-pub");
        assert_eq!(cfg.client.preferred_protocols, vec!["naive_tcp", "wss"]);
    }
}
