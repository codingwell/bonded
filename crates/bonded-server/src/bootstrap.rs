//! Bootstrap server: a single TCP listener that serves both the bootstrap REST
//! API (e.g. `GET /v1/bootstrap/cert-proof`) and WebSocket session upgrades on
//! the same port and TLS configuration.
//!
//! Flow for each inbound connection:
//! 1. Optionally terminate TLS with the configured acceptor.
//! 2. Read the HTTP request line and headers (up to `\r\n\r\n`).
//! 3. If the request carries an `Upgrade: websocket` header, replay the
//!    buffered bytes via a [`PrependedStream`] and hand off to the WebSocket
//!    session path.
//! 4. Otherwise, route by URL path to the appropriate REST handler.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};

use anyhow::Context as _;
use bonded_core::auth::{sign_bytes, DeviceKeypair};
use bonded_core::session::{SessionFrame, SessionHeader, FLAG_PING, FLAG_PONG};
use bonded_core::transport::{PrependedStream, Transport, WebSocketTlsTransport};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_rustls::{server::TlsStream as ServerTlsStream, TlsAcceptor};
use tracing::{error, info, warn};

use crate::auth_handshake::perform_websocket_auth_handshake;
use crate::authorized_keys::AuthorizedKeysStore;
use crate::session_registry::SessionRegistry;
use crate::smoltcp_forwarder::SmoltcpForwarder;
use crate::tunnel_pcap::TunnelPcapLogger;

/// Maximum bytes to read while searching for the end of HTTP request headers.
const MAX_HEADER_BYTES: usize = 16 * 1024;

/// Maximum frames to drain from the forwarder response queue per scheduler turn.
const MAX_DRAIN: usize = 256;

type ForwarderRegistry = Arc<RwLock<HashMap<u64, Arc<SmoltcpForwarder>>>>;

// ── Bootstrap context ─────────────────────────────────────────────────────────

/// Shared context injected into every connection handler.
pub struct BootstrapContext {
    /// Stable server identity key.  Signs the TLS cert fingerprint for the
    /// cert-proof endpoint so clients can trust a self-signed TLS cert using
    /// the already-trusted QR-provisioned ed25519 key.
    pub server_identity: Arc<DeviceKeypair>,

    /// DER bytes of the leaf TLS certificate.  `None` when TLS is not
    /// configured — the cert-proof endpoint returns `501 Not Implemented` in
    /// that case since there is no cert to prove.
    pub tls_cert_der: Option<Arc<Vec<u8>>>,

    /// Public HTTPS/WSS endpoint (`hostname:port`), reported in capabilities.
    pub server_public_address: String,

    /// Server WireGuard keypair.  `Some` when the WireGuard endpoint is active.
    pub wireguard_keypair: Option<Arc<bonded_core::transport::WireGuardKeypair>>,

    /// WireGuard peer registry.  Populated via `POST /v1/bootstrap/wireguard/peer`.
    pub wireguard_peers: Option<Arc<crate::wireguard::WireGuardPeerRegistry>>,

    /// Public WireGuard endpoint (`hostname:port`), or `None` when WireGuard
    /// is not enabled.  Reported in capabilities alongside the provisioning URL.
    pub wireguard_public_addr: Option<String>,
}

impl BootstrapContext {
    /// QUIC is available whenever a TLS certificate is configured.
    pub fn quic_enabled(&self) -> bool {
        self.tls_cert_der.is_some()
    }

    /// WireGuard is available whenever a keypair is present.
    pub fn wireguard_enabled(&self) -> bool {
        self.wireguard_keypair.is_some()
    }

    /// Compute the SHA-256 fingerprint of the TLS cert and return an ed25519
    /// signature over the string `"sha256:<hex>"` using the server identity key.
    /// Returns `None` when no TLS cert is configured.
    pub fn cert_proof(&self) -> Option<anyhow::Result<(String, String)>> {
        let der = self.tls_cert_der.as_ref()?;
        let digest = Sha256::digest(der.as_slice());
        let hex_str: String = digest.iter().map(|b| format!("{b:02x}")).collect();
        let fingerprint = format!("sha256:{hex_str}");
        let sig = sign_bytes(&self.server_identity, fingerprint.as_bytes());
        Some(sig.map(|s| (fingerprint, s)).map_err(anyhow::Error::from))
    }
}

// ── Public entry point ────────────────────────────────────────────────────────

pub async fn run_bootstrap_websocket_server(
    bind: &str,
    invite_tokens_file: &str,
    authorized_keys: AuthorizedKeysStore,
    sessions: SessionRegistry,
    forwarders: ForwarderRegistry,
    tls_acceptor: Option<TlsAcceptor>,
    tunnel_pcap: Option<Arc<TunnelPcapLogger>>,
    ctx: Arc<BootstrapContext>,
) -> anyhow::Result<()> {
    let listener = tokio::net::TcpListener::bind(bind)
        .await
        .with_context(|| format!("failed to bind bootstrap listener on {bind}"))?;
    info!(bind = %bind, tls = tls_acceptor.is_some(), "bootstrap listener bound");

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(err) => {
                error!(error = %err, "failed to accept bootstrap connection");
                continue;
            }
        };

        let ctx = ctx.clone();
        let tls_acceptor = tls_acceptor.clone();
        let invite_tokens_file = invite_tokens_file.to_owned();
        let authorized_keys = authorized_keys.clone();
        let sessions = sessions.clone();
        let forwarders = forwarders.clone();
        let tunnel_pcap = tunnel_pcap.clone();

        tokio::spawn(async move {
            let result = if let Some(acceptor) = tls_acceptor {
                match acceptor.accept(stream).await {
                    Ok(tls_stream) => {
                        handle_tls_stream(
                            tls_stream,
                            peer,
                            &ctx,
                            &invite_tokens_file,
                            authorized_keys,
                            sessions,
                            forwarders,
                            tunnel_pcap,
                        )
                        .await
                    }
                    Err(err) => Err(anyhow::anyhow!("TLS handshake with {peer} failed: {err}")),
                }
            } else {
                handle_plain_connection(
                    stream,
                    peer,
                    &ctx,
                    &invite_tokens_file,
                    authorized_keys,
                    sessions,
                    forwarders,
                    tunnel_pcap,
                )
                .await
            };

            if let Err(err) = result {
                warn!(peer = %peer, error = %err, "bootstrap connection error");
            }
        });
    }
}

// ── Per-connection dispatch ───────────────────────────────────────────────────

async fn handle_tls_stream(
    tls_stream: ServerTlsStream<TcpStream>,
    peer: SocketAddr,
    ctx: &BootstrapContext,
    invite_tokens_file: &str,
    authorized_keys: AuthorizedKeysStore,
    sessions: SessionRegistry,
    forwarders: ForwarderRegistry,
    tunnel_pcap: Option<Arc<TunnelPcapLogger>>,
) -> anyhow::Result<()> {
    let (request_bytes, is_ws, tls_stream) = read_http_headers_tls(tls_stream).await?;

    if is_ws {
        let prepended = PrependedStream::new(request_bytes, tls_stream);
        let transport = WebSocketTlsTransport::from_routed_tls(prepended)
            .await
            .context("websocket upgrade failed on TLS stream")?;
        handle_websocket_session(
            transport,
            peer,
            invite_tokens_file,
            authorized_keys,
            sessions,
            forwarders,
            tunnel_pcap,
        )
        .await
    } else {
        let (method, path, body) = parse_request_parts(&request_bytes);
        handle_rest_request(path, method, body, ctx, tls_stream).await
    }
}

async fn handle_plain_connection(
    stream: TcpStream,
    peer: SocketAddr,
    ctx: &BootstrapContext,
    invite_tokens_file: &str,
    authorized_keys: AuthorizedKeysStore,
    sessions: SessionRegistry,
    forwarders: ForwarderRegistry,
    tunnel_pcap: Option<Arc<TunnelPcapLogger>>,
) -> anyhow::Result<()> {
    let (request_bytes, is_ws, stream) = read_http_headers_plain(stream).await?;

    if is_ws {
        let prepended = PrependedStream::new(request_bytes, stream);
        let transport = WebSocketTlsTransport::from_routed_plain(prepended)
            .await
            .context("websocket upgrade failed on plain stream")?;
        handle_websocket_session(
            transport,
            peer,
            invite_tokens_file,
            authorized_keys,
            sessions,
            forwarders,
            tunnel_pcap,
        )
        .await
    } else {
        let (method, path, body) = parse_request_parts(&request_bytes);
        handle_rest_request(path, method, body, ctx, stream).await
    }
}

// ── HTTP header reading ───────────────────────────────────────────────────────

async fn read_http_headers_tls(
    mut stream: ServerTlsStream<TcpStream>,
) -> anyhow::Result<(Vec<u8>, bool, ServerTlsStream<TcpStream>)> {
    let (buf, is_ws) = read_until_end_of_headers(&mut stream).await?;
    Ok((buf, is_ws, stream))
}

async fn read_http_headers_plain(
    mut stream: TcpStream,
) -> anyhow::Result<(Vec<u8>, bool, TcpStream)> {
    let (buf, is_ws) = read_until_end_of_headers(&mut stream).await?;
    Ok((buf, is_ws, stream))
}

/// Read bytes until the HTTP header terminator `\r\n\r\n` is found or
/// `MAX_HEADER_BYTES` is consumed.  Returns `(bytes_read, is_websocket_upgrade)`.
async fn read_until_end_of_headers<S: AsyncReadExt + Unpin>(
    stream: &mut S,
) -> anyhow::Result<(Vec<u8>, bool)> {
    let mut buf = Vec::with_capacity(512);
    let mut tmp = [0u8; 256];

    loop {
        if buf.len() >= MAX_HEADER_BYTES {
            anyhow::bail!("HTTP request headers exceeded {MAX_HEADER_BYTES} bytes");
        }
        let n = stream
            .read(&mut tmp)
            .await
            .context("error reading HTTP request headers")?;
        if n == 0 {
            anyhow::bail!("connection closed before HTTP request headers were complete");
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }

    let is_ws = is_websocket_upgrade(&buf);
    Ok((buf, is_ws))
}

/// Return `true` if the buffered request contains an `Upgrade: websocket` header.
fn is_websocket_upgrade(headers: &[u8]) -> bool {
    let text = std::str::from_utf8(headers).unwrap_or("");
    text.lines().any(|line| {
        let lower = line.to_ascii_lowercase();
        lower.starts_with("upgrade:") && lower.contains("websocket")
    })
}

/// Parse the HTTP method, path, and request body from the raw request bytes.
///
/// The body is the text after the `\r\n\r\n` header separator.
fn parse_request_parts(headers: &[u8]) -> (&str, &str, &str) {
    let text = std::str::from_utf8(headers).unwrap_or("");
    let first_line = text.lines().next().unwrap_or("");
    let mut parts = first_line.splitn(3, ' ');
    let method = parts.next().unwrap_or("GET");
    let path = parts.next().unwrap_or("/");

    // Find the body (after \r\n\r\n).
    let body = if let Some(idx) = text.find("\r\n\r\n") {
        &text[idx + 4..]
    } else {
        ""
    };
    (method, path, body)
}

// ── REST routing ─────────────────────────────────────────────────────────────

async fn handle_rest_request<S: AsyncWriteExt + Unpin>(
    path: &str,
    method: &str,
    body: &str,
    ctx: &BootstrapContext,
    mut stream: S,
) -> anyhow::Result<()> {
    let path_no_query = path.split('?').next().unwrap_or(path);
    let (status, body_resp) = match (method, path_no_query) {
        (_, "/v1/bootstrap/cert-proof") => cert_proof_response(ctx),
        (_, "/v1/bootstrap/capabilities") => capabilities_response(ctx),
        ("POST", "/v1/bootstrap/wireguard/peer") => wireguard_peer_response(ctx, body),
        _ => ("404 Not Found", r#"{"error":"not found"}"#.to_owned()),
    };

    let response = format!(
        "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body_resp}",
        body_resp.len()
    );
    stream.write_all(response.as_bytes()).await?;
    stream.flush().await?;
    Ok(())
}

fn cert_proof_response(ctx: &BootstrapContext) -> (&'static str, String) {
    match ctx.cert_proof() {
        None => (
            "501 Not Implemented",
            r#"{"error":"TLS not configured on this server; cert-proof requires TLS"}"#.to_owned(),
        ),
        Some(Err(err)) => {
            error!(error = %err, "failed to generate cert-proof signature");
            (
                "500 Internal Server Error",
                r#"{"error":"failed to generate cert proof"}"#.to_owned(),
            )
        }
        Some(Ok((fingerprint, signature))) => {
            let body = serde_json::json!({
                "cert_fingerprint": fingerprint,
                "ed25519_signature": signature,
            })
            .to_string();
            ("200 OK", body)
        }
    }
}

/// `GET /v1/bootstrap/capabilities`
///
/// Returns a JSON object describing which transport endpoints the server
/// currently offers.  Clients should call this after cert-proof to decide
/// which protocols to dial.
///
/// Example response when only WSS is active:
/// ```json
/// {
///   "transports": ["wss"],
///   "wss": { "endpoint": "1.2.3.4:8443" }
/// }
/// ```
fn capabilities_response(ctx: &BootstrapContext) -> (&'static str, String) {
    let mut transports: Vec<&str> = vec!["wss"];
    let mut obj = serde_json::json!({
        "wss": {
            "endpoint": ctx.server_public_address,
        }
    });

    if ctx.quic_enabled() {
        transports.push("h3");
        obj["h3"] = serde_json::json!({
            "endpoint": ctx.server_public_address,
        });
    }

    if ctx.wireguard_enabled() {
        transports.push("wireguard");
        let wg_endpoint = ctx
            .wireguard_public_addr
            .as_deref()
            .unwrap_or(&ctx.server_public_address);
        let provision_url = format!(
            "https://{}/v1/bootstrap/wireguard/peer",
            ctx.server_public_address
        );
        let server_wg_pubkey = ctx
            .wireguard_keypair
            .as_ref()
            .map(|kp| kp.public_key_b64())
            .unwrap_or_default();
        obj["wireguard"] = serde_json::json!({
            "endpoint": wg_endpoint,
            "provision_endpoint": provision_url,
            "server_public_key": server_wg_pubkey,
        });
    }

    obj["transports"] = serde_json::json!(transports);
    ("200 OK", obj.to_string())
}

/// `POST /v1/bootstrap/wireguard/peer`
///
/// Request body (JSON):
/// ```json
/// {
///   "device_public_key": "<ed25519 key b64>",
///   "wg_public_key": "<x25519 key b64>"
/// }
/// ```
///
/// Response (JSON):
/// ```json
/// {
///   "server_wg_public_key": "...",
///   "peer_ip": "100.64.1.x/32"
/// }
/// ```
fn wireguard_peer_response(ctx: &BootstrapContext, body: &str) -> (&'static str, String) {
    let (Some(kp), Some(peers)) = (ctx.wireguard_keypair.as_ref(), ctx.wireguard_peers.as_ref())
    else {
        return (
            "501 Not Implemented",
            r#"{"error":"WireGuard is not enabled on this server"}"#.to_owned(),
        );
    };

    let req: serde_json::Value = match serde_json::from_str(body.trim()) {
        Ok(v) => v,
        Err(_) => {
            return (
                "400 Bad Request",
                r#"{"error":"invalid JSON body"}"#.to_owned(),
            )
        }
    };
    let device_pk = req
        .get("device_public_key")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let wg_pk = req
        .get("wg_public_key")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if device_pk.is_empty() || wg_pk.is_empty() {
        return (
            "400 Bad Request",
            r#"{"error":"device_public_key and wg_public_key are required"}"#.to_owned(),
        );
    }

    let peer_ip = peers.register_peer(device_pk, wg_pk);
    let body = serde_json::json!({
        "server_wg_public_key": kp.public_key_b64(),
        "peer_ip": peer_ip,
    })
    .to_string();
    ("200 OK", body)
}

async fn handle_websocket_session(
    mut transport: WebSocketTlsTransport,
    peer: SocketAddr,
    invite_tokens_file: &str,
    authorized_keys: AuthorizedKeysStore,
    sessions: SessionRegistry,
    forwarders: ForwarderRegistry,
    tunnel_pcap: Option<Arc<TunnelPcapLogger>>,
) -> anyhow::Result<()> {
    let public_key = match perform_websocket_auth_handshake(
        &mut transport,
        authorized_keys,
        std::path::Path::new(invite_tokens_file),
    )
    .await
    {
        Ok(pk) => pk,
        Err(err) => {
            warn!(peer = %peer, error = %err, "websocket client authentication failed");
            return Ok(());
        }
    };

    let handle = sessions.register_client(public_key.clone());
    info!(
        peer = %peer,
        public_key = %public_key,
        session_id = handle.session_id,
        "websocket client authenticated via bootstrap listener"
    );

    let (forward_tx, mut forward_rx) = mpsc::unbounded_channel::<SessionFrame>();
    let forwarder = Arc::new(SmoltcpForwarder::new(handle.session_id, forward_tx));

    forwarders
        .write()
        .expect("forwarder registry lock should not be poisoned")
        .insert(handle.session_id, forwarder.clone());

    loop {
        // Drain queued response frames before blocking in select! to avoid
        // serialising bursty traffic to one frame per scheduler turn.
        for _ in 0..MAX_DRAIN {
            let frame = match forward_rx.try_recv() {
                Ok(f) => f,
                Err(_) => break,
            };
            log_tunnel_packet(&tunnel_pcap, &frame.payload);
            if let Err(err) = transport.send(frame).await {
                warn!(peer = %peer, session_id = handle.session_id, error = %err,
                    "failed to return drained websocket frame");
                break;
            }
        }

        tokio::select! {
            maybe_frame = forward_rx.recv() => {
                let Some(frame) = maybe_frame else {
                    warn!(peer = %peer, session_id = handle.session_id,
                        "websocket forwarder response queue closed");
                    break;
                };
                log_tunnel_packet(&tunnel_pcap, &frame.payload);
                if let Err(err) = transport.send(frame).await {
                    warn!(peer = %peer, session_id = handle.session_id, error = %err,
                        "failed to send websocket frame");
                    break;
                }
            }
            recv_result = transport.recv() => {
                match recv_result {
                    Ok(frame) => {
                        log_tunnel_packet(&tunnel_pcap, &frame.payload);
                        if frame.header.flags & FLAG_PING != 0 && frame.payload.is_empty() {
                            let pong = SessionFrame {
                                header: SessionHeader {
                                    connection_id: frame.header.connection_id,
                                    sequence: frame.header.sequence,
                                    flags: FLAG_PONG,
                                },
                                payload: frame.payload,
                            };
                            if let Err(err) = transport.send(pong).await {
                                warn!(peer = %peer, session_id = handle.session_id, error = %err,
                                    "failed to send heartbeat pong");
                                break;
                            }
                            continue;
                        }
                        forwarder.ingest_packet(frame);
                    }
                    Err(err) => {
                        info!(peer = %peer, public_key = %public_key,
                            session_id = handle.session_id, error = ?err,
                            "websocket client session ended");
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
    Ok(())
}

#[inline]
fn log_tunnel_packet(pcap: &Option<Arc<TunnelPcapLogger>>, payload: &bytes::Bytes) {
    if payload.is_empty() {
        return;
    }
    if let Some(logger) = pcap {
        logger.log_packet(payload);
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use bonded_core::auth::DeviceKeypair;
    use std::collections::HashMap;
    use std::sync::{Arc, RwLock};

    /// Build a minimal `BootstrapContext` suitable for testing.
    /// No TLS cert is configured, so cert-proof returns 501.
    fn test_ctx() -> Arc<BootstrapContext> {
        Arc::new(BootstrapContext {
            server_identity: Arc::new(DeviceKeypair::generate()),
            tls_cert_der: None,
            server_public_address: "127.0.0.1:8443".to_owned(),
            wireguard_keypair: None,
            wireguard_peers: None,
            wireguard_public_addr: None,
        })
    }

    /// Start a plain-TCP bootstrap server on an ephemeral port and return the
    /// bound address.  The server task is spawned as a background task and
    /// will be dropped (and therefore stop accepting) when the returned
    /// `tokio::task::JoinHandle` is dropped.
    async fn start_plain_server() -> (SocketAddr, tokio::task::JoinHandle<()>) {
        use crate::authorized_keys::AuthorizedKeysStore;
        use crate::session_registry::SessionRegistry;

        let ctx = test_ctx();
        let _authorized_keys = AuthorizedKeysStore::default();
        let _sessions = SessionRegistry::default();
        let _forwarders: ForwarderRegistry = Arc::new(RwLock::new(HashMap::new()));

        // Bind to an ephemeral port.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind ephemeral port");
        let addr = listener.local_addr().expect("local addr");

        let handle = tokio::spawn(async move {
            // Re-use the private `run_bootstrap_websocket_server` logic by
            // directly calling `handle_connection` for each accepted connection.
            loop {
                match listener.accept().await {
                    Ok((stream, peer)) => {
                        let ctx_inner = ctx.clone();
                        tokio::spawn(async move {
                            // No TLS — go straight to plain HTTP routing.
                            let result = handle_plain_connection(
                                stream,
                                peer,
                                &ctx_inner,
                                "unused-invites.toml",
                                AuthorizedKeysStore::default(),
                                SessionRegistry::default(),
                                Arc::new(RwLock::new(HashMap::new())),
                                None,
                            )
                            .await;
                            if let Err(e) = result {
                                eprintln!("[test] connection error: {e}");
                            }
                        });
                    }
                    Err(_) => break,
                }
            }
        });

        (addr, handle)
    }

    /// Send a raw HTTP/1.1 GET to the given address and return the full response.
    async fn http_get(addr: SocketAddr, path: &str) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut stream = tokio::net::TcpStream::connect(addr)
            .await
            .expect("connect to test server");
        let request =
            format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
        stream
            .write_all(request.as_bytes())
            .await
            .expect("send request");
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.expect("read response");
        String::from_utf8_lossy(&buf).into_owned()
    }

    #[tokio::test]
    async fn cert_proof_returns_501_when_no_tls() {
        let (addr, _handle) = start_plain_server().await;
        let response = http_get(addr, "/v1/bootstrap/cert-proof").await;
        assert!(
            response.starts_with("HTTP/1.1 501"),
            "expected 501, got: {response}"
        );
        assert!(response.contains("TLS not configured"));
    }

    #[tokio::test]
    async fn capabilities_returns_wss_transport() {
        let (addr, _handle) = start_plain_server().await;
        let response = http_get(addr, "/v1/bootstrap/capabilities").await;
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "expected 200, got: {response}"
        );
        let body = response.split("\r\n\r\n").nth(1).unwrap_or("");
        let json: serde_json::Value = serde_json::from_str(body.trim()).expect("valid JSON body");
        let transports = json["transports"].as_array().expect("transports array");
        assert!(
            transports.iter().any(|t| t.as_str() == Some("wss")),
            "expected 'wss' in transports: {transports:?}"
        );
        assert_eq!(
            json["wss"]["endpoint"].as_str(),
            Some("127.0.0.1:8443"),
            "unexpected wss endpoint"
        );
    }

    #[tokio::test]
    async fn unknown_path_returns_404() {
        let (addr, _handle) = start_plain_server().await;
        let response = http_get(addr, "/v1/no-such-endpoint").await;
        assert!(
            response.starts_with("HTTP/1.1 404"),
            "expected 404, got: {response}"
        );
    }

    #[tokio::test]
    async fn capabilities_includes_h3_when_quic_enabled() {
        use crate::authorized_keys::AuthorizedKeysStore;
        use crate::session_registry::SessionRegistry;

        // tls_cert_der being Some triggers quic_enabled() = true.
        let ctx = Arc::new(BootstrapContext {
            server_identity: Arc::new(DeviceKeypair::generate()),
            tls_cert_der: Some(Arc::new(vec![0u8; 32])), // non-empty → QUIC on
            server_public_address: "10.0.0.1:9443".to_owned(),
            wireguard_keypair: None,
            wireguard_peers: None,
            wireguard_public_addr: None,
        });

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("local addr");

        let _handle = tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, peer)) => {
                        let ctx_inner = ctx.clone();
                        tokio::spawn(async move {
                            let _ = handle_plain_connection(
                                stream,
                                peer,
                                &ctx_inner,
                                "unused.toml",
                                AuthorizedKeysStore::default(),
                                SessionRegistry::default(),
                                Arc::new(RwLock::new(HashMap::new())),
                                None,
                            )
                            .await;
                        });
                    }
                    Err(_) => break,
                }
            }
        });

        let response = http_get(addr, "/v1/bootstrap/capabilities").await;
        let body = response.split("\r\n\r\n").nth(1).unwrap_or("");
        let json: serde_json::Value = serde_json::from_str(body.trim()).expect("valid JSON");
        let transports = json["transports"].as_array().expect("transports array");
        assert!(
            transports.iter().any(|t| t.as_str() == Some("h3")),
            "expected 'h3' in transports when tls_cert_der is Some: {transports:?}"
        );
        // wireguard_keypair is None, so WireGuard should NOT appear
        assert!(
            !transports.iter().any(|t| t.as_str() == Some("wireguard")),
            "expected no 'wireguard' in transports when wireguard_keypair is None: {transports:?}"
        );
    }
}
