//! QUIC (HTTP/3) server endpoint.
//!
//! Runs a `quinn::Endpoint` bound to the same address as the WebSocket TLS
//! server (or a configurable separate address) and accepts inbound QUIC
//! connections.  For each connection it accepts the first bidirectional stream
//! and treats it as a [`QuicTransport`] session, running the same auth
//! handshake as the WebSocket path.
//!
//! ## TLS sharing
//!
//! The QUIC endpoint reuses the same TLS certificate and private key as the
//! bootstrap WebSocket listener so clients can use the same pinned fingerprint
//! for both WSS and QUIC connections.
//!
//! ## Design constraints
//! - QUIC runs over UDP; sockets must be "protected" on Android before use.
//! - Only one bidirectional stream per connection is accepted; multiplexing is
//!   a Phase 7 concern.
//! - Authentication uses the same challenge-response handshake as WSS.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};

use anyhow::Context as _;
use bonded_core::session::{SessionFrame, SessionHeader, FLAG_PING, FLAG_PONG};
use bonded_core::transport::{QuicTransport, Transport as _};
use quinn::{Endpoint, ServerConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::auth_handshake::perform_quic_auth_handshake;
use crate::authorized_keys::AuthorizedKeysStore;
use crate::session_registry::SessionRegistry;
use crate::smoltcp_forwarder::SmoltcpForwarder;

/// Maximum frames to drain from the forwarder response queue per scheduler turn.
const MAX_DRAIN: usize = 256;

type ForwarderRegistry = Arc<RwLock<HashMap<u64, Arc<SmoltcpForwarder>>>>;

/// Build a QUIC `ServerConfig` from DER-encoded certificate and private key
/// bytes (both in DER / PKCS#8 format).  Called by `main.rs` when it has
/// already loaded a TLS cert for the bootstrap server.
pub fn build_quic_server_config(
    cert_der: Vec<u8>,
    key_der: Vec<u8>,
) -> anyhow::Result<ServerConfig> {
    let cert = CertificateDer::from(cert_der);
    let key = PrivateKeyDer::try_from(key_der)
        .map_err(|e| anyhow::anyhow!("invalid QUIC private key DER: {e}"))?;

    let tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .context("failed to build QUIC TLS config")?;

    let mut server_config = ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(tls_config)
            .context("failed to build QUIC server crypto config")?,
    ));

    // Allow some concurrent bidirectional streams per connection.
    let mut transport = quinn::TransportConfig::default();
    transport.max_concurrent_bidi_streams(4u32.into());
    server_config.transport_config(Arc::new(transport));

    Ok(server_config)
}

/// Start the QUIC endpoint and accept sessions until the endpoint is closed.
pub async fn run_quic_server(
    bind: &str,
    cert_der: Vec<u8>,
    key_der: Vec<u8>,
    invite_tokens_file: String,
    authorized_keys: AuthorizedKeysStore,
    sessions: SessionRegistry,
    forwarders: ForwarderRegistry,
) -> anyhow::Result<()> {
    let server_config = build_quic_server_config(cert_der, key_der)?;

    let addr: SocketAddr = bind
        .parse()
        .with_context(|| format!("invalid QUIC bind address: {bind}"))?;

    let endpoint = Endpoint::server(server_config, addr)
        .with_context(|| format!("failed to bind QUIC endpoint on {bind}"))?;

    info!(bind = %bind, "QUIC endpoint bound");

    loop {
        let incoming = match endpoint.accept().await {
            Some(inc) => inc,
            None => {
                info!("QUIC endpoint closed");
                break;
            }
        };

        let invite_tokens_file = invite_tokens_file.clone();
        let authorized_keys = authorized_keys.clone();
        let sessions = sessions.clone();
        let forwarders = forwarders.clone();

        tokio::spawn(async move {
            let remote = incoming.remote_address();
            match incoming.await {
                Err(err) => {
                    warn!(peer = %remote, error = %err, "QUIC handshake failed");
                }
                Ok(connection) => {
                    let result = handle_quic_connection(
                        connection,
                        &invite_tokens_file,
                        authorized_keys,
                        sessions,
                        forwarders,
                    )
                    .await;
                    if let Err(err) = result {
                        warn!(peer = %remote, error = %err, "QUIC session error");
                    }
                }
            }
        });
    }

    Ok(())
}

async fn handle_quic_connection(
    connection: quinn::Connection,
    invite_tokens_file: &str,
    authorized_keys: AuthorizedKeysStore,
    sessions: SessionRegistry,
    forwarders: ForwarderRegistry,
) -> anyhow::Result<()> {
    let peer = connection.remote_address();
    info!(peer = %peer, "QUIC connection established");

    let mut transport = QuicTransport::from_server_connection(connection).await?;

    let public_key = match perform_quic_auth_handshake(
        &mut transport,
        invite_tokens_file,
        &authorized_keys,
    )
    .await
    {
        Ok(pk) => pk,
        Err(err) => {
            warn!(peer = %peer, error = %err, "QUIC client authentication failed");
            return Ok(());
        }
    };

    let handle = sessions.register_client(public_key.clone());
    info!(
        peer = %peer,
        public_key = %public_key,
        session_id = handle.session_id,
        "QUIC client authenticated"
    );

    let (forward_tx, mut forward_rx) = mpsc::unbounded_channel::<SessionFrame>();
    let forwarder = Arc::new(SmoltcpForwarder::new(handle.session_id, forward_tx));

    forwarders
        .write()
        .expect("forwarder registry lock should not be poisoned")
        .insert(handle.session_id, forwarder.clone());

    'session: loop {
        // Drain queued response frames before blocking.
        for _ in 0..MAX_DRAIN {
            let frame = match forward_rx.try_recv() {
                Ok(f) => f,
                Err(_) => break,
            };
            if let Err(err) = transport.send(frame).await {
                warn!(peer = %peer, session_id = handle.session_id, error = %err,
                    "QUIC: failed to send drained response frame");
                break 'session;
            }
        }

        tokio::select! {
            maybe_frame = forward_rx.recv() => {
                let Some(frame) = maybe_frame else {
                    warn!(peer = %peer, session_id = handle.session_id,
                        "QUIC: forwarder response queue closed");
                    break;
                };
                if let Err(err) = transport.send(frame).await {
                    warn!(peer = %peer, session_id = handle.session_id, error = %err,
                        "QUIC: failed to send response frame");
                    break;
                }
            }
            recv_result = transport.recv() => {
                match recv_result {
                    Ok(frame) => {
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
                                warn!(peer = %peer, session_id = handle.session_id,
                                    error = %err, "QUIC: failed to send heartbeat pong");
                                break;
                            }
                            continue;
                        }
                        forwarder.ingest_packet(frame);
                    }
                    Err(err) => {
                        info!(peer = %peer, public_key = %public_key,
                            session_id = handle.session_id, error = ?err,
                            "QUIC client session ended");
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
