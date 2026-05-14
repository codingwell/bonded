//! Client-side certificate-proof bootstrapping.
//!
//! Flow:
//! 1. Open a TLS connection with validation *disabled* (the cert may be
//!    self-signed — that is the whole point of this bootstrap).
//! 2. Capture the leaf certificate's DER bytes from the TLS handshake.
//! 3. Send `GET /v1/bootstrap/cert-proof HTTP/1.1` over the open TLS stream.
//! 4. Parse the JSON response `{cert_fingerprint, ed25519_signature}`.
//! 5. Verify the ed25519 signature over `cert_fingerprint` using the
//!    server's public key (already trusted from the QR pairing scan).
//! 6. Confirm the received cert's SHA-256 fingerprint matches the value in
//!    the response (detects transparent MITM relays).
//! 7. Return the `"sha256:<hex>"` fingerprint string.  The caller should
//!    persist this as `client.tls_cert_fingerprint` and use it to pin
//!    subsequent TLS connections.
//!
//! ## Pinning future connections
//!
//! Use [`make_pinned_tls_config`] to build a `rustls::ClientConfig` that
//! accepts a server cert if and only if its SHA-256 fingerprint matches the
//! pinned value.  Pass it to `tokio_tungstenite::client_async_tls_with_config`
//! as `Some(Connector::Rustls(...))`.

use std::sync::{Arc, Mutex};

use rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error as TlsError, SignatureScheme};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

// ── Public API ────────────────────────────────────────────────────────────────

/// Fetch the server's TLS cert fingerprint via the bootstrap cert-proof
/// endpoint, verify the ed25519 signature, and return the fingerprint.
///
/// `server_public_key_b64` must be the standard-base64 ed25519 public key
/// from the pairing QR — it is used to verify the signature in the response.
///
/// # Security
///
/// The initial TLS connection is made with certificate validation **disabled**.
/// An active MITM who presents its own cert will be detected in step 6 because
/// the fingerprint of the received cert will not match the signed fingerprint
/// in the response (which was signed by the real server's ed25519 key).
pub async fn fetch_and_verify_cert_proof(
    host: &str,
    port: u16,
    server_public_key_b64: &str,
) -> anyhow::Result<String> {
    let captured_cert: Arc<Mutex<Option<Vec<u8>>>> = Arc::new(Mutex::new(None));

    // Build a TLS config that skips normal cert validation but captures the
    // leaf cert bytes.
    let verifier = Arc::new(CapturingVerifier {
        captured: captured_cert.clone(),
    });
    let client_config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(client_config));

    // TCP connect
    let tcp = TcpStream::connect(format!("{host}:{port}")).await?;

    // TLS handshake (skips validation, captures cert)
    let server_name = ServerName::try_from(host.to_owned())
        .map_err(|_| anyhow::anyhow!("invalid TLS server name: {host}"))?;
    let mut tls = connector.connect(server_name, tcp).await?;

    // Plain HTTP GET over the insecure TLS channel
    let request = format!(
        "GET /v1/bootstrap/cert-proof HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
    );
    tls.write_all(request.as_bytes()).await?;
    tls.flush().await?;

    let mut raw = Vec::new();
    tls.read_to_end(&mut raw).await?;
    let response =
        std::str::from_utf8(&raw).map_err(|_| anyhow::anyhow!("non-UTF8 in cert-proof response"))?;

    // Extract JSON body (everything after the blank line that ends the headers)
    let body = response
        .split("\r\n\r\n")
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("no HTTP body in cert-proof response"))?;

    // Parse status line
    let status_line = response.lines().next().unwrap_or("");
    if !status_line.contains("200") {
        anyhow::bail!(
            "cert-proof endpoint returned non-200 status: {status_line} (body: {body})"
        );
    }

    let parsed: serde_json::Value = serde_json::from_str(body.trim())
        .map_err(|e| anyhow::anyhow!("invalid JSON in cert-proof response: {e}"))?;

    let fingerprint = parsed["cert_fingerprint"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("cert-proof response missing 'cert_fingerprint'"))?;
    let signature = parsed["ed25519_signature"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("cert-proof response missing 'ed25519_signature'"))?;

    // Verify ed25519 signature over the fingerprint string using the
    // server identity key (already trusted from QR scan).
    bonded_core::auth::verify_signature(
        server_public_key_b64,
        fingerprint.as_bytes(),
        signature,
    )
    .map_err(|e| anyhow::anyhow!("cert-proof signature verification failed: {e}"))?;

    // Verify that the cert we received matches the signed fingerprint.
    // This detects a transparent relay / MITM that forwarded the cert-proof
    // response without injecting its own cert.
    let captured = captured_cert
        .lock()
        .unwrap()
        .clone()
        .ok_or_else(|| anyhow::anyhow!("no server certificate was captured during TLS handshake"))?;

    let computed = compute_fingerprint(&captured);
    if computed != fingerprint {
        anyhow::bail!(
            "cert-proof fingerprint mismatch: server presented cert with fingerprint {computed} \
             but cert-proof response claimed {fingerprint}. This may indicate an active MITM."
        );
    }

    Ok(fingerprint.to_owned())
}

/// Build a `rustls::ClientConfig` that accepts server certs if and only if the
/// leaf cert's SHA-256 fingerprint matches `expected_fingerprint`
/// (`"sha256:<hex>"`).
///
/// Use with `Connector::Rustls(make_pinned_tls_config(...))` in
/// `tokio_tungstenite::client_async_tls_with_config`.
pub fn make_pinned_tls_config(expected_fingerprint: impl Into<String>) -> Arc<ClientConfig> {
    let verifier = Arc::new(PinnedCertVerifier {
        expected: expected_fingerprint.into(),
    });
    let config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    Arc::new(config)
}

/// Compute `"sha256:<lowercase hex>"` of the raw DER bytes of a certificate.
pub fn compute_fingerprint(der: &[u8]) -> String {
    let digest = Sha256::digest(der);
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    format!("sha256:{hex}")
}

// ── Dangerous cert verifiers ──────────────────────────────────────────────────

/// A `ServerCertVerifier` that skips all validation but captures the leaf cert.
#[derive(Debug)]
struct CapturingVerifier {
    captured: Arc<Mutex<Option<Vec<u8>>>>,
}

impl ServerCertVerifier for CapturingVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        *self.captured.lock().unwrap() = Some(end_entity.as_ref().to_vec());
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::ED448,
        ]
    }
}

/// A `ServerCertVerifier` that accepts a server cert only if its SHA-256
/// fingerprint matches the pinned value.
#[derive(Debug)]
struct PinnedCertVerifier {
    expected: String,
}

impl ServerCertVerifier for PinnedCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        let actual = compute_fingerprint(end_entity.as_ref());
        if actual == self.expected {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(TlsError::General(format!(
                "TLS certificate fingerprint mismatch: got {actual}, expected {}",
                self.expected
            )))
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::ED448,
        ]
    }
}
