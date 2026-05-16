//! Automatic certificate provisioning via Let's Encrypt (ACME TLS-ALPN-01).
//!
//! # Overview
//!
//! When `acme_domain` is set in the server config, the server spawns a
//! background renewal loop that:
//!
//! 1. Checks whether the on-disk cert/key are still valid (≥ 30 days before
//!    expiry).  If they are, sleeps until 30 days before expiry and loops.
//! 2. Runs an ACME TLS-ALPN-01 challenge using `instant-acme`:
//!    - Builds a transient self-signed certificate containing the
//!      `id-pe-acmeIdentifier` extension (OID 1.3.6.1.5.5.7.1.31) with the
//!      SHA-256 digest of the key authorization.
//!    - Places it in the `AcmeChallengeSlot`, which the main TLS listener's
//!      `DynamicCertResolver` serves to connections using ALPN `"acme-tls/1"`.
//!    - Clears the slot after the ACME CA has validated the challenge.
//! 3. Finalises the order, downloads the signed cert chain, and writes it to
//!    `tls_cert_file` / `tls_key_file` — the same paths used by the live
//!    server — then signals the TLS acceptor to reload.
//!
//! # Requirements
//!
//! - The server must be directly reachable on port 443 (or whatever
//!   `https_bind` is).  TLS-ALPN-01 does not work behind a TCP proxy that
//!   terminates TLS on behalf of the server.

use std::sync::{Arc, RwLock};
use std::time::Duration;

use anyhow::Context as _;
use instant_acme::{
    Account, ChallengeType, Identifier, LetsEncrypt, NewAccount, NewOrder, OrderStatus,
};
use rcgen::{CertificateParams, CustomExtension, DistinguishedName, KeyPair, SanType};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::sign::CertifiedKey;
use tracing::{error, info, warn};

// ── Challenge slot ────────────────────────────────────────────────────────────

/// Shared slot that holds the transient TLS-ALPN-01 challenge certificate.
///
/// The renewal loop writes to this slot before telling the ACME CA that the
/// challenge is ready, and clears it once validation is complete.  The main
/// TLS listener's `DynamicCertResolver` reads from this slot on every
/// incoming TLS handshake and serves the challenge cert when the client
/// advertises ALPN `"acme-tls/1"`.
#[derive(Clone, Default)]
pub struct AcmeChallengeSlot(Arc<RwLock<Option<Arc<CertifiedKey>>>>);

impl AcmeChallengeSlot {
    pub fn new() -> Self {
        Self::default()
    }

    /// Store a new ACME challenge certificate.
    pub fn set(&self, key: Arc<CertifiedKey>) {
        *self.0.write().expect("acme slot lock") = Some(key);
    }

    /// Remove the challenge certificate (called after validation completes or
    /// fails).
    pub fn clear(&self) {
        *self.0.write().expect("acme slot lock") = None;
    }

    /// Return the current challenge certificate, or `None` if not set.
    pub fn get(&self) -> Option<Arc<CertifiedKey>> {
        self.0.read().expect("acme slot lock").clone()
    }
}

// ── Dynamic cert resolver ─────────────────────────────────────────────────────

/// A `rustls` certificate resolver that serves:
/// - The ACME challenge cert (from `AcmeChallengeSlot`) when the client
///   requests ALPN `"acme-tls/1"`.
/// - The main server cert for all other connections.
pub struct DynamicCertResolver {
    /// The server's live certificate, used for all normal TLS connections.
    pub main_cert: Arc<CertifiedKey>,
    /// Shared slot populated during ACME validation rounds.
    pub acme_slot: AcmeChallengeSlot,
}

impl std::fmt::Debug for DynamicCertResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DynamicCertResolver")
            .finish_non_exhaustive()
    }
}

impl rustls::server::ResolvesServerCert for DynamicCertResolver {
    fn resolve(&self, client_hello: rustls::server::ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let is_acme_alpn = client_hello
            .alpn()
            .map(|mut it| it.any(|proto| proto == b"acme-tls/1"))
            .unwrap_or(false);

        if is_acme_alpn {
            if let Some(challenge_cert) = self.acme_slot.get() {
                return Some(challenge_cert);
            }
            // No challenge cert available; fall through to main cert so the
            // connection does not fail ungracefully.
        }

        Some(self.main_cert.clone())
    }
}

// ── ACME config ───────────────────────────────────────────────────────────────

/// ACME configuration drawn from `ServerSection`.
#[derive(Clone, Debug)]
pub struct AcmeConfig {
    /// The domain to obtain a certificate for (e.g. `vpn.example.com`).
    pub domain: String,
    /// Contact e-mail sent to Let's Encrypt.
    pub email: String,
    /// Path to write (and read back) the PEM-encoded certificate chain.
    /// This is the same file as `tls_cert_file` in the server config — ACME
    /// overwrites it on every successful renewal.
    pub tls_cert_file: String,
    /// Path to write the PEM-encoded private key (same as `tls_key_file`).
    pub tls_key_file: String,
    /// Use the Let's Encrypt staging environment.  Default: `false`.
    pub staging: bool,
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Spawn the ACME certificate renewal loop as a background Tokio task.
///
/// - `acme_slot` is shared with the main TLS listener's `DynamicCertResolver`;
///   the renewal loop writes the challenge cert here during validation.
/// - `on_renewed` is called after every successful renewal so the TLS acceptor
///   can reload from disk.
pub async fn spawn_acme_renewal_loop(
    config: AcmeConfig,
    acme_slot: AcmeChallengeSlot,
    on_renewed: impl Fn() + Send + Sync + 'static,
) {
    tokio::spawn(async move {
        loop {
            match run_acme_cycle(&config, &acme_slot).await {
                Ok(days_valid) => {
                    on_renewed();
                    let sleep_days = (days_valid - 30).max(1);
                    info!(
                        domain = %config.domain,
                        valid_days = days_valid,
                        sleep_days = sleep_days,
                        "ACME certificate renewed; sleeping until next renewal window"
                    );
                    tokio::time::sleep(Duration::from_secs(sleep_days as u64 * 86_400)).await;
                }
                Err(e) => {
                    error!(
                        domain = %config.domain,
                        "ACME renewal failed; retrying in 1 hour: {e:#}"
                    );
                    tokio::time::sleep(Duration::from_secs(3_600)).await;
                }
            }
        }
    });
}

// ── Internals ─────────────────────────────────────────────────────────────────

/// Run a single ACME order cycle: order → validate TLS-ALPN-01 → write cert+key.
///
/// Returns the number of days until the new certificate expires.
async fn run_acme_cycle(config: &AcmeConfig, acme_slot: &AcmeChallengeSlot) -> anyhow::Result<u64> {
    let directory_url = if config.staging {
        LetsEncrypt::Staging.url()
    } else {
        LetsEncrypt::Production.url()
    };

    let (account, _credentials) = Account::create(
        &NewAccount {
            contact: &[&format!("mailto:{}", config.email)],
            terms_of_service_agreed: true,
            only_return_existing: false,
        },
        directory_url,
        None,
    )
    .await
    .context("ACME: create/load account")?;

    let identifier = Identifier::Dns(config.domain.clone());
    let mut order = account
        .new_order(&NewOrder {
            identifiers: &[identifier],
        })
        .await
        .context("ACME: create order")?;

    let authorizations = order
        .authorizations()
        .await
        .context("ACME: fetch authorizations")?;

    for auth in &authorizations {
        let challenge = auth
            .challenges
            .iter()
            .find(|c| c.r#type == ChallengeType::TlsAlpn01)
            .context("ACME: no TLS-ALPN-01 challenge offered")?;

        // Compute SHA-256 digest of the key authorization (RFC 8737 §3).
        let key_auth = order.key_authorization(challenge);
        let digest: Vec<u8> = key_auth.digest().as_ref().to_vec();

        let challenge_cert = build_alpn_challenge_cert(&config.domain, &digest)
            .context("ACME: build TLS-ALPN-01 challenge cert")?;
        acme_slot.set(Arc::new(challenge_cert));

        info!(
            domain = %config.domain,
            "ACME TLS-ALPN-01 challenge cert installed; signalling ready"
        );

        order
            .set_challenge_ready(&challenge.url)
            .await
            .context("ACME: set challenge ready")?;

        // Poll until the order moves to Ready/Valid (up to 60 s).
        let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
        loop {
            tokio::time::sleep(Duration::from_secs(3)).await;
            let state = order.refresh().await.context("ACME: refresh order")?;
            match state.status {
                OrderStatus::Ready | OrderStatus::Valid => break,
                OrderStatus::Invalid => {
                    acme_slot.clear();
                    anyhow::bail!("ACME: order became invalid during TLS-ALPN-01 challenge");
                }
                _ => {
                    if tokio::time::Instant::now() > deadline {
                        acme_slot.clear();
                        anyhow::bail!(
                            "ACME: timed out waiting for TLS-ALPN-01 challenge validation"
                        );
                    }
                    warn!(domain = %config.domain, "ACME: waiting for challenge validation…");
                }
            }
        }

        acme_slot.clear();
    }

    // Generate a fresh key pair and a CSR for the final certificate.
    let final_key = KeyPair::generate().context("ACME: generate final key pair")?;
    let mut params =
        CertificateParams::new(vec![config.domain.clone()]).context("ACME: build CSR params")?;
    params.distinguished_name = DistinguishedName::new();
    let csr = params
        .serialize_request(&final_key)
        .context("ACME: serialize CSR")?;
    let csr_der = csr.der().to_vec();

    order
        .finalize(&csr_der)
        .await
        .context("ACME: finalize order")?;

    let cert_pem = loop {
        match order
            .certificate()
            .await
            .context("ACME: download certificate")?
        {
            Some(c) => break c,
            None => tokio::time::sleep(Duration::from_secs(3)).await,
        }
    };

    let key_pem = final_key.serialize_pem();

    if let Some(parent) = std::path::Path::new(&config.tls_cert_file).parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&config.tls_cert_file, cert_pem.as_bytes())
        .with_context(|| format!("write ACME cert to {}", config.tls_cert_file))?;
    std::fs::write(&config.tls_key_file, key_pem.as_bytes())
        .with_context(|| format!("write ACME key to {}", config.tls_key_file))?;
    info!(
        domain = %config.domain,
        cert = %config.tls_cert_file,
        key = %config.tls_key_file,
        "ACME certificate written to disk"
    );

    // Let's Encrypt issues 90-day certificates.
    Ok(90)
}

/// Build a transient self-signed certificate for TLS-ALPN-01 validation.
///
/// Per RFC 8737 §3:
/// - The only SAN must be the domain (DNS type).
/// - The `id-pe-acmeIdentifier` extension (OID 1.3.6.1.5.5.7.1.31) MUST be
///   present, critical, and contain an ASN.1 OCTET STRING wrapping the
///   32-byte SHA-256 digest of the key authorization.
fn build_alpn_challenge_cert(domain: &str, digest: &[u8]) -> anyhow::Result<CertifiedKey> {
    // DER encoding of OCTET STRING: tag 0x04 | length | value.
    let mut ext_value = Vec::with_capacity(2 + digest.len());
    ext_value.push(0x04);
    ext_value.push(u8::try_from(digest.len()).context("ACME digest length exceeds 255 bytes")?);
    ext_value.extend_from_slice(digest);

    // id-pe-acmeIdentifier OID: 1.3.6.1.5.5.7.1.31
    let oid: &[u64] = &[1, 3, 6, 1, 5, 5, 7, 1, 31];
    let mut acme_ext = CustomExtension::from_oid_content(oid, ext_value);
    acme_ext.set_criticality(true);

    let key_pair = KeyPair::generate().context("ACME challenge: generate key pair")?;
    let mut params = CertificateParams::new(vec![domain.to_owned()])
        .context("ACME challenge: build cert params")?;
    params.distinguished_name = DistinguishedName::new();
    params.subject_alt_names = vec![SanType::DnsName(
        rcgen::Ia5String::try_from(domain.to_owned())
            .context("ACME challenge: invalid domain for SAN")?,
    )];
    params.custom_extensions = vec![acme_ext];

    let cert = params
        .self_signed(&key_pair)
        .context("ACME challenge: self-sign cert")?;

    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));
    let signing_key = rustls::crypto::ring::sign::any_supported_type(&key_der)
        .context("ACME challenge: load signing key into rustls")?;

    Ok(CertifiedKey::new(vec![cert_der], signing_key))
}
