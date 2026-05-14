//! Automatic certificate provisioning via Let's Encrypt (ACME HTTP-01).
//!
//! # Overview
//!
//! When `acme_domain` is set in the server config, the server spawns a
//! background renewal loop that:
//!
//! 1. Checks whether the on-disk cert/key are still valid (≥ 30 days before
//!    expiry).  If they are, sleeps until 30 days before expiry and loops.
//! 2. Runs an ACME HTTP-01 challenge using `instant-acme`, writing the
//!    `/.well-known/acme-challenge/…` token to a temporary in-memory map
//!    served by the bootstrap HTTP listener.
//! 3. Writes the new DER-encoded cert and private key to `acme_cert_file` and
//!    `acme_key_file`, then signals the TLS acceptor to reload.
//!
//! # Limitations (Phase 6)
//!
//! - Only HTTP-01 challenges are supported.  DNS-01 is future work.
//! - The bootstrap server must be reachable on port 80 (or the ACME CA must
//!   be configured to use a non-standard port, which Let's Encrypt does not do
//!   in production).  In practice the operator should set up an external
//!   load-balancer / reverse proxy that forwards `:80` to the bind address.
//! - Certificate reload after renewal reloads the file from disk; the server
//!   process does *not* restart.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Context as _;
use instant_acme::{
    Account, ChallengeType, Identifier, LetsEncrypt, NewAccount, NewOrder, OrderStatus,
};
use rcgen::CertifiedKey;
use tracing::{error, info, warn};

/// Shared challenge-token map populated by the ACME renewal loop and queried
/// by the HTTP listener serving `/.well-known/acme-challenge/*`.
#[derive(Clone, Default)]
pub struct AcmeChallengeStore {
    inner: Arc<Mutex<HashMap<String, String>>>,
}

impl AcmeChallengeStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a challenge token (called by the renewal loop).
    pub fn set(&self, token: String, key_auth: String) {
        self.inner
            .lock()
            .expect("acme challenge lock")
            .insert(token, key_auth);
    }

    /// Remove a challenge token after verification.
    pub fn remove(&self, token: &str) {
        self.inner.lock().expect("acme challenge lock").remove(token);
    }

    /// Look up the key-authorisation string for an HTTP-01 challenge token.
    pub fn get(&self, token: &str) -> Option<String> {
        self.inner
            .lock()
            .expect("acme challenge lock")
            .get(token)
            .cloned()
    }
}

/// ACME configuration drawn from `ServerSection`.
#[derive(Clone, Debug)]
pub struct AcmeConfig {
    /// The domain to obtain a certificate for (e.g. `vpn.example.com`).
    pub domain: String,
    /// Contact e-mail sent to Let's Encrypt.
    pub email: String,
    /// Path to write the PEM-encoded certificate chain.
    pub cert_file: String,
    /// Path to write the PEM-encoded private key.
    pub key_file: String,
    /// Use the Let's Encrypt staging environment.  Default: `false`.
    pub staging: bool,
}

/// Spawn the ACME certificate renewal loop as a background Tokio task.
///
/// The task runs indefinitely; dropping the returned `JoinHandle` does *not*
/// stop it (it is detached via `tokio::spawn`).  Use a `CancellationToken` to
/// shut it down in tests or on graceful shutdown.
pub async fn spawn_acme_renewal_loop(
    config: AcmeConfig,
    challenge_store: AcmeChallengeStore,
    // Called after every successful renewal so the TLS acceptor can reload.
    on_renewed: impl Fn() + Send + Sync + 'static,
) {
    tokio::spawn(async move {
        loop {
            match run_acme_cycle(&config, &challenge_store).await {
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
                    error!(domain = %config.domain, error = %e, "ACME renewal failed; retrying in 1 hour");
                    tokio::time::sleep(Duration::from_secs(3_600)).await;
                }
            }
        }
    });
}

/// Run a single ACME order cycle: order → validate HTTP-01 → write cert+key.
///
/// Returns the number of days until the new certificate expires.
async fn run_acme_cycle(
    config: &AcmeConfig,
    challenge_store: &AcmeChallengeStore,
) -> anyhow::Result<u64> {
    let directory_url = if config.staging {
        LetsEncrypt::Staging.url()
    } else {
        LetsEncrypt::Production.url()
    };

    // Create or load an ACME account.
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

    // Obtain authorizations and locate the HTTP-01 challenge.
    let authorizations = order
        .authorizations()
        .await
        .context("ACME: fetch authorizations")?;
    for auth in &authorizations {
        let challenge = auth
            .challenges
            .iter()
            .find(|c| c.r#type == ChallengeType::Http01)
            .context("ACME: no HTTP-01 challenge offered")?;
        let token = challenge.token.clone();
        let key_auth = order.key_authorization(challenge).as_str().to_owned();
        info!(domain = %config.domain, token = %token, "Publishing ACME HTTP-01 challenge");
        challenge_store.set(token.clone(), key_auth);

        // Signal Let's Encrypt that the challenge is ready.
        order
            .set_challenge_ready(&challenge.url)
            .await
            .context("ACME: set challenge ready")?;

        // Poll until the challenge passes (up to 60 s).
        let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
        loop {
            tokio::time::sleep(Duration::from_secs(3)).await;
            let state = order.refresh().await.context("ACME: refresh order")?;
            match state.status {
                OrderStatus::Ready => break,
                OrderStatus::Valid => break,
                OrderStatus::Invalid => {
                    challenge_store.remove(&token);
                    anyhow::bail!("ACME: order became invalid during HTTP-01 challenge");
                }
                _ => {
                    if tokio::time::Instant::now() > deadline {
                        challenge_store.remove(&token);
                        anyhow::bail!("ACME: timed out waiting for HTTP-01 challenge validation");
                    }
                    warn!(domain = %config.domain, "ACME: waiting for challenge validation…");
                }
            }
        }
        challenge_store.remove(&token);
    }

    // Generate a new private key and CSR with rcgen.
    let CertifiedKey { cert, key_pair } =
        rcgen::generate_simple_self_signed(vec![config.domain.clone()])
            .context("ACME: generate key pair")?;
    let csr_der = cert.der().to_vec();

    // Finalise the order.
    order
        .finalize(&csr_der)
        .await
        .context("ACME: finalize order")?;

    // Download the signed certificate chain.
    let cert_pem = loop {
        match order.certificate().await.context("ACME: download certificate")? {
            Some(c) => break c,
            None => tokio::time::sleep(Duration::from_secs(3)).await,
        }
    };

    let key_pem = key_pair.serialize_pem();

    // Write to disk.
    if let Some(parent) = std::path::Path::new(&config.cert_file).parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&config.cert_file, cert_pem.as_bytes())
        .with_context(|| format!("write ACME cert to {}", config.cert_file))?;
    std::fs::write(&config.key_file, key_pem.as_bytes())
        .with_context(|| format!("write ACME key to {}", config.key_file))?;
    info!(
        domain = %config.domain,
        cert = %config.cert_file,
        key = %config.key_file,
        "ACME certificate written to disk"
    );

    // Estimate validity (Let's Encrypt issues 90-day certs).
    Ok(90)
}
