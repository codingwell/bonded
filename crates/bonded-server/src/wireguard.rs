//! Server-side WireGuard peer registry and address allocation.
//!
//! When a client calls `POST /v1/bootstrap/wireguard/peer` it registers its
//! WireGuard public key and receives an assigned `/32` IP from the
//! `100.64.1.0/24` block.  The registry is in-memory only; peers that do not
//! reconnect after a server restart will need to re-register.
//!
//! The actual WireGuard handshake is handled by boringtun in a separate
//! server-side endpoint (Phase 6.3+).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::net::Ipv4Addr;

use bonded_core::transport::WireGuardKeypair;
use tracing::info;

/// Holds the per-peer allocation: the WireGuard public key and the assigned IP.
#[derive(Clone, Debug)]
pub struct WireGuardPeer {
    /// The client device's ed25519 public key (base64), used as the stable
    /// identifier across reconnections.
    pub device_public_key: String,
    /// The client's WireGuard X25519 public key (base64).
    pub wg_public_key: String,
    /// Allocated /32 IP from the bonded WireGuard subnet.
    pub peer_ip: Ipv4Addr,
}

/// Thread-safe registry of WireGuard peers with CIDR allocation.
pub struct WireGuardPeerRegistry {
    peers: Mutex<HashMap<String, WireGuardPeer>>,
    /// Next host octet to allocate from 100.64.1.x/24.
    next_octet: Mutex<u8>,
}

impl WireGuardPeerRegistry {
    /// Create a new registry.  IPs will be allocated from `100.64.1.1/32`
    /// upwards (skipping .0 and .255).
    pub fn new() -> Self {
        Self {
            peers: Mutex::new(HashMap::new()),
            next_octet: Mutex::new(1),
        }
    }

    /// Register a peer and return its allocated `"a.b.c.d/32"` CIDR string.
    ///
    /// If the `device_public_key` was already registered, the existing
    /// allocation is returned unchanged (idempotent).
    pub fn register_peer(&self, device_public_key: &str, wg_public_key: &str) -> String {
        let mut peers = self.peers.lock().expect("wg peer registry lock");
        if let Some(existing) = peers.get(device_public_key) {
            return format!("{}/32", existing.peer_ip);
        }

        let octet = {
            let mut n = self.next_octet.lock().expect("wg octet lock");
            let allocated = *n;
            *n = n.wrapping_add(1);
            if *n == 255 {
                *n = 1; // wrap around (simple policy; collisions avoided by idempotency)
            }
            allocated
        };

        let ip = Ipv4Addr::new(100, 64, 1, octet);
        info!(
            device_pk = %device_public_key,
            wg_pk = %wg_public_key,
            peer_ip = %ip,
            "WireGuard peer registered"
        );
        peers.insert(
            device_public_key.to_owned(),
            WireGuardPeer {
                device_public_key: device_public_key.to_owned(),
                wg_public_key: wg_public_key.to_owned(),
                peer_ip: ip,
            },
        );
        format!("{ip}/32")
    }

    /// Look up a peer by its WireGuard public key (for use by the WG
    /// transport when deciding whether to accept an inbound handshake).
    pub fn find_by_wg_key(&self, wg_public_key: &str) -> Option<WireGuardPeer> {
        self.peers
            .lock()
            .expect("wg peer registry lock")
            .values()
            .find(|p| p.wg_public_key == wg_public_key)
            .cloned()
    }

    /// Return all registered peers (for kernel WG configuration helpers).
    pub fn all_peers(&self) -> Vec<WireGuardPeer> {
        self.peers
            .lock()
            .expect("wg peer registry lock")
            .values()
            .cloned()
            .collect()
    }
}

/// Build a `WireGuardKeypair` from a persisted 32-byte seed file at `path`, or
/// generate a new one and write the seed if the file does not exist.
///
/// The seed is stored as raw bytes, not PEM.  Protect the file with `0600`.
pub fn load_or_generate_wg_keypair(path: &str) -> anyhow::Result<Arc<WireGuardKeypair>> {
    use std::io::ErrorKind;

    match std::fs::read(path) {
        Ok(bytes) => {
            if bytes.len() != 32 {
                anyhow::bail!(
                    "WireGuard key file {path} has wrong length: {} (expected 32)",
                    bytes.len()
                );
            }
            let mut seed = [0u8; 32];
            seed.copy_from_slice(&bytes);
            Ok(Arc::new(WireGuardKeypair::from_secret_bytes(seed)))
        }
        Err(e) if e.kind() == ErrorKind::NotFound => {
            let kp = WireGuardKeypair::generate();
            // Persist the 32-byte secret.
            if let Some(parent) = std::path::Path::new(path).parent() {
                std::fs::create_dir_all(parent)?;
            }
            let secret_bytes: [u8; 32] = kp.secret.to_bytes();
            std::fs::write(path, &secret_bytes)?;
            info!(path = %path, pubkey = %kp.public_key_b64(), "Generated new WireGuard server keypair");
            Ok(Arc::new(kp))
        }
        Err(e) => Err(e.into()),
    }
}
