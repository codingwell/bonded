# Server Configuration for Local Testing

## Default Development Config

Based on [`crates/bonded-core/src/config.rs`](crates/bonded-core/src/config.rs:290), the server config defaults are:

| Setting | Default Value | Purpose |
|---------|---------------|---------|
| `hostname` | `""` (empty) | Combined with port to form public address; use `"localhost"` for local testing |
| `https_bind` | `"0.0.0.0:443"` | Local bind for HTTPS/WSS/QUIC listener |
| `https_public` | `443` | Public port for HTTPS/WSS connections |
| `tls_cert_file` | `""` (empty) | Auto-generated self-signed cert if not present |
| `tls_key_file` | `""` (empty) | Auto-generated self-signed key if not present |
| `wireguard_bind` | `None` | Optional WireGuard listener for multi-transport testing |
| `tcp_bind` | `None` | Optional debug NaiveTCP listener |
| `status_bind` | `"0.0.0.0:8082"` | Status endpoint (health, sessions, flows) |
| `health_bind` | `"0.0.0.0:8081"` | Health check endpoint |
| `log_level` | `"info"` | Tracing log level |
| `forwarding_mode` | `"proxy"` | Proxy or TUN forwarding mode |

## Recommended Local Testing Configuration

```toml
[server]
hostname = "localhost"
https_bind = "127.0.0.1:443"
https_public = 443
tls_cert_file = "/tmp/bonded-server.crt"
tls_key_file = "/tmp/bonded-server.key"

# Optional: WireGuard for multi-transport testing
wireguard_bind = "127.0.0.1:51820"
wireguard_public = 51820
wireguard_key_file = "/tmp/bonded-server-wg.key"
wireguard_peers_file = "/tmp/wg-peers.toml"

# Optional: Debug NaiveTCP for unencrypted testing
tcp_bind = "127.0.0.1:8000"
tcp_public = 8000

status_bind = "127.0.0.1:9002"
health_bind = "127.0.0.1:9001"
log_level = "info"
forwarding_mode = "proxy"
tun_name = "bonded0"
tun_cidr = "100.64.0.1/24"
tun_mtu = 1420

authorized_keys_file = "/tmp/auth.toml"
invite_tokens_file = "/tmp/tokens.toml"
identity_key_file = "/tmp/server-identity.pem"
```

## Running the Server

### Direct from Workspace Root

```bash
cargo run -p bonded-server --config server.toml
```

Or with environment overrides:

```bash
BONDED_HOSTNAME=localhost \
BONDED_HTTPS_BIND="127.0.0.1:443" \
BONDED_STATUS_BIND="127.0.0.1:8082" \
BONDED_HEALTH_BIND="127.0.0.1:8081" \
cargo run -p bonded-server --config server.toml
```

### Docker (for containerized testing)

```bash
docker build -f server/Dockerfile -t bonded-server .
docker run -p 443:443 -p 51820:51820 -p 8082:8082 -p 8081:8081 \
    -v $(pwd)/server.toml:/etc/bonded/server.toml \
    bonded-server
```

## Expected Endpoints After Startup

| Endpoint | Port | Protocol | Purpose |
|----------|------|----------|---------|
| `/api/health` | 8081 | HTTP | Health check |
| `/status/*` | 8082 | HTTP | Status (sessions, flows) |
| `wss://localhost:443/v1/bootstrap/cert-proof` | 443 | WSS/HTTPS | Bootstrap API for cert-proof verification |
| `ws://localhost:443/v1/bootstrap/*` | 443 | WebSocket | Bootstrap API (plain HTTP fallback) |
| `tcp://localhost:8000/api/auth` | 8000 | TCP/NaiveTCP | Debug unencrypted transport |

## Generating Invite Token for Pairing

After server starts, generate an invite token via the bootstrap API:

```bash
curl -X POST "https://localhost:443/v1/bootstrap/invite" \
    --data-raw '{"device_name": "test-device"}'
```

Response includes `token` and `public_key_b64` for QR code pairing.

## Auto-Generated State Files

The server creates these files automatically on first boot:

| File | Purpose |
|------|---------|
| `/tmp/auth.toml` | Authorized device keys (empty initially) |
| `/tmp/tokens.toml` | Invite tokens (single-use, short-lived) |
| `/tmp/server-identity.pem` | Server's stable ed25519 identity key for cert-proof signing |
| `/tmp/bonded-server.crt` / `.key` | TLS certificate/key pair (self-signed if not present) |
| `/tmp/bonded-server-wg.key` | WireGuard private key seed (if WG enabled) |
| `/tmp/wg-peers.toml` | WireGuard peer allocation state (if WG enabled) |

## Validation Commands

```bash
# Build workspace baseline
cargo build --workspace

# Run all tests including Android FFI smoke tests
cargo test --workspace

# Check formatting
cargo fmt --all --check

# Run server with config file
cargo run -p bonded-server --config server.toml
```
