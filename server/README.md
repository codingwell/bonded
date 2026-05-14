# Bonded Server

Rust-based aggregation server for Bonded.

The primary server crate now lives at `crates/bonded-server` in the workspace root. This directory is kept for Docker assets and migration compatibility.

## Building

```bash
cargo build -p bonded-server           # debug
cargo build -p bonded-server --release # release
```

## Running

```bash
cargo run -p bonded-server
```

## Docker

```bash
docker build -f server/Dockerfile -t ghcr.io/codingwell/bonded-server .
docker run \
	-p 443:443 -p 443:443/udp -p 8081:8081 \
	-v "$PWD/server.toml:/etc/bonded/server.toml:ro" \
	-v "$PWD/data:/var/lib/bonded" \
	ghcr.io/codingwell/bonded-server
```

### Docker Compose

```yaml
# docker-compose.yml
services:
  bonded-server:
    image: ghcr.io/codingwell/bonded-server:latest
    ports:
      - "443:443"         # HTTPS / WSS / QUIC (TCP + UDP)
      - "443:443/udp"     # QUIC
      - "8081:8081"       # Health check
      - "51820:51820/udp" # WireGuard (optional, set wireguard_bind)
    volumes:
      - ./server.toml:/etc/bonded/server.toml:ro
      - bonded-data:/var/lib/bonded
    environment:
      - BONDED_CONFIG=/etc/bonded/server.toml
    restart: unless-stopped

volumes:
  bonded-data:
```

## Configuration

The server is configured via a TOML file (default: `/etc/bonded/server.toml`). The path can be overridden with the `--config` flag or the `BONDED_CONFIG` environment variable. All fields can also be overridden with environment variables.

On startup, the server auto-creates missing state files and parent directories for `authorized_keys_file` and `invite_tokens_file`.

### Sample `server.toml`

```toml
[server]
hostname = "vpn.example.com"
https_bind = "0.0.0.0:443"
https_public = 443
tls_cert_file = "/var/lib/bonded/server.crt"
tls_key_file  = "/var/lib/bonded/server.key"

health_bind = "0.0.0.0:8081"
log_level = "info"
authorized_keys_file = "/var/lib/bonded/authorized_keys.toml"
invite_tokens_file = "/var/lib/bonded/invite_tokens.toml"

# WireGuard (optional — enables WireGuard when set)
wireguard_bind   = "0.0.0.0:51820"
wireguard_public = 51820

# Debug NaiveTCP — enable only for testing
# tcp_bind   = "0.0.0.0:8000"
# tcp_public = 8000

# ACME / Let's Encrypt (TLS-ALPN-01 — optional, requires direct port 443 access)
# acme_domain  = "vpn.example.com"
# acme_email   = "admin@example.com"
# acme_staging = false   # set true while testing
```

### Fields

| Field | Default | Description |
|---|---|---|
| `hostname` | *(empty)* | Public hostname shown in QR codes and capabilities — **must be set** |
| `https_bind` | `0.0.0.0:443` | Local bind for HTTPS / WSS / QUIC (TCP + UDP) |
| `https_public` | `443` | Public HTTPS port. Combined with `hostname` for the advertised endpoint |
| `tls_cert_file` | *(empty)* | PEM certificate chain. Empty = TLS disabled (no QUIC) |
| `tls_key_file` | *(empty)* | PEM private key. Empty = TLS disabled |
| `wireguard_bind` | *(unset)* | UDP bind for WireGuard. Setting this enables the WG endpoint |
| `wireguard_public` | *(unset)* | Public WireGuard UDP port |
| `wireguard_key_file` | *(unset)* | Path to WireGuard private key seed (auto-generated on first boot) |
| `tcp_bind` | *(unset)* | NaiveTCP debug listener. Only started when set |
| `tcp_public` | *(unset)* | Public NaiveTCP port |
| `health_bind` | `0.0.0.0:8081` | Health-check HTTP listener |
| `status_bind` | `0.0.0.0:8082` | Status/metrics HTTP listener |
| `log_level` | `info` | Tracing level (`trace`, `debug`, `info`, `warn`, `error`) |
| `authorized_keys_file` | `/var/lib/bonded/authorized_keys.toml` | Authorized device keys file |
| `invite_tokens_file` | `/var/lib/bonded/invite_tokens.toml` | Invite tokens file |
| `acme_domain` | *(unset)* | Domain for ACME TLS-ALPN-01 cert automation |
| `acme_email` | *(unset)* | Contact email for Let's Encrypt |
| `acme_staging` | `false` | Use Let's Encrypt staging environment |

**Feature auto-detection:** capabilities are enabled automatically based on which config values are present:
- **QUIC** — enabled when `tls_cert_file` + `tls_key_file` are set (same port as HTTPS, UDP)
- **WireGuard** — enabled when `wireguard_bind` is set
- **ACME** — enabled when `acme_domain` is set; writes renewed certs to `tls_cert_file`/`tls_key_file`
- **NaiveTCP** — enabled when `tcp_bind` is set (debug/testing only)

### Environment Variable Overrides

| Env Variable | Config Field |
|---|---|
| `BONDED_HOSTNAME` | `hostname` |
| `BONDED_HTTPS_BIND` | `https_bind` |
| `BONDED_HTTPS_PUBLIC` | `https_public` |
| `BONDED_TLS_CERT_FILE` | `tls_cert_file` |
| `BONDED_TLS_KEY_FILE` | `tls_key_file` |
| `BONDED_WIREGUARD_BIND` | `wireguard_bind` |
| `BONDED_WIREGUARD_PUBLIC` | `wireguard_public` |
| `BONDED_TCP_BIND` | `tcp_bind` |
| `BONDED_TCP_PUBLIC` | `tcp_public` |
| `BONDED_HEALTH_BIND` | `health_bind` |
| `BONDED_STATUS_BIND` | `status_bind` |
| `BONDED_LOG_LEVEL` | `log_level` |
| `BONDED_AUTHORIZED_KEYS_FILE` | `authorized_keys_file` |
| `BONDED_INVITE_TOKENS_FILE` | `invite_tokens_file` |
