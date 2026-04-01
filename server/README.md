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
	-p 8080:8080 -p 8081:8081 \
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
      - "8080:8080"   # NaiveTCP
      - "8081:8081"   # Health check
      - "8443:8443"   # WebSocket (optional)
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
bind = "0.0.0.0:8080"
public_address = "bonded.example.com:8080"
health_bind = "0.0.0.0:8081"
log_level = "info"
supported_protocols = ["naive_tcp"]
authorized_keys_file = "/var/lib/bonded/authorized_keys.toml"
invite_tokens_file = "/var/lib/bonded/invite_tokens.toml"

# WebSocket / TLS (optional)
websocket_bind = "0.0.0.0:8443"
websocket_tls_cert_file = ""
websocket_tls_key_file = ""

# Upstream forwarding (optional)
upstream_tcp_target = ""
```

### Fields

| Field | Default | Description |
|---|---|---|
| `bind` | `0.0.0.0:8080` | NaiveTCP listener address |
| `public_address` | *(empty)* | Public address shown in the QR code for clients — **must be set** |
| `health_bind` | `0.0.0.0:8081` | Health-check HTTP listener |
| `log_level` | `info` | Tracing level (`trace`, `debug`, `info`, `warn`, `error`) |
| `supported_protocols` | `["naive_tcp"]` | Protocols advertised to clients |
| `authorized_keys_file` | `/var/lib/bonded/authorized_keys.toml` | Authorized device keys file |
| `invite_tokens_file` | `/var/lib/bonded/invite_tokens.toml` | Invite tokens file |
| `websocket_bind` | `0.0.0.0:8443` | WebSocket listener address |
| `websocket_tls_cert_file` | *(empty)* | Path to WSS certificate (PEM). Empty = no TLS |
| `websocket_tls_key_file` | *(empty)* | Path to WSS private key. Empty = no TLS |
| `upstream_tcp_target` | *(empty)* | Optional upstream target for frame forwarding |

### Environment Variable Overrides

Every field can be overridden via `BONDED_` prefixed environment variables:

| Env Variable | Config Field |
|---|---|
| `BONDED_BIND` | `bind` |
| `BONDED_PUBLIC_ADDRESS` | `public_address` |
| `BONDED_HEALTH_BIND` | `health_bind` |
| `BONDED_LOG_LEVEL` | `log_level` |
| `BONDED_SUPPORTED_PROTOCOLS` | `supported_protocols` (comma-separated) |
| `BONDED_AUTHORIZED_KEYS_FILE` | `authorized_keys_file` |
| `BONDED_INVITE_TOKENS_FILE` | `invite_tokens_file` |
| `BONDED_WEBSOCKET_BIND` | `websocket_bind` |
| `BONDED_WEBSOCKET_TLS_CERT_FILE` | `websocket_tls_cert_file` |
| `BONDED_WEBSOCKET_TLS_KEY_FILE` | `websocket_tls_key_file` |
| `BONDED_UPSTREAM_TCP_TARGET` | `upstream_tcp_target` |
