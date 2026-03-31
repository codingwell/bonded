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
docker build -f server/Dockerfile -t bonded-server .
docker run \
	-p 8080:8080 -p 8081:8081 \
	-v "$PWD/server.toml:/etc/bonded/server.toml:ro" \
	-v "$PWD/data:/var/lib/bonded" \
	bonded-server
```

## Configuration

TBD — will support environment variables and/or config file.
