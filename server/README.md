# Bonded Server

Rust-based aggregation server for Bonded.

## Building

```bash
cargo build          # debug
cargo build --release # release
```

## Running

```bash
cargo run
```

## Docker

```bash
docker build -t bonded-server .
docker run -p 8080:8080 bonded-server
```

## Configuration

TBD — will support environment variables and/or config file.
