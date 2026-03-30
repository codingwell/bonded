#!/bin/bash
set -e

echo "=== Bonded devcontainer post-create setup ==="

# Verify Rust
if command -v rustc &> /dev/null; then
    echo "Rust: $(rustc --version)"
    echo "Cargo: $(cargo --version)"
else
    echo "WARNING: Rust not found"
fi

# Verify Flutter
if command -v flutter &> /dev/null; then
    echo "Flutter: $(flutter --version --machine | head -1)"
    flutter precache
    flutter doctor
else
    echo "WARNING: Flutter not found"
fi

# Install Rust components
rustup component add clippy rustfmt

# Server dependencies
cd /workspace/server
cargo fetch || echo "No server dependencies to fetch yet"

echo "=== Setup complete ==="
