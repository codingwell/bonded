#!/usr/bin/env bash
# Build the bonded-ffi native library for Android and copy it into jniLibs.
# Run from the workspace root.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

JNILIBS_DIR="$WORKSPACE_ROOT/android/android/app/src/main/jniLibs"

echo "Ensuring Android Rust targets are installed..."
rustup target add aarch64-linux-android x86_64-linux-android

echo "Building bonded-ffi for aarch64-linux-android (arm64 physical devices)..."
cargo build --target aarch64-linux-android -p bonded-ffi --release

echo "Building bonded-ffi for x86_64-linux-android (emulators)..."
cargo build --target x86_64-linux-android -p bonded-ffi --release

echo "Copying .so files to jniLibs..."
mkdir -p "$JNILIBS_DIR/arm64-v8a"
mkdir -p "$JNILIBS_DIR/x86_64"

cp "$WORKSPACE_ROOT/target/aarch64-linux-android/release/libbonded_ffi.so" \
   "$JNILIBS_DIR/arm64-v8a/libbonded_ffi.so"

cp "$WORKSPACE_ROOT/target/x86_64-linux-android/release/libbonded_ffi.so" \
   "$JNILIBS_DIR/x86_64/libbonded_ffi.so"

echo "Done. Native libraries are ready at:"
echo "  $JNILIBS_DIR/arm64-v8a/libbonded_ffi.so ($(du -sh "$JNILIBS_DIR/arm64-v8a/libbonded_ffi.so" | cut -f1))"
echo "  $JNILIBS_DIR/x86_64/libbonded_ffi.so ($(du -sh "$JNILIBS_DIR/x86_64/libbonded_ffi.so" | cut -f1))"
