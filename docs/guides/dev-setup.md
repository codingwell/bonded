# Development Environment Setup

## Prerequisites

### Common

- Git 2.30+
- Docker & Docker Compose (for running the server locally)

### Server Development

- [Rust](https://rustup.rs/) (stable toolchain)
- `cargo` (comes with Rust)

### Client Development

- [Flutter SDK](https://docs.flutter.dev/get-started/install) (stable channel)
- **Android:** Android Studio + Android SDK
- **iOS:** Xcode (macOS only)
- **Windows:** Visual Studio with "Desktop development with C++" workload
- **macOS:** Xcode command line tools

## First-Time Setup

```bash
# Clone the repository
git clone https://github.com/<org>/bonded.git
cd bonded

# Workspace baseline
cargo build --workspace
cargo test --workspace
```

The Rust workspace scaffolding is present. Android scaffold is planned and not yet created.

## Running Locally

### Server

```bash
# Direct from workspace root
cargo run -p bonded-server

# Docker
docker build -f server/Dockerfile -t bonded-server .
docker run -p 8080:8080 bonded-server
```

### Planned Validation Flow

```bash
# Workspace baseline once migrated
cargo fmt --all --check
cargo test --workspace

# Android smoke build once scaffolded
cd android
flutter pub get
flutter build apk --debug
```

There is not yet a Flutter client scaffold in the repository. The implementation order is:

1. Shared Rust core
2. Server
3. Linux CLI client
4. Android client

## IDE Recommendations

- **VS Code** with extensions:
  - rust-analyzer (server)
  - Flutter / Dart (client)
  - Even Better TOML (Cargo.toml editing)
- **Android Studio** — alternative for Flutter development

## Android Build Guide

Bonded's Android client uses Flutter for UI and a pre-compiled Rust shared library (`libbonded_ffi.so`) for VPN/session logic.

### Prerequisites

- Rust toolchain with Android targets:
  ```bash
  rustup target add aarch64-linux-android x86_64-linux-android
  ```
- Android NDK 26.x installed. A working `.cargo/config.toml` is committed at the repo root — update the NDK version path if your installation differs.
- Flutter SDK (stable channel) and Android SDK.

### Building the Native Library

```bash
# Build for physical devices (arm64)
cargo build --target aarch64-linux-android -p bonded-ffi --release

# Build for x86_64 emulators
cargo build --target x86_64-linux-android -p bonded-ffi --release

# Copy to jniLibs
mkdir -p android/android/app/src/main/jniLibs/arm64-v8a
mkdir -p android/android/app/src/main/jniLibs/x86_64
cp target/aarch64-linux-android/release/libbonded_ffi.so android/android/app/src/main/jniLibs/arm64-v8a/
cp target/x86_64-linux-android/release/libbonded_ffi.so android/android/app/src/main/jniLibs/x86_64/
```

### Building the APK

```bash
cd android
flutter pub get
flutter build apk --debug
# APK will be at: build/app/outputs/flutter-apk/app-debug.apk
```

### Quick Validation (no device needed)

```bash
# All workspace tests including Android FFI smoke tests
cargo test --workspace

# Flutter static analysis
cd android && flutter analyze
```
