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
