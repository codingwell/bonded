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

# Server
cd server
cargo build
cargo test

# Client
cd ../client
flutter pub get
flutter test
```

## Running Locally

### Server

```bash
cd server

# Direct
cargo run

# Docker
docker build -t bonded-server .
docker run -p 8080:8080 bonded-server
```

### Client

```bash
cd client

# Run on connected device / emulator
flutter run

# Run on specific platform
flutter run -d windows
flutter run -d macos
flutter run -d chrome  # for quick iteration (web not a target but useful for dev)
```

## IDE Recommendations

- **VS Code** with extensions:
  - rust-analyzer (server)
  - Flutter / Dart (client)
  - Even Better TOML (Cargo.toml editing)
- **Android Studio** — alternative for Flutter development
