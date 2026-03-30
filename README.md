# Bonded

An open source tool to leverage multiple internet connections for a more robust, reliable connection.

This repository is in early implementation. The current source of truth for scope and sequencing is:

- `docs/requirements/product-requirements.md`
- `docs/requirements/platform-requirements.md`
- `docs/requirements/open-questions.md`
- `docs/design/implementation-plan.md`
- `AGENTS.md`

## Overview

Bonded aggregates several internet connections (Wi-Fi, cellular, Ethernet, etc.) to provide improved reliability, bandwidth, and failover. It consists of a server component that acts as a traffic aggregation point and client applications that manage local network interfaces and tunnel traffic through them.

## Architecture

```
┌─────────────────────┐         ┌──────────────────┐
│      Client          │         │      Server       │
│  (Flutter app)       │         │  (Rust + Docker)  │
│                      │         │                   │
│  ┌──────────────┐   │  ═══╗   │  ┌─────────────┐ │
│  │  Interface A  │───┼─────╬───┼──│  Aggregator  │ │
│  │  (Wi-Fi)      │   │    ║   │  │              │ │
│  ├──────────────┤   │    ║   │  │  Reassemble   │ │
│  │  Interface B  │───┼─────╬───┼──│  & Forward   │ │
│  │  (Cellular)   │   │    ║   │  │              │ │
│  ├──────────────┤   │    ║   │  └──────┬──────┘ │
│  │  Interface C  │───┼─────╝   │         │        │
│  │  (Ethernet)   │   │         │         ▼        │
│  └──────────────┘   │         │     Internet      │
└─────────────────────┘         └──────────────────┘
```

## Repository Structure

```
bonded/
├── server/             # Current Rust server prototype
├── docs/
│   ├── requirements/   # Product requirements and specifications
│   ├── design/         # Technical design documents
│   └── guides/         # Developer guides and onboarding
└── AGENTS.md           # Implementation instructions for coding agents
```

Planned near-term structure:

```
bonded/
├── crates/
│   ├── bonded-core/
│   ├── bonded-server/
│   ├── bonded-client/
│   └── bonded-cli/
├── android/
├── docs/
└── AGENTS.md
```

## Getting Started

> **Note:** This project is in early development. See [docs/guides/dev-setup.md](docs/guides/dev-setup.md) for development environment setup.

### Prerequisites

- **Server:** Rust (stable), Docker
- **Client:** Flutter SDK (stable channel), platform-specific SDKs for target platforms

### Building

```bash
# Current server prototype
cd server
cargo build
```

Planned clients are not scaffolded yet. Implementation order is:

1. Shared Rust core
2. Server
3. Linux CLI client
4. Android client

## Supported Platforms

| Platform | Role   | Status  |
| -------- | ------ | ------- |
| Linux    | Server + CLI Client | Planned |
| Android  | Client | Planned |
| iOS      | Client | Planned |
| Windows  | Client | Planned |
| macOS    | Client | Planned |

## License

TBD — See [LICENSE](LICENSE) for details.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.
