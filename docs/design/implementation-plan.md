# Implementation Plan — Server, Linux Client, Android Client

**Status:** Not Started
**Last Updated:** 2026-03-30

This is a living document. Update the status column and notes as work progresses.

---

## Preflight Checklist

Complete these before broad implementation begins.

| # | Item | Status | Notes |
|---|------|--------|-------|
| P1 | Create implementation instructions for the coding agent | completed | See `AGENTS.md` |
| P2 | Confirm repo structure migration plan (`server/` to workspace crates) | not-started | Decide whether to migrate immediately or stage it |
| P3 | Define first runnable milestone | completed | Server + Linux client over NaiveTCP |
| P4 | Define validation commands for each phase | not-started | Build, test, integration, Android smoke test |
| P5 | Decide config file format and locations | not-started | Server config, authorized keys, client keypair |
| P6 | Decide initial Rust crypto and TUN libraries | not-started | Record in `Key Implementation Decisions` |
| P7 | Define how progress is resumed after interruption | completed | Update this file every session |

---

## First Milestone

The first mandatory milestone is:

`Linux CLI client pairs with server, creates a NaiveTCP path, establishes a TUN-backed session, and successfully sends traffic through the server.`

Do not treat Android work as the first proof point. Linux is the primary test harness for validating the shared core.

---

## Session Update Protocol

At the end of each work session:

1. Mark every touched task as `in-progress`, `blocked`, or `completed`
2. Add concise notes describing what was implemented and what remains
3. Add newly discovered tasks to the relevant phase
4. Record blockers with exact failure mode
5. Record design decisions with dates

This document must be sufficient for another implementation session to resume work without rereading the entire repository.

---

## Architecture Summary

```
[ App Traffic ]
      ↓
[ VPN / TUN interface ]
      ↓
[ Session Layer: virtual conn ID, sequencing, reassembly ]
      ↓
[ Scheduler: assigns packets to paths (naive in v1) ]
      ↓                    ↓
[ Path A: Wi-Fi ]    [ Path B: Cellular ]
  (NaiveTCP)           (NaiveTCP)
      ↓                    ↓
[ Server: reassembles, forwards to internet ]
```

Shared Rust crate (`bonded-core`) contains: session layer, scheduler, transport traits, auth, protocol framing. Server and Linux client are separate binaries depending on this crate. Android client uses the same core via JNI/FFI.

---

## Workspace Structure (Target)

```
/workspace
├── crates/
│   ├── bonded-core/         # Shared: session, scheduler, transports, auth, framing
│   ├── bonded-server/       # Server binary
│   ├── bonded-client/       # Shared client logic (TUN, path management)
│   └── bonded-cli/          # Linux CLI client binary
├── android/                 # Flutter + platform channels (later: Android-specific)
├── server/                  # (migrate to crates/bonded-server)
└── docs/
```

---

## Phase 1: Core Protocol & Shared Library

Build `bonded-core` with the foundational protocol pieces. Everything in this phase is shared between server and all clients.

| # | Task | Status | Notes |
|---|------|--------|-------|
| 1.1 | Set up Cargo workspace with `bonded-core`, `bonded-server`, `bonded-cli` crates | not-started | Migrate existing `server/` into workspace |
| 1.2 | Define session frame format (connection ID, sequence number, payload, flags) | not-started | Binary protocol, consider using `bytes` crate |
| 1.3 | Implement session layer — framing, sequencing, reassembly, connection ID tracking | not-started | Core of CR-10 |
| 1.4 | Define `Transport` trait (async read/write framed packets) | not-started | CR-8 pluggable interface |
| 1.5 | Implement NaiveTCP transport (client + server sides) | not-started | First transport for testing |
| 1.6 | Define `Scheduler` trait (given packet + available paths → chosen path) | not-started | CR-11 pluggable interface |
| 1.7 | Implement round-robin scheduler | not-started | Simplest naive scheduler |
| 1.8 | Implement active-standby failover scheduler | not-started | Primary use case for v1 |
| 1.9 | Keypair generation and storage utilities | not-started | Ed25519 or X25519 |
| 1.10 | Invite token generation and redemption protocol | not-started | OQ-1 decision |
| 1.11 | Public key challenge authentication on reconnect | not-started | Post-pairing auth |
| 1.12 | Unit tests for session layer (framing, reordering, reassembly) | not-started | |
| 1.13 | Unit tests for transports and schedulers | not-started | |

Acceptance gate:

- Shared crates build successfully
- Session framing and reassembly tests pass
- NaiveTCP transport can exchange framed packets between two local processes
- Auth pairing primitives compile and have unit coverage

---

## Phase 2: Server

Build the server binary on top of `bonded-core`.

| # | Task | Status | Notes |
|---|------|--------|-------|
| 2.1 | Server config loading (env vars + config file) | not-started | PUBLIC_ADDRESS, port, log level |
| 2.2 | Authorized keys file — load, watch for changes, reload | not-started | SRV-11, CR-12 |
| 2.3 | Accept NaiveTCP connections, perform auth handshake | not-started | |
| 2.4 | Server-side session management (multiple concurrent clients) | not-started | SRV-2 |
| 2.5 | IP packet forwarding — read from session, write to internet (TUN or raw socket) | not-started | SRV-3 |
| 2.6 | Return traffic — read from internet, write back to correct client session | not-started | |
| 2.7 | Invite token creation (on admin request / startup) | not-started | |
| 2.8 | QR code generation and emission to logs | not-started | SRV-9, CR-6a |
| 2.9 | Health check endpoint (HTTP) | not-started | SRV-6 |
| 2.10 | Configurable log verbosity | not-started | SRV-7 |
| 2.11 | Dockerfile update for new workspace structure | not-started | |
| 2.12 | Integration test: server starts, accepts connection, forwards traffic | not-started | |

Acceptance gate:

- Server starts from config
- Authorized keys reload works
- Pairing token and QR payload generation work
- A Linux client can authenticate and exchange framed traffic with the server

---

## Phase 3: Linux CLI Client

Build the Linux client on top of `bonded-core` + a thin `bonded-client` lib.

| # | Task | Status | Notes |
|---|------|--------|-------|
| 3.1 | TUN device setup on Linux | not-started | LNX-3 |
| 3.2 | Network interface detection and enumeration | not-started | LNX-1 |
| 3.3 | Client config (server address, auth token or keypair path) | not-started | |
| 3.4 | Pairing flow — redeem invite token, register keypair | not-started | |
| 3.5 | Establish NaiveTCP path to server, perform auth handshake | not-started | |
| 3.6 | Capture traffic from TUN → session layer → transport → server | not-started | |
| 3.7 | Receive traffic from server → session layer → TUN | not-started | |
| 3.8 | Multi-path: establish paths on multiple interfaces simultaneously | not-started | CR-1 |
| 3.9 | Failover: detect path death, shift traffic to surviving paths | not-started | CR-2 |
| 3.10 | Integration test: client + server, ping through tunnel | not-started | |
| 3.11 | Integration test: failover — kill one path, traffic continues | not-started | |

Acceptance gate:

- Client can pair with the server
- TUN traffic traverses the server end-to-end
- At least two paths can be established
- Killing one path does not terminate the session

---

## Phase 4: Android Client

Build the Android platform layer. The core Rust logic is shared via FFI.

| # | Task | Status | Notes |
|---|------|--------|-------|
| 4.1 | Flutter project setup (Android target initially) | not-started | |
| 4.2 | Rust → Android FFI bridge (bonded-core compiled for Android targets) | not-started | `cargo-ndk` or `uniffi` |
| 4.3 | Platform channel: Dart ↔ Rust FFI | not-started | FLT-2 |
| 4.4 | Android VPN Service implementation | not-started | AND-2 |
| 4.5 | Multi-network support (Wi-Fi + Cellular simultaneously) | not-started | AND-1, AND-3. Use `ConnectivityManager.requestNetwork()` |
| 4.6 | QR code scanner screen | not-started | AND-9, FLT-7 |
| 4.7 | Pairing flow UI — scan QR, redeem token, store keypair | not-started | |
| 4.8 | Connection status dashboard UI | not-started | FLT-3 |
| 4.9 | Server configuration screen | not-started | FLT-4 |
| 4.10 | Background operation | not-started | AND-4 |
| 4.11 | End-to-end test: Android → server → internet | not-started | |

Acceptance gate:

- Android app can scan QR and pair
- VPN service starts successfully
- At least one path to the server is established from Android
- Basic tunneled traffic succeeds

---

## Phase 5: Second Transport + Polish

Add a production transport protocol and harden.

| # | Task | Status | Notes |
|---|------|--------|-------|
| 5.1 | Implement WebSocket over TLS (wss://) transport | not-started | Highest value production transport |
| 5.2 | Test WSS transport end-to-end (Linux client + server) | not-started | |
| 5.3 | Test mixed transports (one path NaiveTCP, one path WSS) | not-started | |
| 5.4 | QUIC transport (evaluate `quinn` crate) | not-started | |
| 5.5 | Server advertises supported protocols in QR code | not-started | OQ-5 |
| 5.6 | Client tries all advertised protocols per interface | not-started | OQ-5 |

Acceptance gate:

- WSS transport functions end-to-end
- Mixed-protocol paths work in one session
- Supported protocols are advertised and attempted correctly

---

## Deferred to Later Phases

These are in v1 scope but depend on the above being stable first:

- **Peer connection sharing (CR-7)** — mDNS discovery, peer trust handshake, bidirectional path sharing
- **ShadowSocks transport** — evaluate effort after WSS and QUIC
- **Battery optimization (AND-6)**
- **Quick settings tile (AND-7)**

---

## Key Implementation Decisions

Decisions made during implementation that aren't in the requirements docs.

| Decision | Date | Notes |
|----------|------|-------|
| | | |

---

## Blockers / Issues

| Issue | Status | Resolution |
|-------|--------|------------|
| | | |
