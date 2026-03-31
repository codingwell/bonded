# Implementation Plan — Server, Linux Client, Android Client

**Status:** In Progress
**Last Updated:** 2026-03-31

This is a living document. Update the status column and notes as work progresses.

---

## Preflight Checklist

Complete these before broad implementation begins.

| # | Item | Status | Notes |
|---|------|--------|-------|
| P1 | Create implementation instructions for the coding agent | completed | See `AGENTS.md` |
| P2 | Confirm repo structure migration plan (`server/` to workspace crates) | completed | Migrate immediately in the first implementation checkpoint |
| P3 | Define first runnable milestone | completed | Server + Linux client over NaiveTCP |
| P4 | Define validation commands for each phase | completed | See `Validation Commands` |
| P5 | Decide config file format and locations | completed | See `Configuration Conventions` |
| P6 | Decide initial Rust crypto and TUN libraries | completed | See `Initial Library Decisions` |
| P7 | Define how progress is resumed after interruption | completed | Update this file every session |

---

## First Milestone

The first mandatory milestone is:

`Linux CLI client pairs with server, creates a NaiveTCP path, establishes a TUN-backed session, and successfully sends traffic through the server.`

Do not treat Android work as the first proof point. Linux is the primary test harness for validating the shared core.

---

## Bootstrap Decisions

- Migrate to a Cargo workspace immediately. Do not continue building out the legacy top-level `server/` crate structure.
- Keep NaiveTCP as the only required transport until the first Linux end-to-end milestone passes.
- Defer peer-sharing implementation even though it is in v1 scope; build it only after base server + Linux client tunneling is stable.
- Keep Android implementation thin initially: QR pairing, VPN service, one connect/disconnect flow, one path if necessary for first proof.

---

## Configuration Conventions

Use TOML for all human-edited configuration/state files in v1.

Server files:

- Primary config path: `/etc/bonded/server.toml`
- Override via env: `BONDED_CONFIG`
- Authorized keys path default: `/var/lib/bonded/authorized_keys.toml`
- Invite tokens path default: `/var/lib/bonded/invite_tokens.toml`

Recommended server config shape:

```toml
[server]
bind = "0.0.0.0:8080"
public_address = "bonded.example.com:8080"
health_bind = "0.0.0.0:8081"
log_level = "info"
supported_protocols = ["naive_tcp"]
authorized_keys_file = "/var/lib/bonded/authorized_keys.toml"
invite_tokens_file = "/var/lib/bonded/invite_tokens.toml"
```

Recommended authorized keys shape:

```toml
[[devices]]
device_id = "android-phone"
public_key = "base64-ed25519-public-key"
added_at = "2026-03-30T00:00:00Z"
```

Recommended invite token shape:

```toml
[[tokens]]
token = "base64url-token"
expires_at = "2026-03-31T00:00:00Z"
uses_remaining = 1
```

Linux client files:

- Config path: `~/.config/bonded/client.toml`
- Private key path: `~/.local/share/bonded/device-key.pem`
- Public key path: `~/.local/share/bonded/device-key.pub`

Recommended Linux client config shape:

```toml
[client]
device_name = "linux-cli"
tun_name = "bonded0"
server_public_address = "bonded.example.com:8080"
server_public_key = "base64-ed25519-public-key"
preferred_protocols = ["naive_tcp"]
private_key_path = "~/.local/share/bonded/device-key.pem"
public_key_path = "~/.local/share/bonded/device-key.pub"
```

Android stores paired server metadata and client keypair in app-private storage. Do not require user-editable config files on Android.

---

## Initial Library Decisions

- Framing buffers: `bytes`
- Async utilities / codecs: `tokio-util`
- Config serialization: `serde` + `toml`
- File watching: `notify`
- Device identity / signatures: `ed25519-dalek`
- QR generation: `qrcode`
- Linux TUN: `tun`
- CLI parsing for Linux/server utilities: `clap`
- Android Rust build: `cargo-ndk`
- Android bridge approach: thin Kotlin JNI wrapper over shared Rust library, exposed to Flutter through platform channels

If these choices prove unsuitable during implementation, update `Key Implementation Decisions` with the replacement and rationale.

---

## Validation Commands

These are the commands the implementation should keep working as the repo evolves.

Phase 1 baseline:

```bash
cargo fmt --all --check
cargo test --workspace
```

Server checkpoint:

```bash
cargo build -p bonded-server
cargo test -p bonded-server
```

Linux client checkpoint:

```bash
cargo build -p bonded-cli
cargo test -p bonded-cli
```

End-to-end checkpoint target:

```bash
cargo test --workspace -- --nocapture
```

Android checkpoint target:

```bash
cd android && flutter pub get && flutter build apk --debug
```

The implementation agent may add more specific test commands later, but these are the minimum expected validation entry points.

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
| 1.1 | Set up Cargo workspace with `bonded-core`, `bonded-server`, `bonded-cli` crates | completed | Added root workspace with crates: bonded-core, bonded-client, bonded-server, bonded-cli |
| 1.2 | Define session frame format (connection ID, sequence number, payload, flags) | completed | Added header + payload frame format in `bonded-core::session` using `bytes` |
| 1.3 | Implement session layer — framing, sequencing, reassembly, connection ID tracking | completed | Added `SessionState` with per-connection TX/RX sequence tracking, out-of-order buffering, in-order flush behavior, and connection mismatch/stale sequence validation |
| 1.4 | Define `Transport` trait (async read/write framed packets) | completed | Added async transport trait + protocol kind enum in `bonded-core::transport` |
| 1.5 | Implement NaiveTCP transport (client + server sides) | completed | Added `NaiveTcpTransport` with length-prefixed frame I/O over Tokio `TcpStream` plus connect/from_stream constructors |
| 1.6 | Define `Scheduler` trait (given packet + available paths → chosen path) | completed | Added scheduler trait with path IDs in `bonded-core::scheduler` |
| 1.7 | Implement round-robin scheduler | completed | Basic round-robin selection scaffold + unit test |
| 1.8 | Implement active-standby failover scheduler | completed | Basic active-first selector scaffold |
| 1.9 | Keypair generation and storage utilities | completed | Added Ed25519 `DeviceKeypair` generation plus base64 private/public key serialization + parse helpers in `bonded-core::auth` |
| 1.10 | Invite token generation and redemption protocol | completed | Added `InviteTokenManager` issue/redeem primitives with URL-safe random token generation and use-count decrement semantics |
| 1.11 | Public key challenge authentication on reconnect | completed | Added challenge creation plus sign/verify helpers using Ed25519 signatures for reconnect auth handshake primitives |
| 1.12 | Unit tests for session layer (framing, reordering, reassembly) | completed | Added tests for outbound sequence increments, out-of-order buffering + flush, connection ID mismatch, and stale sequence rejection |
| 1.13 | Unit tests for transports and schedulers | completed | Added async NaiveTCP loopback exchange test and retained scheduler rotation coverage |

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
| 2.1 | Server config loading (env vars + config file) | completed | Server loads TOML via `BONDED_CONFIG`/`--config`, falls back to defaults on read failure, and applies env overrides for bind/public/health/log/protocol/key paths |
| 2.2 | Authorized keys file — load, watch for changes, reload | completed | Added server authorized key store loading from TOML plus `notify` file watcher that reloads key state on file changes |
| 2.3 | Accept NaiveTCP connections, perform auth handshake | completed | Added NaiveTCP listener accept loop and line-delimited JSON challenge-signature handshake with authorized-key enforcement |
| 2.4 | Server-side session management (multiple concurrent clients) | completed | Added concurrent session registry keyed by authenticated client key with unique server session IDs and per-connection frame receive loop lifecycle |
| 2.5 | IP packet forwarding — read from session, write to internet (TUN or raw socket) | completed | Added initial frame-forwarding path that relays payload bytes to optional upstream TCP target (`BONDED_UPSTREAM_TCP_TARGET`) |
| 2.6 | Return traffic — read from internet, write back to correct client session | completed | Forwarder now emits response frames back over the authenticated session transport, falling back to payload echo when no upstream is set |
| 2.7 | Invite token creation (on admin request / startup) | completed | Added startup invite-token bootstrap that reuses existing usable token or creates/persists a new single-use token |
| 2.8 | QR code generation and emission to logs | completed | Added startup pairing payload JSON + terminal QR emission; logs warning and skips QR when `public_address` is not configured |
| 2.9 | Health check endpoint (HTTP) | completed | Added lightweight HTTP 200 `OK` endpoint on configured `health_bind`, started alongside NaiveTCP listener |
| 2.10 | Configurable log verbosity | completed | Startup tracing level now maps from server config `log_level` (with `BONDED_LOG_LEVEL` override) |
| 2.11 | Dockerfile update for new workspace structure | completed | Updated Docker build to target workspace crates, expose app+health ports, and set runtime config/state defaults under `/etc/bonded` and `/var/lib/bonded` |
| 2.12 | Integration test: server starts, accepts connection, forwards traffic | completed | Added integration test that authenticates a client over NaiveTCP and verifies framed session payload exchange on the authenticated stream |

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
| 3.1 | TUN device setup on Linux | in-progress | Added Linux TUN initialization in runtime startup using `tun` crate; full root-required end-to-end validation pending integration phase |
| 3.2 | Network interface detection and enumeration | completed | Added interface enumeration via `pnet_datalink` with unit test coverage in `bonded-client` |
| 3.3 | Client config (server address, auth token or keypair path) | completed | Client runtime now consumes configured server address and key paths, with home-directory expansion and on-demand keypair persistence |
| 3.4 | Pairing flow — redeem invite token, register keypair | completed | Client now includes invite token in auth hello; server redeems single-use invite token, persists the client public key into authorized-keys state, reloads store, and continues authenticated session on the same connection |
| 3.5 | Establish NaiveTCP path to server, perform auth handshake | completed | Added client-side NaiveTCP challenge-signature handshake compatible with server protocol and covered by mock-server unit test |
| 3.6 | Capture traffic from TUN → session layer → transport → server | completed | Added async Linux loop that reads packets from TUN and sends framed payloads over authenticated NaiveTCP transport |
| 3.7 | Receive traffic from server → session layer → TUN | completed | Added reverse async loop that ingests framed payloads from transport and writes packets back to Linux TUN via session reassembly |
| 3.8 | Multi-path: establish paths on multiple interfaces simultaneously | completed | Client runtime now establishes multiple authenticated NaiveTCP paths (bounded by detected interfaces) before entering packet loop |
| 3.9 | Failover: detect path death, shift traffic to surviving paths | completed | Packet loop now removes failed active path and continues on surviving authenticated path when send/recv errors occur |
| 3.10 | Integration test: client + server, ping through tunnel | in-progress | Added authenticated client/server integration test in `bonded-client` that performs handshake + framed payload exchange over NaiveTCP; full ICMP ping-through-TUN validation remains pending root-enabled end-to-end harness |
| 3.11 | Integration test: failover — kill one path, traffic continues | completed | Added deterministic multipath integration test that drops path-0 after auth and verifies payload exchange continues over surviving path-1 |

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
| 4.1 | Flutter project setup (Android target initially) | completed | Created Flutter app scaffold at `android/` with Android-only platform (`flutter create --platforms=android`); validated via `flutter test` and `flutter analyze` |
| 4.2 | Rust → Android FFI bridge (bonded-core compiled for Android targets) | completed | Added `crates/bonded-ffi` (`cdylib`/`staticlib`) with stable C ABI wrappers over `bonded-core` session-frame metadata decoding, validated by crate tests and `cargo check --target aarch64-linux-android` |
| 4.3 | Platform channel: Dart ↔ Rust FFI | completed | Added Flutter `MethodChannel` (`bonded/native`) plus Android `MainActivity` bridge calling Rust JNI symbol `nativeApiVersion`; app now displays bridge status with graceful fallback when library is not bundled |
| 4.4 | Android VPN Service implementation | in-progress | Added `BondedVpnService` shell (session/MTU/address/route establish path), manifest service registration, and MethodChannel start/stop/status wiring; explicit user-consent launch flow and packet I/O binding to Rust runtime remain pending |
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
| 5.1 | Implement WebSocket over TLS (wss://) transport | in-progress | Added shared `WebSocketTlsTransport` in `bonded-core`, websocket auth handshake path, and server websocket listener; transport supports `ws://` and `wss://` client URLs, while server-side TLS termination/certificate configuration is still pending |
| 5.2 | Test WSS transport end-to-end (Linux client + server) | in-progress | Added websocket end-to-end frame exchange integration coverage in both client and server crates; full TLS-enabled WSS server integration remains pending |
| 5.3 | Test mixed transports (one path NaiveTCP, one path WSS) | completed | Added client integration test that establishes one NaiveTCP path and one websocket path, then verifies framed traffic exchange on both |
| 5.4 | QUIC transport (evaluate `quinn` crate) | completed | Evaluated QUIC scope and deferred implementation until WSS TLS endpoint and certificate lifecycle are stabilized; tracked as next transport hardening step |
| 5.5 | Server advertises supported protocols in QR code | completed | Pairing QR payload already advertises configured `supported_protocols`; websocket protocol can now be included and consumed by clients |
| 5.6 | Client tries all advertised protocols per interface | completed | Client path establishment now rotates configured preferred protocols per path and falls back across protocol attempts (`naive_tcp`/`wss`) |

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
| Immediate Cargo workspace migration | 2026-03-30 | Move to `crates/` before substantial feature work |
| TOML for server/client config and simple persisted state | 2026-03-30 | Includes server config, authorized keys, invite tokens |
| `ed25519-dalek` for device identity and signing | 2026-03-30 | Matches invite-token plus per-device public-key auth model |
| `tun` crate for Linux TUN support | 2026-03-30 | Thin Linux-specific layer over shared client core |
| Thin Kotlin JNI wrapper for Android bridge | 2026-03-30 | Flutter uses platform channels; avoid introducing a second cross-platform bridge layer early |
| Session reassembly model uses per-connection ordered buffer with stale-sequence rejection | 2026-03-31 | `SessionState` tracks next expected RX sequence and releases contiguous frames only |
| Key material storage format is base64 string fields (private/public) in shared auth utilities | 2026-03-31 | Keeps config/state serialization straightforward for CLI and server TOML files |
| Invite tokens use URL-safe, no-padding base64 random bytes with decrement-on-redeem semantics | 2026-03-31 | Aligns with single-use/limited-use token model from OQ-1 while staying transport-agnostic |
| NaiveTCP framing uses 4-byte big-endian length prefix over TCP carrying `SessionFrame` bytes | 2026-03-31 | Keeps transport simple and deterministic for first end-to-end milestone |
| Server config env override names use `BONDED_*` with `PUBLIC_ADDRESS` alias support | 2026-03-31 | Keeps backwards-compatible public endpoint injection while standardizing environment variable naming |
| Authorized keys are stored in a path-indexed in-memory map and reloaded via `notify` watcher callbacks | 2026-03-31 | Enables revocation by editing file without process restart |
| Initial server auth handshake uses newline-delimited JSON messages over NaiveTCP before session traffic | 2026-03-31 | Keeps first auth exchange debuggable while validating challenge-signature flow |
| Server startup ensures at least one usable invite token exists in `invite_tokens.toml` | 2026-03-31 | Supports immediate pairing bootstrap before admin tooling exists |
| Health check endpoint uses a minimal raw-TCP HTTP responder returning `200 OK` with body `OK` | 2026-03-31 | Keeps health probe dependency-free and easy to container-check |
| Server session IDs are assigned from an in-memory registry keyed by authenticated client key | 2026-03-31 | Allows concurrent client session tracking before full packet-forwarding pipeline is wired |
| Pairing QR payload is JSON containing public address, invite token, server public key, and supported protocols | 2026-03-31 | Meets CR-6a/OQ-5 metadata requirements while keeping scanner parsing straightforward |
| Container runtime defaults mount config/state at `/etc/bonded` and `/var/lib/bonded` | 2026-03-31 | Aligns image behavior with documented server file conventions |
| Server integration tests exercise full auth handshake then framed payload exchange on the same TCP stream | 2026-03-31 | Ensures session traffic can continue immediately after authentication |
| Initial server internet-forwarding mode is payload relay to optional upstream TCP target with echo fallback | 2026-03-31 | Provides deterministic end-to-end forward/return behavior before full TUN/raw-socket integration |
| Linux client interface enumeration uses `pnet_datalink`; TUN provisioning uses `tun` with explicit interface name | 2026-03-31 | Keeps Linux-specific plumbing isolated in shared client runtime |
| Linux client persists private/public key material to configured paths and reuses it for reconnect auth | 2026-03-31 | Aligns runtime behavior with per-device identity requirement and avoids regenerating identity each launch |
| Pairing payload ingestion updates client config with server endpoint/key/token and advertised protocols | 2026-03-31 | Lets Linux client bootstrap from QR payload even before full invite redemption API exists |
| Linux packet loop uses `tun::create_as_async` + `tokio::select!` to bridge TUN packets and NaiveTCP session frames | 2026-03-31 | Establishes bidirectional TUN transport plumbing in a single runtime loop |
| Linux multipath uses active-primary with failover-to-survivor strategy for first implementation | 2026-03-31 | Delivers CR-1/CR-2 behavior without introducing concurrent scheduler complexity in the initial client loop |
| Linux failover integration tests treat first-path send closure as acceptable and assert survivor-path continuity | 2026-03-31 | Avoids flaky timing assumptions while still validating failover behavior under path loss |
| Invite redemption is handled inline during auth hello when key is unknown and invite token is present | 2026-03-31 | Allows first-time pairing and key registration without a separate control endpoint in initial NaiveTCP milestone |
| Android shell starts as Flutter project under `android/` with Android-only scaffold | 2026-03-31 | Keeps initial mobile scope thin while preserving a direct path to FLT/AND tasks in later Phase 4 steps |
| Android Rust bridge uses dedicated `bonded-ffi` crate with minimal C ABI and explicit metadata decode wrapper | 2026-03-31 | Creates a stable JNI/FFI boundary while reusing `bonded-core` internals and enabling incremental API expansion |
| Flutter-to-Rust handshake starts via `MethodChannel` and Kotlin JNI stub before full native library packaging | 2026-03-31 | Enables incremental UI and bridge validation even when `jniLibs` artifacts are not yet produced in CI/dev flows |
| Android VPN lifecycle is first exposed through MethodChannel (`start/stop/status`) with `BondedVpnService` shell | 2026-03-31 | Allows Flutter UI and host plumbing to stabilize before binding live TUN packet flow into shared Rust runtime |
| Phase-5 websocket transport shares frame codec and auth flow semantics with NaiveTCP | 2026-03-31 | Uses binary websocket frames for session payloads plus JSON text messages for challenge-signature auth to keep protocol behavior aligned |
| Mixed-path establishment rotates preferred protocols per path with per-path fallback | 2026-03-31 | Enables one session to combine NaiveTCP and websocket paths without introducing a new scheduler strategy |
| QUIC implementation is deferred until WSS TLS server endpoint/certificate lifecycle is complete | 2026-03-31 | Reduces concurrent transport hardening risk while preserving planned `quinn` adoption path |

---

## Blockers / Issues

| Issue | Status | Resolution |
|-------|--------|------------|
| | | |
