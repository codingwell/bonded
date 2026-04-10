# Implementation Plan — Server, Linux Client, Android Client

**Status:** In Progress
**Last Updated:** 2026-04-10 (session 28)

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
status_bind = "0.0.0.0:8082"
public_address = "bonded.example.com:8080"
health_bind = "0.0.0.0:8081"
log_level = "info"
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
| 2.1 | Server config loading (env vars + config file) | completed | Server loads TOML via `BONDED_CONFIG`/`--config`, falls back to defaults on read failure, applies env overrides for bind/public/health/log/key paths, and now deserializes partial `server.toml` files by filling missing options from defaults |
| 2.2 | Authorized keys file — load, watch for changes, reload | completed | Added server authorized key store loading from TOML plus `notify` watcher callbacks; hardened watcher to ignore non-mutating access events and debounce rapid bursts to avoid self-triggered tight reload loops; server startup pre-creates missing state files/directories so operators only need to provide `server.toml` |
| 2.3 | Accept NaiveTCP connections, perform auth handshake | completed | Added NaiveTCP listener accept loop and line-delimited JSON challenge-signature handshake with authorized-key enforcement |
| 2.4 | Server-side session management (multiple concurrent clients) | completed | Added concurrent session registry keyed by authenticated client key with unique server session IDs and per-connection frame receive loop lifecycle; improved per-session runtime by offloading frame forwarding into sharded worker queues so slow flow forwarding no longer blocks the transport receive loop; heartbeat handling now only consumes empty-payload `FLAG_PING` frames so data frames with incidental ping-bit are forwarded instead of dropped |
| 2.5 | IP packet forwarding — read from session, write to internet (TUN or raw socket) | in-progress | Added user-space internet egress for IPv4+UDP and IPv4 ICMP echo frames: UDP payloads are relayed via `UdpSocket`; ICMP echo requests are relayed via IPv4 ICMP datagram sockets (`socket2`) with echo-id/sequence matching; retains optional upstream TCP relay fallback for non-IP payloads; ICMP echo traffic now uses a dedicated bounded per-session worker queue (128 frames) so ping bursts are isolated from TCP/UDP forwarding. Added TUN runtime in `bonded-server` with config/env-gated `forwarding_mode=tun`, automatic Linux TUN interface provisioning (`tun_name`, `tun_cidr`, `tun_mtu`), automatic iptables NAT/FORWARD rule installation, default-route egress auto-detection from `/proc/net/route`, and best-effort teardown/restoration on process exit. Added usable first data path via `tun_bridge`: naive-tcp client frames are injected into TUN, return packets are routed back to sessions via destination-IP mapping with per-session server sequence generation; websocket listener is currently disabled in tun mode and remains a follow-up. |
| 2.6 | Return traffic — read from internet, write back to correct client session | completed | Added checksum-correct IPv4 response synthesis for UDP and ICMP echo reply traffic, and wired `forward_frame` to return `None` on per-protocol timeout/no-response so tunneled packets are not spuriously echoed |
| 2.7 | Invite token creation (on admin request / startup) | completed | Added startup invite-token bootstrap that reuses existing usable token or creates/persists a new single-use token |
| 2.8 | QR code generation and emission to logs | completed | Added startup pairing payload JSON + terminal QR emission; logs warning and skips QR when `public_address` is not configured |
| 2.9 | Health check endpoint (HTTP) | completed | Added lightweight HTTP 200 `OK` endpoint on configured `health_bind`, started alongside NaiveTCP listener |
| 2.10 | Configurable log verbosity | completed | Startup tracing level now maps from server config `log_level` (with `BONDED_LOG_LEVEL` override) |
| 2.11 | Dockerfile update for new workspace structure | completed | Updated Docker build to target workspace crates, expose app+health ports, and set runtime config/state defaults under `/etc/bonded` and `/var/lib/bonded` |
| 2.12 | Integration test: server starts, accepts connection, forwards traffic | completed | Added integration test that authenticates a client over NaiveTCP and verifies framed session payload exchange on the authenticated stream |
| 2.13 | Rust-only localhost E2E DNS diagnostic harness | completed | Added ignored/manual `bonded-server` integration test that boots `run_server` on localhost, connects using `bonded-client::establish_naive_tcp_session`, injects synthetic IPv4 UDP DNS query packet to `8.8.8.8:53`, and asserts/prints response-path diagnostics |
| 2.14 | Rust-only localhost E2E HTTP diagnostic harness | completed | Added ignored/manual `bonded-server` integration test that boots `run_server` on localhost, resolves `example.com`, drives synthetic IPv4 TCP handshake + HTTP GET over packet relay, and asserts a valid HTTP status line in returned payload |
| 2.15 | Rust-only localhost E2E SMTP diagnostic harness | completed | Added ignored/manual `bonded-server` integration test that boots `run_server` on localhost, resolves `smtp.gmail.com:587`, drives synthetic IPv4 TCP handshake, sends SMTP `EHLO` and `QUIT`, and asserts SMTP reply codes in returned payload |
| 2.16 | UDP flow sessions with idle timeout and async return path | completed | Replaced one-shot UDP forwarding with per-session flow table keyed by 4-tuple; each flow now uses a persistent connected ephemeral UDP socket, stays alive for 4 minutes since last client packet, and forwards all upstream UDP packets back to the client asynchronously while active |
| 2.17 | Status webpage endpoint for live connection state | completed | Added dedicated status listener (`status_bind`, env override `BONDED_STATUS_BIND`) with a live HTML dashboard and `/api/status` JSON endpoint; the page polls REST data every 2s instead of full-page refreshes and now shows per-flow packet counts in both directions for active UDP/TCP connections alongside authenticated sessions and recent ICMP probe outcomes |

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
| 4.4 | Android VPN Service implementation | in-progress | Added `BondedVpnService` shell (session/MTU/address/route establish path), foreground/background lifecycle wiring, manifest service registration, and MethodChannel start/stop/status wiring; explicit user-consent launch flow is implemented via native permission callback; VPN loop now submits outbound TUN packets to Rust JNI and polls inbound JNI packets; added paired-server persistence on Android plus a Rust single-path NaiveTCP session worker that redeems invite tokens, persists key material under app storage, bridges outbound/inbound packet queues, and exposes session-health snapshots back to Kotlin/Flutter for UI status updates; paired-server configuration edits and deletion now persist through platform channels, and the home list refreshes after configuration changes; Android 14/15 foreground startup now declares `specialUse` FGS type in the manifest and passes `FOREGROUND_SERVICE_TYPE_SPECIAL_USE` to `startForeground()` to satisfy VPN background startup enforcement; DNS servers (8.8.8.8, 1.1.1.1) added to VPN builder; routing-loop deadlock fixed via `VpnService.protect()` callback from Rust over JNI; `JNI_OnLoad`/`ANDROID_JVM` pattern used to enable protect calls from Rust threads; session snapshot extended with `outboundBytes`, `inboundBytes`, `connectedAtMs`; dashboard UI rewritten with bytes/uptime display, error banner, and improved connect/disconnect button; home screen adds per-server quick connect/disconnect icon buttons and live "Connected" chip; outbound packet loop now uses a bounded pending queue in Kotlin so transient native-session restart gaps buffer packets instead of repeatedly rejecting/dropping them; VPN builder now disallows the app package (`addDisallowedApplication(packageName)`) so control-plane sockets bypass capture, and Android client path setup no longer hard-fails on `protect(fd)=false` |
| 4.5 | Multi-network support (Wi-Fi + Cellular simultaneously) | in-progress | Added Android `ConnectivityManager.requestNetwork()`-based path manager that actively requests Wi-Fi/cellular/ethernet networks, derives per-network local bind addresses from `LinkProperties`, and feeds those addresses into the shared Rust client so NaiveTCP paths bind to distinct local IPs; `BondedVpnService` now restarts the native session when the active network set changes and surfaces active-path count back to the dashboard; client transport establishment now degrades to a single connected path when additional paths fail instead of hard-failing session startup |
| 4.6 | QR code scanner screen | completed | Added `mobile_scanner` package with QRScannerScreen widget; includes Android camera permission request handling, camera preview, QR detection, duplicate-scan suppression during navigation, and JSON payload parsing |
| 4.7 | Pairing flow UI — scan QR, redeem token, store keypair | completed | Added `ServerPairingPayload` model, `PairingService` MethodChannel wrapper, and `PairingConfirmScreen` with server details display and redemption UI; updated QR parser to accept server-emitted `server_public_address` (with legacy `public_address` fallback) and reject payloads missing required fields, plus regression tests in `android/test/pairing_model_test.dart` |
| 4.8 | Connection status dashboard UI | completed | Added `DashboardScreen` with VPN toggle, status display, and connection details; added `HomeScreen` listing paired servers; updated main.dart with named routing for all screens |
| 4.9 | Server configuration screen | completed | Added ServerConfigScreen showing server details, supported protocols display, and save/delete actions; integrated with HomeScreen PopupMenuButton for server management |
| 4.10 | Background operation | completed | Completed MethodChannel/EventChannel wiring for `startBackgroundVpn`/`stopBackgroundVpn`/`isBackgroundVpnRunning`; `BondedVpnService` now supports Android foreground-service mode with persistent notification and emits background lifecycle events consumed by Dashboard UI |
| 4.11 | End-to-end test: Android → server → internet | in-progress | Added host-side `bonded-ffi` smoke test that redeems an invite token, starts the Android session runtime, queues an outbound packet, and verifies echoed inbound traffic over NaiveTCP; host-side client/runtime tests now also assert that requested local bind addresses are actually used for outbound session connections (`127.0.0.2` loopback source assertion), while full APK/device validation remains blocked by Maven DNS/network resolution in the dev container |
| 4.11 | End-to-end test: Android → server → internet | in-progress | Host-side FFI smoke tests pass (50/50 including bind-address assertion); `libbonded_ffi.so` built for arm64-v8a and x86_64 and placed in jniLibs; debug APK builds successfully; full device/emulator validation (actual VPN tunnel + internet traffic) requires a physical device or running emulator — remaining for device testing phase; added Android broadcast diagnostic action `com.bonded.bonded_app.TEST_VPN_STATUS` to log `BondedVpnService.isRunning()` + current session snapshot so DNS/UDP tests can be gated on explicit VPN-up evidence; applied Android protect-path mitigation (app disallowed from VPN, protect non-fatal on Android, protect-before-bind ordering) and rebuilt JNI libs + APK, but device run still times out path-0 connect with `deadline has elapsed`; latest explicit receiver tests now validate DNS target `unifi.g.codingwell.net` with expected IP `34.82.88.79`, while requested TCP probe to `codingwell.net:80` still times out after 10s even with app foregrounded |

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
| 5.1 | Implement WebSocket over TLS (wss://) transport | completed | Added shared `WebSocketTlsTransport` with TLS accept/connect support, plus server rustls-based WSS termination driven by configurable cert/key file paths (`BONDED_WEBSOCKET_TLS_CERT_FILE`, `BONDED_WEBSOCKET_TLS_KEY_FILE`) |
| 5.2 | Test WSS transport end-to-end (Linux client + server) | completed | Added TLS-enabled websocket integration test in `bonded-server` using self-signed cert trust bootstrap and authenticated framed traffic exchange over `wss://` |
| 5.3 | Test mixed transports (one path NaiveTCP, one path WSS) | completed | Added client integration test that establishes one NaiveTCP path and one websocket path, then verifies framed traffic exchange on both |
| 5.4 | QUIC transport (evaluate `quinn` crate) | completed | Evaluated QUIC scope and deferred implementation until WSS TLS endpoint and certificate lifecycle are stabilized; tracked as next transport hardening step |
| 5.5 | Server advertises supported protocols in QR code | completed | Updated design: pairing QR payload now excludes protocol metadata; protocol selection happens at VPN session startup via runtime transport negotiation/fallback |
| 5.6 | Client tries all advertised protocols per interface | completed | Client path establishment now rotates configured preferred protocols per path and falls back across protocol attempts (`naive_tcp`/`wss`) |

Acceptance gate:

- WSS transport functions end-to-end
- Mixed-protocol paths work in one session
- Supported protocols are attempted correctly at session startup

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
| Pairing QR payload is JSON containing only public address, invite token, and server public key | 2026-04-04 | Transport protocol metadata removed from pairing so clients negotiate protocols when starting VPN sessions |
| Container runtime defaults mount config/state at `/etc/bonded` and `/var/lib/bonded` | 2026-03-31 | Aligns image behavior with documented server file conventions |
| Server integration tests exercise full auth handshake then framed payload exchange on the same TCP stream | 2026-03-31 | Ensures session traffic can continue immediately after authentication |
| Initial server internet-forwarding mode is payload relay to optional upstream TCP target with echo fallback | 2026-03-31 | Provides deterministic end-to-end forward/return behavior before full TUN/raw-socket integration |
| Linux client interface enumeration uses `pnet_datalink`; TUN provisioning uses `tun` with explicit interface name | 2026-03-31 | Keeps Linux-specific plumbing isolated in shared client runtime |
| Linux client persists private/public key material to configured paths and reuses it for reconnect auth | 2026-03-31 | Aligns runtime behavior with per-device identity requirement and avoids regenerating identity each launch |
| Pairing payload ingestion updates client config with server endpoint/key/token only | 2026-04-04 | Prevents stale protocol hints from pairing and keeps transport negotiation runtime-driven |
| Linux packet loop uses `tun::create_as_async` + `tokio::select!` to bridge TUN packets and NaiveTCP session frames | 2026-03-31 | Establishes bidirectional TUN transport plumbing in a single runtime loop |
| Linux multipath uses active-primary with failover-to-survivor strategy for first implementation | 2026-03-31 | Delivers CR-1/CR-2 behavior without introducing concurrent scheduler complexity in the initial client loop |
| Linux failover integration tests treat first-path send closure as acceptable and assert survivor-path continuity | 2026-03-31 | Avoids flaky timing assumptions while still validating failover behavior under path loss |
| Invite redemption is handled inline during auth hello when key is unknown and invite token is present | 2026-03-31 | Allows first-time pairing and key registration without a separate control endpoint in initial NaiveTCP milestone |
| Android shell starts as Flutter project under `android/` with Android-only scaffold | 2026-03-31 | Keeps initial mobile scope thin while preserving a direct path to FLT/AND tasks in later Phase 4 steps |
| Android Rust bridge uses dedicated `bonded-ffi` crate with minimal C ABI and explicit metadata decode wrapper | 2026-03-31 | Creates a stable JNI/FFI boundary while reusing `bonded-core` internals and enabling incremental API expansion |
| Flutter-to-Rust handshake starts via `MethodChannel` and Kotlin JNI stub before full native library packaging | 2026-03-31 | Enables incremental UI and bridge validation even when `jniLibs` artifacts are not yet produced in CI/dev flows |
| Android VPN lifecycle is first exposed through MethodChannel (`start/stop/status`) with `BondedVpnService` shell | 2026-03-31 | Allows Flutter UI and host plumbing to stabilize before binding live TUN packet flow into shared Rust runtime |
| Android background mode uses `BondedVpnService` foreground-service startup plus EventChannel status streaming | 2026-03-31 | Satisfies long-running VPN requirements and keeps Flutter UI synchronized with native service lifecycle |
| Android VPN foreground startup uses `specialUse` FGS declaration and runtime type flag | 2026-04-01 | Target SDK 35 requires both manifest declaration/permission and `startForeground(..., type)`; `systemExempted` is reserved for specific configured VPN cases, so `specialUse` is the safe general Bonded app path |
| Android socket protect: `JNI_OnLoad` stores `JavaVM`; `nativeStartSession` stores `GlobalRef` to service; `protect_fd()` attaches worker thread as daemon and calls `vpnService.protect(fd)` via JNI before each TCP socket `connect()` | 2026-04-01 | Prevents routing loop where Rust session TCP sockets got captured by the VPN TUN, deadlocking transport path establishment |
| `SocketProtectFn` newtype wrapping `Arc<dyn Fn(i32) -> bool + Send + Sync>` added to `ClientConfig` as `#[serde(skip)]` field | 2026-04-01 | Allows Android-specific JNI protect callback to be injected without leaking platform concerns into the shared config parsing path |
| `establish_naive_tcp_session` now uses `TcpSocket` (not `TcpStream::connect`) to access raw fd before connecting | 2026-04-01 | Required to call `protect(fd)` before the OS assigns the socket to the VPN routing table via `connect()` |
| VPN builder adds `addDnsServer("8.8.8.8")` and `addDnsServer("1.1.1.1")` | 2026-04-01 | Without explicit DNS servers, hostname lookups fail when VPN captures the default route |
| Session snapshot tracks `outboundBytes`, `inboundBytes`, `connectedAtMs` (ms since epoch) updated per packet in the Rust session loop | 2026-04-01 | Enables dashboard display of bytes sent/received and connection uptime without Kotlin-side instrumentation |
| Android pairing metadata is stored in app `SharedPreferences`, while device key material is persisted by Rust under app-private files dir | 2026-03-31 | Keeps Flutter pairing UI simple and gives the native VPN service enough data to bootstrap reconnects without reusing invite tokens |
| Android VPN UI status is driven by Rust session snapshots polled by Kotlin service, not only service lifecycle flags | 2026-03-31 | Distinguishes VPN-service startup from actual transport/session connectivity in the dashboard and background events |
| Android multi-path currently steers NaiveTCP paths by binding each Rust socket to a local IP derived from Android `LinkProperties`, and restarts the native session when the active network set changes | 2026-03-31 | Preserves the shared Rust transport/session stack while giving Android concrete per-network path steering before a deeper socket-factory-based integration exists |
| Android cross-compilation configured via workspace-root `.cargo/config.toml` with NDK 26 linker/ar/CC/CXX/AR env vars per target | 2026-03-31 | `cc-rs` build scripts look for unversioned `aarch64-linux-android-clang`; explicit `CC_aarch64_linux_android` env var overrides that search; NDK 26.3.11579264 is the installed version; NDK 27 download attempted but incomplete |
| VPN notification icon changed from `android.R.drawable.stat_sys_vpn_ic` to `R.mipmap.ic_launcher` | 2026-03-31 | `stat_sys_vpn_ic` was removed from Android API 34; `R.mipmap.ic_launcher` is always present in Flutter-generated Android projects |
| Pre-compiled `libbonded_ffi.so` bundled in `jniLibs/arm64-v8a/` and `jniLibs/x86_64/` for debug builds | 2026-03-31 | Keeps Flutter Gradle build self-contained without requiring NDK in every CI/dev environment; `scripts/build-android-native.sh` automates rebuild on Rust changes |
| GitHub Actions artifact workflow builds both Docker image tarball and Android debug APK | 2026-03-31 | Added `.github/workflows/build-artifacts.yml`; Docker job exports `/tmp/bonded-server-image.tar`; Android job builds Rust JNI libs via `cargo-ndk`, runs `flutter build apk --debug`, and uploads APK artifact |
| Phase-5 websocket transport shares frame codec and auth flow semantics with NaiveTCP | 2026-03-31 | Uses binary websocket frames for session payloads plus JSON text messages for challenge-signature auth to keep protocol behavior aligned |
| Mixed-path establishment rotates preferred protocols per path with per-path fallback | 2026-03-31 | Enables one session to combine NaiveTCP and websocket paths without introducing a new scheduler strategy |
| QUIC implementation is deferred until WSS TLS server endpoint/certificate lifecycle is complete | 2026-03-31 | Reduces concurrent transport hardening risk while preserving planned `quinn` adoption path |
| Session forwarding sharding: 256 TCP flow shards and 16 UDP session shards per client session | 2026-04-08 | Reduces lock contention on per-session flow tables; each shard has its own Mutex<HashMap> so concurrent worker threads can access different flows in parallel without stalling; critical for supporting 50+ concurrent TCP connections without head-of-line blocking |
| Forwarding worker pool increased from 16 shards to 256 shards | 2026-04-08 | With 50+ concurrent connections, the 16-shard pool resulted in ~3 connections per shard causing head-of-line interference; 256 shards provides one worker per connection on average; ICMP remains on dedicated bounded queue (128 frames) per session to prevent ping storms from affecting TCP/UDP |
| Batch draining of response queue before select blocking | 2026-04-08 | Session send loops now pre-drain all available responses via try_recv() before blocking on tokio::select!; prevents artificial latency when multiple responses are queued from the 256 forwarding workers; critical for keeping ICMP/TCP response latency low when many connections are active |
| Server WSS termination uses rustls with PEM certificate/key configuration and optional enablement | 2026-03-31 | Websocket listener remains `ws://` when TLS files are unset and upgrades to `wss://` when both files are provided |
| WSS integration tests use generated self-signed certificates with explicit client trust roots | 2026-03-31 | Validates authenticated frame exchange over true TLS websocket without relying on external PKI in CI |
| Server startup pre-creates missing state files (`authorized_keys.toml`, `invite_tokens.toml`) and parent directories | 2026-04-01 | Ensures first boot succeeds with only `/etc/bonded/server.toml` present; keeps state-file defaults under configured paths (including `/var/lib/bonded`) |
| Authorized-keys watcher reloads only on mutating events and applies short debounce | 2026-04-01 | Prevents notify access/read event feedback loops and duplicate reload bursts when authorized-keys file is rewritten during pairing/auth flows |
| Server frame forwarder now performs user-space IPv4+UDP relay and response packet synthesis before fallback behavior | 2026-04-02 | Enables DNS/UDP tunnel round-trip without kernel NAT as first incremental gateway slice; TCP user-space flow tracking remains future work |
| Client multipath establishment now requires path 0 success but treats later-path failures as degradable warnings | 2026-04-02 | Prevents Android VPN session startup from collapsing when Wi-Fi+cellular dual-path setup partially fails; preserves failover architecture while prioritizing a working single-path tunnel |
| Android session startup diagnostics now preserve first transport-establish error and avoid clobbering it with downstream queue-closed noise | 2026-04-02 | `establish_transport_paths` now reports underlying timeout/connect/protect failures, Android socket protect failures are fatal, and FFI queue-closed updates keep prior `lastError` when already set |
| NaiveTCP client path establishment now always binds the socket to an ephemeral local wildcard address before VPN protect/connect | 2026-04-02 | Makes both explicit-bind and default paths follow bind -> protect -> connect ordering, aligning Android VPN socket-handling expectations and simplifying behavior across paths |
| Android VPN service now buffers outbound TUN packets during native-session restarts and flushes on reconnect | 2026-04-02 | Reduces `Native packet queue rejected outbound packet` spikes caused by short stop/start windows during recovery or network rebind; bounded queue avoids unbounded memory growth |
| Android socket-protect path now emits explicit protect(fd) success/failure diagnostics from both Kotlin and Rust layers | 2026-04-02 | JNI now calls `protectSocketForNative(fd)` (with fallback to `protect(fd)`), logging each result to distinguish true protect failures from downstream transport/auth disconnects |
| NaiveTCP session-frame receive path now fails fast on invalid tiny frame lengths and logs exact sizes for header-underflow decode errors | 2026-04-02 | Distinguishes malformed/corrupted framed data (`len < 16`) from generic transport disconnects and makes Android/server recovery diagnostics actionable |
| NaiveTCP auth handshake now reads newline-delimited JSON directly from TcpStream (byte-by-byte) instead of BufReader split/reunite | 2026-04-02 | Prevents buffered over-read during auth from consuming first framed session bytes, which could desynchronize length-prefix parsing and trigger `buffer too small for frame header` recovery loops |
| Android paired-server persistence is schema-tolerant across app updates | 2026-04-04 | `PairedServerStore` now tolerates malformed/partial entries, skips invalid records, and migrates legacy single-record preference keys into the current records array to avoid apparent unpairing after upgrades |
| Bind-aware path establishment now follows protocol negotiation order (including WebSocket) | 2026-04-04 | Removed special-case NaiveTCP pre-attempt for bound paths and added bind-aware WebSocket dialing so Android `wss` preference is honored when path bind addresses are present |
| Device-test workflow now gates DNS checks on explicit Android-side VPN state probe (`TEST_VPN_STATUS`) before running network diagnostics | 2026-04-02 | Avoids ambiguous results from DNS checks that run before VPN session establishment and keeps tunnel validation aligned with UDP-forwarding goals |
| Android network diagnostics now default DNS checks to `unifi.g.codingwell.net` with optional `expected_ip` assertion and use explicit component broadcasts for deterministic receiver execution | 2026-04-02 | Ensures DNS test intent validates a concrete expected answer (`34.82.88.79`) and avoids implicit-broadcast delivery ambiguity during adb-driven validation |
| Android VPN now disallows the app package from tunnel capture and treats `protect(fd)=false` as non-fatal on Android | 2026-04-02 | Prevents startup deadlocks when control-plane sockets would otherwise be captured by the VPN and removes brittle dependency on per-socket protect success |
| Android launcher icon generation is managed via `flutter_launcher_icons` using workspace-root `icon.png` | 2026-04-03 | Keeps launcher assets reproducible across densities and Android adaptive-icon resources instead of hand-editing mipmap files |
| Rust-only DNS tunnel diagnostics use an ignored localhost integration test in `bonded-server` that runs real server+client crates and injects synthetic UDP DNS probes | 2026-04-03 | Enables reproducible E2E debugging of server/client forwarding behavior without Android app/device dependencies |
| Server frame forwarder now handles IPv4 ICMP echo request/reply in addition to UDP | 2026-04-03 | Uses Linux-compatible IPv4 ICMP datagram sockets through `socket2`, matches echo identifier/sequence, and synthesizes IPv4 ICMP reply packets with recomputed checksums for client return path |
| UDP forwarding now uses per-client-session long-lived flow sockets with 4-minute idle expiry | 2026-04-06 | Each UDP 4-tuple creates/reuses a connected ephemeral socket; server pushes all remote datagrams back to client asynchronously until no client packet is seen for 4 minutes |
| Server exposes a lightweight status HTML endpoint on a dedicated bind (`status_bind`) | 2026-04-06 | Page auto-refreshes and reports authenticated sessions plus active UDP/TCP flow tables and recent ICMP outcomes to aid runtime diagnostics during tunnel bring-up |
| Per-session frame forwarding now runs through sharded async workers and a response queue (16 shards by connection ID) | 2026-04-08 | Reduces head-of-line blocking where one slow forward (for example upstream TCP timeout) could stall unrelated flows in the same session; preserves serialized transport writes in the main session loop |
| Per-session ICMP echo traffic is isolated onto a dedicated bounded worker queue | 2026-04-08 | IPv4 ICMP echo requests bypass the generic forwarding shards and use one dedicated per-session worker with a 128-frame queue; prevents ping storms from monopolizing normal forwarding workers and causing unrelated flow timeouts |
| Server heartbeat filter only treats empty-payload ping-flag frames as control messages | 2026-04-08 | Prevents accidental data-plane stalls where non-empty frames carrying `FLAG_PING` were consumed as heartbeats and never reached TCP/UDP/ICMP forwarding or status trackers |
| Server now supports config-gated Linux TUN runtime bootstrap/cleanup inside container namespace | 2026-04-10 | `forwarding_mode=tun` provisions `tun_name`/`tun_cidr`/`tun_mtu`, auto-detects default egress interface (or uses override), enables `ip_forward`, installs iptables MASQUERADE/FORWARD rules, and restores/removes state at shutdown to minimize manual Docker networking setup |
| TUN bridge routes naive-tcp session frames to Linux TUN and sends return packets back by destination-IP ownership map | 2026-04-10 | `tun_bridge` now tracks session registration and client source-IP ownership, writes client payload packets into TUN, reads return packets from TUN, and emits framed responses with per-session server sequence counters; this makes `forwarding_mode=tun` usable for naive-tcp transport in containerized deployments |

---

## Blockers / Issues

| Issue | Status | Resolution |
|-------|--------|------------|
| Android `flutter build apk --debug` fails in dev container due Maven hostname resolution (`repo.maven.apache.org: No address associated with hostname`) while resolving `mobile_scanner` Gradle dependencies | **resolved** | Maven is accessible; APK builds successfully in ~3s (Gradle cache warm). Fixed notification icon (`stat_sys_vpn_ic` removed in API 34, replaced with `R.mipmap.ic_launcher`). APK is at `android/build/app/outputs/flutter-apk/app-debug.apk`. |
| Android-target Rust validation for `bonded-ffi` is blocked in this dev container because `aarch64-linux-android-clang` is unavailable while building `aws-lc-sys` | **resolved** | NDK 26.3.11579264 was already installed; configured `.cargo/config.toml` with per-target `linker`/`ar` paths and `CC_*`/`CXX_*`/`AR_*` env vars for `cc-rs`; `cargo build --target aarch64-linux-android -p bonded-ffi --release` now produces `libbonded_ffi.so`; both arm64-v8a and x86_64 `.so` files are committed to `android/android/app/src/main/jniLibs/`. |
| Android VPN connect crashed on API 35 with `MissingForegroundServiceTypeException` | **resolved** | Declared `android:foregroundServiceType="specialUse"`, added `FOREGROUND_SERVICE_SPECIAL_USE` permission and special-use subtype property, and updated `BondedVpnService` to call `startForeground(..., ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)`. |
| VPN-connected-but-no-traffic: two root causes — (A) no DNS in VPN builder, (B) routing-loop deadlock when Rust session TCP sockets were captured by the VPN TUN before transport paths could be established | **resolved** | (A) fixed by adding `addDnsServer()` calls; (B) fixed by calling `VpnService.protect(fd)` from Rust via stored JVM/GlobalRef before each `socket.connect()`. |
| Server internet egress was previously payload-echo/TCP-relay oriented and could not return real DNS/UDP tunnel traffic | **resolved** | Implemented user-space IPv4+UDP relay in `frame_forwarder` with checksum-correct packet synthesis for return traffic; validated with new unit test `forwarder_relays_ipv4_udp_payload_and_builds_response_packet` and full `bonded-server` test suite. |
| Flutter update remains blocked in this dev container due outbound network restrictions (`storage.googleapis.com` and `pub.dev`/`pub.flutter-io.cn` are not reachable) | **open** | `flutter upgrade --force` fails downloading Dart SDK; manual SDK restore attempt hit flutter-tool dependency refresh limits because hosted pub packages for newer toolchain metadata cannot be fetched from this environment. |
| Android VPN runtime still intermittently loops in `connecting` with zero session counters on device despite active TUN reads | **open** | Retested after mitigations (app disallowed from VPN, protect non-fatal on Android, protect-before-bind ordering) and rebuilt JNI libs/APK. Result: `protect(fd)` still reports false, path-0 still fails with `deadline has elapsed`, `TEST_VPN_STATUS` remains `running=false/state=connecting`, and app-level `TEST_TCP` to `charter.codingwell.net:8080` times out in this environment. |
| Android broadcast-started VPN reports running in app status but is not visible as active in system UI | **resolved** | Root cause: `Builder.establish()` can return null when VPN permission is missing/revoked; service previously logged success without null-check and status logic masked this. Fixed by failing fast when establish returns null and restoring strict `isRunning()` semantics. Current device run shows explicit error: `VpnService.Builder.establish() returned null (VPN permission missing or revoked)`. |

---

## Phase 4 Android UI Implementation Session (2026-03-31)

Completed QR scanner, pairing flow, and dashboard UI:

| Item | Details |
|------|---------|
| 4.6 QR Scanner | `mobile_scanner` Flutter package with camera preview, QR detection via native platform channels, JSON payload parsing via `jsonDecode`; scanning overlay with framing guides |
| 4.7 Pairing Flow | `ServerPairingPayload` model parsing QR JSON, `PairingService` MethodChannel wrapper for Rust-side token redemption, `PairingConfirmScreen` displaying server details with confirm/cancel buttons and error display |
| 4.8 Dashboard | `DashboardScreen` with VPN status indicator, connect/disconnect toggle, connection details display, and per-device ID tracking; `HomeScreen` listing paired servers with navigation options |
| Navigation | Main.dart updated with `initialRoute`, `routes` map for static screens, `onGenerateRoute` for dynamic screens with arguments (ServerPairingPayload, deviceId, etc.); supports deep linking |
| Analysis | `flutter analyze` clean; `flutter pub get` successful with mobile_scanner ^5.2.0; all async BuildContext gaps protected with `mounted` checks |
