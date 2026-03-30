# Platform-Specific Requirements — Bonded

**Status:** Draft
**Last Updated:** 2026-03-30

## Server (Rust + Docker)

| ID    | Requirement                                           | Priority |
| ----- | ----------------------------------------------------- | -------- |
| SRV-1 | Run as a single Docker container                      | Must     |
| SRV-2 | Accept connections from multiple clients              | Must     |
| SRV-3 | Forward aggregated traffic to the internet            | Must     |
| SRV-4 | Encryption for all client connections                  | Must     |
| SRV-5 | Configurable via environment variables or config file | Must     |
| SRV-6 | Health check endpoint                                 | Should   |
| SRV-7 | Logging with configurable verbosity                   | Should   |
| SRV-8 | Minimal resource footprint                            | Should   |
| SRV-9 | Generate and emit QR code to container logs on startup | Must     |
| SRV-10 | Invite-based device pairing, key storage, and per-device revocation | Must     |
| SRV-11 | Authorized client keys stored in a config file; reload on change | Must     |
| SRV-12 | Session layer: virtual connection IDs, packet sequencing, reassembly | Must |
| SRV-13 | Pluggable transport protocol support                  | Must     |
| SRV-14 | Pluggable path scheduler                              | Must     |
| SRV-15 | Require configured public address for QR code generation | Must     |

## Android Client

| ID    | Requirement                                    | Priority |
| ----- | ---------------------------------------------- | -------- |
| AND-1 | Detect and use Wi-Fi + Cellular simultaneously | Must     |
| AND-2 | Run as a VPN service (Android VPN API)         | Must     |
| AND-3 | Route server traffic over all available networks (Wi-Fi + Cellular) while VPN is active | Must     |
| AND-4 | Background operation                           | Must     |
| AND-5 | Bidirectional peer discovery and connection sharing on the local network | Must     |
| AND-6 | Battery usage optimization                     | Should   |
| AND-7 | Quick settings tile for toggling               | Nice     |
| AND-8 | Support Android 10+ (API 29+)                  | Must     |
| AND-9 | Scan QR code to pair with server               | Must     |

## iOS Client

| ID    | Requirement                                    | Priority |
| ----- | ---------------------------------------------- | -------- |
| IOS-1 | Detect and use Wi-Fi + Cellular simultaneously | Must     |
| IOS-2 | Network Extension (Packet Tunnel Provider)     | Must     |
| IOS-3 | Background operation within iOS limits         | Must     |
| IOS-4 | Bidirectional peer discovery and connection sharing on the local network | Must     |
| IOS-5 | Support iOS 15+                                | Must     |
| IOS-6 | Scan QR code to pair with server               | Must     |

## Windows Client

| ID    | Requirement                             | Priority |
| ----- | --------------------------------------- | -------- |
| WIN-1 | Detect all available network interfaces | Must     |
| WIN-2 | Bidirectional peer discovery and connection sharing on the local network | Must     |
| WIN-3 | System tray operation                   | Should   |
| WIN-4 | Support Windows 10 21H2+                | Must     |
| WIN-5 | Virtual network adapter or proxy mode   | Must     |
| WIN-6 | Pair with server via manual entry or paste of connection details | Must     |

## macOS Client

| ID    | Requirement                             | Priority |
| ----- | --------------------------------------- | -------- |
| MAC-1 | Detect all available network interfaces | Must     |
| MAC-2 | Bidirectional peer discovery and connection sharing on the local network | Must     |
| MAC-3 | Menu bar operation                      | Should   |
| MAC-4 | Support macOS 12+ (Monterey)            | Must     |
| MAC-5 | Network Extension support               | Must     |
| MAC-6 | Pair with server via manual entry or paste of connection details | Must     |

## Linux Client

| ID    | Requirement                             | Priority |
| ----- | --------------------------------------- | -------- |
| LNX-1 | Detect all available network interfaces | Must     |
| LNX-2 | CLI operation (no GUI required)         | Must     |
| LNX-3 | TUN device for traffic capture          | Must     |
| LNX-4 | Bidirectional peer discovery and connection sharing on the local network | Must     |
| LNX-5 | Serve as development and integration test client | Must     |

## Cross-Platform Client (Flutter)

Flutter covers Android, iOS, Windows, and macOS. The Linux client is a standalone Rust CLI and is not part of the Flutter app.

| ID    | Requirement                               | Priority |
| ----- | ----------------------------------------- | -------- |
| FLT-1 | Shared UI across all platforms            | Must     |
| FLT-2 | Platform channels for native network APIs | Must     |
| FLT-3 | Connection status dashboard               | Must     |
| FLT-4 | Server configuration screen               | Must     |
| FLT-5 | Per-interface statistics                  | Should   |
| FLT-6 | Dark/light theme                          | Nice     |
| FLT-7 | QR code scanner for server pairing        | Must     |
| FLT-8 | Session layer integration via platform channels | Must |
