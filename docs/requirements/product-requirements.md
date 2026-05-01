# Product Requirements — Bonded

**Status:** Draft
**Last Updated:** 2026-04-01

## Vision

Bonded is an open source tool that aggregates multiple internet connections to provide a more robust, reliable, and resilient network experience. Users run a client on their device and connect through a server that combines traffic from all available network interfaces.

## Problem Statement

Single internet connections are unreliable — Wi-Fi drops, cellular is spotty, wired connections fail. Users with access to multiple connections (e.g., Wi-Fi + cellular on a phone, or Wi-Fi + Ethernet on a laptop) have no simple way to use them simultaneously for improved reliability and throughput.

## Target Users

- Mobile users who need reliable connectivity (field workers, travelers)
- Remote workers with unstable home internet
- Power users who want to bond multiple ISP connections
- Organizations needing resilient client connectivity

## Core Requirements

### CR-1: Multi-Interface Aggregation

The client MUST be able to utilize multiple network interfaces simultaneously to route traffic through the server.

### CR-2: Seamless Failover

When one connection drops, traffic MUST seamlessly shift to remaining connections without interrupting active sessions.

### CR-3: Cross-Platform Client

The client MUST support Android, iOS, Windows, macOS, and Linux.

### CR-4: Self-Hosted Server

The server MUST be deployable as a Docker container on user-controlled infrastructure.

### CR-5: Connection Security

All traffic between client and server MUST be encrypted.

### CR-6: Minimal Configuration

The client SHOULD require minimal setup — ideally a single QR code scan or a server address and pairing token.

For server operators, the default first-boot flow SHOULD only require creating `server.toml`; missing state files for authorized keys and invite tokens should be initialized automatically at startup.

### CR-6a: QR Code Pairing

The server MUST emit a QR code to its container logs on startup that encodes the connection details needed for pairing. The QR code payload MUST include the server's public address, port, an invite token, the server public key, and the list of supported transport protocols. The server MUST require a configured public address (e.g., environment variable); if not set, the server MUST log a warning and skip QR code generation. Mobile clients MUST be able to scan this QR code to configure their server connection automatically.

### CR-7: Peer Connection Sharing

Clients MUST be able to discover other authenticated clients on the same local network and bidirectionally share internet connections as additional paths to the server. Either peer MAY act as a provider or consumer of connectivity simultaneously.

### CR-8: Extensible Transport Protocols

The client and server MUST support a pluggable set of transport protocols. Adding a new protocol MUST NOT require changes to the core aggregation or failover logic.

The following protocols are candidates for evaluation:

| Protocol | Purpose | Priority |
|---|---|---|
| NaiveTCP | Development and testing | v1 |
| WebSocket over TLS (wss://) | Firewall resilience — indistinguishable from HTTPS on port 443 | v1 |
| QUIC | Low-latency, multiplexed, UDP-based transport | v1 |
| ShadowSocks | Firewall/DPI evasion via encrypted proxy protocol | v1 if feasible |
| obfs4 | Strong censorship resistance — traffic looks like random bytes to DPI | Future |

At least two protocols (NaiveTCP for testing and one production protocol) MUST be supported in v1.

The server MUST advertise its supported protocols to clients (via the QR code and/or configuration). Clients MUST attempt to establish paths using supported protocols independently per interface. Different paths MAY use different protocols simultaneously. No protocol negotiation handshake is required — whatever connects becomes a path in the session layer (CR-10).

### CR-9: Authentication and Device Identity

Each client device MUST have a unique identity that the server can independently authenticate and manage.

- The server MUST support a pairing flow that allows new devices to register without manual configuration of keys or certificates.
- The QR code (CR-6a) MUST encode sufficient information for a client to complete pairing in a single scan.
- The server MUST be able to revoke access for individual devices without affecting other connected clients.
- The server MUST act as the trust root: for peer interactions (CR-7), clients MUST trust peers that the server vouches for.

### CR-10: Session Layer

The client and server MUST maintain a virtual session that is independent of any single network path.

- Each session MUST be identified by a unique connection ID that persists across path changes.
- Traffic MUST be framed into packets with sequence numbers for ordering and reassembly.
- The session layer MUST sit above the transport protocols (CR-8) and treat them as interchangeable pipes.
- The session layer MUST support distributing packets across multiple paths simultaneously and reassembling them at the receiver.
- Loss of any single path MUST NOT terminate the session if other paths remain available.

### CR-11: Path Scheduler

The component that assigns packets to paths MUST be a pluggable subsystem of the session layer (CR-10).

- v1 MUST ship with at least one simple scheduler (e.g., active-standby failover or round-robin).
- The scheduler interface MUST support future implementations such as latency-aware, weighted, or redundant-send strategies without changes to the session layer.

### CR-12: Device Management

The server MUST support revoking access for individual devices. Revocation MUST take effect without requiring a full server restart. The server SHOULD provide a way for administrators to list authorized devices.

## Future Considerations (Not in Scope for v1)

- Web-based management dashboard
- Bandwidth aggregation (increased throughput, not just failover)
- Traffic policies and routing rules
- Multiple server support / mesh
- Connection quality metrics and analytics

## Success Metrics

- Client can maintain an active connection when any single interface drops
- Latency overhead is < 20ms compared to direct connection
- Client app is usable by non-technical users
- Session survives a complete path migration (e.g., Wi-Fi → cellular) without dropping active connections
- At least two transport protocols function simultaneously on different paths
- Peer path sharing works across devices on a local network
