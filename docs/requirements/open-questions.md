# Open Questions — Bonded v1

**Status:** In Progress
**Last Updated:** 2026-03-30

Items to resolve before beginning v1 implementation.

---

## OQ-1: Authentication Model — RESOLVED

CR-5 requires encryption, CR-6 references credentials, CR-6a uses QR code pairing, and CR-7 references authenticated clients — but no requirement specifies the actual authentication mechanism.

**Decision:** Invite Token → Client Keypair (Option B)

1. Server generates short-lived, single-use invite tokens
2. QR code contains: server address, port, invite token, server public key
3. Client scans QR, redeems token, registers its public key with the server
4. Server stores authorized client public keys (revocation = remove key)
5. Subsequent connections authenticate via public key challenge
6. Peers trust each other because the server vouches (signs peer introductions)
7. Noise-framework handshake is a future upgrade path

See CR-9 in product-requirements.md.

---

## OQ-2: Tunnel / Session Layer — RESOLVED

CR-2 requires seamless failover without interrupting active sessions, but TCP connections break when network paths change. A virtual session layer that survives path changes is implied but not specified.

**Decision:** Packet-level multiplexing with pluggable scheduler (Approach A).

Architecture (top to bottom):

1. **VPN / TUN interface** — captures app traffic
2. **Session layer** — virtual connection ID, packet sequencing, reassembly. Survives path changes. This is the v1 infrastructure investment.
3. **Scheduler** — decides which path gets each packet. Pluggable. v1 ships with a naive implementation (e.g., active-standby or round-robin). Sophisticated schedulers (latency-aware, weighted, redundant) are future work.
4. **Transport paths** — each path uses a pluggable transport protocol (CR-8). Session layer treats transports as dumb pipes.

The session layer sits above transports and below the OS tunnel. Transports do not need to be session-aware.

See CR-10 and CR-11 in product-requirements.md.

---

## OQ-3: Scope of CR-7 (Peer Connection Sharing) — RESOLVED

Bidirectional peer discovery, trust negotiation, and simultaneous provider/consumer roles is a significant subsystem — mDNS discovery, peer authentication, routing decisions, and added attack surface.

**Decision:** Full bidirectional peer sharing stays in v1.

Key use case: A laptop with only Wi-Fi bonds through multiple phones' cellular connections on the same local network. Phones simultaneously benefit from the laptop's wired connection. Both directions are needed.

Implementation notes:
- Discovery via mDNS/DNS-SD on the local network
- Peer trust via server vouching (per OQ-1 — server signs peer introductions)
- Peer connections are additional paths in the session layer (CR-10) — architecturally, a peer is just another path
- Each device can simultaneously act as path provider and path consumer

CR-7 remains as written.

---

## OQ-4: Server Public Endpoint for QR Code — RESOLVED

CR-6a requires the server to emit a QR code with connection details, but a Docker container doesn't inherently know its own public IP address.

**Decision:** Required configuration (Option A).

The server MUST require a configured public address (env var or config file). If not set, the server MUST warn in logs and skip QR code generation. The admin provides the address — they already know it since they're self-hosting.

QR code payload: server public address, port, invite token, server public key.

---

## OQ-5: Protocol Negotiation — RESOLVED

CR-8 defines multiple transport protocols but no mechanism for the client and server to agree on which one to use.

**Decision:** Per-path independent selection with server-advertised protocol list (Option C + A).

- The server MUST advertise its supported protocols (in the QR code payload and/or config).
- The client attempts to establish paths using each supported protocol across each available interface independently.
- Whatever connects becomes a path in the session layer. No negotiation handshake needed.
- Different paths MAY use different protocols simultaneously (e.g., Wi-Fi via WSS, cellular via QUIC).
- This aligns with CR-10: the session layer treats all paths as interchangeable pipes regardless of underlying protocol.

---

## OQ-6: Client Lifecycle Management — RESOLVED

SRV-2 says the server accepts multiple clients, but there is no story for managing them.

**Decision:** Config file only (Option C) for v1.

The server maintains a config file of authorized client public keys. To revoke a device, the admin removes its key from the file. The server watches for changes or reloads on signal/restart. CLI tooling and an admin API are future upgrades.

See CR-12 in product-requirements.md.

---

## OQ-7: Linux Client in v1 — RESOLVED

Linux is currently listed as future scope, but the server is Rust on Linux. A Linux client would share most networking code and serve as the easiest development and testing tool.

**Decision:** Add Linux CLI client to v1 scope.

A CLI-only client targeting Linux. Shares the session layer, transport plugins, scheduler, and auth code with the server. Primary role is development and integration testing, but also a functional client. Platform-specific layer is minimal (TUN device setup).

See LNX-1 through LNX-5 in platform-requirements.md.

---

## Resolution Log

| OQ | Decision | Date |
|----|----------|------|
| OQ-1 | Invite Token → Client Keypair with server as trust root | 2026-03-30 |
| OQ-2 | Packet-level multiplexing with pluggable naive scheduler in v1 | 2026-03-30 |
| OQ-3 | Full bidirectional peer sharing stays in v1 | 2026-03-30 |
| OQ-4 | Required public address config; no auto-detect | 2026-03-30 |
| OQ-5 | Per-path independent protocol selection; server advertises supported list | 2026-03-30 |
| OQ-6 | Config file for authorized client keys; edit to revoke | 2026-03-30 |
| OQ-7 | Linux CLI client added to v1 scope | 2026-03-30 |
