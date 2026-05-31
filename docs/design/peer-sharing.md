# Peer Sharing Design

## Goal

Implement CR-7 so authenticated Bonded clients on the same local network can discover each other and contribute additional upstream paths to the same server, while preserving the existing session-layer invariant: a peer-contributed path must look like just another `ClientTransport` to the scheduler.

## Non-Goals

- Peer-to-peer mesh routing between different servers
- Replacing the main server trust root with ad-hoc peer trust
- Exposing raw TUN traffic directly to another device without authenticated encapsulation

## Roles

- Consumer: the device that wants to use another device's uplink as an additional path to the server
- Provider: the device that offers one or more of its own server-connected transports for relay use
- Dual-role peer: any device may be consumer and provider simultaneously

## Architecture

1. Every client may run a local peer-share listener on the LAN.
2. Every listener advertises itself over mDNS/DNS-SD using a Bonded-specific service type.
3. mDNS only provides a hint that a candidate peer exists; it is never a trust decision.
4. The consumer asks the server for a short-lived signed introduction bound to the advertised peer instance.
5. The consumer dials the peer listener and presents the server-signed introduction.
6. The provider verifies the introduction and, if valid, accepts a peer relay stream.
7. The resulting relay is wrapped as an additional session-layer path for the consumer.

## Discovery

Service type:

- `_bonded-peer._udp.local` if the listener transport is QUIC

Advertised TXT fields:

- `version`: protocol version
- `device_key`: consumer/provider ed25519 public key (base64)
- `server_key`: Bonded server ed25519 public key (base64) for affinity matching
- `instance_nonce`: random per-listener nonce rotated on listener restart
- `capabilities`: comma-separated capabilities, initially `relay`
- `endpoint`: `ip:port` endpoint advertised by the listener
- `cert_fingerprint`: pinned `sha256:<hex>` fingerprint of the provider's current peer listener certificate

Rules:

- Clients ignore advertisements whose `server_key` does not match the currently paired server.
- Clients ignore their own `device_key`.
- Advertisements are cached briefly but treated as unauthenticated hints only.

## Trust Model

The server remains the trust root.

New bootstrap endpoint:

- `POST /v1/bootstrap/peer-share/introduction`

Request body:

```json
{
  "consumer_device_public_key": "<consumer ed25519 key>",
  "provider_device_public_key": "<provider ed25519 key>",
  "provider_instance_nonce": "<provider advertised nonce>",
  "provider_endpoint": "192.168.1.20:54443",
  "listener_transport": "quic",
  "listener_cert_fingerprint": "sha256:<hex>",
  "consumer_signature": "<ed25519 signature over the canonical request body>"
}
```

Response body:

```json
{
  "introduction": {
    "consumer_device_public_key": "<consumer key>",
    "provider_device_public_key": "<provider key>",
    "provider_instance_nonce": "<advertised nonce>",
    "provider_endpoint": "192.168.1.20:54443",
    "expires_at": 1767225600,
    "listener_transport": "quic",
    "listener_cert_fingerprint": "sha256:<hex>"
  },
  "server_signature": "<ed25519 signature over canonical JSON>"
}
```

Verification rules:

- The consumer verifies `server_signature` using the paired server ed25519 public key.
- The provider verifies the same signature and ensures `provider_device_public_key` matches itself.
- The provider rejects introductions whose `provider_instance_nonce` does not match the current listener instance.
- Both sides reject expired introductions.

## Peer Transport

Initial transport choice:

- QUIC with ALPN `bonded-peer`

Rationale:

- Already present in the workspace via `quinn`
- Encrypted by default
- Handles multiplexed request/response streams cleanly
- Fits the existing cert-fingerprint + server-vouched-cert model

The provider listener uses a short-lived self-signed certificate. The consumer does not trust it directly; it trusts the server-signed introduction that binds the listener cert fingerprint, endpoint, provider key, and instance nonce together.

## Relay Model

The provider does not become a second server. It acts as a relay for a consumer-specific virtual path.

Initial relay behavior:

- Consumer sends already-framed Bonded session frames to the provider over the peer QUIC stream.
- The provider establishes a dedicated upstream server transport for each accepted peer relay and immediately sends a relay-registration control frame carrying the same server-signed introduction it just verified from the consumer.
- The server verifies that registration against its own identity key, checks that the authenticated upstream transport belongs to the introduced provider, and binds that dedicated upstream connection to the introduced consumer session before normal data forwarding starts.
- Return traffic from the server is sent back over the peer QUIC stream to the consumer.

This keeps the session layer transport-agnostic: a peer relay is just another path carrying `SessionFrame` bytes.

Current limitations:

- The provider still creates a fresh dedicated upstream transport per accepted peer relay instead of exporting capacity from its existing live transport pool.
- Peer-share runtime reconnect and teardown hardening, plus real multi-device validation, remain follow-up work.

## Scheduling Policy

Initial policy:

- Peer-shared paths start as secondary/failover paths, not primary paths.
- The scheduler may promote them later if direct paths fail or if policy explicitly allows it.
- A provider may cap the number of exported peer paths and the number of concurrent consumers.

## Security Constraints

- No trust is derived from mDNS alone.
- All peer introductions are short-lived and server-signed.
- Listener instance nonces prevent replay across provider restarts.
- Provider listeners only accept peers vouched for by the same paired server.
- The provider must be able to revoke all exported paths immediately when its own server session is lost.
- The consumer must drop peer-shared paths immediately when the introduction expires or the provider disconnects.

## Implementation Slices

1. Shared protocol types for advertisements, introductions, and peer relay frames
2. Server bootstrap endpoint for signed peer introductions
3. Client-side peer listener + QUIC handshake verification
4. mDNS advertiser/browser integration
5. Relay path plumbing into the existing client session runtime
6. Android UI/status exposure and dual-device validation

## Validation Plan

1. Unit-test signed introduction encoding/verification and expiry handling.
2. Integration-test peer listener handshake with a server-signed introduction.
3. Integration-test relay framing: consumer -> provider -> server -> provider -> consumer.
4. Integration-test the server relay-registration binding: provider-authenticated upstream transport must be rebound to the consumer session before data is accepted.
5. Validate on two ADB-connected devices with one device contributing a peer-shared path while both remain connected to the same server.