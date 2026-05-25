# Debugging Android VPN Traffic

This guide covers the current Android debugging path for Bonded after the WebSocket/TLS connection issue was fixed.

## What Changed

Android now uses two server addresses during VPN startup:

- `server_address`: the original hostname from pairing, used for WebSocket/TLS identity and cert-proof validation
- `server_resolved_address`: the pre-resolved IP:port, used only for socket dialing

This split is required because Android may lose reliable DNS once the VPN comes up, but TLS must still validate the DNS name from the certificate.

## Fast Path

Use the debug activity plus filtered logcat.

```bash
adb -s DEVICE_ID logcat -c
adb -s DEVICE_ID logcat -v brief -s "BondedFFI:V BondedVPN:V DebugVPN:V"
```

In another terminal:

```bash
adb -s DEVICE_ID shell am start -n com.bonded.bonded_app/.DebugVpnActivity --es action connect
```

Useful companion commands:

```bash
adb -s DEVICE_ID shell am start -n com.bonded.bonded_app/.DebugVpnActivity --es action status
adb -s DEVICE_ID shell am start -n com.bonded.bonded_app/.DebugVpnActivity --es action disconnect
```

## Healthy Startup Sequence

On a successful run, expect this order:

```text
I/DebugVPN: Received action='connect'
I/DebugVPN: Using first paired server: ... addr=charter.codingwell.net:8080
I/BondedVPN: resolveServerAddressEarly() called with: charter.codingwell.net:8080
I/BondedVPN: Pre-resolved charter.codingwell.net -> 97.115.185.254:8080
I/BondedVPN: Starting native session: server=charter.codingwell.net:8080, resolved=97.115.185.254:8080, ...
I/BondedFFI: Starting Android session: server=charter.codingwell.net:8080 resolved=97.115.185.254:8080 ...
I/BondedFFI: Worker: establishing transport paths
I/BondedVPN: protect(fd=...) returned true
I/BondedFFI: Transport paths established: count=1
I/BondedFFI:   transport[0] = WebSocketTLS
I/BondedVPN: Native snapshot: state=connected, outbound=..., inbound=..., lastError=null
```

Key invariants:

- `server=` must remain the hostname, not the IP literal
- `resolved=` should be the cached IP:port
- `transport[0] = WebSocketTLS` confirms WSS came up cleanly
- `state=connected` with non-zero counters confirms real traffic flow

## Interpreting Failures

### Failure: old IP-literal TLS identity

```text
websocket TLS/upgrade failed for wss://97.115.185.254:8080 ...
invalid peer certificate: certificate not valid for name "97.115.185.254"
```

Meaning:

- the client is still using the resolved IP as the TLS/WebSocket identity
- you are either on an old APK or the hostname/resolved split regressed

Expected fix:

- Kotlin logs `server=HOSTNAME, resolved=IP:PORT`
- Rust logs `server=HOSTNAME resolved=IP:PORT`

### Failure: rustls provider panic

```text
PANIC at ... Could not automatically determine the process-level CryptoProvider
```

Meaning:

- rustls was used before a process-wide provider was installed

Expected fix:

- `JNI_OnLoad` installs `rustls::crypto::ring::default_provider()`

### Failure: protect callback / socket capture

Symptoms:

- repeated connect timeouts
- no `Transport paths established`
- `protect(fd=...) returned false`

Meaning:

- control-plane sockets may still be getting captured by the VPN

Checks:

- confirm the app is disallowed from the VPN builder
- confirm the service logs successful `protect(fd=...)`
- confirm the native session starts after VPN establishment, not before protection wiring

### Failure: outbound queue closed

Symptoms:

- `Failed to queue outbound packet: channel closed`
- `Channel closed; existing last_error=...`

Meaning:

- this is usually a downstream symptom, not the root cause
- look earlier in logcat for `Failed to establish transport paths`, a panic, or a transport recv/send failure

## Triage Order

Use this order when a device run fails:

1. Check whether Kotlin logged both hostname and resolved address separately.
2. Check whether `BondedFFI` reached `Worker: establishing transport paths`.
3. Check for `protect(fd=...) returned true`.
4. Check whether WSS failed before auth (`TLS/upgrade failed`) or after auth (`websocket auth handshake failed`).
5. Check the latest native snapshot state and `lastError`.

## Useful Filters

Only the high-signal lines:

```bash
adb -s DEVICE_ID logcat -v brief -s "BondedFFI:V BondedVPN:V DebugVPN:V" | grep -E "Starting native session|Starting Android session|Transport paths established|state=|lastError=|protect\(fd=|TLS/upgrade failed|websocket auth handshake failed|PANIC"
```

Only errors and warnings:

```bash
adb -s DEVICE_ID logcat -v brief -s "BondedFFI:V BondedVPN:V" | grep -E " E/| W/|Failed|PANIC|lastError"
```

## Current Known-Good Validation

The Android WSS fix is considered verified when one clean run shows all of the following:

- Kotlin logs `server=charter.codingwell.net:8080, resolved=97.115.185.254:8080`
- Rust logs the same hostname/resolved split
- `Transport paths established: count=1`
- `transport[0] = WebSocketTLS`
- `Native snapshot: state=connected`
- inbound and outbound counters are both non-zero

## Notes

- The Android VPN MTU is currently `1420`, not `1500`.
- `naive_tcp` failures during Android runs are secondary if WSS is the intended production transport.
- If logcat still shows `server=97.115.185.254:8080 (original: charter.codingwell.net:8080)`, you are looking at stale logs or an old build.

---

**Last Updated**: 2026-05-25
**Status**: Android WSS connection path verified on device
