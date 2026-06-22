# DEBUGGING

This note captures the current Android/VPN validation flow used in this workspace so the next debugging pass can start quickly.

## 1. Start the local server for device testing

Use a temporary local config so the phone can connect to a reachable endpoint instead of the remote production host.

```bash
cat > /tmp/bonded-local.toml <<'EOF'
[server]
hostname = "127.0.0.1"
https_bind = "0.0.0.0:8443"
https_public = 8443
status_bind = "0.0.0.0:9002"
health_bind = "0.0.0.0:9001"
authorized_keys_file = "/tmp/authorized_keys.toml"
invite_tokens_file = "/tmp/invite_tokens.toml"
identity_key_file = "/tmp/server-identity.pem"
tcp_bind = "0.0.0.0:8000"
tcp_public = 8000
EOF

cargo run -p bonded-server -- --config /tmp/bonded-local.toml
```

Expected startup endpoints:
- TCP debug listener on `0.0.0.0:8000`
- HTTPS/WSS listener on `0.0.0.0:8443`
- health on `0.0.0.0:9001`
- status on `0.0.0.0:9002`

## 2. Pair the phone to the local server

Expose the local server port to the device and invoke the ADB pair flow.

```bash
cd /workspace/android/android
adb -s DEVICE_ID reverse tcp:8000 tcp:8000
adb -s DEVICE_ID shell am start -n com.bonded.bonded_app/.MainActivity \
  --es adb_action pair \
  --es device_id 'local-test-device' \
  --es server_address '127.0.0.1:8000' \
  --es bootstrap_server_address '127.0.0.1:8000' \
  --es server_public_key 'U5yGEOIqNQB5pMWqTJc5+kBygrwaqcYbp1MeJyJToLo=' \
  --es invite_token '5YN96DmX80Z0d9dj6A6I0lZ5ky-_R5uN' \
  --es supported_protocols 'naive_tcp'
```

Verify the pairing result with:

```bash
adb -s DEVICE_ID logcat -d | grep -E 'BondedMain|ADB pair succeeded|ADB pair failed|nativeRedeemInviteToken'
```

A working result should log `ADB pair succeeded` and the local `127.0.0.1:8000` values.

## 3. Start the VPN debug flow on the phone

```bash
adb -s DEVICE_ID shell am start -n com.bonded.bonded_app/.DebugVpnActivity --es action connect
```

Useful companion actions:

```bash
adb -s DEVICE_ID shell am start -n com.bonded.bonded_app/.DebugVpnActivity --es action status
adb -s DEVICE_ID shell am start -n com.bonded.bonded_app/.DebugVpnActivity --es action disconnect
```

## 4. Capture the high-signal log output

Use a focused filter so the important lines are easy to scan:

```bash
adb -s DEVICE_ID logcat -c
adb -s DEVICE_ID logcat -v brief -s "BondedFFI:V BondedVPN:V DebugVPN:V"
```

A tighter one-liner for the current investigation:

```bash
adb -s DEVICE_ID logcat -d | grep -E 'BondedFFI|BondedVPN|VpnService|protect\(|bind_socket_to_network|transport attempt|Starting native session|Native snapshot|Failed to establish transport paths|Connection refused|nativeStartSession|stop_android_session' | tail -n 200
```

## 5. H3/QUIC validation notes

The HTTP/3 path is the production transport path to validate next. The local Rust integration tests that exercise the H3 bootstrap and mixed fallback logic are:

```bash
cargo test -p bonded-client h3_bootstrap_request_fetches_capabilities_after_cert_proof -- --nocapture
cargo test -p bonded-client mixed_websocket_quic_failover_continues_exchange -- --nocapture
```

For real-device validation, the host must be reachable from the phone on the same LAN (the phone cannot use the container-only `172.19.0.2` address in this environment). The H3/QUIC path is UDP-based, so `adb reverse` is not sufficient for the final transport test; the phone must be able to dial the host directly over UDP on the same port used by the TLS/bootstrap listener.

If you are pairing specifically for an H3 test run, use the TLS-enabled server config above and ensure the stored `supported_protocols` include `h3` (or the default `wss,h3,wireguard` order if you are not overriding them).

## 6. What success looks like

The current validation target is:
- the app reaches the VPN service start path,
- the native session starts,
- transport attempts reach the local server instead of the production endpoint,
- and the session transitions from `connecting` to a stable state without repeated `Connection refused` errors.

In the logs, you want to see the server address and the transport path establishment flow, not just repeated recovery loops.

## 7. What to investigate if it still fails

If the phone still fails to connect:
1. confirm the local server is actually listening on the expected ports,
2. confirm the phone is paired to `127.0.0.1:8000`,
3. confirm the VPN service and native session actually start,
4. inspect whether the transport fails on `Connection refused`, DNS resolution, or path establishment,
5. compare the logs against the previous real-device output to see whether the failure moved from the remote production host to the local test path.

## 8. Current practical note

The current real-device issue is not a simple “VPN permission revoked” problem; the transport path is still failing during startup. The local server path above is the quickest way to validate that the Android VPN path itself is working once the transport endpoint is reachable.
