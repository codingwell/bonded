# ADB Testing Guide — Bonded Android App

This guide covers how to control and inspect the Bonded VPN app entirely over ADB without touching the device screen.

---

## Prerequisites

```bash
# Connect to the device (adjust IP as needed)
adb connect 192.168.1.140:5555

# Verify connection
adb -s 192.168.1.140:5555 devices

# Launch the app (required before using broadcast-based tests)
adb -s 192.168.1.140:5555 shell am start -n com.bonded.bonded_app/.MainActivity
```

## Pairing via ADB

The release app now supports a minimal ADB-triggered pairing path through `MainActivity`.
This is useful for local-server testing when you do not want to scan a QR code on-device.

### Pair to a server directly
```bash
adb -s 192.168.1.140:5555 shell am start \
  -n com.bonded.bonded_app/.MainActivity \
  --es adb_action pair \
  --es device_id "00000000-0000-0000-0000-000000000001" \
  --es server_address "127.0.0.1:8000" \
  --es bootstrap_server_address "127.0.0.1:8000" \
  --es server_public_key "<server public key>" \
  --es invite_token "<invite token>" \
  --es supported_protocols "naive_tcp"
```

`server_address` is the address used for native invite redemption.
`bootstrap_server_address` is optional; when set, it is the address persisted in the paired-server record and later used by the VPN runtime for bootstrap and transport setup.
This is useful when local tests redeem over NaiveTCP on one port and bootstrap WireGuard over a different published port.

Look for `BondedMain` log lines like:

```text
I/BondedMain: Redeeming invite token via native runtime for server=127.0.0.1:8000 ...
I/BondedMain: ADB pair succeeded: deviceId=... redeemServer=127.0.0.1:8000 bootstrapServer=127.0.0.1:8000 protocols=[naive_tcp]
```

### Local server over `adb reverse`

For a local devcontainer/server test, expose the host NaiveTCP listener to the device first:

```bash
adb -s 192.168.1.140:5555 reverse tcp:8000 tcp:8000
adb -s 192.168.1.140:5555 reverse --list
```

Then pair using `server_address=127.0.0.1:8000` and connect with the same `device_id`.

---

## VPN Connect / Disconnect

These commands use `VpnControlReceiver`, which is always exported and works whether or not the app UI is in the foreground.

### Connect (uses first paired server automatically)
```bash
adb -s 192.168.1.140:5555 shell am broadcast \
  -a com.bonded.bonded_app.VPN_START \
  com.bonded.bonded_app
```

### Connect with a specific device ID
```bash
adb -s 192.168.1.140:5555 shell am broadcast \
  -a com.bonded.bonded_app.VPN_START \
  --es device_id "<UUID from getPairedServers>" \
  com.bonded.bonded_app
```

### Connect in foreground (non-background) mode
```bash
adb -s 192.168.1.140:5555 shell am broadcast \
  -a com.bonded.bonded_app.VPN_START \
  --ez run_background false \
  com.bonded.bonded_app
```

### Disconnect
```bash
adb -s 192.168.1.140:5555 shell am broadcast \
  -a com.bonded.bonded_app.VPN_STOP \
  com.bonded.bonded_app
```

> **Note:** `VPN_START` defaults to `run_background=true`. Both receivers are in `VpnControlReceiver.kt`.
> If VPN permission was never granted on this device, `VPN_START` will be silently ignored — open the app and connect once manually to grant the permission, then ADB control works thereafter.

### Connect a specifically paired local server via `DebugVpnActivity`
```bash
adb -s 192.168.1.140:5555 shell am start \
  -n com.bonded.bonded_app/.DebugVpnActivity \
  --es action connect \
  --es device_id "00000000-0000-0000-0000-000000000001"
```

---

## VPN Status & Session Info

These use `NetworkTestReceiver` (log tag: `NetworkTest`).

### Check VPN running state and session snapshot
```bash
adb -s 192.168.1.140:5555 shell am broadcast \
  -a com.bonded.bonded_app.TEST_VPN_STATUS \
  com.bonded.bonded_app
```
Look for `NetworkTest` lines in logcat. Reports: `running`, `state`, `serverAddress`, `outbound/inbound counters`, `lastError`.

### Check VPN permission status
```bash
adb -s 192.168.1.140:5555 shell am broadcast \
  -a com.bonded.bonded_app.TEST_VPN_PREPARED \
  com.bonded.bonded_app
```
Reports whether `VpnService.prepare()` returns null (already granted) or requires user confirmation.

### Connect / Disconnect (via NetworkTestReceiver)
```bash
# Connect using first paired server
adb -s 192.168.1.140:5555 shell am broadcast \
  -a com.bonded.bonded_app.TEST_VPN_CONNECT \
  com.bonded.bonded_app

# Disconnect
adb -s 192.168.1.140:5555 shell am broadcast \
  -a com.bonded.bonded_app.TEST_VPN_DISCONNECT \
  com.bonded.bonded_app
```

---

## Network Diagnostic Tests

These run in a foreground service and log results under the `NetworkTest` tag. Tests work both inside and outside the VPN tunnel — run them before and after connecting to compare.

### DNS resolution
```bash
# Default host (unifi.g.codingwell.net → expected 34.82.88.79)
adb -s 192.168.1.140:5555 shell am broadcast \
  -a com.bonded.bonded_app.TEST_DNS \
  com.bonded.bonded_app

# Custom host
adb -s 192.168.1.140:5555 shell am broadcast \
  -a com.bonded.bonded_app.TEST_DNS \
  --es host "example.com" \
  com.bonded.bonded_app

# Custom host with expected IP check
adb -s 192.168.1.140:5555 shell am broadcast \
  -a com.bonded.bonded_app.TEST_DNS \
  --es host "example.com" \
  --es expected_ip "93.184.216.34" \
  com.bonded.bonded_app
```

### TCP connection
```bash
# Default (unifi.g.codingwell.net:443)
adb -s 192.168.1.140:5555 shell am broadcast \
  -a com.bonded.bonded_app.TEST_TCP \
  com.bonded.bonded_app

# Custom host/port
adb -s 192.168.1.140:5555 shell am broadcast \
  -a com.bonded.bonded_app.TEST_TCP \
  --es host "charter.codingwell.net" \
  --ei port 8080 \
  com.bonded.bonded_app
```

### HTTP/HTTPS fetch
```bash
# Custom URL
adb -s 192.168.1.140:5555 shell am broadcast \
  -a com.bonded.bonded_app.TEST_HTTP \
  --es url "https://example.com" \
  com.bonded.bonded_app

# Preset: codingwell.net suite
adb -s 192.168.1.140:5555 shell am broadcast \
  -a com.bonded.bonded_app.TEST_HTTP_CODINGWELL \
  com.bonded.bonded_app
```

### Protocol stress test (DNS + TCP + HTTP + HTTP/3 over multiple rounds)
```bash
# Defaults: cloudflare.com, http://httpforever.com/, https://cloudflare-quic.com/, 5 rounds
adb -s 192.168.1.140:5555 shell am broadcast \
  -a com.bonded.bonded_app.TEST_PROTOCOL_STRESS \
  com.bonded.bonded_app

# Custom parameters
adb -s 192.168.1.140:5555 shell am broadcast \
  -a com.bonded.bonded_app.TEST_PROTOCOL_STRESS \
  --es host "cloudflare.com" \
  --es resolver "1.1.1.1" \
  --es http_url "http://httpforever.com/" \
  --es https_url "https://example.com/" \
  --es http3_url "https://cloudflare-quic.com/" \
  --ei rounds 5 \
  com.bonded.bonded_app
```

### Run all tests at once
```bash
adb -s 192.168.1.140:5555 shell am broadcast \
  -a com.bonded.bonded_app.TEST_ALL \
  com.bonded.bonded_app
```

---

## Reading Logs

### Stream all Bonded-related logs (recommended during active testing)
```bash
adb -s 192.168.1.140:5555 logcat -v threadtime \
  | grep -E "BondedVPN|NetworkTest|VpnControlReceiver|BondedMain"
```

### Key log tags

| Tag | Source | What it shows |
|-----|--------|---------------|
| `BondedVPN` | `BondedVpnService.kt` | VPN lifecycle, native session state, protect() calls, TUN I/O |
| `NetworkTest` | `NetworkTestReceiver.kt` | DNS/TCP/HTTP test results |
| `VpnControlReceiver` | `VpnControlReceiver.kt` | VPN_START / VPN_STOP receipts |
| `BondedMain` | `MainActivity.kt` | Pairing / invite token redemption |

### Session snapshot fields (in `BondedVPN` logs every 5 seconds)
```
Native snapshot: state=connected, outbound=12/4.2KB, inbound=8/3.1KB, lastError=null
```
- `state`: `connecting` | `connected` | `error` | `stopped`
- `lastError`: set when state is `error`; `null` when healthy

### Protect-call logging
Each time a socket is created that needs to bypass the VPN, you should see:
```
I/BondedVPN: protect(fd=42) returned true
```
For a WSS connection you expect **two** protect calls per connection attempt:
1. WebSocket socket
2. Cert-proof bootstrap socket

If you see `returned false`, the socket was not exempted from the tunnel — likely a crash in the protect JNI callback.

### Dump the last N logcat lines including Bonded entries
```bash
adb -s 192.168.1.140:5555 logcat -d -t 500 \
  | grep -E "BondedVPN|NetworkTest|VpnControlReceiver|BondedMain"
```

---

## Pairing / Server Info

### List paired servers (run from dev machine, not device)
The paired server list is stored in SharedPreferences (`bonded.paired_servers`). On a non-rooted release build you cannot read it directly via ADB. Options:

1. **From logcat**: The `BondedVPN` session monitor logs `serverAddress` each cycle once connected.
2. **Re-pair**: Regenerate an invite token on the server and scan the QR code in the app.
3. **Debug build**: Build with `debuggable true` in `build.gradle.kts` to use `adb shell run-as com.bonded.bonded_app cat shared_prefs/bonded.paired_servers.xml`.

---

## Common Workflows

### Full connect-and-verify cycle
```bash
# 1. Clear old logs
adb -s 192.168.1.140:5555 logcat -c

# 2. Ensure app is in foreground
adb -s 192.168.1.140:5555 shell am start -n com.bonded.bonded_app/.MainActivity

# 3. Trigger connect
adb -s 192.168.1.140:5555 shell am broadcast \
  -a com.bonded.bonded_app.VPN_START \
  com.bonded.bonded_app

# 4. Stream logs (watch for state=connected)
adb -s 192.168.1.140:5555 logcat -v brief \
  | grep -E "BondedVPN|VpnControlReceiver"
```

### Diagnose "channel closed" or session errors
```bash
# Connect and watch for error transitions
adb -s 192.168.1.140:5555 logcat -c
adb -s 192.168.1.140:5555 shell am broadcast -a com.bonded.bonded_app.VPN_START com.bonded.bonded_app
timeout 60 adb -s 192.168.1.140:5555 logcat -v threadtime \
  | grep -E "BondedVPN|VpnControlReceiver"
# Look for: state=error, lastError=<reason>
# Two protect(fd=N) calls should appear before state transitions to connected
```

### Test that traffic actually flows through the tunnel
```bash
# After connecting, run DNS test — if inside tunnel, DNS resolves via bonded server
adb -s 192.168.1.140:5555 shell am broadcast \
  -a com.bonded.bonded_app.TEST_DNS \
  --es host "example.com" \
  com.bonded.bonded_app

# Then run TCP test to the Bonded server port directly
adb -s 192.168.1.140:5555 shell am broadcast \
  -a com.bonded.bonded_app.TEST_TCP \
  --es host "charter.codingwell.net" \
  --ei port 8080 \
  com.bonded.bonded_app

# Watch NetworkTest logs for ✓ or ✗ results
adb -s 192.168.1.140:5555 logcat -d | grep "NetworkTest"
```

### Disconnect and reconnect cleanly
```bash
adb -s 192.168.1.140:5555 shell am broadcast -a com.bonded.bonded_app.VPN_STOP com.bonded.bonded_app
sleep 3
adb -s 192.168.1.140:5555 shell am broadcast -a com.bonded.bonded_app.VPN_START com.bonded.bonded_app
```

---

## Build & Deploy

### Full rebuild and reinstall (native + Flutter)
```bash
cd /workspace
bash scripts/build-android-native.sh

cd /workspace/android
flutter build apk --release
adb -s 192.168.1.140:5555 install -r build/app/outputs/flutter-apk/app-release.apk
adb -s 192.168.1.140:5555 shell am start -n com.bonded.bonded_app/.MainActivity
```

### Check what native lib version is deployed
```bash
# Timestamp of .so in jniLibs (source)
ls -la android/app/src/main/jniLibs/arm64-v8a/libbonded_ffi.so

# Timestamp of Rust source
ls -la /workspace/crates/bonded-ffi/src/lib.rs

# The .so must be newer than lib.rs for changes to be included
```
