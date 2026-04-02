# Debugging VPN Traffic Flow Issues

**Issue**: Android app creates a VPN session but no traffic flows through to the server.

## Root Cause

The VPN packet flow was completely opaque - there was no logging to diagnose where packets were being lost. This document describes the comprehensive logging system that's been added to trace the entire packet journey.

## Quick Start: Enable Logcat

```bash
# Terminal 1: Connect Android Studio Logcat to see logs
adb logcat | grep -E "BondedVPN|bonded-ffi"
```

## Expected Log Sequence

When traffic flows successfully, you should see (in this exact order):

### Phase 1: Startup (happens once)
```
[BondedVPN] Establishing VPN interface: address=10.8.0.2/32, mtu=1500, route=0.0.0.0/0
[BondedVPN] VPN interface established successfully
[bonded-ffi] Starting Android session to SERVER_ADDRESS
[bonded-ffi] Protocols: naive_tcp, Paths: 1, Bind addresses: [192.168.x.x]
[bonded-ffi] Worker thread: establishing transport paths
[bonded-ffi] Transport paths established, count: 1
[BondedVPN] Packet I/O loop started
```

### Phase 2: Per-Packet Flow (repeats for each packet)
```
[BondedVPN] Read 64 bytes from TUN device
[BondedVPN] Sending 64 bytes to native layer (packet type: IPv4(proto=6,192.168.x.x->8.8.8.8))
[bonded-ffi] Queuing 64 byte outbound packet
[bonded-ffi] Worker: sending 64 byte outbound packet via transport index 0
[bonded-ffi] Worker: received frame from transport 0
[bonded-ffi] Worker: ingested 1 packets, 64 bytes total
[bonded-ffi] Polled 64 byte inbound packet
[BondedVPN] Received 64 bytes from native layer (packet type: IPv4(proto=6,8.8.8.8->192.168.x.x))
[BondedVPN] Writing 64 inbound bytes to TUN device
```

### Phase 3: Statistics (every 200 packets)
```
[BondedVPN] I/O loop: 5 outbound (320B), 5 inbound (320B)
[bonded-ffi] Worker: heartbeat - 200 select cycles
```

## Diagnostic Checklist

Use this table to identify where traffic stops:

| Log Appears? | Next Log? | Status | Problem |
|---|---|---|---|
| Startup ✓ | VPN Interface ✓ | ✓ | Continue |
| VPN Interface ✓ | Transport established ✓ | ✓ | Continue |
| Transport ✓ | Packet I/O loop ✓ | ✓ | App ready |
| Phase 2: Read bytes ✓ | Sending to native ✓ | ✓ | Packets being read |
| Sending to native ✓ | (MISSING) | ✗ | **Issue A: Native handler crashed** |
| Sending to native ✓ | Queuing packet ✓ | ✓ | FFI working |
| Queuing packet ✓ | Worker sending ✗ | ✗ | **Issue B: Worker thread hung/crashed** |
| Worker sending ✓ | (MISSING) | ✗ | **Issue C: Server not responding** |
| Worker received ✓ | Ingested packets ✓ | ✓ | Session working |
| Polled inbound ✓ | (MISSING) | ✗ | **Issue D: Android VPN I/O broken** |
| Writing inbound ✓ | (MISSING) | ✗ | **Issue E: TUN device write failed** |

## Common Issues and Fixes

### Issue A: Native Handler Crashed
**Logs**: Sending to native ✓ but Queuing packet ✗

**Possible causes**:
- FFI library not loaded (`bonded_ffi` .so file missing)
- Packet buffer too large (>32KB)
- Memory corruption in native code

**Fix**:
1. Check `nativeLoaded` boolean is true (see MainActivity startup)
2. Verify `.so` file exists at `lib/arm64-v8a/libbonded_ffi.so`
3. Try with DNS traffic first (small packets ~64B)

### Issue B: Worker Thread Hung
**Logs**: Queuing packet ✓ but Worker sending ✗

**Possible causes**:
- Tokio runtime deadlocked
- Transport path establishment never completed
- Socket creation blocked

**Fix**:
```bash
# Check if Rust thread is actually running
adb shell ps | grep bonded
# Look for >1 thread in bonded process
```

### Issue C: Server Not Responding
**Logs**: Worker sending ✓ but Worker received ✗

**Possible causes**:
- Server not listening on that address
- Firewall blocking traffic
- Wrong server address configured
- Network path binding failed

**Fix**:
1. Verify server is actually running: `curl {SERVER_ADDRESS}`
2. Check bind address in logs: "Bind addresses: [...]"
3. Try with explicit server address (not DNS name)

### Issue D: Android VPN I/O Broken
**Logs**: Ingested packets ✓ but Received inbound ✗

**Possible causes**:
- Inbound queue overflow (packets dropped silently)
- Poll loop not running / deadlocked
- MAX_POLLED_INBOUND_PER_CYCLE too low

**Fix**:
- Check `MAX_POLLED_INBOUND_PER_CYCLE` value in code (default: 32)
- Look for queue lock contention

### Issue E: TUN Device Write Failed
**Logs**: Writing inbound ✓ but no subsequent traffic ✗

**Possible causes**:
- TUN device closed
- Invalid packet format (wrong IP headers)
- MTU mismatch

**Fix**:
1. Verify packet type shows "IPv4" not "unknown"
2. Check MTU size in startup logs (should be 1500)
3. Verify packet has valid IP headers

## Packet Type Decoder

When you see packet logs like:
```
IPv4(proto=6,192.168.1.100->8.8.8.8)
```

Breakdown:
- `IPv4` = IP version 4 packet
- `proto=6` = Protocol number 6 = TCP
  - Other common: 17=UDP, 1=ICMP
- `192.168.1.100->8.8.8.8` = Source IP, Destination IP

If you see:
- `unknown(v=?)` = Packet format issue, check packet data
- `IPv6` = IPv6 packet (may not be supported yet)

## Filtering Noisy Logs

To focus on packet operations:
```bash
adb logcat | grep -E "Read.*bytes from TUN|Sending.*bytes to native|received frame"
```

To see only errors:
```bash
adb logcat | grep -E "BondedVPN.*error|bonded-ffi.*Failed|Worker.*failed"
```

## Performance Analysis

Look for stats lines:
```
[BondedVPN] I/O loop: 1000 outbound (65000B), 950 inbound (61750B)
```

This shows:
- 1000 packets sent out, 950 returned = 95% delivery
- Average packet size: 65B outbound, 65B inbound (consistent)
- If inbound << outbound: server not responding properly

## Next Steps

1. **Enable logging** by running app with logcat
2. **Trigger traffic** (ping, DNS query, HTTP request)
3. **Record logs** and check against the diagnostic table
4. **Share problem logs** when submitting bug reports

## Implementation Details

### Android VPN Service Changes (Kotlin)
- File: `android/android/app/src/main/kotlin/com/bonded/bonded_app/BondedVpnService.kt`
- Added logging to `startPacketIoLoopIfNeeded()`
- Added `describePacket()` for IPv4/IPv6 detection
- Tracks outbound/inbound counts and bytes

### FFI Changes (Rust)
- File: `crates/bonded-ffi/src/lib.rs`
- Added logging to `queue_outbound_packet()`
- Added logging to `poll_inbound_packet()`
- Added worker thread logging in `start_android_session()`
- Traces packets through transport layer

---

**Last Updated**: 2026-04-02 (Session 5)
**Status**: Logging infrastructure complete, ready for live debugging
