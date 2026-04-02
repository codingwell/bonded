# Android VPN Traffic Flow Investigation Report

**Completed**: 2026-04-02  
**Focus**: Full packet flow trace from TUN device to FFI to Rust to transport and back

---

## Executive Summary

The Android VPN packet flow **is architecturally sound** and **passes end-to-end synthetic tests**, but there are several **critical issues** preventing real traffic:

1. **No packet fragmentation/reassembly logic** — packets are wrapped raw without MTU awareness
2. **TUN device configuration gaps** — Linux client uses defaults; Android likely needs explicit setup
3. **Insufficient logging** — packet flow is opaque, making it hard to debug live issues
4. **FFI tests only use non-IP data** — no validation with real binary IP packets

---

## Detailed Packet Flow Analysis

### 1. **Android → FFI Boundary** ✓ WORKING

**Flow**: Android TUN device → Java VPN service → JNI → Rust FFI

**Code Path**:
- [BondedVpnService.kt](android/android/app/src/main/kotlin/com/bonded/bonded_app/BondedVpnService.kt#L206): Reads from TUN via FileInputStream
  ```kotlin
  val readBytes = input.read(buffer)  // 32KB buffer
  processOutboundPacket(buffer, readBytes)
  ```

- [BondedVpnService.kt](android/android/app/src/main/kotlin/com/bonded/bonded_app/BondedVpnService.kt#L321): Copies and passes to native code
  ```kotlin
  private fun processOutboundPacket(buffer: ByteArray, length: Int) {
      val packet = buffer.copyOf(length)
      nativeHandleTunOutbound(packet)  // JNI call
  }
  ```

- [bonded-ffi/src/lib.rs](crates/bonded-ffi/src/lib.rs#L588): JNI handler
  ```rust
  pub extern "system" fn Java_com_bonded_bonded_1app_BondedVpnService_nativeHandleTunOutbound(
      env: jni::JNIEnv,
      _obj: jni::objects::JObject,
      packet: jni::objects::JByteArray,
  ) {
      if let Ok(packet) = env.convert_byte_array(&packet) {
          queue_outbound_packet(packet);  // ← Direct pass-through
      }
  }
  ```

**Status**: ✓ **WORKING** — JNI conversion is straightforward, no data loss.

---

### 2. **FFI Outbound Queue** ✓ WORKING

**Code**: [bonded-ffi/src/lib.rs](crates/bonded-ffi/src/lib.rs#L422)

```rust
fn queue_outbound_packet(packet: Vec<u8>) {
    if let Some(handle) = android_session_slot().lock().ok() {
        let _ = handle.outbound_tx.send(packet);  // ← mpsc channel
    }
}
```

**Status**: ✓ **WORKING** — Unbounded channel, packets queued reliably.

---

### 3. **Worker Thread → Session Layer → Transport** ✓ MOSTLY WORKING

**Code**: [bonded-ffi/src/lib.rs](crates/bonded-ffi/src/lib.rs#L280)

The worker thread (spawned in `start_android_session`) runs this loop:

```rust
tokio::select! {
    // Outbound path
    maybe_packet = outbound_rx.recv() => {
        match maybe_packet {
            Some(packet) => {
                if packet.is_empty() && worker_stop_flag.load(Ordering::SeqCst) {
                    break;
                }

                let packet_len = packet.len() as u64;
                // ← Packet wrapped in SessionFrame here
                let frame = session.create_outbound_frame(Bytes::from(packet), 0);
                if let Err(err) = transports[active_index].send(frame).await {
                    // ← Handle transport failure
                    if transports.len() == 1 {
                        update_snapshot(..., "error");
                        break;
                    }
                    transports.remove(active_index);
                    // Switch active path
                }
                // ← Increment counters
                update_snapshot(&worker_snapshot, |s| {
                    s.outbound_packets += 1;
                    s.outbound_bytes += packet_len;
                });
            }
            None => break,
        }
    }

    // Inbound path
    frame_result = transports[active_index].recv() => {
        match frame_result {
            Ok(frame) => {
                // ← Reassemble via session layer
                let ready = match session.ingest_inbound(frame) {
                    Ok(ready) => ready,
                    Err(err) => {
                        update_snapshot(..., "error");
                        break;
                    }
                };

                if !ready.is_empty() {
                    let mut queue = worker_inbound_queue.lock().ok();
                    for packet in ready {
                        // ← Raw payload (no SessionFrame header) pushed to queue
                        queue.push_back(packet.payload.to_vec());
                    }
                }
            }
            Err(err) => { /* handle failure, switch paths */ }
        }
    }
}
```

**Key Points**:
- Packets are wrapped by `session.create_outbound_frame(packet, flags=0)`
- Sent via `transports[active_index].send(frame)`
- On receive, frames are reassembled via `session.ingest_inbound(frame)`
- Final payloads (without SessionFrame header) pushed to `inbound_queue`

**Status**: ✓ **WORKING** — Logic is sound, but see issues below.

---

### 4. **Session Layer Framing** ✓ WORKING

**Code**: [bonded-core/src/session.rs](crates/bonded-core/src/session.rs#L64)

```rust
pub fn create_outbound_frame(&mut self, payload: Bytes, flags: u32) -> SessionFrame {
    let frame = SessionFrame {
        header: SessionHeader {
            connection_id: self.connection_id,  // Always 1 for now
            sequence: self.next_tx_sequence,    // Incremented each time
            flags,                               // Always 0 (unused)
        },
        payload,  // ← Raw packet data, no fragmentation
    };
    self.next_tx_sequence = self.next_tx_sequence.wrapping_add(1);
    frame
}

pub fn encode(&self) -> Bytes {
    // Pack: connection_id(u32) + sequence(u64) + flags(u32) + payload
    let mut buf = BytesMut::with_capacity(HEADER_LEN + self.payload.len());
    buf.put_u32(self.header.connection_id);
    buf.put_u64(self.header.sequence);
    buf.put_u32(self.header.flags);
    buf.extend_from_slice(&self.payload);
    buf.freeze()
}

pub fn decode(raw: &[u8]) -> Result<Self, FrameError> {
    if raw.len() < HEADER_LEN {
        return Err(FrameError::BufferTooSmall);
    }
    let mut raw = raw;
    let connection_id = raw.get_u32();
    let sequence = raw.get_u64();
    let flags = raw.get_u32();
    let payload = Bytes::copy_from_slice(raw);  // ← Everything else is payload
    Ok(Self {
        header: SessionHeader { connection_id, sequence, flags },
        payload,
    })
}

pub fn ingest_inbound(
    &mut self,
    frame: SessionFrame,
) -> Result<Vec<SessionFrame>, SessionStateError> {
    // Validate connection_id and sequence
    // Store in reorder_buffer
    // Return contiguous sequence starting from next_rx_sequence
    let mut ready = Vec::new();
    while let Some(next) = self.reorder_buffer.remove(&self.next_rx_sequence) {
        ready.push(next);
        self.next_rx_sequence = self.next_rx_sequence.wrapping_add(1);
    }
    Ok(ready)
}
```

**Frame Format** (16-byte header + variable payload):
```
  0:  u32 connection_id
  4:  u64 sequence
 12:  u32 flags
 16:  ... raw IP packet ...
```

**Status**: ✓ **WORKING** — Well-tested via unit tests in [session.rs](crates/bonded-core/src/session.rs#L145).

**ISSUE**: `flags` is always 0 and unused. No fragmentation support.

---

### 5. **NaiveTCP Transport** ✓ WORKING

**Code**: [bonded-core/src/transport.rs](crates/bonded-core/src/transport.rs#L125)

```rust
impl Transport for NaiveTcpTransport {
    async fn send(&mut self, frame: SessionFrame) -> anyhow::Result<()> {
        let encoded = frame.encode();  // ← 16-byte header + payload
        let len = u32::try_from(encoded.len())?;
        self.stream.write_all(&len.to_be_bytes()).await?;  // ← 4-byte length prefix
        self.stream.write_all(&encoded).await?;
        self.stream.flush().await?;
        Ok(())
    }

    async fn recv(&mut self) -> anyhow::Result<SessionFrame> {
        let mut len_buf = [0_u8; 4];
        self.stream.read_exact(&mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf) as usize;
        
        let mut payload = vec![0_u8; len];
        self.stream.read_exact(&mut payload).await?;
        Ok(SessionFrame::decode(&payload)?)
    }
}
```

**Format on Wire**:
```
[4 bytes: length][16 bytes: frame header][N bytes: payload]
```

**Status**: ✓ **WORKING** — Simple length-prefixed encoding, matches recv exactly.

**Note**: No fragmentation of frames across TCP packet boundaries, relies on TCP buffering.

---

### 6. **Inbound Queue → Java** ✓ WORKING

**Code**: [bonded-ffi/src/lib.rs](crates/bonded-ffi/src/lib.rs#L435)

```rust
fn poll_inbound_packet() -> Option<Vec<u8>> {
    android_session_slot()
        .lock()
        .ok()
        .and_then(|handle| {
            handle.inbound_queue.lock().ok().and_then(|mut q| q.pop_front())
        })
}
```

**Java Call** [BondedVpnService.kt](android/android/app/src/main/kotlin/com/bonded/bonded_app/BondedVpnService.kt#L342):
```kotlin
private fun pollInboundPacket(): ByteArray? {
    if (!nativeProcessingAvailable) return null
    return try {
        nativePollTunInbound()  // ← JNI call
    } catch (_: UnsatisfiedLinkError) {
        nativeProcessingAvailable = false
        null
    }
}

// In packet loop:
repeat(MAX_POLLED_INBOUND_PER_CYCLE) {
    val inbound = pollInboundPacket()
    if (inbound == null || inbound.isEmpty()) return@repeat
    output.write(inbound)  // ← Write to VPN device
    output.flush()
}
```

**Status**: ✓ **WORKING** — Packets are returned to Java and written to TUN device.

---

## Comparison: Linux Client vs. Android FFI

Both use **identical** session/transport logic:

| Component | Linux | Android |
|-----------|-------|---------|
| TUN read | `device.recv(&mut tun_buf)` | `FileInputStream.read(buffer)` |
| Frame creation | `state.create_outbound_frame()` | `session.create_outbound_frame()` |
| Transport send | `transports[i].send(frame)` | `transports[i].send(frame)` |
| Transport recv | `transports[i].recv()` | `transports[i].recv()` |
| Packet reassembly | `state.ingest_inbound()` | `session.ingest_inbound()` |
| TUN write | `device.send(&packet)` | `FileOutputStream.write(inbound)` |

**Linux Packet Loop**: [bonded-client/src/lib.rs](crates/bonded-client/src/lib.rs#L450)
```rust
async fn run_linux_packet_loop(
    tun_name: &str,
    transports: Vec<ClientTransport>,
) -> anyhow::Result<()> {
    let config = build_tun_config(tun_name);
    let device = tun::create_as_async(&config)?;
    let mut state = SessionState::new(1);
    let mut tun_buf = vec![0_u8; 8192];

    loop {
        select! {
            tun_result = device.recv(&mut tun_buf) => {
                let read = tun_result?;
                if read == 0 { continue; }
                
                let frame = state.create_outbound_frame(Bytes::copy_from_slice(&tun_buf[..read]), 0);
                match transports[active_index].send(frame).await {
                    Ok(()) => {}
                    Err(err) => {
                        if transports.len() == 1 {
                            return Err(err);
                        }
                        transports.remove(active_index);
                        if active_index >= transports.len() { active_index = 0; }
                    }
                }
            }
            frame_result = transports[active_index].recv() => {
                match frame_result {
                    Ok(frame) => {
                        let ready = state.ingest_inbound(frame)?;
                        for packet in ready {
                            let _ = device.send(&packet.payload).await?;
                        }
                    }
                    Err(err) => { /* switch path */ }
                }
            }
        }
    }
}
```

---

## Critical Issues Found

### Issue 1: **No Packet Fragmentation/Reassembly**

The `flags` field in SessionFrame is **always 0** and **never used**.

There is **no mechanism** to:
- Fragment packets larger than MTU
- Reassemble fragmented packets
- Mark fragmented frames
- Handle MTU path discovery

**Impact**: If a TUN device produces a 1500-byte IP packet and the MTU is smaller, the frame will fail or be corrupted.

**Evidence**:
- [bonded-core/src/session.rs](crates/bonded-core/src/session.rs#L64): `flags` parameter always passed as `0`
- No fragmentation flag definitions anywhere
- Android FFI: [line 315](crates/bonded-ffi/src/lib.rs#L315)
  ```rust
  let frame = session.create_outbound_frame(Bytes::from(packet), 0);
  ```
- Linux client: [line 464](crates/bonded-client/src/lib.rs#L464)
  ```rust
  let frame = state.create_outbound_frame(Bytes::copy_from_slice(&tun_buf[..read]), 0);
  ```

**Fix Needed**: Implement fragmentation in session layer or at TUN boundary.

---

### Issue 2: **Linux TUN Configuration Using Defaults**

**Code**: [bonded-client/src/lib.rs](crates/bonded-client/src/lib.rs#L445)

```rust
#[cfg(target_os = "linux")]
fn build_tun_config(tun_name: &str) -> Configuration {
    let mut config = Configuration::default();
    config.tun_name(tun_name).up();
    config  // ← Uses all defaults!
}
```

**Missing Configuration**:
- No IP address assignment
- No netmask
- No MTU setting
- No routes
- Device is `up()` but not configured

**Impact**: The TUN device may not function correctly. Packets arriving at the device might be dropped if there are no matching routes.

**Android Comparison**: The Kotlin VPN service uses [VpnService.Builder](https://developer.android.com/reference/android/net/VpnService.Builder) which explicitly:
- Sets address: `10.8.0.2/32`
- Sets route: `0.0.0.0/0` (default route via VPN)
- Sets MTU: 1500 (default Android)

**Expected Linux Configuration**:
```rust
fn build_tun_config(tun_name: &str) -> Configuration {
    let mut config = Configuration::default();
    config
        .tun_name(tun_name)
        .address("10.8.0.1", 24)  // Or /32 like Android
        .up()
        .mtu(1500);
    config
}
```

**Fix Needed**: Explicitly configure TUN address, routes, and MTU.

---

### Issue 3: **No Logging in Packet Path**

The packet flow is completely opaque:
- No logs when packets are queued
- No logs when frames are sent/received
- No logs of frame sizes or sequence numbers
- No logs of transport errors

**Impact**: When debugging live traffic issues, there's no visibility into where packets are dropped.

**Affected Code**:
- [bonded-ffi/src/lib.rs](crates/bonded-ffi/src/lib.rs#L422): `queue_outbound_packet()` — no logging
- [bonded-ffi/src/lib.rs](crates/bonded-ffi/src/lib.rs#L280): Worker loop — only snapshot updates, no per-packet logs
- [bonded-core/src/transport.rs](crates/bonded-core/src/transport.rs#L125): `NaiveTcpTransport::send()` — no logs
- [bonded-core/src/session.rs](crates/bonded-core/src/session.rs#L77): `ingest_inbound()` — no reordering logs

**Fix Needed**: Add `tracing::debug!()` or `eprintln!()` at packet boundaries.

---

### Issue 4: **FFI Tests Use Non-IP Data**

**Code**: [bonded-ffi/src/lib.rs](crates/bonded-ffi/src/lib.rs#L771)

```rust
#[test]
fn android_session_runtime_can_pair_and_exchange_packets() {
    // ... setup ...
    
    queue_outbound_packet(b"android-smoke".to_vec());  // ← String, not IP packet!

    let echoed = (0..30)
        .find_map(|_| {
            std::thread::sleep(Duration::from_millis(100));
            poll_inbound_packet()
        })
        .expect("inbound packet should be echoed back");
    assert_eq!(echoed, b"android-smoke");
}
```

**Impact**: 
- Proves the flow works for arbitrary data
- Does NOT prove it works for real IP packets
- Real IP packets have different structure: IP header, TCP/UDP headers, payload
- Real packets may trigger different buffering behavior in TUN devices

**What's Missing**:
- Test with actual IP packet (e.g., ICMP ping request)
- Test with large packets (>1500 bytes)
- Test with fragmented IP packets
- Test with rapid packet sequences

**Fix Needed**: Add integration test with real IP packets.

---

### Issue 5: **Potential Android MTU/Buffer Mismatch**

**Android VPN Buffer Size**: [BondedVpnService.kt](android/android/app/src/main/kotlin/com/bonded/bonded_app/BondedVpnService.kt#L190)
```kotlin
val buffer = ByteArray(32767)  // ← 32KB buffer
```

**Typical MTU**: 1500 bytes (per-packet) or larger

**Typical TUN MTU**: 1500-4096 bytes depending on system

**Issue**: If the Android OS is configured with a TUN MTU of 4KB but the app sets VPN interface address with MTU 1500, there may be a mismatch. Or if packets are being coalesced by the TUN layer before reaching the app, the buffer might be insufficient.

**Evidence**: Device characteristics unknown from code alone — needs runtime inspection.

---

### Issue 6: **No Flow Control on Inbound Queue**

**Code**: [bonded-ffi/src/lib.rs](crates/bonded-ffi/src/lib.rs#L353)

```rust
for packet in ready {
    queue.push_back(packet.payload.to_vec());  // ← Unbounded push
}
```

**Issue**: If the Java side (`pollInboundPacket`) is slow or blocking, packets accumulate in the queue. There's no backpressure mechanism.

**Impact**: Memory leak if Java loops blocks while packets keep arriving.

**Fix Needed**: Implement a bounded queue with backpressure or drop old packets.

---

## Test Coverage Summary

| Layer | Test | Status |
|-------|------|--------|
| JNI → Rust FFI | `bonded_ffi` integration test | ✓ PASSING (non-IP data) |
| Session state | `session.rs` unit tests | ✓ PASSING |
| Transport | `transport.rs` unit tests | ✓ PASSING |
| Linux auth | `client_integration.rs` | ✓ PASSING |
| **Real IP packets through TUN** | *None* | ✗ **MISSING** |
| **Large packet handling** | *None* | ✗ **MISSING** |
| **Android full integration** | *Manual only* | ✗ **NOT AUTOMATED** |

---

## Suggested Debugging Steps

### 1. Add Packet-Level Logging

Add to [bonded-ffi/src/lib.rs](crates/bonded-ffi/src/lib.rs#L422):
```rust
fn queue_outbound_packet(packet: Vec<u8>) {
    eprintln!("[bonded-ffi] Outbound packet: {} bytes, first 4: {:02x?}", 
        packet.len(), 
        &packet[..4.min(packet.len())]);
    if let Some(handle) = android_session_slot().lock().ok() {
        let _ = handle.outbound_tx.send(packet);
    }
}
```

Add to [bonded-core/src/session.rs](crates/bonded-core/src/session.rs#L77):
```rust
pub fn ingest_inbound(&mut self, frame: SessionFrame) -> Result<Vec<SessionFrame>, SessionStateError> {
    eprintln!("[session] RX frame: seq={}, payload_size={}", frame.header.sequence, frame.payload.len());
    // ... rest of code ...
    eprintln!("[session] Ready packets: {}", ready.len());
    Ok(ready)
}
```

### 2. Fix Linux TUN Configuration

Update [bonded-client/src/lib.rs](crates/bonded-client/src/lib.rs#L445):
```rust
#[cfg(target_os = "linux")]
fn build_tun_config(tun_name: &str) -> Configuration {
    let mut config = Configuration::default();
    config
        .tun_name(tun_name)
        .address("10.8.0.1", 32)  // Match Android's /32
        .up()
        .mtu(1500);
    config
}
```

### 3. Create IP Packet Test

Add to [crates/bonded-ffi/src/lib.rs](crates/bonded-ffi/src/lib.rs#L900):
```rust
#[test]
fn ffi_handles_real_ip_packets() {
    // Create a minimal ICMP echo request packet
    let icmp_packet = vec![
        0x45, 0x00, 0x00, 0x54,  // IP header: version, tos, length
        0x00, 0x00, 0x40, 0x00,  // IP: id, flags, ttl
        0x01, 0xa7,              // IP: protocol (ICMP), checksum
        // ... more header and payload ...
    ];
    
    queue_outbound_packet(icmp_packet.clone());
    // Assert it was queued and echoed back
}
```

### 4. Inspect Android Runtime

Add to [BondedVpnService.kt](android/android/app/src/main/kotlin/com/bonded/bonded_app/BondedVpnService.kt#L321):
```kotlin
private fun processOutboundPacket(buffer: ByteArray, length: Int) {
    val packet = buffer.copyOf(length)
    Log.d("BondedVPN", "TUN outbound: $length bytes, first_4_hex=${packet.take(4).joinToString(",") { "%02x".format(it) }}")
    nativeHandleTunOutbound(packet)
}
```

---

## Summary of Root Causes (Probable)

1. **Linux client TUN not configured** → packets dropped by OS
2. **Fragmentation not implemented** → large packets fail
3. **No logging** → impossible to see where packets drop
4. **Android/Linux MTU mismatch** → payload corrupted or truncated
5. **Tests only use synthetic data** → real packet handling untested

**Most Likely Culprit**: Issue #1 (Linux TUN configuration) combined with #4 (MTU handling).

