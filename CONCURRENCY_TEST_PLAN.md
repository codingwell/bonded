# High-Concurrency Performance Test Plan

## Test Scenario: 50 Concurrent TCP Connections with ICMP

This test plan validates that the lock contention fixes resolve the user-reported issues.

### Setup
```bash
# Terminal 1: Start bonded server
cargo run -p bonded-server --release

# Terminal 2: Run test client that establishes 50 concurrent connections
# Each connection forwards TCP packets and ICMP probes simultaneously
```

### Expected Behavior (Post-Fix)

#### Before Optimization (Old Architecture)
- 16 forwarding workers → ~3 connections per shard
- Single global TcpFlowTable Mutex → lock contention
- Single global UdpSessionManager Mutex → lock contention
- select! processes one response per iteration → artificial latency
- **Result**: TCP timeouts, ICMP lag, response latencies 100-500ms

#### After Optimization (New Architecture)
- 256 forwarding workers → one per connection average
- 256 independent TcpFlowTable shards → parallel lock-free lookups
- 16 independent UdpSessionManager shards → distributed access
- Batch pre-draining → responses processed immediately
- **Result**: No timeouts, ICMP responds in <10ms, consistent throughput

### Key Metrics to Monitor

1. **TCP Connection Latency**
   - Expected: <50ms per PSH-ACK cycle
   - Old: 200-1000ms under load

2. **ICMP Echo Response Time**
   - Expected: <10ms from request to response
   - Old: 100-500ms lag when concurrent traffic present

3. **CPU Usage**
   - Expected: Efficient (not spinning on locks)
   - Old: High CPU from lock contention

4. **Memory**
   - Expected: Stable per-shard allocations
   - Old: Spike when all traffic serializes through single lock

### Validation Commands

```rust
// Pseudocode for validation test
async fn test_high_concurrency() {
    // Establish 50 connections
    let clients = establish_50_connections().await;
    
    // Measure TCP PSH-ACK latency across all connections
    for client in clients {
        assert!(client.measure_latency() < 50ms);
    }
    
    // Measure concurrent ICMP response time
    let start = Instant::now();
    measure_icmp_echo_time_under_load(clients).await;
    assert!(start.elapsed() < 10ms);
    
    // Verify no connection drops
    assert_eq!(active_connections.len(), 50);
}
```

### Artifacts of Successful Fix

1. ✅ All 30 unit tests pass
2. ✅ No lock poisoning errors in logs
3. ✅ Response queue draining active in logs
4. ✅ Forwarding shards distributed evenly
5. ✅ No "slow forward" warnings

### Rollback If Needed

If issues persist:
1. Revert commits: 90b1e14, 36452f4, c9059e3
2. Check for other bottlenecks (tracing, logging overhead during load)
3. Consider if FORWARD_WORKER_SHARDS=256 needs tuning back to 128 or 512
