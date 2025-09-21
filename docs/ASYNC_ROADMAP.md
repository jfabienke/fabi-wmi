# Async API Roadmap

This document tracks the async API implementation status and roadmap for linux-wmi.

## Current Status (January 2024)

### ✅ Already Implemented

#### Core Async Transport (`src/transport.rs`)
- `AsyncRealRpcTransport` (lines 1468-1911) - Full async RPC transport
  - `async fn connect()` - Async connection establishment
  - `async fn invoke()` - Async RPC invocation
  - `async fn check()` - Connection health check
  - `async fn shutdown()` - Clean shutdown
- Helper functions:
  - `async fn write_all_with_timeout()`
  - `async fn read_pdu_async()`
  - `async fn read_exact_with_timeout()`
  - `async fn read_chunk_with_timeout()`

#### Connection Pooling (`src/pool.rs`)
- `AsyncTransportManager` - Pool manager for async transports
- `GenericConnectionPool<M>` - Generic async connection pool
- `ConnectionPool` - Production connection pool
- Full deadpool integration with health checks and recycling

#### Async NDR Wrapper (`src/ndr.rs`)
- `AsyncNdrCodec` struct (lines 64-101)
  - `async fn encode_exec_query()`
  - `async fn decode_exec_query()`
- Uses `spawn_blocking` for CPU-intensive NDR operations

### 🚧 Partially Implemented

#### Kerberos Async (`src/transport.rs`)
- `connect_with_kerberos()` (line 504) - Exists but marked as dead code
- Needs to be made truly async (currently may block on kinit)

### ❌ Not Yet Implemented

#### Async WMI Session
Need to create async versions of:
- `WmiSession::new()` → `WmiSession::async_new()`
- `exec_query()` → `async fn exec_query()`
- `open_namespace()` → `async fn open_namespace()`

#### Async Examples
- Convert `examples/full_wmi_query.rs` to async
- Add `examples/async_pool_demo.rs`
- Add `examples/async_concurrent_queries.rs`

## Implementation Plan

### Phase 1: Complete Core Async (Week 1)

#### Day 1-2: Async WmiSession
```rust
// src/wmi.rs
impl WmiSession {
    pub async fn async_new(
        host: &str,
        credentials: Option<Credentials>,
    ) -> Result<Self, WmiError> {
        // Use AsyncRealRpcTransport
        // Handle async authentication
    }

    pub async fn exec_query_async(&self, query: &str) -> Result<Vec<Value>, WmiError> {
        // Use async transport
        // Decode with AsyncNdrCodec
    }
}
```

#### Day 3-4: Fix Kerberos Async
```rust
// Make connect_with_kerberos truly async
// Handle kinit in spawn_blocking if needed
// Integrate with async handshake
```

#### Day 5-7: Testing & Examples
- Integration tests with tokio::test
- Convert full_wmi_query.rs example
- Add concurrent query example
- Benchmark async vs sync

### Phase 2: Performance Optimization (Week 2)

#### Connection Pool Tuning
- Optimal pool size discovery
- Connection warmup strategies
- Idle timeout configuration

#### Buffer Management
- Reusable buffer pools
- Zero-copy where possible
- Optimal read/write buffer sizes

#### Concurrency Patterns
```rust
// Enable concurrent queries
let futures = queries.iter().map(|q| session.exec_query_async(q));
let results = futures::future::join_all(futures).await?;
```

### Phase 3: Advanced Features (Week 3+)

#### Streaming Results
```rust
// For large result sets
impl WmiSession {
    pub fn exec_query_stream(&self, query: &str)
        -> impl Stream<Item = Result<Value, WmiError>> {
        // Stream results as they arrive
    }
}
```

#### Async Notifications
```rust
// WMI event subscriptions
pub async fn subscribe_events(
    &self,
    query: &str
) -> impl Stream<Item = WmiEvent> {
    // Async event stream
}
```

## Feature Flags

```toml
[features]
default = ["kerberos"]
async = ["tokio", "async-trait", "deadpool", "deadpool-runtime"]
async-std-runtime = ["async-std", "async-trait"]  # Future: async-std support
```

## Testing Strategy

### Unit Tests
- Mock async transports
- Test timeout behavior
- Test concurrent operations

### Integration Tests
```rust
#[tokio::test]
async fn test_async_wmi_query() {
    let session = WmiSession::async_new("host", None).await?;
    let results = session.exec_query_async("SELECT * FROM Win32_Process").await?;
    assert!(!results.is_empty());
}
```

### Performance Tests
```rust
#[tokio::test]
async fn benchmark_async_vs_sync() {
    // Compare throughput
    // Measure latency
    // Test under load
}
```

## Dependencies

### Current
- `tokio = { version = "1.36", features = ["rt-multi-thread", "net", "time", "macros", "io-util"] }`
- `async-trait = "0.1"`
- `deadpool = { version = "0.12", features = ["managed", "rt_tokio_1"] }`

### Future Considerations
- `async-std` - Alternative async runtime
- `smol` - Lightweight async runtime
- `futures = "0.3"` - Stream utilities

## Migration Guide

### For Users

#### Sync to Async
```rust
// Before (sync)
let session = WmiSession::new("host", Some(creds))?;
let results = session.exec_query("SELECT * FROM Win32_Process")?;

// After (async)
let session = WmiSession::async_new("host", Some(creds)).await?;
let results = session.exec_query_async("SELECT * FROM Win32_Process").await?;
```

#### Using the Connection Pool
```rust
let pool = ConnectionPool::new(config, 10)?;
let conn = pool.acquire().await?;
let results = conn.exec_query("SELECT * FROM Win32_Process").await?;
// Connection automatically returned to pool on drop
```

## Success Criteria

- [ ] All async functions properly use .await
- [ ] No blocking operations in async contexts
- [ ] Connection pool maintains health
- [ ] Async performance ≥ sync performance
- [ ] Examples demonstrate concurrent operations
- [ ] Documentation complete with async patterns
- [ ] CI tests pass with async feature enabled

## Timeline

- **Week 1**: Core async implementation complete
- **Week 2**: Performance optimization and tuning
- **Week 3+**: Advanced features as needed
- **Release**: v0.3.0 with async as stable feature

## Risks & Mitigations

### Risk: Blocking Operations
**Mitigation**: Use `spawn_blocking` for CPU-intensive or potentially blocking operations

### Risk: Tokio Lock Contention
**Mitigation**: Use async-aware locks (`tokio::sync::Mutex` not `std::sync::Mutex`)

### Risk: Connection Pool Exhaustion
**Mitigation**: Implement proper timeout and retry strategies

### Risk: Breaking Changes
**Mitigation**: Keep sync API as default, async behind feature flag initially