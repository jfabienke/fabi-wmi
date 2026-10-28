# Async Transport Design

> **Heads-up for the team:** Phase 5 async work is in flight. Keep referencing this doc for day-to-day status; the synchronous API remains the default surface until the async feature flag ships.

_Last updated: 2025-09-18_

---

## 1. Goals and Non-Goals

### Goals
- Deliver a Tokio-based async transport while preserving the existing synchronous API.
- Surface real WMI results by decoding `IEnumWbemClassObject` responses (no more stub fallback).
- Introduce connection pooling and rate limiting to support ≥1 000 concurrent queries.
- Add structured metrics/tracing for latency, pool utilisation, and error rates.
- Expose async-friendly FFI entrypoints without breaking the current C#/C consumers.

### Non-Goals
- Kerberos or SSPI authentication (NTLMv2 only).
- WMI event subscriptions or CIM/HTTP support.
- Full async rewrite of legacy examples; instead, add new async variants.
- Production orchestration (service management, packaging) beyond the library scope.

---

## 2. Current State Snapshot
- Synchronous pipeline (DCOM activation → NTLM bind/alter → RPC invoke) is stable; 68 sync tests pass.
- NDR encoder builds spec-compliant ExecQuery requests, but the decoder still falls back to stub JSON when the server returns an enumerator pointer.
- No async modules, connection pooling, or telemetry; every session opens a fresh `TcpStream`.

---

## 3. Target Architecture

```
                  ┌─────────────────────────────┐
                  │ AsyncWmiSession (new)       │
                  │  async exec_query/method    │
                  │  pulls from connection pool │
                  └──────────────┬──────────────┘
                                 │
┌─────────────────────────────┐  │
│ WmiConnectionPool (new)     ├──┼── deadpool::Pool<AsyncRealRpcTransport>
│  max_size, wait_timeout     │  │
│  semaphore limits           │  │ (`tokio::sync::Semaphore`)
│  concurrency                │  │
└──────────────┬──────────────┘  │
               │                 │
        ┌──────┴────────┐    ┌───┴────────────────────────┐
        │AsyncRealRpc   │    │ NdrCodec blocking wrapper  │
        │Transport (new)│    │ (spawn_blocking for encode │
        │ tokio::net    │    │ /decode until codec async) │
        │  ::TcpStream  │    │                            │
        └───────────────┘    └────────────────────────────┘
```

- `AsyncRpcTransport` trait provides `async fn invoke` wrapping `tokio::net::TcpStream`.
- Request encoding reuses existing sync codec; response decoding goes through `tokio::task::spawn_blocking` for now.
- Pool built on `deadpool` with a custom `Manager` for create/test/drop semantics.
- A `tokio::sync::Semaphore` enforces a global concurrency limit (default 100; env-tunable).
- Tracing spans annotate requests; optional `metrics` feature exports to OpenTelemetry.

---

## 4. API & Feature Flags

- `async` feature flag (disabled by default). When enabled:
  - `AsyncWmiSession` exposed via `fabi_wmi::async_api`.
  - FFI gains async variants:
    ```c
    typedef void (*wmi_async_callback)(const char* json, size_t len, int status, void* user);

    void wmi_exec_query_async(
        WmiSession* session,
        const char* namespace,
        const char* wql,
        wmi_async_callback cb,
        void* user_data);
    ```
  - Runtime spun up lazily for async calls (if caller doesn’t provide one).

- Synchronous entrypoints (`wmi_exec_query_json`, etc.) stay default and unchanged.
- `metrics` feature enables OTEL exporter with minimal boilerplate (using `tracing-opentelemetry`).

---

## 5. Dependencies

```toml
[dependencies]
tokio = { version = "1.37", features = ["rt-multi-thread", "net", "time", "macros"], optional = true }
async-trait = { version = "0.1", optional = true }
deadpool = { version = "0.12", optional = true }
deadpool-runtime = { version = "0.1", features = ["tokio_1"], optional = true }
opentelemetry = { version = "0.23", optional = true }
tracing-opentelemetry = { version = "0.25", optional = true }

[features]
default = []
async = ["tokio", "async-trait", "deadpool", "deadpool-runtime"]
metrics = ["async", "opentelemetry", "tracing-opentelemetry"]
```

---

## 6. Implementation Plan

| Day       | Tasks                                                                                                                                                                                            |
|-----------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Day 1** | Define `AsyncRpcTransport` (`async fn invoke`/`read_pdu`/`write_pdu`). Implement `AsyncRealRpcTransport` using `tokio::net::TcpStream` with async bind/alter flow (reuse existing PDU builders). |
| **Day 2** | Wrap existing codec via `spawn_blocking` for encode/decode. Implement enumerator decoding for the common `IEnumWbemClassObject::Next` (single batch).                                            |
| **Day 3** | Build `WmiConnectionPool` with `deadpool`. Configure max size, wait timeout, and a `tokio::sync::Semaphore` to limit in-flight requests.                                                         |
| **Day 4** | Create `AsyncWmiSession` API mirroring the sync version (`connect_server_async`, `exec_query_async`). Integrate pool/semaphore; expose builder options (env overrides).                          |
| **Day 5** | Extend FFI: add async exec/query with callback. Use `tokio::spawn` + `mpsc` to return results; document callback lifetime. Provide C#/C example.                                                 |
| **Day 6** | Instrument with tracing spans (`Span::record` for host/opnum). Optional metrics exporter under `metrics` feature. Add async unit/integration tests (`tokio::test`).                              |
| **Day 7** | Benchmark (criterion) for 1 000 concurrent queries. Run soak/chaos tests (simulated delays, dropped connections). Update docs/changelog.                                                         |

---

## 7. Testing & Validation

- **Async unit/integration tests**: `tokio::test` to cover happy path, pool exhaustion, semaphore limiting, transport errors, enumerator decoding.
- **Load & soak tests**: Criterion benchmark + manual soak (script hitting stub + real Windows host when available).
- **FFI tests**: small C harness verifying callback invoked exactly once per request.
- **Chaos testing**: optional use of `tokio::time::pause`/`advance` to simulate timeouts.
- **Coverage**: aim ≥65% with async modules included.

---

## 8. Risks & Mitigations

| Risk                                                             | Mitigation                                                                                                        |
|------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------|
| Asynchronous FFI callbacks mishandled (double-free, reentrancy). | Document callback requirements; enforce pointer validity checks; ensure Rust owns buffers until callback returns. |
| Connection pool hides unhealthy connections.                     | Implement `Manager::check` that sends a small ping (e.g., ORPC KeepAlive). Expire idle connections.               |
| Blocking decode stalls runtime.                                  | Use `spawn_blocking` and size the blocking pool appropriately; future work can move codec to async if needed.     |
| Enumerator decoding misses multi-batch responses.                | For Phase 5 handle single `Next` batch; log warning if more data expected and track for Phase 6.                  |
| Tokio runtime conflicts when embedded.                           | Provide helper to run in externally provided runtime; document `Runtime::new` fallback.                           |

---

## 9. Documentation Updates

- Update `ARCHITECTURE.md` with async layer diagram and feature flag explanation.
- Update `IMPLEMENTATION-STRATEGY.md` to reflect Phase 5 checklist (async transport, pool, enumerator decoding).
- Once enumerator decoding is complete, revise `PROTOCOL-COMPLETION.md` percentages (NDR/WMI >80%).
- Add README section for async API (Rust + C#/FFI usage).

---

## 10. Success Criteria

- Async ExecQuery returns real JSON (no stub fallback).
- 1 000 concurrent async queries complete with <500 ms average latency (<1 % failure) in benchmark.
- Sync API semantics unchanged; existing examples/tests continue to pass.
- Async FFI callback verified (sample C#/C harness).|
- Optional metrics feature exports spans/histograms via OpenTelemetry.

---

## 11. Next Steps

1. Create feature branch `async`.
2. Implement Day 1 deliverables (async transport handshake) and add initial async tests.
3. Iterate through plan, keeping docs updated and rerunning `cargo test`/`cargo bench`.

With this design, the project moves from “prototype” toward “production-ready,” enabling the high-volume, low-latency WMI workloads outlined in the original goals.
