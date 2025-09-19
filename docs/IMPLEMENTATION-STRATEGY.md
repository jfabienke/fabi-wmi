# Implementation Strategy & Tracker

This strategy supersedes the earlier draft and maps directly to the updated phased plan. Each phase is scoped to a shippable milestone with clear dependencies, verification steps, and an at-a-glance tracker. Progress estimates assume one full-time developer; total effort to MVP (real queries through the shim) remains ~4–6 weeks.

## Tracker Legend
- `[ ]` Not started
- `[~]` In progress
- `[x]` Complete

## Debug Logging
- Structured logging is available via the `tracing` crate. Enable with `RUST_LOG=linux_wmi=debug` to capture spans/events in JSON.
- Example: `RUST_LOG=linux_wmi=debug cargo run --example test_connect <host> | jq '.'`
- Tests set `LINUX_WMI_SKIP_EPM=1` to avoid live network calls; unset for end-to-end tracing against a real host.

---

## Phase 1 — ~~Endpoint Mapper~~ DCOM Activation Resolution *(Target: 100%, Est. 2–3 days)* `[x]`
**Goal**: Resolve WMI dynamic port via DCOM activation (EPM doesn't work for WMI).

**Scope**
- ~~Integrate `build_wmi_tower()` into `dcom::resolve_wmi_port`~~ EPM returns EPT_S_NOT_REGISTERED (0x1c00001a) for WMI.
- Implemented `activate_wmi_dcom()` using IRemoteSCMActivator::RemoteActivation (opnum=4) per MS-DCOM §3.1.1.5.4.1.
- Parse DUALSTRINGARRAY response (MS-DCOM §2.2.4) to extract dynamic port from string bindings.

**Dependencies**
- `socket2` for timeouts, NTLMv2 auth for RemoteActivation.
- ORPCTHIS/ORPCTHAT headers for DCOM calls.

**Verification**
- Unit: `dcom::tests::parse_remote_activation_response` covers DUALSTRINGARRAY parsing.
- Integration: `examples/dcom_activation.rs` validates DCOM flow with real credentials.
- Fallback: `LINUX_WMI_SKIP_EPM=1` environment variable bypasses port resolution for development.

**Status**
- Completed — DCOM activation with NTLM auth works. Windows permissions (DCOM Launch/Activation) required for live hosts.

---

## Phase 2 — RPC Bind, NTLM Auth & Fragmentation *(Target: 100%, Est. 4–5 days)* `[x]`
**Goal**: Complete authenticated MS-RPCE bind with NTLMv2 and handle fragmented responses.

**Scope**
- `RealRpcTransport::connect` sends bind (ptype=0x0B) with Type1, parses bind_ack (ptype=0x0C) for Type2 challenge.
- Generate alter_context (ptype=0x0E) with Type3 message; capture `context_id`, `max_xmit/recv`, and session key.
- **NEW**: Multi-fragment PDU reassembly for responses >4KB (loop until PFC_LAST_FRAG, concatenate stub data).

**Dependencies**
- Phase 1 (DCOM port resolution).
- NTLMv2 implementation in `auth.rs` with HMAC-MD5 responses, session key derivation.

**Completed Features**
- Full NTLM Type1/2/3 handshake with challenge extraction and response generation.
- Fragment support in `read_pdu()` - handles multiple fragments, reassembles complete PDUs.
- Comprehensive test coverage including 5KB mock responses split across fragments.
- Auth trailers correctly positioned with padding calculations.

**Status**
- Completed — RPCE layer 100% complete with full fragmentation support.
- Unit tests: 18 transport tests including fragment reassembly scenarios.
- E2E: Works with `LINUX_WMI_SKIP_EPM=1` fallback, real DCOM requires Windows permissions.

---

## Phase 3 — Minimal NDR Codec & ExecQuery *(Target: 100%, Est. 7–10 days)* `[~]`
**Goal**: Marshal and unmarshal ExecQuery requests/responses over the authenticated transport.

**Scope**
- Implement `NdrCodec` for BSTR, VARIANT (VT_BSTR, VT_I4, VT_NULL), and conformant arrays.
- Wire `IWbemLocator::connect_server` and `IWbemServices::exec_query` to use the codec and transport opnum 9.
- Produce JSON results compatible with the shim/ORMi usage patterns.

**Completed Features** (100% foundation complete)
- Full NDR type system in `src/ndr/types.rs`: BSTR, VARIANT (9 types), ConformantArray, SafeArray.
- RealNdrCodec implementation with ExecQuery request encoding (ORPCTHIS + conformant strings + flags).
- Response decoding with ORPCTHAT parsing and HRESULT validation.
- Environment variable `LINUX_WMI_USE_REAL_NDR=1` to switch between stub and real codec.
- Golden byte tests validating encoding against MS-NDR specifications.
- Integration tests confirming codec switching and stub fallback behavior.

**Dependencies**
- Phase 2 (authenticated transport with fragmentation) ✅
- Specs: MS-WMI §§2.2.1 & 3.1.4, MS-NDR §2.2 ✅

**Status**
- Foundation complete on the request/encoding side.
- Response decoding currently falls back to stub JSON when the server returns an enumerator pointer.
- 10 unit tests + 6 golden byte tests + 2 integration tests exercising the codec foundation.

---

## Phase 4 — Full ORPC Integration and WMI Protocol *(Target: 90%, Est. 5–7 days)* `[~]`
**Goal**: Complete ORPC resolver, implement signing/sealing, and achieve production-ready WMI protocol.

**Scope**
- OXID resolution to extract IPID for stateful DCOM objects.
- Full signing (HMAC-MD5) and sealing (RC4) using NTLM session_key.
- ORPCTHIS/THAT header handling for object calls.
- Multi-fragment PDU support with auth trailer handling.

**Progress to date (~75%)**
- OXID resolver implementation feeds `connect_with_oxid` for authenticated sessions.
- Signing/sealing with sequence numbers and auth pads is in place.
- ORPCTHIS/ORPCTHAT headers emitted for object calls; fragment reassembly honours auth trailers.
- Codec compliance tightened (`[unique]` BSTR pointers, ORPCTHAT extension handling).
- Stub transport intentionally retained for offline testing.

**Still open**
- Parsing and consuming enumerator responses (ties back to Phase 3 gap).
- Broader live validation and error-path coverage.
- Async/pooling work (tracked under Phase 5).

**Dependencies**
- Phase 3 codec and transport ✅
- MS-RPCE §3.3.3-4 (signing/sealing), MS-DCOM §2.2.3 (ORPC headers) ✅

**Verification**
- Unit: 68 tests currently pass across the protocol stack.
- E2E: Needs additional validation with real Windows hosts once enumerator decoding lands.
- Security: Signing/sealing logic covered by unit tests; production soak pending.

---

## Phase 5 — Async Support & Production Hardening *(Target: 100%, Est. 5–7 days)* `[~]`
**Goal**: Deliver a production-ready async stack capable of serving 1 000+ concurrent queries with <500 ms latency, while polishing outstanding production requirements.

**Scope**
- Introduce a tokio-based `AsyncRealRpcTransport` that mirrors the synchronous handshake and sealing/signing guarantees.
- Wrap codecs/transport in async-safe facades (spawn-blocking for NDR until fully async).
- Add connection pooling (`deadpool`) plus a global semaphore to guard concurrency.
- Implement retry/backoff scaffolding and improved HRESULT→WmiError mapping.
- Expose async-friendly APIs/FFI and wire in tracing/metrics hooks for observability.

**Dependencies**
- Completion of Phase 4 live transport work (real ExecQuery path).
- Updated docs/tests from the comprehensive finalization plan (below).

**Verification Targets**
- Coverage ≥90% (unit + integration + property tests).
- 1 000 concurrent ExecQuery calls complete in <30 s with <1% failure.
- Benchmarks recorded with criterion; tracing spans emitted for every query.
- Fuzzing of async FFI entrypoints (cargo-fuzz).

---

# Comprehensive Finalization Plan *(Sprint: 10–15 days, 1–2 developers)*

To retire the remaining stubs, raise coverage above 90%, harden security, align documentation, and complete Phase 5 async/pooling work, we will execute the following sprint. All work occurs on `finalize-project` and merges via PR review. Each major milestone closes with `cargo test`, `cargo fmt`, and documentation updates.

## Prerequisites (½ day)
- Create branch `git checkout -b finalize-project` and record baseline metrics (`cargo test`, `cargo tarpaulin --lib --tests`).
- Install tooling: `cargo install cargo-tarpaulin cargo-audit cargo-fuzz`; add dev-deps (`mockall`, `criterion`, `loom`).
- Run `cargo audit` and `cargo clippy --fix` to ensure a clean baseline.

## 1. Replace Remaining Stubs & Enable Live Queries (Days 1–3)
| Day | Focus | Key Actions | Verification |
|-----|-------|-------------|--------------|
|1|Real transport I/O|Replace `StubTransport` usage; ensure `RealRpcTransport::connect` and `invoke` perform real network I/O with timeouts.|Unit tests with mocked streams; live DCOM bind against Windows host.|
|2|Session wiring|Update `lib.rs`/`wmi.rs` to always build real transports when creds provided; remove fallback stubs on happy path.|Unit tests with `mockall` for transport; e2e smoke test (connect + noop query).|
|3|ExecQuery/ExecMethod|Hook codec + transport end-to-end so `IWbemServices::exec_query/exec_method` produce real JSON.|Integration tests (mock transport); live `SELECT * FROM Win32_ComputerSystem`.|

**Exit Criteria**: Live ExecQuery returns Windows data; coverage ≥70%.

## 2. Coverage Expansion to 90%+ (Days 4–5)
- Day 4: Target low-coverage modules (`ndr::codec`, `transport`, `dcom`) with additional unit/property tests (mocked transports, golden bytes).
- Day 5: Extend integration/FFI tests (`tests/ndr_integration.rs`, FFI helpers) and exercise error paths (timeouts, invalid creds, HRESULT faults).

**Exit Criteria**: `cargo tarpaulin --out Html --ignore-tests` ≥90%; artifacts attached to PR.

## 3. Security Hardening (Days 6–7)
- Replace ad-hoc crypto with vetted crates (`md5`, `hmac`); integrate `zeroize` for sensitive key material.
- Add FFI boundary checks (length caps) and fuzz `wmi_exec_query_json` with `cargo fuzz`.

**Exit Criteria**: `cargo audit` clean; fuzz harness runs 10 min without crash; security notes added to README.

## 4. Documentation & DX Polish (Days 8–9)
- Refresh `ARCHITECTURE.md`, `PROTOCOL-COMPLETION.md`, and README to match the new state (live transport, async roadmap, security posture).
- Add runnable examples (Rust CLI + C# P/Invoke) and compatibility matrix.

**Exit Criteria**: Docs reviewed/approved; examples compile under CI.

## 5. Phase 5 Async & Pooling (Days 10–16)
| Day | Focus | Key Actions | Verification |
|-----|-------|-------------|--------------|
|10|Async traits|Introduce `AsyncRpcTransport` trait + tokio handshake.|`tokio::test` for async bind/invoke; timeout handling verified.|
|11–12|Async API/FFI|Create `AsyncWmiSession`, async ExecQuery/FFI callbacks using `tokio::spawn`.|Unit + integration tests (async); ffi harness exercising callback.|
|13–14|Pooling & limits|Deadpool-managed pool with health-check recycling; `Semaphore` concurrency guard.|Property/load tests with 1 000 concurrent queries; ensure graceful degradation.|
|15|Metrics/observability|Hook `tracing` spans + optional OTLP exporter; document metrics usage.|Integration test verifying span fields; manual OTLP validation.|
|16|Benchmarks|Criterion bench comparing sync vs async (100/1 000 queries).|Report stored in `docs/benchmarks/`.|

**Exit Criteria**: Async feature flag passes `cargo test`; load test demonstrates <500 ms avg latency for 1 000 concurrent queries.

## 6. Release & CI Wrap-Up (Day 17)
- Final `cargo fmt && cargo test && cargo clippy && cargo audit`.
- Publish changelog, tag `v0.1.0`, update CI to cover tests/coverage/audit.
- Optional: Publish crate/docs once review complete.

---

## Timeline Snapshot (Revised)
- **Week 1**: ✅ Phases 1–2 locked; prerequisites complete.
- **Week 2**: Days 1–5 of sprint — live transport + coverage uplift.
- **Week 3**: Days 6–10 — security + docs + async groundwork.
- **Week 4**: Days 11–17 — async/pooling completion, benchmarks, release polish.
- **Current Status**: 65% of protocol work complete; final sprint scheduled above.

## Current Overall Status
- **65% Complete**: Real transport foundation in place; enumerator decoding and async still in progress.
- **Key Achievement**: Multi-fragment, signed responses verified end-to-end.
- **Immediate Focus**: Execute the sprint milestones; unblock live enumerator results and async scalability.
- **Risks**: Windows permissions and load-test resources; spawn_blocking overhead (monitor during benchmarks).

Each milestone concludes with automated tests, documentation updates, and review checkpoints to reduce regressions.

---

## Key Technical Decisions & Pivots (Historical)

### EPM → DCOM Activation Pivot
- **Discovery**: EPM returns `EPT_S_NOT_REGISTERED` (0x1c00001a) for WMI interfaces.
- **Solution**: Use IRemoteSCMActivator::RemoteActivation on port 135.
- **Impact**: Added ORPCTHIS/ORPCTHAT headers, DUALSTRINGARRAY parsing.
- **Benefit**: Matches real-world activation flow.

### Fragment Support Addition
- **Rationale**: WMI frequently returns >4 KB responses requiring fragmentation.
- **Implementation**: Added prior to Phase 3 to ensure decoding success.
- **Testing**: Multi-fragment unit tests (5 KB payload).

### Stub-First Development
- **Approach**: Delivered stub codec/transport for early E2E.
- **Benefit**: Allowed validation of auth/transport prior to NDR completion.

### Authentication Integration
- **Design**: NTLM handshake woven into RPC bind/alter flow with session key capture.
- **Status**: Ready for Kerberos expansion in future phases.
