# kerbsec — Minimal, MIT‑only Kerberos (GSS‑API) for DCE/RPC on Unix

**kerbsec** is a small Rust crate that provides a **Kerberos RFC 4121 security context** for DCE/RPC transports (e.g., WMI/DCOM) on **Unix‑like platforms** by leveraging the **system GSS‑API** (MIT Kerberos or Heimdal). It is **transport‑agnostic**, **async‑first**, and **MIT‑licensed**. The crate focuses on the **DCE‑style 3‑leg handshake** and **per‑message protection** (Integrity/Privacy) via **IOV** without re‑implementing the Kerberos protocol itself.

- **License:** MIT
- **Platforms:** Linux, macOS, FreeBSD/UNIX (via system GSS). **Windows is out of scope** (use native SSPI).
- **Design goals:** ergonomic API, minimal surface, stable interop with AD/MIT/Heimdal, easy to embed in existing DCE/RPC stacks.

---

## TL;DR

- Unix‑only backend using **`libgssapi`**; no SSPI in v0.1 (feature gate reserved for future).
- **DCE‑style** AP‑REQ → AP‑REP → (final leg, send even if empty) handshake.
- **Per‑message** Integrity/Privacy via **GSS IOV wrap/unwrap**; correct sequencing & replay detection.
- **SPN policy:** default `HOST/<canonical-fqdn>`; **IP targets require `spn_override`**.
- **DNS:** `hickory-resolver` for SRV `_kerberos._tcp.<REALM>`, A/AAAA, and **CNAME→FQDN canonicalization**.
- **MIT‑only dependency set:** `libgssapi`, `hickory-resolver`, `tokio`, `bytes`, `thiserror`, `anyhow`.
- CI matrix for **Ubuntu** (MIT Kerberos) and **macOS** (Heimdal).

---

## Goals & Non‑Goals

### Goals
- Provide a **Rust‑native**, ergonomic API for Kerberos security contexts suitable for WMI/DCOM.
- Keep the crate **transport‑agnostic**: users own RPC PDU framing; kerbsec only produces/consumes GSS tokens.
- **Interop first**: rely on system GSS to match AD/MIT/Heimdal behavior including AP‑REP subkey and IOV.
- **MIT‑only licensing** with small dependency footprint.

### Non‑Goals
- No full RFC 4120/4121 implementation in Rust.
- No Windows SSPI support in v0.1 (reserved feature gate).
- No SPNEGO or cross‑realm referrals in v0.1.
- No password→TGT flows in v0.1 (optional ccache writer may arrive later).

---

## Platforms & Support Policy

| OS family     | GSS implementation | Support | Notes                                                              |
|---------------|--------------------|---------|--------------------------------------------------------------------|
| Linux         | MIT Kerberos       | ✅      | IOV supported in modern libkrb5; install `libkrb5-dev` for builds. |
| macOS         | Apple Heimdal      | ✅      | System Heimdal; test IOV behavior on supported macOS versions.     |
| FreeBSD/UNIX  | Heimdal (base)     | ✅      | Base Heimdal typically provides IOV; verify on target release.     |

Minimums: documented in README. IOV (`gss_wrap_iov` / `gss_unwrap_iov`) and DCE‑style contexts are required.

---

## Architecture Overview

kerbsec sits between your transport and the OS GSS stack:

```
Your RPC Transport  <—auth trailer—>  kerbsec  <—GSS tokens—>  libgssapi  <—>  System Kerberos
```

- You keep control of **RPC framing** and **auth trailers** (pad length, context id, seqno).
- kerbsec exposes a **Context** that:
  - emits **AP‑REQ** (bind), accepts **AP‑REP** (bind_ack), and produces the **third leg** (alter_context).
  - **wraps/unwraps** PDUs via IOV, returning header/trailer fragments for your auth trailers.

---

## Module Layout & Estimated LOC

```text
fabi-kerbsec/
├── Cargo.toml                         — features (dns,runtime,ccache), pins, gates         —  ~45
├── LICENSE                            — MIT                                                —   ~2
├── README.md                          — overview, macOS/MIT notes, CI matrix               —  ~80
├── examples/
│   └── wmi_client.rs                  — demo handshake + wrap                              —  ~60
└── src/
    ├── lib.rs                         — re-exports, feature glue                           —  ~20
    ├── error.rs                       — thiserror Error/Result                             —  ~90
    ├── config.rs                      — builder, KRB5CCNAME, timeouts, channel bindings    —  ~90
    ├── context.rs                     — default_auth, mech OID, GSS glue                   — ~160
    ├── util/
    │   └── bytes.rs                   — IOV buffers, seq helpers                           —  ~50
    ├── dns/
    │   ├── mod.rs                     — prelude                                            —  ~20
    │   ├── resolver.rs                — SRV, A/AAAA, CNAME→FQDN, cache (hickory)           — ~130
    │   └── spn.rs                     — HOST/<fqdn>, IP→override guard                     —  ~80
    ├── security/
    │   ├── mod.rs                     — trait, QoP, Oid, ChannelBindings                   — ~140
    │   └── gss.rs                     — IOV wrap/unwrap, DCE flags, AP‑REP subkey          — ~330
    ├── rpc/
    │   └── dce.rs                     — auth trailer helpers (pad, ctx_id, seqno)          — ~140
    └── ccache/ (feature="ccache")
        ├── mod.rs                     — prelude                                            —  ~20
        └── writer.rs                  — minimal ccache v4 writer                           — ~380
```
**Core subtotal:** ~**1,155–1,185 LOC**
**ccache (optional):** ~**380 LOC**
**Total:** ~**1,535–1,565 LOC**

---

## Dependencies (MIT‑only)

- **libgssapi** (Unix GSS‑API) — pinned to a known‑good IOV build.
- **hickory‑resolver** — async DNS SRV + A/AAAA + system config.
- **tokio** — async runtime (no background tasks).
- **bytes** — efficient byte buffers.
- **thiserror**, **anyhow** — error ergonomics.
- *(Optional dev)*: **proptest**, **rstest**, **pretty_assertions**.

**Cargo (condensed):**
```toml
[package]
name = "kerbsec"
version = "0.1.0"
edition = "2021"
license = "MIT"

[features]
default = ["dns","runtime"]
dns = ["hickory-resolver"]
runtime = ["tokio"]
ccache = []
windows-sspi = []   # reserved; no code in v0.1

[dependencies]
thiserror = "1.0"
anyhow = "1"
bytes = "1"
tracing = "0.1"
tokio = { version = "1.38", features = ["rt-multi-thread","net","time"], optional = true }
hickory-resolver = { version = "0.25", optional = true }

[target.'cfg(unix)'.dependencies]
libgssapi = { version = "=0.9.1", default-features = false }
```

---

## Public API

### Core types
```rust
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthLevel { Integrity, Privacy }

#[derive(Clone, Debug, Default)]
pub struct ChannelBindings {
    pub initiator_addr: Option<std::net::SocketAddr>,
    pub acceptor_addr: Option<std::net::SocketAddr>,
    pub application_data: Option<Vec<u8>>,
}

#[derive(Clone, Debug)]
pub struct Oid {
    dotted: &'static str,
    der: &'static [u8],
}
impl Oid {
    pub const fn new(dotted: &'static str, der: &'static [u8]) -> Self { Self { dotted, der } }
    pub fn dotted(&self) -> &'static str { self.dotted }
    pub fn der(&self) -> &'static [u8] { self.der }
}
pub const KRB5_MECH_OID: Oid = Oid::new(
    "1.2.840.113554.1.2.2",
    &[0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x12, 0x01, 0x02, 0x02],
);

#[derive(Clone, Debug)]
pub struct KerberosConfig {
    pub realm: String,
    pub target_fqdn: String,             // canonicalized (CNAME→A/AAAA)
    pub spn_override: Option<String>,    // required for IP targets
    pub default_auth: AuthLevel,         // default = Privacy
    pub dns_timeout: std::time::Duration,
    pub gss_timeout: std::time::Duration,
    pub kccache: Option<String>,
    pub channel_bindings: Option<ChannelBindings>,
}

pub struct KerberosConfigBuilder { /* ergonomic setters ... */ }

pub struct HandshakeTokens {
    pub ap_req: Vec<u8>,                 // bind PDU
    pub alter_context: Option<Vec<u8>>,  // third leg; send even if empty
}

pub struct IovWrap {
    pub header: bytes::Bytes,            // placed before/inside RPC verifier as needed
    pub trailer: bytes::Bytes,           // goes into RPC auth verifier
    pub conf: bool,                      // true if Privacy (sealed), false if Integrity (MIC only)
}
```

### Context
```rust
pub struct Context { /* opaque GSS handles + state */ }

impl Context {
    /// Resolve & canonicalize FQDN; error if target is an IP and no spn_override provided.
    pub async fn config_from_target(
        realm: impl Into<String>,
        target_host: impl AsRef<str>,
    ) -> Result<KerberosConfig, Error>;

    pub fn new(cfg: KerberosConfig) -> Result<Self, Error>;

    pub fn mech_oid(&self) -> &'static Oid { &KRB5_MECH_OID }

    pub fn set_channel_bindings(&mut self, cb: Option<ChannelBindings>);

    /// Leg 1: produce AP‑REQ for bind
    pub fn initial_token(&mut self) -> Result<Vec<u8>, Error>;

    /// Leg 2→3: feed AP‑REP; returns final token (Some(vec![]) means "send empty leg")
    pub fn accept_ap_rep(&mut self, ap_rep: &[u8]) -> Result<Option<Vec<u8>>, Error>;

    pub fn established(&self) -> bool;

    /// Use context’s default AuthLevel
    pub fn wrap_iov(&mut self, pdu: &[u8]) -> Result<IovWrap, Error>;

    /// Per‑call override
    pub fn wrap_iov_with(&mut self, pdu: &[u8], level: AuthLevel) -> Result<IovWrap, Error>;

    pub fn unwrap_iov(&mut self, token: &[u8]) -> Result<Vec<u8>>, Error>;

    pub fn session_key(&self) -> Option<Vec<u8>>;  // diagnostics only
}
```

### Error model
```rust
#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("GSS error: {major:#x}/{minor:#x}: {text}")]
    Gss { major: u32, minor: u32, text: String },

    #[error("DNS error: {0}")]
    Dns(#[from] anyhow::Error),

    #[error("Target is an IP address; SPN override is required")]
    IpTargetRequiresSpnOverride,

    #[error("Could not canonicalize FQDN for {0}")]
    CanonicalizationFailed(String),

    #[error("Handshake not established")]
    NotEstablished,

    #[error("Invalid token shape")]
    TokenShape,
}
```

---

## DNS, SPN & Discovery

- Use `hickory-resolver` to **load system DNS config** and perform:
  - **SRV** lookups for `_kerberos._tcp.<REALM>` (KDC discovery) when needed.
  - **A/AAAA** with **CNAME chasing** to **canonicalize FQDN**.
- SPN policy: **`HOST/<canonical-fqdn>`** by default; if the target is an **IP address**, the builder **errors** unless `spn_override` is supplied.
- DNS timeouts/retries are configurable in `KerberosConfig`.

---

## GSS‑API Integration Details (Unix)

- **Mechanism:** Kerberos V5 (OID `1.2.840.113554.1.2.2`), exposed via `mech_oid()`.
- **Handshake:** DCE‑style, odd‑leg sequence:
  1) Client emits **AP‑REQ** (goes in RPC `bind` auth_data).
  2) Server responds with **AP‑REP** (in `bind_ack`).
  3) Client sends **third leg** in `alter_context` (**always send**, even if empty token).
- **Session key:** For mutual auth, the **AP‑REP subkey** becomes the effective context key.
- **Per‑message protection:** Use **IOV** `wrap/unwrap` for RPC auth trailers; enforce **sequence** and **replay** protection.
- **Auth levels:** `Integrity` (MIC only) and `Privacy` (seal+MIC). Default is **Privacy** at the context level; **per‑call override** supported.

---

## RPC/DCE Integration Contract

- kerbsec returns **IOV fragments** (`IovWrap { header, trailer, conf }`).
- Your transport constructs the **RPC auth verifier**, handling:
  - `auth_pad_length`, `auth_context_id`.
  - **Sequence numbers** (increment per PDU).
  - Placement of header/trailer bytes and payload according to DCE/RPC rules.
- Both **Integrity** and **Privacy** paths must be tested with small and large PDUs.

---

## Configuration & Environment

- **Credential cache:** honors `KRB5CCNAME` when present; otherwise uses system default.
- **Channel bindings:** optional in config and via runtime setter (future‑proofing for RPC over HTTP(S)).
- **Timeouts:** DNS and GSS operations have configurable timeouts in `KerberosConfig`.

---

## Security Posture

- **Enctypes:** AES128/256 only by default; RC4 is disabled.
- **Zeroization:** session keys and sensitive buffers are not logged; optional zeroize hooks can be added if required.
- **Logging:** feature‑gated structured logs via `tracing`; never log secrets (only `{qop, seqno, token_len}`).
- **Clock skew:** users should keep hosts in sync (NTP); typical tolerance ±5–10 minutes at the KDC.

---

## Performance Targets

- **Handshake:** < 150 ms over LAN for the 3‑leg exchange.
- **Per‑PDU wrap/unwrap:** < 1 ms for 64 KB PDU at `Privacy`.
- **Sizing:** use `gss_wrap_size_limit` (via libgssapi) to choose fragment sizes and avoid excessive padding.

---

## Build & CI

- **Pin `libgssapi`** to a known‑good (e.g., `=0.9.1`) to keep IOV behavior stable.
- CI matrix covers **Ubuntu** (MIT Kerberos) and **macOS** (Heimdal).

```yaml
name: ci
on: [push, pull_request]
jobs:
  build-test:
    strategy:
      matrix:
        os: [ubuntu-latest, macos-latest]
        features: [ "dns,runtime", "dns,runtime,ccache" ]
    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - name: Install system krb5 (Ubuntu)
        if: startsWith(matrix.os, 'ubuntu')
        run: sudo apt-get update && sudo apt-get install -y libkrb5-dev
      - name: Build
        run: cargo build --features ${{ matrix.features }} --all-targets --verbose
      - name: Test
        run: cargo test --features ${{ matrix.features }} --verbose
```

**Heimdal vs MIT notes (to document):**
- Both provide IOV; minor differences exist in sign‑only fragment handling—covered by tests.
- macOS uses a system credential store by default; `kinit` writes to the system cache; `klist` to inspect.

---

## Testing Strategy

- **Handshake correctness:** wire‑level capture showing bind/AP‑REQ → bind_ack/AP‑REP → alter_context (3rd leg sent even if empty).
- **Per‑message protection:** Integrity & Privacy round‑trips; **replay** and **out‑of‑order** negative tests.
- **Enctypes:** AES128/256 green; RC4 disabled.
- **SPN rules:** FQDN default works; **IP requires `spn_override`** (negative test).
- **Cross‑platform:** Linux ↔ Windows server; macOS ↔ Windows server (same harness).
- **Property tests:** IOV symmetry; padding calculations.
- **(Optional) Fuzzing:** token parsers and error paths with `cargo‑fuzz` (dev‑only).

---

## Example Usage

```rust
use kerbsec::{Context, KerberosConfig, AuthLevel, ChannelBindings};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Build config (canonicalizes to FQDN; errors on IP targets without spn_override)
    let cfg = Context::config_from_target("CONTOSO.COM", "wmi01.contoso.com").await?
        .with_default_auth(AuthLevel::Privacy)
        .with_channel_bindings(None);

    // Create context
    let mut ctx = Context::new(cfg)?;

    // Leg 1: AP‑REQ (put into RPC bind)
    let ap_req = ctx.initial_token()?;

    // ... send bind, receive bind_ack with AP‑REP ...
    let ap_rep: Vec<u8> = /* from bind_ack */ vec![];

    // Leg 2→3: accept AP‑REP; send third leg (even if empty)
    if let Some(final_leg) = ctx.accept_ap_rep(&ap_rep)? {
        // send alter_context with `final_leg`
    }
    assert!(ctx.established());

    // Wrap a PDU using default (Privacy)
    let wrap = ctx.wrap_iov(&/* pdu bytes */ [])?;
    // -> place `wrap.header` and `wrap.trailer` in RPC auth verifier

    // Override per‑call to Integrity
    let _mic_only = ctx.wrap_iov_with(&[], AuthLevel::Integrity)?;

    Ok(())
}
```

---

## Integration Notes (linux‑wmi)

- Replace in‑crate Kerberos with dependency on **kerbsec**.
- Keep the fallback chain **in the application** (Kerberos → NTLM → Anonymous). kerbsec focuses purely on Kerberos.
- Remove Windows SSPI paths; rely on native Windows for Windows‑side scenarios (out of scope for kerbsec v0.1).

---

## Roadmap

- **v0.1**: Unix GSS‑only Kerberos; DCE‑style handshake; Integrity/Privacy; SPN canonicalization + IP guard; CI on Ubuntu/macOS.
- **v0.2**: Optional **ccache v4 writer** (MIT), SPNEGO (if needed), expanded docs & examples.
- **v0.3+**: Optional **windows‑sspi** feature (separate backend), channel binding helpers for RPC over HTTP(S).

---

## Versioning

- **SemVer**: v0.x while API stabilizes; aim for v1.0 after field validation on Linux/macOS/FreeBSD.
- Changelog per release; lock `libgssapi` version per minor until expanded CI coverage.

---

## Appendix: Builder Ergonomics (sketch)

```rust
impl KerberosConfig {
    pub fn builder() -> KerberosConfigBuilder { /* ... */ }
}

impl KerberosConfigBuilder {
    pub fn realm(mut self, r: impl Into<String>) -> Self { /* ... */ }
    pub fn target_host(mut self, h: impl Into<String>) -> Self { /* raw host; canonicalized later */ }
    pub fn spn_override(mut self, s: Option<String>) -> Self { /* ... */ }
    pub fn default_auth(mut self, a: AuthLevel) -> Self { /* Privacy default */ }
    pub fn dns_timeout(mut self, d: Duration) -> Self { /* ... */ }
    pub fn gss_timeout(mut self, d: Duration) -> Self { /* ... */ }
    pub fn kccache(mut self, path: Option<String>) -> Self { /* honors KRB5CCNAME by default */ }
    pub fn channel_bindings(mut self, cb: Option<ChannelBindings>) -> Self { /* ... */ }

    /// Resolve & canonicalize FQDN (CNAME→A/AAAA) and build the final config.
    pub async fn build_async(self) -> Result<KerberosConfig, Error> { /* uses hickory-resolver */ }
}
```

---

**Contact / Contributing:** PRs welcome for portability, tests, and docs. Please include your OS/GSS versions in bug reports.
