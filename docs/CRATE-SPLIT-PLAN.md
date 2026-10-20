# Crate split plan: from one client to generic RPC / DCOM / WMI / Kerberos crates

Status: proposal, not started. Recorded 2026-10-20, after commit `81f0cdc`
(legacy stack removed). The recommendation came from an Opus 4.8 design
review in that session; this document records it with the code locations
behind each point.

## Goal

The original goal of the project: a set of generic, Windows-compatible Rust
crates for DCE/RPC, DCOM, WMI and Kerberos, with linux-wmi (the C ABI and the
ORMi-compatible .NET shim) as one consumer.

## Where each layer stands

The layers are not equally far along. Percentages are rough "fraction of a
generic crate's surface that exists and is validated today".

### MS-WMIO decoder (`src/wmio.rs`) — ~90%

Pure bytes-to-JSON, no network, no state: `decode_next_response`
(`wmio.rs:324`) and the class/instance/value decoders beneath it. Every CIM
type, arrays, embedded objects, NULL and class-default handling, all
golden-tested against captured Windows objects. This is already a reusable
crate in all but name. Only coupling to remove: `parse_next_response`
(`wmio.rs:54`) and `parse_objref_custom` (`wmio.rs:103`) unwrap the ORPC
OBJREF_CUSTOM envelope, which belongs in the DCOM layer (see duplication
below); the decoder proper should take a WMIO blob.

### RPC (`src/rpc.rs`) — ~60%

Generic and byte-validated: PDU framing, `build_bind_pdu`/`build_auth3_pdu`,
`parse_bind_ack`, signed (integrity) and sealed (privacy) request/response
PDUs, `read_pdu`, fault mapping. Gaps that a general `dcerpc` crate needs:

- **No connection object.** Activation (`dcom.rs::activate_with`,
  `dcom.rs:85`) and the WMI side (`client.rs::WmiConnection`, `client.rs:82`)
  each drive their own socket + bind + call loop. A generic crate wants one
  `RpcConnection` that owns the socket, the handshake, call dispatch and
  fragment reassembly.
- **Auth seam is NTLM-shaped.** The PDU builders hardcode `AUTH_TYPE_NTLM`
  (`rpc.rs:97`, `rpc.rs:113`) and assume a 16-byte auth value
  (`rpc.rs:260`, `rpc.rs:309`). The `AuthProvider` trait (`auth.rs:70`)
  returns `Vec<u8>` already, which is the right shape, but the callers assume
  NTLM's fixed MAC length. Kerberos GSS tokens are variable-length and need
  the IOV header/trailer split exposed.
- **No request fragmentation.** A stub larger than `max_xmit_frag` is
  rejected (`client.rs:194`); large WQL or method parameters need the request
  split across fragments.

### DCOM (`src/dcom.rs`) — ~25%

The thin layer. It activates exactly one hardcoded CLSID
(`CLSID_WBEM_LEVEL1_LOGIN`, `dcom.rs:69`) through one interface
(IActivation::RemoteActivation, `activate_with` at `dcom.rs:85`). A generic
`ms-dcom` crate needs:

- Activation of an **arbitrary** CLSID/IID.
- **OXID resolution** (IObjectExporter::ResolveOxid) — this existed as
  `resolve_oxid` and was deleted in the `81f0cdc` cleanup; it must come back
  for the general case (connecting to an already-activated object, or an
  object on a different string binding than the one activation returned).
- **IRemUnknown2** lifecycle beyond release — we have RemRelease encoding
  (`wmi_proto.rs::encode_rem_release`, `wmi_proto.rs:214`, with
  `IID_IREMUNKNOWN` at `wmi_proto.rs:25`), but it currently lives in the WMI
  crate, not DCOM.

**Biggest structural debt: OBJREF/ORPC marshaling is duplicated across three
files**, each written against its own capture:
- `dcom.rs::find_objref_ipid` (`dcom.rs:386`) — the activation response's
  OBJREF_STANDARD.
- `wmi_proto.rs::parse_interface_response` (`wmi_proto.rs:153`) — the
  interface pointer returned by NTLMLogin/ExecQuery.
- `wmio.rs::parse_objref_custom` (`wmio.rs:103`) — the OBJREF_CUSTOM wrapping
  each enumerated object.

All three scan for the `MEOW` signature and parse an STDOBJREF /
MInterfacePointer by hand. They should be one marshaling module in `ms-dcom`.

### WMI (`src/wmi_proto.rs`) — ~50%

Stub encoders (`encode_ntlm_login` `wmi_proto.rs:83`, `encode_exec_query`
`wmi_proto.rs:118`, Next, RemRelease) are solid and golden-tested, but
one-path: ExecQuery/Next only. No ExecMethod, no class/instance Put, no WQL
beyond `SELECT`. It also mixes ORPC concerns (the OBJREF parsing above) into
WMI code.

### Kerberos (`../kerbsec`) — already a separate crate

But two things block it from being the RPC auth provider:
- Its DCE/RPC IOV wrap (`gss_iov.rs::wrap_iov_real`, `kerbsec
  gss_iov.rs:109`) wraps the whole PDU as one buffer. DCE/RPC needs the RPC
  header and sec_trailer as **sign-only** IOV buffers (MS-RPCE 3.3.1.5.2)
  with the GSS token as the auth value. The fallback path
  (`wrap_iov_fallback`, `gss_iov.rs:244`) just calls plain `gss_wrap` and
  puts the whole token in the header, which is not DCE-compatible.
- Nothing implements the RPC auth seam over it. `kerberos_adapter.rs` does
  the handshake half (negotiate/respond) but its `seal_rpc`/`sign_rpc` return
  "not implemented" (`kerberos_adapter.rs:645`, via `not_wired`).

## Recommendation: refactor into a workspace, do not reimplement

The value in this code is not its structure — it is the **byte-exact
correctness**, proven against real Windows captures with golden tests and
mutation testing. The expensive discoveries (PKT_INTEGRITY vs PRIVACY on the
WMI port; `WBEM_S_FALSE = 1`; the NdTable class-default bits; the NTLM
byte-order fixes; the activation layout) live in those bytes and those tests.
A clean-slate rewrite re-risks every one of them and gains nothing the tests
don't already give. So: carve, consolidate, and fill in — keep the validated
primitives, rewrite only the parts that are currently one-path-specific.

### Proposed workspace

| Crate | Content | Depends on |
|---|---|---|
| `ms-wmio` | `wmio.rs` value decoder, bytes→`serde_json::Value` | — |
| `dcerpc` | `rpc.rs` + `RpcConnection` + fragmentation + generalized SSP trait | — |
| `ms-dcom` | OXID resolution, activation of arbitrary CLSID/IID, one OBJREF marshaling module, IRemUnknown | `dcerpc` |
| `ms-wmi` | WMI interfaces, WQL, ExecMethod | `ms-dcom`, `ms-wmio` |
| `kerbsec` | exists; fix IOV, implement the `dcerpc` SSP trait | `dcerpc` (or a bridge, to avoid a dependency cycle) |
| `linux-wmi` | thin C ABI + ORMi shim | `ms-wmi` |

NTLM (`sspi_ntlm.rs`) becomes a small SSP impl, either in `dcerpc` or its own
bridge crate.

### Two points that need real design, not relocation

1. **The consolidated ORPC/OBJREF marshaling** (the three copies above):
   one type that parses/builds STDOBJREF, OBJREF_CUSTOM and MInterfacePointer
   and DUALSTRINGARRAY, which both activation and the interface/object paths
   use.
2. **The generalized auth seam**: the SSP trait and the PDU builders must
   stop assuming a 16-byte auth value and an NTLM auth type, and must expose
   the sign-only buffer boundaries so both NTLM's MAC and Kerberos's GSS
   token fit.

Everything else is move-the-code and keep the tests green.

### Suggested order

1. Extract `ms-wmio` — lowest risk, proves the workspace split.
2. `dcerpc` with the `RpcConnection` object and the generalized auth seam.
3. Consolidate the three OBJREF copies into `ms-dcom`; restore OXID
   resolution; generalize activation.
4. Widen `ms-wmi` (ExecMethod first, since the shim's `ExecuteStaticMethod`
   needs it).
5. Fix kerbsec IOV and wire Kerberos into the `dcerpc` SSP seam.

The test suite stays green at every step — that is the whole advantage over a
rewrite.

### Scope caution

A genuinely generic DCOM/RPC crate (arbitrary interfaces, server side, full
OXID lifecycle) is a large surface. Scope the crates to "what a management
client needs" first, and let generality grow from a real second consumer
rather than speculatively building the entire MS-DCOM surface.
