  1. Endpoint Mapper (EPM) & RPC Bind
      - Finish TowerConnect/TowerParse so you can resolve the WMI endpoint dynamically.
      - Reuse the existing NTLM scaffolding to complete the RPC bind and produce a RpcTransport that can send signed/sealed PDUs (PacketPrivacy).
      - Verify with unit/integration tests that a bind succeeds against a known host (even if the stub codec still returns fake JSON).
  2. Minimal NDR Codec
      - Implement just enough encoding/decoding for the calls you care about first:
          - BSTR (for namespaces, WQL, object paths).
          - VARIANT for the simple types in GetOwner/ExecQuery (e.g., VT_I4, VT_BSTR).
          - Conformant arrays for enumerator results (single fragment).
      - Use recorded traces or IDL data to produce golden tests for encode/decode.
  3. ExecQuery in the Real Pipeline
      - Marshal the WQL request with NdrCodec, invoke RpcTransport::invoke(opnum = 9), and unmarshal the enumerator response into JSON.
      - Add tests that feed the codec and transport with fixtures (Wireshark captures or mock responses) to verify correctness.
  4. ExecMethod / GetOwner
      - Implement input parameter encoding (BSTR object path, method name, VARIANT parameters) and output decoding (ReturnValue, Domain, User).
      - Again, rely on captured responses for testing.
  5. Extend Error Handling & Fragmentation
      - Handle multi-fragment replies (alloc_hint > max fragment). For big WQL results you’ll need to reassemble multiple PDUs.
      - Map common HRESULTs to meaningful WmiError variants, propagate through the FFI.
  6. Auth Enhancements & Options
      - If needed, support alternate auth providers (e.g., Kerberos) by plugging a new AuthProvider implementation into the existing trait.
  7. Refine / Extract
      - Once everything’s working, consider extracting NdrCodec, RpcTransport, etc. to separate crates or modules if that makes sense.

  Each stage keeps the earlier layers intact and lets you ship incremental improvements (e.g., once stage 3 is done, ExecQuery returns real data).

  ---

Implementation Steps for Step 1

  #### Stage A – Endpoint Mapper Lookup

  1. Connect to TCP/135.
  2. Send the EptMap RPC request (opnum 3) using the tower payload.
  3. Read the RPC response and walk the tower floors to find the ncacn_ip_tcp floor and extract the port.

  Key helpers to implement:

  fn resolve_wmi_port(host: &str) -> Result<u16, TransportError>;
  fn build_epm_request_pdu(call_id: u32, tower: &[u8]) -> Vec<u8>;
  fn parse_epm_response(pdu: &[u8]) -> Result<u16, TransportError>;

  You can leverage the sample request/response wires we discussed, or capture your own.

  #### Stage B – Authenticated RPC Bind

  The RPC bind handshake is a three-step process:

  1. bind PDU with NTLM NEGOTIATE.
  2. bind_ack with NTLM CHALLENGE.
  3. alter_context PDU with NTLM AUTHENTICATE.

  Since we exposed AuthProvider, plug it in like this:

  let negotiate = auth_provider.negotiate()?;
  // build bind PDU around `negotiate`
  stream.write_all(&bind_pdu)?;

  let bind_ack = read_pdu(&mut stream)?;
  let challenge = extract_challenge(&bind_ack)?;

  let authenticate = auth_provider.respond(&challenge)?;
  // build alter-context PDU around `authenticate`
  stream.write_all(&alter_context_pdu)?;

  // Validate final response, capture context ID, etc.

  Crucially, record:

  - Context ID from the bind ack.
  - Session key derived by AuthProvider (NTLM). Use it later to sign/seal request PDUs.

  Reusable helpers you’ll add:

  fn build_bind_pdu(call_id: u32, context_id: u16, ntlm_neg: &[u8]) -> Vec<u8>;
  fn parse_bind_ack(pdu: &[u8]) -> Result<(u16, Vec<u8>), TransportError>;
  fn build_alter_context_pdu(call_id: u32, context_id: u16, ntlm_auth: &[u8]) -> Vec<u8>;

  Once that’s working, RealRpcTransport::invoke can start sending real RPC requests with signed stub data.
