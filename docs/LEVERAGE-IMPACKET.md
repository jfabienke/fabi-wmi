# Impacket Usage Notes

Impacket (Azure/Impacket, license: **AGPL-3.0**) is an invaluable reference when validating our RPC/WMI implementation, but its copyleft license prevents us from reusing any of its source directly. This document clarifies how we interact with the project so we stay fully compliant with our MIT license.

## What We Use Impacket For
- **Traffic generation & captures**: Tools such as `rpcdump.py`, `wmiexec.py`, and `ticketer.py` are run against a lab Windows host to generate Wireshark traces. These traces provide ground‑truth PDUs (EPM requests, bind handshakes, ExecQuery responses) that we can compare against the PDUs produced by our Rust transport.
- **Behavioral reference**: Reading the Python sources (e.g., `impacket/ntlm.py`, `impacket/dcerpc/v5/rpcrt.py`) helps us understand edge cases—such as how NTLM signing/sealing maintains RC4 state or how the RPC layer increments sequence numbers. We treat this as documentation only.

## What We **Do Not** Do
- **No copying of code**: We never transplant functions, algorithms, or tables from Impacket into the Rust codebase. All logic (e.g., NTLM key derivation, RPC PDU assembly) is written from scratch, guided by Microsoft specifications and permissively licensed samples.
- **No dependency linkage**: Impacket is not a Cargo dependency. It is used only as an external CLI/test tool and should not ship with releases.

## Workflow Guidelines
1. **Capture**: Run the relevant Impacket tool against the test domain/host while capturing traffic.
2. **Compare**: Use Wireshark to inspect the capture and compare it against our PDUs (logged via `tracing` or dumped from tests).
3. **Implement**: Reimplement any needed behaviors using the Microsoft Open Specifications or permissive references (e.g., windows-classic-samples, windows-rs).
4. **Document**: Note the insight in `docs/REFERENCES.md` or commit messages (e.g., “Validated NTLM sealing state against Impacket capture (no code imported)”).

This approach lets us benefit from Impacket’s maturity without inheriting its licensing constraints. If a future task appears to require code reuse, stop and re-evaluate—there is almost always a permissively licensed alternative or a spec section we can rely on instead.
