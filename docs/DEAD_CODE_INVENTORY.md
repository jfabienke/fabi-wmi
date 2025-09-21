# Dead Code Inventory

This document tracks code marked as dead that can be safely removed vs code that appears dead but is needed for future features.

## ✅ Safe to Delete

### Kerberos Integration Functions (src/kerberos_integration.rs)
These functions were replaced by kerbsec integration and are no longer needed:
- `build_bind_pdu_with_kerberos()` - Line 129
- `build_alter_context_with_kerberos()` - Line 199
- `parse_bind_ack_auth()` - Line 267
- `build_protected_pdu()` - Line 299
- `extract_auth_trailer()` - Line 332

### Duplicate Constants
Multiple definitions of the same constants across files:
- `AUTH_TYPE_NTLM` (0x0A) - Defined in both transport.rs and dcom.rs
- `AUTH_TYPE_SPNEGO` (0x09) - Defined in both transport.rs and kerberos_integration.rs
- `AUTH_TYPE_KERBEROS` (0x10) - Defined in both transport.rs and kerberos_integration.rs

**Action**: Keep one set in transport.rs, remove others

### Unused Security Context Constants
Constants in security_context modules that are never referenced:
- `src/security_context/sspi.rs`:
  - ISC_REQ_MUTUAL_AUTH (line 103)
  - ISC_REQ_CONFIDENTIALITY (line 105)
  - ISC_REQ_INTEGRITY (line 107)
  - ISC_REQ_USE_DCE_STYLE (line 109)
  - ISC_REQ_SEQUENCE_DETECT (line 111)
  - ISC_REQ_REPLAY_DETECT (line 113)
  - RPC_C_AUTHN_GSS_KERBEROS (line 117)
  - RPC_C_AUTHN_GSS_NEGOTIATE (line 119)

- `src/security_context/gssapi.rs`:
  - GSS_C_MUTUAL_FLAG (line 103)
  - GSS_C_CONF_FLAG (line 105)
  - GSS_C_INTEG_FLAG (line 107)
  - GSS_C_DCE_STYLE (line 109)

### Potentially Unused Structures
**Verify before deletion**:
- `dcom.rs: ObjectReference` struct (line 1320) - Check if used in any future DCOM operations
- `dcom.rs: parse_dualstringarray_port()` (line 1323) - May be superseded by newer parsing

## ⚠️ Keep for Async API

### Async Infrastructure (DO NOT DELETE)
These appear dead but are essential for async implementation:

#### transport.rs
- `AsyncRpcTransport` trait (line 1434) - Core async trait
- `connect_with_kerberos()` (line 504) - Needs to be made truly async
- `write_all_with_retry()` (line 1074) - May be useful for async retry logic

#### ndr.rs
- `AsyncNdrCodec` struct (line 64) - Async wrapper for NDR operations
- Implementation already exists, just needs testing

### Pool Infrastructure (KEEP)
All code in `src/pool.rs` - fully implemented async connection pooling

## 🧪 Keep for Testing

### Test Infrastructure (MOVE, DON'T DELETE)
These should be moved to a test_support module:

#### transport.rs
- `StubTransport` struct (line 318) - Used when LINUX_WMI_USE_STUB=1

#### ndr.rs
- `StubNdrCodec` struct (line 59) - Provides mock WMI responses
- `stub_results_for_query()` (line 61) - Mock data generator

#### security_context/mock.rs
- Entire file - Mock security context for testing

## 🔮 Keep for Future Features

### NDR Type Methods
These seem unused but may be needed for full NDR implementation:

#### ndr/types.rs
- `Bstr::new()`, `encode()`, `decode()` - BSTR handling
- `Variant::to_json_value()`, `var_type()`, `encode()`, `decode()` - VARIANT operations
- `ConformantArray` methods - Array handling
- `SafeArray::encode()` - SafeArray support
- `HResultError::is_success()`, `code()` - Error handling helpers

### Crypto Functions
- `crypto.rs: derive_sealing_key()` (line 103) - May be needed for advanced NTLM

### Helper Functions
- `ndr.rs: read_bstr()` (line 333) - BSTR reading utility
- `ndr/codec.rs: decode_variant()` (line 72) - VARIANT decoding
- `ndr/codec.rs: encode_conformant_string()` (line 206) - String encoding

## Summary Statistics

- **Safe to delete**: ~27 functions/constants (~400 lines)
- **Keep for async**: 4 major components (~200 lines marked dead)
- **Keep for testing**: 3 stub implementations (~150 lines)
- **Keep for future**: ~15 helper functions (~300 lines)

## Recommendations

1. **Immediate removal**: Delete the 5 Kerberos functions and duplicate constants
2. **Reorganize**: Move test stubs to `src/test_support/` module
3. **Document**: Add comments explaining why "dead" async code must be kept
4. **Feature gate**: Consider adding `#[cfg(feature = "full-ndr")]` for unused NDR helpers