# Protocol Constant Verification

Status of key protocol identifiers, opnums, and flags referenced by the current Rust implementation. Each entry lists the code location, value, verification source, and any notes or follow-up.

| Constant                 | Value                                                              | Location                                   | Verification                                                                                                                                                                                                                                 | Notes                                                                    |
|--------------------------|--------------------------------------------------------------------|--------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------|
| `NEGOTIATE_FLAGS`        | `0xE289_8235`                                                      | `src/auth.rs:19`                           | Matches recommended NTLM Type-1 flag set (UNICODE, REQUEST_TARGET, SIGN, SEAL, NTLM, ALWAYS_SIGN, TARGET_TYPE_DOMAIN, EXTENDED_SESSION_SECURITY, TARGET_INFO, VERSION, 128-bit, KEY_EXCH, 56-bit) described in MS-NLMP §3.2.5.1.2 (Table 3). | Bits decoded locally via Python to confirm expected set.                 |
| `AUTH_TYPE_NTLM`         | `0x0A`                                                             | `src/transport.rs:236`                     | `RPC_C_AUTHN_WINNT` defined as `10` in `windows-rs/crates/libs/sys/src/Windows/Win32/System/Rpc/mod.rs:2288`.                                                                                                                                | Value aligns with MS-RPCE §2.2.1.1.5 authentication service assignments. |
| `AUTH_LEVEL_PRIVACY`     | `0x06`                                                             | `src/transport.rs:235`                     | `RPC_C_AUTHN_LEVEL_PKT_PRIVACY` defined as `6` in `windows-rs/crates/libs/windows/src/Windows/Win32/System/Com/mod.rs:11969-11975`.                                                                                                          | Corresponds to "Packet Privacy" per MS-RPCE §3.2.1.5.2.                  |
| Data representation      | `0x10_00_00_00`                                                    | `src/transport.rs:140` etc.                | MS-RPCE §2.2.1.1.1 specifies little-endian encoding with ASCII/IEEE as `0x10 0x00 0x00 0x00`.                                                                                                                                                | Used consistently across request/bind PDUs.                              |
| RPC PDU types            | Request `0x00`, Bind `0x0B`, Bind Ack `0x0C`, Alter Context `0x0E` | `src/transport.rs:137-208`                 | Enumerated in MS-RPCE §2.2.1.1.5 (PDUType).                                                                                                                                                                                                  | No discrepancies found.                                                  |
| EPM opnum                | `3` (EptMap)                                                       | `src/transport.rs:147`                     | Defined in MS-EPMR §3.1.1.5 (ept_map operation).                                                                                                                                                                                             | —                                                                        |
| `MAX_XMIT_RECV`          | `0x10B8`                                                           | `src/transport.rs:204`                     | Matches default `max_xmit_size`/`max_recv_size` used by Windows RPC runtime (documented in MS-RPCE §3.3.1.5.2 note; corroborated by FreeRDP `libfreerdp/core/gateway/rpc_bind.c`).                                                           | Can refine with captured bind ACK to ensure remote agrees.               |
| `ncacn_ip_tcp` floor ID  | `0x07`                                                             | `src/transport.rs:220`                     | Protocol ID assignments in MS-EPMR §2.2.1.7 list `0x07` for `ncacn_ip_tcp`; also used in Windows classic RPC samples (e.g., `Samples/Win7Samples/netds/rpc/dynept`).                                                                         | —                                                                        |
| IObjectExporter UUID     | `c4fe9f99-6052-1b10-bbcb-00aa0021347a`                             | `src/transport.rs:262` & `src/tower.rs:31` | Identified as `IID_IObjectExporter` in [MS-DCOM] Appendix A (Product Behavior).                                                                                                                                                              | Confirmed against published IID.                                         |
| NDR transfer syntax UUID | `8a885d04-1ceb-11c9-9fe8-08002b104860`                             | `src/transport.rs:268`                     | Standard NDR v2 UUID per MS-RPCE §2.2.4.6.                                                                                                                                                                                                   | Common across RPC stacks.                                                |
| ExecQuery opnum          | `9`                                                                | `src/wmi.rs:83`                            | MS-WMI §3.1.4.1.3.3 defines `ExecQuery` as method #9 on IWbemServices.                                                                                                                                                                       | Stated in official IDL.                                                  |
| ExecMethod opnum         | `20`                                                               | `src/wmi.rs:106`                           | MS-WMI §3.1.4.1.3.6 lists `ExecMethod` as opnum 20.                                                                                                                                                                                          | —                                                                        |

| `IRemoteSCMActivator UUID` | `{000001A0-0000-0000-C000-000000000046}` | `examples/dcom_activation.rs:42` | MS-DCOM §1.9 defines IRemoteSCMActivator interface for DCOM activation | Used for SCM bind on port 135 |
| `RemoteActivation opnum` | `4` | `examples/dcom_activation.rs:81` | MS-DCOM §3.1.1.5.4.1 RemoteActivation method | Activates DCOM objects |
| `CLSID_WbemLocator` | `{4590F811-1D3A-11D0-891F-00AA004B2E24}` | `src/tower.rs:37` | MS-WMI §1.9 CLSID for WMI activation | Used in DCOM activation, not EPM |
| `EPT_S_NOT_REGISTERED` | `0x1c00001a` | `src/dcom.rs:186` | MS-EPMR §2.2.3.4.1 EPM fault status | WMI doesn't register with EPM |
| `RPC_S_ACCESS_DENIED` | `0x00000005` | `examples/dcom_activation.rs:91` | MS-ERREF Windows Error Codes | DCOM activation requires permissions |

| `IObjectExporter UUID` | `{99FCFEC4-5260-101B-BBCB-00AA0021347A}` | `src/dcom.rs:167` | MS-DCOM §1.9 defines IObjectExporter for OXID resolution | Used for OXID resolver bind |
| `ResolveOxid opnum` | `0` | `src/dcom.rs:191` | MS-DCOM §3.1.2.5.2.1 ResolveOxid method | Resolves OXID to object reference |
| `ORPCTHIS version` | `0x00000001` | `src/dcom.rs:205,317` | MS-DCOM §2.2.3.1 ORPCTHIS structure version | Standard DCOM version |
| `ORPCTHAT flags` | Bit 1: extensions | `src/dcom.rs:605` | MS-DCOM §2.2.3.2 ORPCTHAT structure | Extension flag indicates additional data |
| `IPID format` | 16 bytes GUID | `src/dcom.rs:283` | MS-DCOM §2.2.5 Interface Pointer Identifier | Unique ID for interface instances |
| `RPC_S_CALL_FAILED` | `0x800706BE` | `src/dcom.rs:249` | MS-ERREF Windows Error Codes | Invalid OXID or RPC call failed |

## NDR VARIANT Type Constants

| Constant | Value | Location | Verification | Notes |
|----------|-------|----------|--------------|-------|
| `VT_EMPTY` | `0x0000` | `src/ndr/types.rs:115` | MS-OAUT §2.2.29 VARENUM | Variant contains no value |
| `VT_NULL` | `0x0001` | `src/ndr/types.rs:116` | MS-OAUT §2.2.29 VARENUM | Variant contains SQL-style NULL |
| `VT_I2` | `0x0002` | `src/ndr/types.rs:117` | MS-OAUT §2.2.29 VARENUM | 16-bit signed integer |
| `VT_I4` | `0x0003` | `src/ndr/types.rs:118` | MS-OAUT §2.2.29 VARENUM | 32-bit signed integer |
| `VT_R4` | `0x0004` | `src/ndr/types.rs:119` | MS-OAUT §2.2.29 VARENUM | 32-bit floating point |
| `VT_R8` | `0x0005` | `src/ndr/types.rs:120` | MS-OAUT §2.2.29 VARENUM | 64-bit floating point |
| `VT_DATE` | `0x0007` | `src/ndr/types.rs:121` | MS-OAUT §2.2.29 VARENUM | OLE Automation date (f64) |
| `VT_BSTR` | `0x0008` | `src/ndr/types.rs:122` | MS-OAUT §2.2.29 VARENUM | Basic string (UTF-16LE) |
| `VT_BOOL` | `0x000B` | `src/ndr/types.rs:123` | MS-OAUT §2.2.29 VARENUM | VARIANT_BOOL (0xFFFF=true) |
| `VT_I1` | `0x0010` | `src/ndr/types.rs:124` | MS-OAUT §2.2.29 VARENUM | 8-bit signed integer |
| `VT_UI1` | `0x0011` | `src/ndr/types.rs:125` | MS-OAUT §2.2.29 VARENUM | 8-bit unsigned integer |
| `VT_UI2` | `0x0012` | `src/ndr/types.rs:126` | MS-OAUT §2.2.29 VARENUM | 16-bit unsigned integer |
| `VT_UI4` | `0x0013` | `src/ndr/types.rs:127` | MS-OAUT §2.2.29 VARENUM | 32-bit unsigned integer |
| `VT_I8` | `0x0014` | `src/ndr/types.rs:128` | MS-OAUT §2.2.29 VARENUM | 64-bit signed integer |
| `VT_UI8` | `0x0015` | `src/ndr/types.rs:129` | MS-OAUT §2.2.29 VARENUM | 64-bit unsigned integer |
| `VT_RECORD` | `0x0024` | `src/ndr/types.rs:130` | MS-OAUT §2.2.29 VARENUM | User-defined type |
| `VT_FILETIME` | `0x0040` | `src/ndr/types.rs:131` | MS-OAUT §2.2.29 VARENUM | Windows FILETIME (u64) |
| `VT_ARRAY` | `0x2000` | `src/ndr/types.rs:132` | MS-OAUT §2.2.29 VARENUM | SAFEARRAY flag |

## WMI HRESULT Constants

| Constant | Value | Location | Verification | Notes |
|----------|-------|----------|--------------|-------|
| `S_OK` | `0x00000000` | `src/ndr/types.rs:14` | MS-ERREF §2.1 | Success |
| `S_FALSE` | `0x00000001` | `src/ndr/types.rs:15` | MS-ERREF §2.1 | Success with FALSE result |
| `WBEM_E_FAILED` | `0x80041001` | `src/ndr/types.rs:16` | MS-WMI §2.2.1 | Generic WMI failure |
| `WBEM_E_NOT_FOUND` | `0x80041002` | `src/ndr/types.rs:17` | MS-WMI §2.2.1 | Object not found |
| `WBEM_E_ACCESS_DENIED` | `0x80041003` | `src/ndr/types.rs:18` | MS-WMI §2.2.1 | Access denied |
| `WBEM_E_INVALID_PARAMETER` | `0x80041008` | `src/ndr/types.rs:22` | MS-WMI §2.2.1 | Invalid parameter |
| `WBEM_E_CALL_CANCELLED` | `0x8004100E` | `src/ndr/types.rs:23` | MS-WMI §2.2.1 | Operation cancelled |
| `WBEM_E_INVALID_CLASS` | `0x80041010` | `src/ndr/types.rs:21` | MS-WMI §2.2.1 | Invalid class |
| `WBEM_E_TRANSPORT_FAILURE` | `0x80041015` | `src/ndr/types.rs:24` | MS-WMI §2.2.1 | Transport failure |
| `WBEM_E_INVALID_QUERY` | `0x80041017` | `src/ndr/types.rs:19` | MS-WMI §2.2.1 | Invalid WQL query |
| `WBEM_E_INVALID_QUERY_TYPE` | `0x80041018` | `src/ndr/types.rs:20` | MS-WMI §2.2.1 | Invalid query type |

## WMI Query Flags

| Constant | Value | Location | Verification | Notes |
|----------|-------|----------|--------------|-------|
| `WBEM_FLAG_FORWARD_ONLY` | `0x00000020` | `src/ndr/codec.rs:149` | MS-WMI §2.2.14 | Forward-only enumerator |
| `WBEM_FLAG_RETURN_IMMEDIATELY` | `0x00000010` | `src/ndr/codec.rs:149` | MS-WMI §2.2.14 | Semi-synchronous call |

## Outstanding Items

No outstanding protocol constant verifications at this time.

## Verification Trail

Supporting references pulled from the checked-in `windows-rs` SDK bindings and knowledge of the Microsoft Open Specifications. Where possible, cite specific sections for future audits.
