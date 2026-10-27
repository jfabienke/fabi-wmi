//! Connection-oriented DCE/RPC (MS-RPCE) PDU framing, [`RpcConnection`],
//! request/response fragmentation, the [`AuthProvider`] SSP trait, and NTLMv2
//! message protection.

mod auth;
mod rpc;
mod sspi_ntlm;

pub use auth::{
    AuthError, AuthProvider, Credentials, AUTH_TYPE_KERBEROS, AUTH_TYPE_NTLM, AUTH_TYPE_SPNEGO,
};
pub use rpc::{
    build_auth3_pdu, build_auth3_pdu_with_auth_type, build_bind_pdu, build_bind_pdu_with_auth_type,
    build_request_fragment_pdu, build_request_pdus, build_sealed_request_pdu,
    build_signed_request_pdu, fault_status, fault_to_hresult, is_last_fragment, parse_bind_ack,
    unseal_response_pdu, unseal_response_stub, verify_signed_response_pdu, BindAck, BoundContext,
    HandshakeStyle, RpcConnection, RpcError, RpcStream, AUTH_LEVEL_PKT_INTEGRITY,
    AUTH_LEVEL_PKT_PRIVACY, DATA_REP, MAX_FRAG, MAX_RESPONSE_LEN, PFC_FIRST_FRAG, PFC_LAST_FRAG,
    PTYPE_ALTER_CONTEXT, PTYPE_ALTER_CONTEXT_RESP, PTYPE_AUTH3, PTYPE_BIND, PTYPE_BIND_ACK,
    PTYPE_BIND_NAK, PTYPE_FAULT, PTYPE_REQUEST, PTYPE_RESPONSE, RPC_IO_TIMEOUT,
};
pub use sspi_ntlm::SspiNtlmClient;
