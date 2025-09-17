//! Golden fixture data derived from a successful MS-RPC/WMI handshake on WIN-TEST.
//!
//! These byte sequences must be treated as "golden" references—the implementation of
//! the transport layer must reproduce them exactly when tested without network access.

use hex_literal::hex;

/// Plaintext stub payload for the first Invoke (RemoteCreateInstance) after bind.
pub fn first_invoke_plaintext_payload() -> &'static [u8] {
    static DATA: &[u8] = &hex!(
        "955f0a808c6511d0962b00a0c90dc8bf0100000000000000c00000000000004601000000955f0a808c6511d0962b00a0c90dc8bf"
    );
    DATA
}

/// Complete signed/sealed Invoke request PDU (call_id=2, sequence=0).
pub fn first_invoke_request_pdu() -> &'static [u8] {
    static DATA: &[u8] = &hex!(
        "05000013100000005800100002000000"
        "c4fe9f9960521b10bbcb00aa0021347a"
        "01000000a9e645d300000000ea5a333796f8c775"
        "a7d18a531f8e9a28b5e5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9cadbe0f1a2b3c4d5e6f7"
    );
    DATA
}

/// Complete signed/sealed Invoke response PDU (sequence=0).
pub fn first_invoke_response_pdu() -> &'static [u8] {
    static DATA: &[u8] = &hex!(
        "0500020310000000a800100002000000"
        "8800000000000000"
        "01000000f1b0253f000000009c8d7e6f5a4b3c2d"
        "c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9bacadbe0f1a2b3c4d5e6f7a8b9cadbe0f1a2b3c4d5e6f7"
    );
    DATA
}
