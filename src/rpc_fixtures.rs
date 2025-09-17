//! Golden fixture data derived from "Wireshark" captures for the MS-RPC handshake.
//!
//! The byte slices below allow us to implement and stage the EPM lookup and
//! NTLM authenticated bind without taking live captures during development.

pub fn epm_request_pdu() -> &'static [u8] {
    static DATA: &[u8] = &hex_literal::hex!(
        // RPC header
        "05 00 00 03 10000000 9800 0000 01000000"
        // alloc hint, context id, opnum
        "e4 04 00 00 00 00 03 00"
        // hEpMapper = NULL
        "00 00 00 00"
        // tower pointer + array
        "00 00 02 00 01 00 00 00 00 00 00 00 01 00 00 00"
        // tower structure (5 floors)
        "05 00"
        // Floor 1: UUID
        "10 00 c4 fe 9f 99 60 52 1b 10 bb cb 00 aa 00 21 34 7a 00 00"
        // Floor 2: version
        "02 00 00 00"
        // Floor 3: NDR syntax
        "14 00 04 5d 88 8a eb 1c c9 11 9f e8 08 00 2b 10 48 60 02 00 00 00"
        // Floor 4: protocol ID (TCP)
        "02 00 07 00"
        // Floor 5: endpoint (empty)
        "06 00 00 00 00 00 00 00 00"
        // Trailing padding / references
        "04 00 00 00 00 00 00 00 00 00 00 00"
    );
    DATA
}

pub fn epm_response_pdu() -> &'static [u8] {
    static DATA: &[u8] = &hex_literal::hex!(
        "05 00 02 03 10000000 7800 0000 01000000 54000000 0000 0000"
        "00 02 00 00 01 00 00 00 00 02 00 00 01 00 00 00 00 00 00 00 01 00 00 00"
        "02 00 02 00 07 00 06 00 05 c0 00 00 00 00"
    );
    DATA
}

pub fn bind_request_pdu(ntlm: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&hex_literal::hex!(
        "d8 10 d8 10 00 00 00 00 01 00 00 00 00 00 c4 fe 9f 99 60 52 1b 10 bb cb 00 aa 00 21 34 7a 00 00"
    ));
    body.extend_from_slice(&hex_literal::hex!(
        "01 00 8a 88 5d 04 1c eb 11 c9 9f e8 08 00 2b 10 48 60 02 00 00 00"
    ));
    body.extend_from_slice(&hex_literal::hex!("0a 06 00 00 00 00 00 00"));
    body.extend_from_slice(ntlm);

    let frag_len = (16 + body.len()) as u16;
    let auth_len = ntlm.len() as u16;
    let mut pdu = Vec::with_capacity(frag_len as usize);
    pdu.extend_from_slice(&hex_literal::hex!("05 00 0b 03 10000000"));
    pdu.extend_from_slice(&frag_len.to_le_bytes());
    pdu.extend_from_slice(&auth_len.to_le_bytes());
    pdu.extend_from_slice(&1u32.to_le_bytes());
    pdu.extend_from_slice(&body);
    pdu
}

pub fn bind_ack_pdu() -> &'static [u8] {
    static DATA: &[u8] = &hex_literal::hex!(
        "05 00 0c 03 10000000 a000 5800 01000000 d8 10 d8 10 15312f01"
        "07 00 2b 00 34 39 31 35 37 00 00 00 00 00 00 00"
        "01 00 00 00 00 00 00 00"
        "0a 06 00 00 00 00 00 00"
        "4e 54 4c 4d 53 53 50 00 02 00 00 00 0c 00 0c 00 38 00 00 00"
        "15 82 8a e2 00 00 00 0f 00 0f 00 44 00 00 00 06 01 b1 1d 00 00 00 0f"
    );
    DATA
}

pub fn alter_context_pdu(ntlm: &[u8], context_id: u16) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&hex_literal::hex!(
        "d8 10 d8 10 00 00 00 00"
    ));
    body.extend_from_slice(&context_id.to_le_bytes());
    body.extend_from_slice(&hex_literal::hex!("01 00"));
    body.extend_from_slice(&hex_literal::hex!(
        "c4 fe 9f 99 60 52 1b 10 bb cb 00 aa 00 21 34 7a 00 00"
    ));
    body.extend_from_slice(&hex_literal::hex!(
        "8a 88 5d 04 1c eb 11 c9 9f e8 08 00 2b 10 48 60 02 00 00 00"
    ));
    body.extend_from_slice(&hex_literal::hex!("0a 06 00 00 00 00 00 00"));
    body.extend_from_slice(ntlm);

    let frag_len = (16 + body.len()) as u16;
    let auth_len = ntlm.len() as u16;
    let mut pdu = Vec::with_capacity(frag_len as usize);
    pdu.extend_from_slice(&hex_literal::hex!("05 00 0e 03 10000000"));
    pdu.extend_from_slice(&frag_len.to_le_bytes());
    pdu.extend_from_slice(&auth_len.to_le_bytes());
    pdu.extend_from_slice(&2u32.to_le_bytes());
    pdu.extend_from_slice(&body);
    pdu
}
