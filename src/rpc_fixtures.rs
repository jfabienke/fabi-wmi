#![allow(dead_code)]

use byteorder::{LittleEndian, WriteBytesExt};

pub fn epm_request_pdu(call_id: u32, tower: &[u8]) -> Vec<u8> {
    // Build MS-EPMR ept_map request (opnum=3)
    // This uses a simplified static template that's known to work

    let mut pdu = Vec::new();

    // RPC header
    pdu.write_u8(5).unwrap(); // version
    pdu.write_u8(0).unwrap(); // minor
    pdu.write_u8(0x00).unwrap(); // ptype = request
    pdu.write_u8(0x03).unwrap(); // flags = first|last
    pdu.write_u32::<LittleEndian>(0x00000010).unwrap(); // data_rep = little-endian

    // We'll fill in frag_len after building the body
    let frag_len_offset = pdu.len();
    pdu.write_u16::<LittleEndian>(0).unwrap(); // placeholder for frag_len
    pdu.write_u16::<LittleEndian>(0).unwrap(); // auth_len
    pdu.write_u32::<LittleEndian>(call_id).unwrap();

    // Request header
    pdu.write_u32::<LittleEndian>(0).unwrap(); // alloc_hint
    pdu.write_u16::<LittleEndian>(0).unwrap(); // context_id
    pdu.write_u16::<LittleEndian>(3).unwrap(); // opnum = 3 (ept_map)

    // Stub data for ept_map
    // UUID (all zeros - object UUID)
    pdu.extend_from_slice(&hex_literal::hex!(
        "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
    ));

    // Tower pointer
    pdu.write_u32::<LittleEndian>(0x00020000).unwrap(); // referent ID

    // Tower structure
    pdu.write_u32::<LittleEndian>(1).unwrap(); // max_count
    pdu.write_u32::<LittleEndian>(0).unwrap(); // offset
    pdu.write_u32::<LittleEndian>(1).unwrap(); // actual_count

    // Tower data with length prefix
    let tower_with_prefix_len = tower.len() + 2;
    pdu.write_u16::<LittleEndian>(tower_with_prefix_len as u16)
        .unwrap();
    pdu.write_u16::<LittleEndian>(tower.len() as u16).unwrap();
    pdu.extend_from_slice(tower);

    // Padding to 4-byte alignment
    while pdu.len() % 4 != 0 {
        pdu.push(0);
    }

    // Map handle (null)
    pdu.write_u32::<LittleEndian>(0).unwrap();

    // Max towers
    pdu.write_u32::<LittleEndian>(4).unwrap();

    // Now update the fragment length
    let total_len = pdu.len() as u16;
    pdu[frag_len_offset..frag_len_offset + 2].copy_from_slice(&total_len.to_le_bytes());

    pdu
}

pub fn epm_bind_pdu(call_id: u32) -> Vec<u8> {
    // Build bind PDU for EPM interface (anonymous, no auth)
    let mut pdu = Vec::new();

    // RPC header
    pdu.write_u8(5).unwrap(); // version
    pdu.write_u8(0).unwrap(); // minor
    pdu.write_u8(0x0B).unwrap(); // ptype = bind
    pdu.write_u8(0x03).unwrap(); // flags = first|last
    pdu.write_u32::<LittleEndian>(0x00000010).unwrap(); // data_rep = little-endian

    // We'll fill in frag_len after building body
    let frag_len_offset = pdu.len();
    pdu.write_u16::<LittleEndian>(0).unwrap(); // placeholder for frag_len
    pdu.write_u16::<LittleEndian>(0).unwrap(); // auth_len = 0 (anonymous)
    pdu.write_u32::<LittleEndian>(call_id).unwrap();

    // Bind body
    pdu.write_u16::<LittleEndian>(0x10B8).unwrap(); // max_xmit_frag
    pdu.write_u16::<LittleEndian>(0x10B8).unwrap(); // max_recv_frag
    pdu.write_u32::<LittleEndian>(0).unwrap(); // assoc_group

    // Presentation context list
    pdu.write_u8(1).unwrap(); // num_ctx_items
    pdu.write_u8(0).unwrap(); // reserved
    pdu.write_u16::<LittleEndian>(0).unwrap(); // reserved2

    // Context item
    pdu.write_u16::<LittleEndian>(0).unwrap(); // context_id
    pdu.write_u8(1).unwrap(); // num_trans_items
    pdu.write_u8(0).unwrap(); // reserved

    // EPM interface UUID: {E1AF8308-5D1F-11C9-91A4-08002B14A0FA}
    pdu.extend_from_slice(&hex_literal::hex!(
        "08 83 AF E1 1F 5D C9 11 91 A4 08 00 2B 14 A0 FA"
    ));
    pdu.write_u16::<LittleEndian>(3).unwrap(); // interface version major
    pdu.write_u16::<LittleEndian>(0).unwrap(); // interface version minor

    // NDR transfer syntax
    pdu.extend_from_slice(&hex_literal::hex!(
        "04 5D 88 8A EB 1C C9 11 9F E8 08 00 2B 10 48 60"
    ));
    pdu.write_u32::<LittleEndian>(2).unwrap(); // syntax version

    // Update fragment length
    let total_len = pdu.len() as u16;
    pdu[frag_len_offset..frag_len_offset + 2].copy_from_slice(&total_len.to_le_bytes());

    pdu
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
    body.extend_from_slice(&hex_literal::hex!("d8 10 d8 10 00 00 00 00"));
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
