use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use linux_wmi::auth_exports::{Credentials, NtlmV2Client};
use std::io::{Cursor, Read, Write};
use std::net::TcpStream;
use std::time::Duration;
use tracing::{debug, info, trace_span};

fn main() {
    tracing_subscriber::fmt::init();

    let host = std::env::args()
        .nth(1)
        .unwrap_or("192.0.2.10".to_string());
    let user = std::env::args().nth(2).unwrap_or("wmi-test".to_string());
    let pass = std::env::args().nth(3).unwrap_or("P@ssw0rd123".to_string());
    let domain = std::env::args().nth(4).unwrap_or("".to_string());

    match activate_wmi(&host, &user, &pass, &domain) {
        Ok((port, oxid)) => {
            println!("✅ DCOM Activation Success!");
            println!("   Dynamic Port: {}", port);
            println!("   OXID: {}", oxid);
        }
        Err(e) => {
            eprintln!("❌ DCOM Activation Failed: {}", e);
            std::process::exit(1);
        }
    }
}

fn activate_wmi(
    host: &str,
    user: &str,
    pass: &str,
    domain: &str,
) -> Result<(u16, String), Box<dyn std::error::Error>> {
    let span = trace_span!("dcom_activation", host = %host);
    let _enter = span.enter();

    info!("Starting DCOM activation for {}", host);

    // Connect to SCM port 135
    let mut stream = TcpStream::connect((host, 135))?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    debug!("Connected to SCM port 135");

    // Step 1: Bind to IRemoteSCMActivator UUID with NTLM auth
    // IRemoteSCMActivator: {000001A0-0000-0000-C000-000000000046}
    let scm_uuid = hex_literal::hex!("a0 01 00 00 00 00 00 00 c0 00 00 00 00 00 00 46");

    // Create NTLM client and get Type1 message
    let creds = Credentials {
        username: user.to_string(),
        password: pass.to_string(),
        domain: domain.to_string(),
        workstation: "LINUX".to_string(),
    };
    let mut ntlm = NtlmV2Client::new(creds)?;
    let type1_msg = ntlm.negotiate_message();
    let type1 = type1_msg.message;

    let bind_pdu = build_scm_bind_pdu_with_auth(1, &scm_uuid, &type1);
    debug!("Sending SCM bind with NTLM, pdu_len={}", bind_pdu.len());
    stream.write_all(&bind_pdu)?;

    let ack_pdu = read_pdu(&mut stream)?;
    debug!(
        "Received bind_ack, len={}, hex={}",
        ack_pdu.len(),
        hex::encode(&ack_pdu)
    );
    let (context_id, type2) = parse_scm_bind_ack_with_auth(&ack_pdu)?;
    debug!(
        "SCM bind ack: context_id={}, got Type2 challenge",
        context_id
    );

    // Complete NTLM handshake with Type3
    let skip_alter = std::env::var("SKIP_ALTER").unwrap_or_default() == "1";

    if !skip_alter {
        let type3_msg = ntlm.respond_message(&type2)?;
        let type3 = type3_msg.message;
        debug!(
            "Type3 message: len={}, hex_preview={}",
            type3.len(),
            hex::encode(&type3[..32.min(type3.len())])
        );

        let auth_pdu = build_alter_context_pdu(2, context_id, &type3);
        debug!(
            "Alter context PDU: len={}, hex_preview={}",
            auth_pdu.len(),
            hex::encode(&auth_pdu[..64.min(auth_pdu.len())])
        );
        stream.write_all(&auth_pdu)?;

        let auth_ack = read_pdu(&mut stream)?;
        debug!(
            "Auth complete, got response ptype=0x{:02x}, len={}",
            auth_ack[2],
            auth_ack.len()
        );

        // Check for fault response
        if auth_ack[2] == 0x03 {
            // fault
            if auth_ack.len() >= 28 {
                let status =
                    u32::from_le_bytes([auth_ack[24], auth_ack[25], auth_ack[26], auth_ack[27]]);
                let reason = if auth_ack.len() >= 32 {
                    u32::from_le_bytes([auth_ack[28], auth_ack[29], auth_ack[30], auth_ack[31]])
                } else {
                    0
                };
                info!(
                    "Alter context fault: status=0x{:08x}, reason=0x{:08x}",
                    status, reason
                );
                info!(
                    "Note: This is often due to DCOM permissions. Try with Administrator account."
                );
                return Err(format!(
                    "Alter context fault: status=0x{:08x}, reason=0x{:08x}",
                    status, reason
                )
                .into());
            }
            return Err("Alter context fault (status unknown)".into());
        }

        if auth_ack[2] != 0x0F {
            // alter_context_resp
            debug!(
                "Warning: expected alter_context_resp (0x0F), got 0x{:02x}",
                auth_ack[2]
            );
        }
    } else {
        info!("Skipping alter_context (SKIP_ALTER=1), using bind auth only");
    }

    // Step 2: RemoteActivation request (opnum=4)
    // CLSID_WbemLocator: {4590F811-1D3A-11D0-891F-00AA004B2E24}
    let clsid_wmi = hex_literal::hex!("11 f8 90 45 3a 1d d0 11 89 1f 00 aa 00 4b 2e 24");
    // IID_IWbemLocator: {dc12a687-737f-11cf-884d-00aa004b2e24}
    let iid_locator = hex_literal::hex!("87 a6 12 dc 7f 73 cf 11 88 4d 00 aa 00 4b 2e 24");

    let stub_payload = encode_remote_activation(&clsid_wmi, &iid_locator)?;
    let req_pdu = build_request_pdu(3, context_id, 4, &stub_payload); // call_id=3 (incremented)
    debug!(
        "Sending RemoteActivation, pdu_len={}, hex_preview={}",
        req_pdu.len(),
        hex::encode(&req_pdu[..32.min(req_pdu.len())])
    );
    stream.write_all(&req_pdu)?;

    // Step 3: Parse response
    let resp_pdu = read_pdu(&mut stream)?;
    debug!(
        "Received response, len={}, hex={}",
        resp_pdu.len(),
        hex::encode(&resp_pdu[..32.min(resp_pdu.len())])
    );
    let (port, oxid) = parse_remote_activation(&resp_pdu)?;
    info!("Activation complete: port={}, OXID={}", port, oxid);

    Ok((port, oxid))
}

#[allow(dead_code)]
fn build_scm_bind_pdu(call_id: u32, scm_uuid: &[u8]) -> Vec<u8> {
    let mut pdu = Vec::new();

    // RPC header
    pdu.write_u8(5).unwrap(); // version
    pdu.write_u8(0).unwrap(); // minor
    pdu.write_u8(0x0B).unwrap(); // ptype = bind
    pdu.write_u8(0x03).unwrap(); // flags = first|last
    pdu.write_u32::<LittleEndian>(0x00000010).unwrap(); // data_rep = little-endian

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

    // IRemoteSCMActivator interface UUID
    pdu.extend_from_slice(scm_uuid);
    pdu.write_u16::<LittleEndian>(0).unwrap(); // interface version major
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

fn build_scm_bind_pdu_with_auth(call_id: u32, scm_uuid: &[u8], ntlm: &[u8]) -> Vec<u8> {
    let mut pdu = Vec::new();

    // RPC header
    pdu.write_u8(5).unwrap(); // version
    pdu.write_u8(0).unwrap(); // minor
    pdu.write_u8(0x0B).unwrap(); // ptype = bind
    pdu.write_u8(0x03).unwrap(); // flags = first|last
    pdu.write_u32::<LittleEndian>(0x00000010).unwrap(); // data_rep = little-endian

    let frag_len_offset = pdu.len();
    pdu.write_u16::<LittleEndian>(0).unwrap(); // placeholder for frag_len
    pdu.write_u16::<LittleEndian>(ntlm.len() as u16).unwrap(); // auth_len
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

    // IRemoteSCMActivator interface UUID
    pdu.extend_from_slice(scm_uuid);
    pdu.write_u16::<LittleEndian>(0).unwrap(); // interface version major
    pdu.write_u16::<LittleEndian>(0).unwrap(); // interface version minor

    // NDR transfer syntax
    pdu.extend_from_slice(&hex_literal::hex!(
        "04 5D 88 8A EB 1C C9 11 9F E8 08 00 2B 10 48 60"
    ));
    pdu.write_u32::<LittleEndian>(2).unwrap(); // syntax version

    // Auth trailer
    pdu.write_u8(0x0A).unwrap(); // auth_type = NTLM
    pdu.write_u8(0x06).unwrap(); // auth_level = privacy
    pdu.write_u8(0).unwrap(); // auth_pad_len
    pdu.write_u8(0).unwrap(); // reserved
    pdu.write_u32::<LittleEndian>(0).unwrap(); // auth_context_id
    pdu.extend_from_slice(ntlm);

    // Update fragment length
    let total_len = pdu.len() as u16;
    pdu[frag_len_offset..frag_len_offset + 2].copy_from_slice(&total_len.to_le_bytes());

    pdu
}

fn build_alter_context_pdu(call_id: u32, _context_id: u16, ntlm: &[u8]) -> Vec<u8> {
    // Similar to bind but with alter_context ptype
    // Note: context_id should match what we got from bind_ack
    let mut pdu = Vec::new();
    pdu.write_u8(5).unwrap();
    pdu.write_u8(0).unwrap();
    pdu.write_u8(0x0E).unwrap(); // ptype = alter_context
    pdu.write_u8(0x03).unwrap();
    pdu.write_u32::<LittleEndian>(0x00000010).unwrap();

    let frag_len_offset = pdu.len();
    pdu.write_u16::<LittleEndian>(0).unwrap();
    pdu.write_u16::<LittleEndian>(ntlm.len() as u16).unwrap();
    pdu.write_u32::<LittleEndian>(call_id).unwrap();

    // Alter context doesn't need the full presentation context
    // Just needs max_xmit/recv and assoc_group
    pdu.write_u16::<LittleEndian>(0x10B8).unwrap();
    pdu.write_u16::<LittleEndian>(0x10B8).unwrap();
    pdu.write_u32::<LittleEndian>(0).unwrap(); // assoc_group

    // No presentation contexts needed for alter_context

    // Auth trailer
    pdu.write_u8(0x0A).unwrap(); // auth_type = NTLM
    pdu.write_u8(0x06).unwrap(); // auth_level = privacy
    pdu.write_u8(0).unwrap(); // auth_pad_len
    pdu.write_u8(0).unwrap(); // reserved
    pdu.write_u32::<LittleEndian>(1).unwrap(); // auth_context_id = 1 (must match bind)
    pdu.extend_from_slice(ntlm);

    let total_len = pdu.len() as u16;
    pdu[frag_len_offset..frag_len_offset + 2].copy_from_slice(&total_len.to_le_bytes());
    pdu
}

#[allow(dead_code)]
fn parse_scm_bind_ack(pdu: &[u8]) -> Result<u16, Box<dyn std::error::Error>> {
    if pdu.len() < 26 {
        return Err("Bind ack too short".into());
    }

    let ptype = pdu[2];
    if ptype != 0x0C {
        return Err(format!("Expected bind_ack (0x0C), got 0x{:02x}", ptype).into());
    }

    // Skip to presentation context results
    let mut pos = 24; // After header + max_xmit/recv + assoc_group

    // Parse sec_addr
    if pdu.len() < pos + 2 {
        return Err("Bind ack truncated at sec_addr".into());
    }
    let sec_addr_len = u16::from_le_bytes([pdu[pos], pdu[pos + 1]]) as usize;
    pos += 2 + sec_addr_len;

    // Align to 4 bytes
    while pos % 4 != 0 {
        pos += 1;
    }

    // Parse results
    if pdu.len() < pos + 4 {
        return Err(format!(
            "Bind ack truncated at results, pos={}, len={}",
            pos,
            pdu.len()
        )
        .into());
    }

    let _num_results = pdu[pos];
    // Context ID is implicitly 0 for single context
    Ok(0)
}

fn parse_scm_bind_ack_with_auth(pdu: &[u8]) -> Result<(u16, Vec<u8>), Box<dyn std::error::Error>> {
    // Parse bind_ack and extract Type2 challenge from auth trailer
    if pdu.len() < 26 {
        return Err("Bind ack too short".into());
    }

    let ptype = pdu[2];
    if ptype != 0x0C {
        return Err(format!("Expected bind_ack (0x0C), got 0x{:02x}", ptype).into());
    }

    let auth_len = u16::from_le_bytes([pdu[10], pdu[11]]) as usize;

    // Extract Type2 from end of PDU
    let type2 = if auth_len > 0 && pdu.len() >= auth_len {
        pdu[pdu.len() - auth_len..].to_vec()
    } else {
        Vec::new()
    };

    Ok((0, type2)) // Context ID 0 for single context
}

fn encode_remote_activation(
    clsid: &[u8; 16],
    iid: &[u8; 16],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    debug!("Encoding RemoteActivation stub");

    // Build ORPCTHIS header (required for DCOM)
    let mut orpcthis = Vec::new();
    orpcthis.write_u32::<LittleEndian>(0x00000001).unwrap(); // version (COM version 5.1)
    orpcthis.write_u32::<LittleEndian>(0x00000000).unwrap(); // flags
    orpcthis.write_u32::<LittleEndian>(0x00000000).unwrap(); // reserved1

    // CID (causality ID) - random GUID for tracking
    orpcthis.extend_from_slice(&[0u8; 16]); // zeros for simplicity

    // Extension array (empty)
    orpcthis.write_u32::<LittleEndian>(0).unwrap(); // no extensions

    // Build RemoteActivation stub (after ORPCTHIS)
    let mut stub = Vec::new();

    // ORPCthis (again? No - this is the actual parameters)
    // Actually RemoteActivation takes an ORPCTHIS in the request

    // Clsid (GUID)
    stub.extend_from_slice(clsid);

    // pwszObjectName (null)
    stub.write_u32::<LittleEndian>(0).unwrap(); // null pointer

    // pObjectStorage (null)
    stub.write_u32::<LittleEndian>(0).unwrap();

    // ClientImpLevel
    stub.write_u32::<LittleEndian>(2).unwrap(); // RPC_C_IMP_LEVEL_IDENTIFY

    // Mode
    stub.write_u32::<LittleEndian>(0).unwrap();

    // Interfaces requested (count)
    stub.write_u32::<LittleEndian>(1).unwrap();

    // Pointer to IID array
    stub.write_u32::<LittleEndian>(0x00020000).unwrap(); // unique pointer

    // IID array
    stub.write_u32::<LittleEndian>(1).unwrap(); // array size
    stub.extend_from_slice(iid);

    // cRequestedProtseqs
    stub.write_u16::<LittleEndian>(1).unwrap(); // one protocol sequence

    // aRequestedProtseqs array pointer
    stub.write_u32::<LittleEndian>(0x00020004).unwrap(); // unique pointer

    // Protocol sequence array
    stub.write_u16::<LittleEndian>(0x07).unwrap(); // ncacn_ip_tcp

    // Combine ORPCTHIS + stub
    let mut result = orpcthis;
    result.extend(stub);

    debug!("RemoteActivation stub built, len={}", result.len());
    Ok(result)
}

fn parse_remote_activation(pdu: &[u8]) -> Result<(u16, String), Box<dyn std::error::Error>> {
    debug!("Parsing RemoteActivation response, len={}", pdu.len());

    if pdu.len() < 24 {
        return Err("Response PDU too short".into());
    }

    let ptype = pdu[2];
    if ptype == 0x03 {
        // Fault response
        if pdu.len() >= 28 {
            let status = u32::from_le_bytes([pdu[24], pdu[25], pdu[26], pdu[27]]);
            return Err(format!("RPC fault: 0x{:08x}", status).into());
        }
        return Err("RPC fault (status unknown)".into());
    }

    if ptype != 0x02 {
        return Err(format!("Expected response (0x02), got 0x{:02x}", ptype).into());
    }

    // Skip RPC header (24 bytes) to get to ORPCTHAT + stub
    if pdu.len() < 24 + 8 {
        return Err("Response too short for ORPCTHAT".into());
    }

    let mut cursor = Cursor::new(&pdu[24..]);

    // Parse ORPCTHAT header
    let orpc_flags = cursor.read_u32::<LittleEndian>()?;
    debug!("ORPCTHAT flags: 0x{:08x}", orpc_flags);

    // Skip extensions if present
    let ext_array_size = cursor.read_u32::<LittleEndian>()?;
    if ext_array_size > 0 {
        // Skip extension data
        cursor.set_position(cursor.position() + ext_array_size as u64);
    }

    // Now we're at the RemoteActivation response stub
    // HRESULT
    let hresult = cursor.read_u32::<LittleEndian>()?;
    if hresult != 0 {
        return Err(format!("RemoteActivation failed: HRESULT=0x{:08x}", hresult).into());
    }

    // OXID (8 bytes)
    let oxid = cursor.read_u64::<LittleEndian>()?;
    let oxid_str = format!("{:016X}", oxid);
    debug!("OXID: {}", oxid_str);

    // Skip pOxidBindings pointer
    cursor.read_u32::<LittleEndian>()?;

    // ipidRemUnknown (16 bytes)
    let mut ipid = [0u8; 16];
    cursor.read_exact(&mut ipid)?;

    // dwAuthnHint
    cursor.read_u32::<LittleEndian>()?;

    // pServerVersion
    let server_version_ptr = cursor.read_u32::<LittleEndian>()?;

    // Skip to DUALSTRINGARRAY (pOxidBindings)
    // This contains the actual binding information with port
    if server_version_ptr != 0 {
        // Server version present, skip it
        cursor.read_u16::<LittleEndian>()?; // MajorVersion
        cursor.read_u16::<LittleEndian>()?; // MinorVersion
    }

    // DUALSTRINGARRAY for bindings
    let string_binding_size = cursor.read_u16::<LittleEndian>()? as usize;
    let security_binding_size = cursor.read_u16::<LittleEndian>()? as usize;

    debug!(
        "DUALSTRINGARRAY: string_binding_size={}, security_binding_size={}",
        string_binding_size, security_binding_size
    );

    // Parse string bindings to find TCP endpoint
    let mut port = 0u16;
    let pos = cursor.position() as usize;
    let binding_data = &pdu[24 + pos..];

    // Look for TCP tower entry (0x07) in string bindings
    for i in 0..string_binding_size {
        if i + 1 < binding_data.len() {
            let tower_id = u16::from_le_bytes([binding_data[i * 2], binding_data[i * 2 + 1]]);
            if tower_id == 0x07 {
                // Found TCP, next should be IP and port
                // Format: 0x07 (TCP), 0x09 (IP), then port
                if i + 8 < binding_data.len() / 2 {
                    // Skip to port (after tower ID and IP address)
                    port = u16::from_le_bytes([
                        binding_data[(i + 7) * 2],
                        binding_data[(i + 7) * 2 + 1],
                    ]);
                    debug!("Found TCP port in DUALSTRINGARRAY: {}", port);
                    break;
                }
            }
        }
    }

    if port == 0 {
        // Fallback: scan for port-like values
        for i in 0..binding_data.len().saturating_sub(2) {
            let potential_port = u16::from_le_bytes([binding_data[i], binding_data[i + 1]]);
            if potential_port >= 49152 {
                port = potential_port;
                debug!("Found potential port by scanning: {}", port);
                break;
            }
        }
    }

    if port == 0 {
        port = 135; // Default fallback
    }

    info!(
        "RemoteActivation successful: port={}, OXID={}",
        port, oxid_str
    );
    Ok((port, oxid_str))
}

fn build_request_pdu(call_id: u32, context_id: u16, opnum: u16, stub: &[u8]) -> Vec<u8> {
    let mut pdu = Vec::new();

    // RPC header
    pdu.write_u8(5).unwrap(); // version
    pdu.write_u8(0).unwrap(); // minor
    pdu.write_u8(0x00).unwrap(); // ptype = request
    pdu.write_u8(0x03).unwrap(); // flags = first|last
    pdu.write_u32::<LittleEndian>(0x00000010).unwrap(); // data_rep

    let frag_len = (24 + stub.len()) as u16;
    pdu.write_u16::<LittleEndian>(frag_len).unwrap();
    pdu.write_u16::<LittleEndian>(0).unwrap(); // auth_len
    pdu.write_u32::<LittleEndian>(call_id).unwrap();

    // Request body
    pdu.write_u32::<LittleEndian>(0).unwrap(); // alloc_hint
    pdu.write_u16::<LittleEndian>(context_id).unwrap();
    pdu.write_u16::<LittleEndian>(opnum).unwrap();

    // ORPCTHIS and stub
    pdu.extend_from_slice(stub);

    pdu
}

fn read_pdu(stream: &mut TcpStream) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut header = [0u8; 16];
    stream.read_exact(&mut header)?;

    let frag_len = u16::from_le_bytes([header[8], header[9]]) as usize;
    if frag_len < 16 {
        return Err(format!("Invalid fragment length: {}", frag_len).into());
    }

    let mut pdu = vec![0u8; frag_len];
    pdu[..16].copy_from_slice(&header);

    if frag_len > 16 {
        stream.read_exact(&mut pdu[16..])?;
    }

    debug!("Read PDU: len={}, ptype=0x{:02x}", frag_len, pdu[2]);
    Ok(pdu)
}
