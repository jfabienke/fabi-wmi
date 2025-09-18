use byteorder::{LittleEndian, WriteBytesExt};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;
use tracing::{debug, info};

fn main() {
    tracing_subscriber::fmt::init();

    let host = std::env::args()
        .nth(1)
        .unwrap_or("192.0.2.10".to_string());

    match probe_wmi_anonymous(&host) {
        Ok(is_windows) => {
            if is_windows {
                println!("✅ Windows WMI/RPC detected on {host}");
                std::process::exit(0);
            } else {
                println!("❌ No Windows WMI/RPC detected on {host}");
                std::process::exit(1);
            }
        }
        Err(e) => {
            eprintln!("❌ Probe failed: {e}");
            std::process::exit(2);
        }
    }
}

fn probe_wmi_anonymous(host: &str) -> Result<bool, Box<dyn std::error::Error>> {
    info!("Starting anonymous WMI probe for {}", host);

    // Try to connect to port 135 (RPC/DCOM)
    let stream_result =
        TcpStream::connect_timeout(&format!("{host}:135").parse()?, Duration::from_secs(5));

    let mut stream = match stream_result {
        Ok(s) => s,
        Err(_) => {
            debug!("Port 135 not reachable");
            return Ok(false);
        }
    };

    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    debug!("Connected to port 135");

    // Send anonymous bind to IRemoteSCMActivator
    let scm_uuid = hex_literal::hex!("a0 01 00 00 00 00 00 00 c0 00 00 00 00 00 00 46");
    let bind_pdu = build_anonymous_bind(1, &scm_uuid);
    debug!("Sending anonymous bind, pdu_len={}", bind_pdu.len());

    if stream.write_all(&bind_pdu).is_err() {
        debug!("Failed to send bind");
        return Ok(false);
    }

    // Try to read response
    let mut header = [0u8; 16];
    match stream.read_exact(&mut header) {
        Ok(_) => {
            // Check if it's an RPC response
            if header[0] == 5 && (header[2] == 0x0C || header[2] == 0x03) {
                // Got RPC bind_ack or fault - this is Windows RPC
                let ptype = header[2];
                debug!("Got RPC response, ptype=0x{:02x}", ptype);

                if ptype == 0x0C {
                    info!("Received bind_ack - Windows RPC confirmed");
                    return Ok(true);
                } else if ptype == 0x03 {
                    // Fault response still indicates Windows RPC
                    info!("Received RPC fault - Windows RPC present (auth required)");
                    return Ok(true);
                }
            }
            debug!("Non-RPC response");
            Ok(false)
        }
        Err(_) => {
            debug!("No response or timeout");
            Ok(false)
        }
    }
}

fn build_anonymous_bind(call_id: u32, uuid: &[u8]) -> Vec<u8> {
    let mut pdu = Vec::new();

    // RPC header
    pdu.write_u8(5).unwrap(); // version
    pdu.write_u8(0).unwrap(); // minor
    pdu.write_u8(0x0B).unwrap(); // ptype = bind
    pdu.write_u8(0x03).unwrap(); // flags = first|last
    pdu.write_u32::<LittleEndian>(0x00000010).unwrap(); // data_rep

    let frag_len_offset = pdu.len();
    pdu.write_u16::<LittleEndian>(0).unwrap(); // placeholder
    pdu.write_u16::<LittleEndian>(0).unwrap(); // auth_len = 0 (anonymous)
    pdu.write_u32::<LittleEndian>(call_id).unwrap();

    // Bind body
    pdu.write_u16::<LittleEndian>(0x10B8).unwrap(); // max_xmit
    pdu.write_u16::<LittleEndian>(0x10B8).unwrap(); // max_recv
    pdu.write_u32::<LittleEndian>(0).unwrap(); // assoc_group

    // Presentation context
    pdu.write_u8(1).unwrap(); // num_ctx_items
    pdu.write_u8(0).unwrap(); // reserved
    pdu.write_u16::<LittleEndian>(0).unwrap(); // reserved2

    // Context item
    pdu.write_u16::<LittleEndian>(0).unwrap(); // context_id
    pdu.write_u8(1).unwrap(); // num_trans_items
    pdu.write_u8(0).unwrap(); // reserved

    // Interface UUID
    pdu.extend_from_slice(uuid);
    pdu.write_u16::<LittleEndian>(0).unwrap(); // version major
    pdu.write_u16::<LittleEndian>(0).unwrap(); // version minor

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
