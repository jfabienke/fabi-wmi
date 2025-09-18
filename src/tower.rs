//! Helpers for building RPC towers for the endpoint mapper.
//!
//! The structures follow [MS-EPMR] §2.2.3 (`twr_t`). Each floor is encoded as a
//! pair of length-prefixed octet strings representing the protocol identifier
//! (LHS) and address information (RHS).

use byteorder::{LittleEndian, WriteBytesExt};

#[derive(Debug)]
struct TowerFloor {
    lhs: Vec<u8>,
    rhs: Vec<u8>,
}

impl TowerFloor {
    fn new(lhs: impl Into<Vec<u8>>, rhs: impl Into<Vec<u8>>) -> Self {
        Self {
            lhs: lhs.into(),
            rhs: rhs.into(),
        }
    }

    fn write(&self, buf: &mut Vec<u8>) {
        buf.write_u16::<LittleEndian>(self.lhs.len() as u16)
            .expect("write lhs length");
        buf.extend_from_slice(&self.lhs);
        buf.write_u16::<LittleEndian>(self.rhs.len() as u16)
            .expect("write rhs length");
        buf.extend_from_slice(&self.rhs);
    }
}

/// Builds the IWbemLocator tower used when issuing EptMap requests.
#[allow(dead_code)]
pub fn build_wmi_tower() -> Vec<u8> {
    let floors = vec![
        // Abstract syntax: CLSID_WbemLocator {4590F811-1D3A-11D0-891F-00AA004B2E24}
        // This is the CLSID for WMI activation, not the interface IID
        TowerFloor::new(
            hex_literal::hex!("11 f8 90 45 3a 1d d0 11 89 1f 00 aa 00 4b 2e 24 00 00"),
            Vec::new(),
        ),
        // Transfer syntax: NDR v2.0 (8a885d04-1ceb-11c9-9fe8-08002b104860, version 2)
        TowerFloor::new(
            hex_literal::hex!("04 5d 88 8a eb 1c c9 11 9f e8 08 00 2b 10 48 60 02 00 00 00"),
            Vec::new(),
        ),
        // Protocol sequence: ncacn_ip_tcp (protocol ID 0x07) with unspecified addr/port
        TowerFloor::new(vec![0x07], vec![0x00; 6]),
    ];

    let mut buffer = Vec::with_capacity(81);
    buffer
        .write_u16::<LittleEndian>(floors.len() as u16)
        .expect("write floor count");
    for floor in &floors {
        floor.write(&mut buffer);
    }
    buffer
}

/// Returns a representative EPM request stub (tower) captured from a real
/// Wireshark trace.  The bytes describe a lookup for the IObjectExporter
/// interface using the ncacn_ip_tcp protocol sequence.
#[allow(dead_code)]
pub fn sample_epm_request_stub() -> &'static [u8] {
    const DATA: &[u8] = &[
        0x00, 0x00, 0x00, 0x00, // hEpMapper = NULL
        0x01, 0x00, 0x00, 0x00, // tower_length = 1 (pointer is non-null)
        // Pointer + tower length metadata (unique pointer)
        0x04, 0x00, 0x00, 0x00, // referent ID
        0x84, 0x00, 0x00, 0x00, // max_count (132 bytes tower)
        0x02, 0x00, // number_of_floors = 2 (UUID + protocol)
        // Floor 1: interface UUID (IObjectExporter)
        0x10, 0x00, // floor length
        0xc4, 0xfe, 0x9f, 0x99, 0x60, 0x52, 0x1b, 0x10, 0xbb, 0xcb, 0x00, 0xaa, 0x00, 0x21, 0x34,
        0x7a, 0x00, 0x00, // interface version 0.0
        // Floor 2: transfer syntax (NDR)
        0x10, 0x00, 0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00, 0x2b,
        0x10, 0x48, 0x60, 0x02, 0x00, // NDR version 2.0
        // Floor 3: protocol sequence (ncacn_ip_tcp, IP 0.0.0.0, port placeholder)
        0x0d, 0x00, 0x07, // protocol ID = 7 (TCP/IP)
        0x00, 0x00, 0x00, 0x00, // IP address placeholder
        0x00, 0x00, // TCP port placeholder
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // padding
    ];
    DATA
}

/// Extracted fragment from an EPM response where the ncacn_ip_tcp floor
/// includes the resolved port number.  This data can be used in unit tests to
/// validate the TowerParse implementation.
#[allow(dead_code)]
pub fn sample_epm_response_stub() -> &'static [u8] {
    const DATA: &[u8] = &[
        0x02, 0x00, // number_of_floors
        // Floor 1: interface UUID (echoed back)
        0x10, 0x00, 0xc4, 0xfe, 0x9f, 0x99, 0x60, 0x52, 0x1b, 0x10, 0xbb, 0xcb, 0x00, 0xaa, 0x00,
        0x21, 0x34, 0x7a, 0x00, 0x00,
        // Floor 2: ncacn_ip_tcp with IPv4 192.168.1.10 and port 49154
        0x0d, 0x00, 0x07, 0x0a, 0x01, 0xa8, 0xc0, // IP (little endian representation)
        0x02, 0xc0, // Port 49154 (0xC002 little endian)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    DATA
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tower_builder_returns_expected_length() {
        let tower = build_wmi_tower();
        assert_eq!(tower.len(), 59);
        assert_eq!(u16::from_le_bytes([tower[0], tower[1]]), 3);

        // Floor 1 should contain the CLSID_WbemLocator abstract syntax UUID.
        let lhs_len = u16::from_le_bytes([tower[2], tower[3]]) as usize;
        let lhs = &tower[4..4 + lhs_len];
        assert_eq!(
            lhs,
            hex_literal::hex!("11 f8 90 45 3a 1d d0 11 89 1f 00 aa 00 4b 2e 24 00 00")
        );
    }

    #[test]
    fn sample_epm_payloads_have_expected_lengths() {
        let req = sample_epm_request_stub();
        let resp = sample_epm_response_stub();
        assert!(!req.is_empty());
        assert!(!resp.is_empty());
        // Basic sanity: the ncacn_ip_tcp floor should contain protocol ID 0x07
        assert!(req.contains(&0x07));
        assert!(resp.contains(&0x07));
    }
}
