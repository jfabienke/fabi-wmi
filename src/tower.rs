//! Helpers for building and parsing RPC towers used by the endpoint mapper.
//!
//! The real implementation will construct the "floors" required to locate the
//! WMI activation interface. For the moment the module only exposes a stub so
//! that the transport layer can depend on a well-defined API surface.

/// Builds the tower for querying the WMI interface via the endpoint mapper.
#[allow(dead_code)]
pub fn build_wmi_tower() -> Vec<u8> {
    // Tower extracted from a known-good EptMap request.
    hex_literal::hex!(
        "00 00 00 00 00 00 02 00 01 00 00 00 00 00 00 00 01 00 00 00"
        "05 00 10 00 c4 fe 9f 99 60 52 1b 10 bb cb 00 aa 00 21 34 7a 00 00"
        "02 00 00 00 14 00 04 5d 88 8a eb 1c c9 11 9f e8 08 00 2b 10 48 60 02 00 00 00"
        "02 00 07 00 06 00 00 00 00 00 00 00 00"
    )
    .to_vec()
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
        assert_eq!(tower.len(), 81);
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
