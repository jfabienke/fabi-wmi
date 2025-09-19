#[cfg(test)]
mod tests {
    use crate::ndr::codec::RealNdrCodec;
    use crate::ndr::types::{Bstr, ConformantArray, Variant};
    use crate::ndr::NdrCodec;
    use hex_literal::hex;

    #[test]
    fn test_bstr_encoding_golden() {
        let bstr = Bstr::new("WQL");
        let encoded = bstr.encode();

        // Expected: 6 bytes length (3 UTF-16 chars * 2), then W(0x57), Q(0x51), L(0x4C), null
        let expected = hex!(
            "06 00 00 00"  // Length: 6 bytes
            "57 00"        // 'W' in UTF-16LE
            "51 00"        // 'Q' in UTF-16LE
            "4C 00"        // 'L' in UTF-16LE
            "00 00"        // Null terminator
        );

        assert_eq!(encoded, expected);
    }

    #[test]
    fn test_variant_i4_golden() {
        let variant = Variant::I4(0x12345678);
        let encoded = variant.encode();

        // Expected: type=3 (VT_I4), 6 bytes reserved, then 4-byte value + 4 bytes padding
        let expected = hex!(
            "03 00"              // VT_I4
            "00 00 00 00 00 00"  // 6 bytes reserved
            "78 56 34 12"        // 0x12345678 in little-endian
            "00 00 00 00"        // Padding to 8 bytes
        );

        assert_eq!(encoded, expected);
    }

    #[test]
    fn test_variant_bool_true_golden() {
        let variant = Variant::Bool(true);
        let encoded = variant.encode();

        // Expected: type=11 (VT_BOOL), 6 bytes reserved, then VARIANT_BOOL true (0xFFFF)
        let expected = hex!(
            "0B 00"              // VT_BOOL
            "00 00 00 00 00 00"  // 6 bytes reserved
            "FF FF"              // VARIANT_BOOL true
            "00 00 00 00 00 00"  // Padding to 8 bytes
        );

        assert_eq!(encoded, expected);
    }

    #[test]
    fn test_exec_query_request_golden() {
        let codec = RealNdrCodec::new();
        let encoded = codec
            .encode_exec_query("WQL", "SELECT * FROM Win32_Process")
            .expect("encode");

        // Check ORPCTHIS header structure (MS-DCOM §2.2.3.1)
        // New field order: Version, Flags, Reserved1, CID, Extensions
        assert_eq!(&encoded[0..4], &[0x01, 0x00, 0x00, 0x00]); // Version (includes version flag)
        assert_eq!(&encoded[4..8], &[0x00, 0x00, 0x00, 0x00]); // Flags
        assert_eq!(&encoded[8..16], &[0u8; 8]); // Reserved1 (8 bytes)

        // CID (Causality ID) - GUID, 16 bytes
        assert_eq!(&encoded[16..32], &[0u8; 16]);

        // Extensions pointer (null)
        assert_eq!(&encoded[32..36], &[0x00, 0x00, 0x00, 0x00]);

        // First BSTR pointer and conformant header for "WQL"
        assert_eq!(&encoded[40..44], &[0x00, 0x00, 0x02, 0x00]); // referent
        assert_eq!(&encoded[44..48], &[0x04, 0x00, 0x00, 0x00]); // max_count (chars incl. null)
        assert_eq!(&encoded[48..52], &[0x00, 0x00, 0x00, 0x00]); // offset
        assert_eq!(&encoded[52..56], &[0x04, 0x00, 0x00, 0x00]); // actual_count

        // "WQL" in UTF-16LE (with null terminator)
        assert_eq!(&encoded[56..58], &[0x57, 0x00]); // 'W'
        assert_eq!(&encoded[58..60], &[0x51, 0x00]); // 'Q'
        assert_eq!(&encoded[60..62], &[0x4C, 0x00]); // 'L'
        assert_eq!(&encoded[62..64], &[0x00, 0x00]); // null terminator

        // Second BSTR pointer and header for the query string
        assert_eq!(&encoded[64..68], &[0x01, 0x00, 0x02, 0x00]); // referent
        assert_eq!(&encoded[68..72], &[0x1C, 0x00, 0x00, 0x00]); // max_count (28 chars incl. null)
        assert_eq!(&encoded[72..76], &[0x00, 0x00, 0x00, 0x00]); // offset
        assert_eq!(&encoded[76..80], &[0x1C, 0x00, 0x00, 0x00]); // actual_count

        // Query string "SELECT * FROM Win32_Process" begins immediately after header
        assert_eq!(&encoded[80..82], &[0x53, 0x00]); // 'S'
        assert_eq!(&encoded[82..84], &[0x45, 0x00]); // 'E'
    }

    #[test]
    fn test_conformant_array_encoding_golden() {
        let array = ConformantArray::new(vec![Variant::I4(1), Variant::I4(2)]);
        let encoded = array.encode();

        // Conformance header
        assert_eq!(&encoded[0..4], &[0x02, 0x00, 0x00, 0x00]); // max_count = 2
        assert_eq!(&encoded[4..8], &[0x00, 0x00, 0x00, 0x00]); // offset = 0
        assert_eq!(&encoded[8..12], &[0x02, 0x00, 0x00, 0x00]); // actual_count = 2

        // First VARIANT (I4 = 1)
        assert_eq!(&encoded[12..14], &[0x03, 0x00]); // VT_I4
        assert_eq!(&encoded[20..24], &[0x01, 0x00, 0x00, 0x00]); // value = 1

        // Second VARIANT (I4 = 2)
        assert_eq!(&encoded[28..30], &[0x03, 0x00]); // VT_I4
        assert_eq!(&encoded[36..40], &[0x02, 0x00, 0x00, 0x00]); // value = 2
    }

    #[test]
    fn test_orpcthat_parsing() {
        // ORPCTHAT with no extensions
        let data = hex!(
            "00 00 00 00"  // Flags
            "00 00 00 00"  // Extensions (none)
            "00 00 00 00"  // HRESULT (S_OK)
        );

        let offset = RealNdrCodec::parse_orpcthat(&data).expect("parse");
        assert_eq!(offset, 8);

        let hresult = RealNdrCodec::decode_hresult(&data, offset).expect("decode");
        assert_eq!(hresult, 0); // S_OK
    }
}
