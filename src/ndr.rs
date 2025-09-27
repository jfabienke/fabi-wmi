pub mod codec;
pub mod types;

#[cfg(test)]
mod golden_tests;

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use serde_json::Value;
use thiserror::Error;

pub use codec::RealNdrCodec;

#[cfg(feature = "async")]
use std::sync::Arc;
#[cfg(feature = "async")]
use tokio::task::spawn_blocking;

/// Errors produced by the NDR codec while encoding or decoding payloads.
#[derive(Debug, Error)]
pub enum NdrError {
    #[error("encoding not implemented")]
    Encode,
    #[error("decoding not implemented")]
    Decode,
    #[error("invalid conformance: max_count ({max}) < actual_count ({actual})")]
    InvalidConformance { max: u32, actual: u32 },
    #[error("array size exceeds limit: {size} bytes (max: {max})")]
    ArrayTooLarge { size: usize, max: usize },
}

/// Abstraction over the NDR encoder/decoder used for RPC payloads.
pub trait NdrCodec: Send + Sync {
    /// Encode an ExecQuery call into a binary payload.
    fn encode_exec_query(&self, language: &str, query: &str) -> Result<Vec<u8>, NdrError>;

    /// Decode the ExecQuery response into JSON values.
    fn decode_exec_query(
        &self,
        _namespace: &str,
        query: &str,
        data: &[u8],
    ) -> Result<Vec<Value>, NdrError>;

    /// Encode an ExecMethod call with arbitrary parameters.
    fn encode_exec_method(
        &self,
        class: &str,
        method: &str,
        params: &Value,
    ) -> Result<Vec<u8>, NdrError>;

    /// Decode the ExecMethod response into JSON values.
    fn decode_exec_method(&self, class: &str, method: &str, data: &[u8])
        -> Result<Value, NdrError>;
}

#[cfg(feature = "async")]
#[derive(Clone)]
#[allow(dead_code)]
pub struct AsyncNdrCodec {
    inner: Arc<dyn NdrCodec + Send + Sync>,
}

#[cfg(feature = "async")]
impl AsyncNdrCodec {
    #[allow(dead_code)]
    pub fn new(inner: Arc<dyn NdrCodec + Send + Sync>) -> Self {
        Self { inner }
    }

    #[allow(dead_code)]
    pub async fn encode_exec_query(
        &self,
        language: &str,
        query: &str,
    ) -> Result<Vec<u8>, NdrError> {
        let language_owned = language.to_owned();
        let query_owned = query.to_owned();
        let inner = Arc::clone(&self.inner);

        spawn_blocking(move || inner.encode_exec_query(&language_owned, &query_owned))
            .await
            .map_err(|_| NdrError::Encode)?
    }

    #[allow(dead_code)]
    pub async fn decode_exec_query(
        &self,
        namespace: &str,
        query: &str,
        data: &[u8],
    ) -> Result<Vec<Value>, NdrError> {
        let namespace_owned = namespace.to_owned();
        let query_owned = query.to_owned();
        let payload = data.to_vec();
        let inner = Arc::clone(&self.inner);

        spawn_blocking(move || inner.decode_exec_query(&namespace_owned, &query_owned, &payload))
            .await
            .map_err(|_| NdrError::Decode)?
    }
}

#[allow(dead_code)] // Used by test_support module
pub(crate) fn write_bstr(buf: &mut Vec<u8>, value: &str) {
    let utf16: Vec<u16> = value.encode_utf16().collect();
    buf.write_u32::<LittleEndian>(utf16.len() as u32)
        .expect("write bstr length");
    for unit in utf16 {
        buf.write_u16::<LittleEndian>(unit)
            .expect("write bstr data");
    }
    buf.write_u16::<LittleEndian>(0)
        .expect("write bstr terminator");
}

#[allow(dead_code)]
pub(crate) fn read_bstr(cursor: &mut std::io::Cursor<&[u8]>) -> Option<String> {
    let len = cursor.read_u32::<LittleEndian>().ok()? as usize;
    let mut data = Vec::with_capacity(len);
    for _ in 0..len {
        data.push(cursor.read_u16::<LittleEndian>().ok()?);
    }
    let _ = cursor.read_u16::<LittleEndian>().ok()?; // terminator
    String::from_utf16(&data).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(any(test, feature = "test-support"))]
    fn encode_exec_query_emits_bstrs() {
        use crate::test_support::StubNdrCodec;
        let codec = StubNdrCodec;
        let payload = codec
            .encode_exec_query("WQL", "SELECT * FROM Win32_ComputerSystem")
            .expect("encode");
        let mut cursor = std::io::Cursor::new(payload.as_slice());
        let language = read_bstr(&mut cursor).expect("language bstr");
        let query = read_bstr(&mut cursor).expect("query bstr");
        assert_eq!(language, "WQL");
        assert_eq!(query, "SELECT * FROM Win32_ComputerSystem");
    }

    #[test]
    #[cfg(any(test, feature = "test-support"))]
    fn stub_results_for_known_query_matches_decode() {
        use crate::test_support::StubNdrCodec;
        let codec = StubNdrCodec;
        let query = "SELECT * FROM Win32_ComputerSystem";
        let payload = codec.encode_exec_query("WQL", query).expect("encode");
        let results = codec
            .decode_exec_query("root\\cimv2", query, &payload)
            .expect("decode");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0]["Name"], "STUB-PC");
    }
}
