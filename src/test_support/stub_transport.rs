//! Stub transport for testing
//!
//! Provides a mock RPC transport that returns empty responses.
//! Used when LINUX_WMI_USE_STUB=1 for integration testing.

use crate::transport::{RpcTransport, TransportError};

/// TEST INFRASTRUCTURE - DO NOT DELETE
///
/// Mock transport that returns empty responses for all RPC calls.
/// This is used for:
/// - Unit tests that don't need actual network communication
/// - Integration tests when LINUX_WMI_USE_STUB=1
/// - Testing error handling paths
pub struct StubTransport;

impl RpcTransport for StubTransport {
    fn name(&self) -> &'static str {
        "stub-transport"
    }

    fn invoke(&mut self, _opnum: u16, _payload: &[u8]) -> Result<Vec<u8>, TransportError> {
        // The stub simply returns an empty buffer. Real transports will marshal and send the
        // payload to a remote endpoint before returning the response.
        Ok(Vec::new())
    }
}
