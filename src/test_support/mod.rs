//! Test support infrastructure
//!
//! This module contains mock implementations and stubs used for testing.
//! These are activated when LINUX_WMI_USE_STUB=1 or in test builds.
//!
//! ⚠️ TEST INFRASTRUCTURE - DO NOT DELETE
//! These mocks are essential for integration testing without real Windows hosts.

#[cfg(any(test, feature = "test-support"))]
pub mod stub_transport;

#[cfg(any(test, feature = "test-support"))]
pub mod stub_ndr;

#[cfg(any(test, feature = "test-support"))]
pub mod mock_security;

// Re-export for convenience
#[cfg(any(test, feature = "test-support"))]
pub use stub_transport::StubTransport;

#[cfg(any(test, feature = "test-support"))]
pub use stub_ndr::StubNdrCodec;