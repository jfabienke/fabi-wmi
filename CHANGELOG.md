# Changelog

All notable changes to linux-wmi will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2025-01-22

### Added
- **Runtime-configurable GSS flags** via kerbsec v0.2.0 integration
  - DCE-style flag (GSS_C_DCE_STYLE) for proper DCE/RPC sequence handling
  - Credential delegation (GSS_C_DELEG_FLAG) for S4U2Self/S4U2Proxy scenarios
  - Mutual authentication configuration
- **Delegation support methods**
  - `has_delegated_credentials()` to check for delegated credentials
  - `export_delegated_credentials()` for impersonation scenarios
- **Enhanced Kerberos configuration**
  - `with_dce_style()` builder method (default: true for DCE/RPC)
  - `with_delegation()` builder method (default: false for security)
  - `with_mutual_auth()` builder method (default: true)
- **New examples**
  - `dce_rpc_kerberos.rs` - Best practices for DCE/RPC with Kerberos
  - Enhanced `test_kerberos.rs` with flag configuration tests
- **Comprehensive documentation**
  - `docs/KERBEROS_CONFIG.md` - Complete Kerberos configuration guide
  - `docs/TODO.md` - Consolidated TODO tracking
  - `docs/ASYNC_ROADMAP.md` - Async implementation roadmap
  - `docs/DEAD_CODE_INVENTORY.md` - Dead code analysis

### Changed
- Moved test support code to dedicated `test_support` module
- Updated kerbsec dependency to v0.2.0
- Improved channel bindings implementation using kerbsec's API

### Fixed
- GSS_C_DCE_STYLE flag now properly applied for DCE/RPC protocols
- Channel bindings now use proper kerbsec constructors

### Removed
- Dead `security_context` module (replaced by kerbsec integration)

### Security
- Credential delegation disabled by default
- DCE-style enabled by default for DCE/RPC compatibility
- Mutual authentication required by default
- Added comprehensive security warnings for delegation

## [0.1.0] - 2024-12-01

### Added
- Initial release with basic WMI over DCE/RPC support
- Kerberos authentication via kerbsec library
- NTLM authentication support
- DCOM activation
- Basic WMI query execution
- Transport layer with TCP support
- NDR encoding/decoding
- Examples for testing connectivity

### Security
- Secure credential handling with zeroization
- Support for packet privacy (encryption) and integrity

---

[Unreleased]: https://github.com/yourusername/linux-wmi/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/yourusername/linux-wmi/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/yourusername/linux-wmi/releases/tag/v0.1.0