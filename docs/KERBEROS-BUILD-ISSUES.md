# Kerberos Build Issues (RESOLVED)

## ~~libgssapi Compatibility Problem~~ ✅ FIXED

### Issue (Historical)
The `libgssapi` crate v0.7.2 had compatibility issues with newer versions of `libgssapi-sys`:

```
error[E0432]: unresolved import `libgssapi_sys::gss_localname`
error[E0432]: unresolved imports `libgssapi_sys::gss_unwrap_iov`, `libgssapi_sys::gss_wrap_iov`, `libgssapi_sys::gss_wrap_iov_length`
```

### Resolution ✅
**This issue has been resolved by:**
1. Upgrading `libgssapi` from v0.7.2 to v0.9.1
2. Disabling default features to avoid macOS-incompatible functions
3. Upgrading `kerbeiros` to `himmelblau_kerbeiros` v0.4.1

The project now compiles successfully with both `kerberos` and `kerberos-minimal` features.

## Current Dependencies

The project now uses:
- `libgssapi` v0.9.1 (with default features disabled for macOS compatibility)
- `himmelblau_kerbeiros` v0.4.1 (actively maintained fork)
- Platform-specific: `trust-dns-resolver` v0.23 for Unix, `sspi` v0.12 for Windows

## Building with Kerberos

```bash
# Full Kerberos support (ticket acquisition + GSSAPI/SSPI)
cargo build --features kerberos

# Minimal Kerberos (GSSAPI/SSPI only, no ticket acquisition)
cargo build --features kerberos-minimal

# Test the Kerberos integration
cargo run --example test_kerberos --features kerberos -- \
    server.contoso.com --user admin --pass <password> \
    --domain CONTOSO.COM --query "SELECT Name FROM Win32_ComputerSystem"
```

## Testing Without Full Kerberos

The Kerberos integration can still be tested at the design level:

1. **Mock testing**: Use the `MockSecurityContext` in tests
2. **Stub authentication**: The transport layer accepts any `AuthProvider`
3. **Integration points**: Verify the auth fallback chain works

## Platform-Specific Notes

### macOS
- System GSSAPI framework may have different symbols than MIT Kerberos
- Consider using Homebrew's krb5: `brew install krb5`

### Linux
- Ensure MIT Kerberos dev packages are installed:
  - Debian/Ubuntu: `sudo apt-get install libkrb5-dev`
  - RHEL/Fedora: `sudo yum install krb5-devel`

### Windows
- SSPI should work without issues (uses Windows native APIs)
- The `sspi` crate is more mature than libgssapi

## Next Steps

1. **For Phase 2 completion**: The Kerberos client structure is in place
2. **For Phase 3**: Focus on integration testing with mocks
3. **For Phase 4**: Resolve the libgssapi issue before production deployment