# Microsoft NTLM Removal Timeline and Impact

## ⚠️ CRITICAL: NTLM Is Being Actively Removed from Windows

Microsoft has accelerated NTLM removal beyond deprecation - they are actively removing the protocol from Windows systems. This directly impacts cross-platform WMI connectivity.

## Timeline of NTLM Removal

### Already Happened (2024)
- **Windows 11 24H2**: NTLMv1 completely removed
- **Windows Server 2025**: NTLMv1 completely removed
- **Impact**: Legacy systems (DOS, Windows 95/98) can no longer authenticate
- **SMB shares** on home networks becoming inaccessible after 24H2 upgrade

### September 2025
- **Audit Mode Rollout**: Windows 11 24H2 will log Event ID 4024 when NTLMv1-derived credentials are used
- Authentication will still work but with warnings
- Organizations should monitor these events to identify dependencies

### October 2026 (Enforcement Deadline)
- **Automatic Enforcement**: `BlockNTLMv1SSO` registry key set to Enforce mode
- **Complete Block**: NTLMv1-derived credentials blocked unless manually overridden
- **Critical for Cross-Platform**: macOS and Linux clients using NTLM will fail

### Future (Post-2026)
- Microsoft's stated goal: "Eliminating the need to use NTLM at all"
- NTLMv2 will eventually be removed (timeline not yet announced)
- Complete transition to Kerberos and modern authentication

## Impact on linux-wmi

### Current Situation
- Windows 11 already rejects NTLM for DCOM authentication
- `bind_nak` errors when attempting DCOM activation
- Direct port specification workaround may stop working

### Why This Matters
1. **DCOM Uses NTLM**: The DCOM activation protocol traditionally relies on NTLM
2. **No Fallback**: Unlike HTTP (which can use Negotiate), DCOM has limited auth options
3. **Cross-Platform Challenge**: Non-Windows systems can't easily join Kerberos realms

## Microsoft's Replacement Strategy

### New Authentication Features
- **IAKerb**: Initial and Pass Through Authentication using Kerberos
- **Local KDC**: Local Key Distribution Center for workgroup scenarios
- **PKU2U**: Public Key Cryptography Based User-to-User authentication

### What This Means
- Kerberos becoming mandatory for enterprise scenarios
- Certificate-based authentication for workgroups
- NTLM proxy solutions as temporary bridges

## Immediate Actions Required

### For Production Systems
1. **Implement Kerberos NOW**: Don't wait for the 2026 deadline
2. **Test with Windows 11 24H2**: Verify your authentication works
3. **Monitor Event Logs**: Look for Event ID 4024 warnings

### For Development
1. **Priority 1**: Complete Kerberos authentication implementation
2. **Priority 2**: Investigate certificate-based authentication
3. **Priority 3**: Consider WinRM as alternative transport

## Temporary Workarounds

### Registry Override (Not Recommended for Production)
```powershell
# Temporarily allow NTLM (will stop working in October 2026)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
  -Name "BlockNTLMv1SSO" -Value 0
```

### Group Policy (Enterprise)
- Configure "Network security: Restrict NTLM" policies
- This is a temporary solution - plan for Kerberos migration

## Technical Details

### Why Windows 11 Blocks NTLM for DCOM
1. **Security Hardening**: DCOM requires packet integrity level 5+
2. **Missing MIC**: Many NTLM implementations lack Message Integrity Code
3. **Protocol Vulnerabilities**: NTLM susceptible to relay attacks

### Authentication Rejection Indicators
- `bind_nak` with reason `0x00`: Generic rejection (Windows 11 24H2)
- `bind_nak` with reason `0x05`: Authentication type not recognized
- Event ID 4024: NTLMv1 credential use logged (starting Sept 2025)

## Long-term Solution: Kerberos

### Requirements
- Kerberos Domain Controller (KDC) access
- Time synchronization (within 5 minutes)
- DNS for realm discovery
- Service Principal Names (SPNs) configured

### Benefits
- Full Windows 11/Server 2025 compatibility
- Stronger security than NTLM
- Delegation capabilities
- Future-proof solution

## References
- [Microsoft's Evolution of Windows Authentication](https://techcommunity.microsoft.com/blog/windows-itpro-blog)
- [Windows 11 24H2 Security Baseline](https://learn.microsoft.com/security/baselines)
- [NTLM Authentication Changes](https://learn.microsoft.com/windows/security/ntlm)

## Bottom Line

**The window for cross-platform DCOM connectivity using NTLM is closing rapidly.** This isn't a configuration issue that can be worked around indefinitely - it's a fundamental shift in Windows authentication architecture. Organizations and developers must prioritize Kerberos implementation or alternative authentication methods immediately.

---
*Last Updated: December 2024*
*Timeline Source: Microsoft Official Communications and Windows 11 24H2 Release Notes*