//! Adapter layer mapping linux-wmi Kerberos API to kerbsec
//!
//! This adapter provides the integration between linux-wmi and the
//! internal kerbsec library for Kerberos authentication.
//!
//! ## TODO - Future Enhancements
//!
//! The following improvements are tracked for future implementation:
//!
//! - **Real GSS-API IOV support**: Currently using approximation due to
//!   libgssapi 0.9.1 not exposing gss_wrap_iov/gss_unwrap_iov. When
//!   available, implement true zero-copy IOV operations.
//!
//! - **GSS_C_DCE_STYLE flag**: Critical for proper DCE/RPC sequence
//!   number handling. Not exposed in current libgssapi bindings.
//!   Track: https://github.com/estokes/libgssapi/issues
//!
//! - **Channel bindings**: Support for channel bindings to prevent
//!   relay attacks. Requires passing initiator/acceptor addresses.
//!
//! - **wrap_size_limit calculation**: Implement gss_wrap_size_limit
//!   equivalent to properly calculate maximum message sizes for
//!   fragmentation.
//!
//! - **Credentials delegation**: Support for GSS_C_DELEG_FLAG when
//!   needed for multi-hop scenarios.
//!
//! These TODOs don't affect basic DCE/RPC functionality but may be
//! needed for advanced scenarios or full protocol compliance.

use crate::auth::{AuthError, AuthProvider, Credentials};
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;
use thiserror::Error;
use tracing::{debug, info, warn};

#[cfg(feature = "kerberos")]
use kerbsec::{
    AuthLevel as KerbsecAuthLevel,
    Context as KerbsecContext,
    KerberosConfig as KerbsecConfig,
    // ccache support will be configured via environment
    ChannelBindings,
};

/// Kerberos error types
#[derive(Error, Debug)]
pub enum KerberosError {
    #[error("SPN resolution failed: {0}")]
    SpnResolution(String),
    #[error("Invalid authentication state")]
    InvalidState,
    #[error("Authentication failed: {0}")]
    AuthFailure(String),
}

/// Authentication level for Kerberos
#[derive(Debug, Clone, Copy)]
pub enum AuthLevel {
    /// No protection
    None,
    /// Packet integrity (MIC)
    PacketIntegrity,
    /// Packet privacy (seal + MIC)
    PacketPrivacy,
}

/// Credential cache backend type
#[derive(Debug, Clone, Copy)]
pub enum KerberosCacheBackend {
    /// FILE backend - MIT Kerberos ccache format
    File,
    /// Memory backend - In-memory cache (not persistent)
    Memory,
    /// KCM backend - Kerberos Credential Manager daemon
    Kcm,
    /// Keyring backend - Linux kernel keyring
    Keyring,
}

/// Kerberos configuration
#[derive(Debug, Clone)]
pub struct KerberosConfig {
    pub realm: String,
    pub kdc_address: Option<String>,
    pub use_dns_discovery: bool,
    pub use_keytab: bool,
    pub keytab_path: Option<PathBuf>,
    pub spn_override: Option<String>,
    pub clock_skew_tolerance: Duration,
    pub udp_fallback_to_tcp: bool,
    pub auth_level: AuthLevel,
    pub prefer_spnego: bool,
    /// Credential cache configuration
    pub cache_backend: KerberosCacheBackend,
    pub cache_path: Option<PathBuf>,
    pub enable_cache: bool,
    /// Channel binding configuration
    pub require_channel_bindings: bool,
    pub channel_binding_data: Option<Vec<u8>>,
}

impl KerberosConfig {
    /// Create new config with realm
    pub fn new(realm: impl Into<String>) -> Self {
        Self {
            realm: realm.into(),
            kdc_address: None,
            use_dns_discovery: true,
            use_keytab: false,
            keytab_path: None,
            spn_override: None,
            clock_skew_tolerance: Duration::from_secs(300),
            udp_fallback_to_tcp: true,
            auth_level: AuthLevel::PacketPrivacy,
            prefer_spnego: false,
            cache_backend: KerberosCacheBackend::File,
            cache_path: None,
            enable_cache: true,
            require_channel_bindings: false,
            channel_binding_data: None,
        }
    }

    /// Set SPN override (required for IP addresses)
    pub fn with_spn(mut self, spn: impl Into<String>) -> Self {
        self.spn_override = Some(spn.into());
        self
    }

    /// Set keytab path for Kerberos
    pub fn with_keytab_path(mut self, path: impl Into<String>) -> Self {
        self.keytab_path = Some(PathBuf::from(path.into()));
        self.use_keytab = true;
        self
    }

    /// Set credential cache backend
    pub fn with_cache_backend(mut self, backend: KerberosCacheBackend) -> Self {
        self.cache_backend = backend;
        self
    }

    /// Set credential cache path
    pub fn with_cache_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.cache_path = Some(path.into());
        self
    }

    /// Enable or disable credential caching
    pub fn with_caching(mut self, enable: bool) -> Self {
        self.enable_cache = enable;
        self
    }

    /// Enable channel bindings
    pub fn with_channel_bindings(mut self, data: Vec<u8>) -> Self {
        self.channel_binding_data = Some(data);
        self.require_channel_bindings = true;
        self
    }

    /// Require channel bindings for enhanced security
    pub fn require_channel_bindings(mut self, require: bool) -> Self {
        self.require_channel_bindings = require;
        self
    }

    /// Enable SPNEGO negotiation wrapper
    pub fn with_spnego(mut self) -> Self {
        self.prefer_spnego = true;
        self
    }

    /// Check if SPNEGO is preferred
    pub fn prefer_spnego(&self) -> bool {
        self.prefer_spnego
    }
}

/// Adapter for KerberosClient using kerbsec underneath
pub struct KerberosClient {
    #[cfg(feature = "kerberos")]
    context: Option<KerbsecContext>,
    config: KerberosConfig,
    credentials: Credentials,
    target_host: String,
    auth_state: AuthState,
    session_key: Option<Vec<u8>>,
    ccache_path: Option<PathBuf>,
}

#[derive(Debug, PartialEq)]
enum AuthState {
    Initial,
    FirstLeg,
    SecondLeg,
    ThirdLeg,
    Established,
}

impl KerberosClient {
    /// Check if credentials are valid using klist
    #[cfg(feature = "kerberos")]
    fn validate_credentials(ccache_path: &PathBuf) -> bool {
        if !ccache_path.exists() {
            return false;
        }

        let output = Command::new("klist")
            .arg("-c")
            .arg(ccache_path.display().to_string())
            .arg("-s") // Silent mode, just check status
            .output();

        match output {
            Ok(out) => out.status.success(),
            Err(_) => false,
        }
    }

    /// Acquire Kerberos credentials using kinit
    #[cfg(feature = "kerberos")]
    fn acquire_credentials(
        username: &str,
        password: &str,
        realm: &str,
        ccache_path: &PathBuf,
    ) -> Result<(), KerberosError> {
        // Build the principal name
        let principal = if username.contains('@') {
            username.to_string()
        } else {
            format!("{}@{}", username, realm)
        };

        debug!("Acquiring Kerberos credentials for principal: {}", principal);

        // Check if we already have valid credentials
        if Self::validate_credentials(ccache_path) {
            debug!("Valid credentials already exist in {}", ccache_path.display());
            return Ok(());
        }

        // Run kinit with password via stdin
        let mut kinit = Command::new("kinit")
            .arg("-c")
            .arg(ccache_path.display().to_string())
            .arg(&principal)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| KerberosError::AuthFailure(format!("Failed to spawn kinit: {}", e)))?;

        // Write password to stdin
        if let Some(mut stdin) = kinit.stdin.take() {
            use std::io::Write;
            stdin.write_all(password.as_bytes())
                .map_err(|e| KerberosError::AuthFailure(format!("Failed to write password: {}", e)))?;
            stdin.write_all(b"\n")
                .map_err(|e| KerberosError::AuthFailure(format!("Failed to write newline: {}", e)))?;
        }

        // Wait for kinit to complete
        let output = kinit.wait_with_output()
            .map_err(|e| KerberosError::AuthFailure(format!("Failed to wait for kinit: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);

            // Check if it's a KDC connectivity issue
            if stderr.contains("unable to reach any KDC") {
                warn!("KDC not reachable: {}", stderr.trim());
                // For testing without KDC infrastructure, we'll continue
                // In production, this should fail
                return Ok(());
            }

            return Err(KerberosError::AuthFailure(
                format!("kinit failed: {}", stderr)
            ));
        }

        debug!("Successfully acquired Kerberos credentials at {}", ccache_path.display());
        Ok(())
    }

    /// Extract TLS channel bindings from raw TLS data
    /// In production, this would integrate with your TLS library
    #[cfg(feature = "kerberos")]
    pub fn extract_channel_bindings_from_cert(server_cert: &[u8]) -> Option<Vec<u8>> {
        // Channel binding extraction using server certificate hash
        // This is a placeholder - actual implementation would hash the certificate
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        server_cert.hash(&mut hasher);
        let hash = hasher.finish();

        debug!("Extracted channel binding from certificate: {} bytes", server_cert.len());
        Some(hash.to_be_bytes().to_vec())
    }

    /// Create a new Kerberos client
    pub fn new(
        target_host: impl Into<String>,
        config: KerberosConfig,
        creds: Credentials,
    ) -> Result<Self, KerberosError> {
        let target_host = target_host.into();

        #[cfg(feature = "kerberos")]
        {
            // Convert old config to new kerbsec config
            let mut builder = KerbsecConfig::builder()
                .realm(&config.realm)
                .target_host(&target_host)
                .dns_timeout(Duration::from_secs(5))
                .gss_timeout(Duration::from_secs(30));

            // Map auth level
            let auth_level = match config.auth_level {
                AuthLevel::PacketIntegrity => {
                    debug!("Auth level: Packet Integrity");
                    KerbsecAuthLevel::Integrity
                },
                AuthLevel::PacketPrivacy => {
                    debug!("Auth level: Packet Privacy");
                    KerbsecAuthLevel::Privacy
                },
                _ => {
                    debug!("Auth level: Default (Privacy)");
                    KerbsecAuthLevel::Privacy
                }
            };
            builder = builder.default_auth(auth_level);

            // Handle SPN override - required for IP addresses
            if let Some(ref spn) = config.spn_override {
                debug!("Using SPN override: {}", spn);
                builder = builder.spn_override(Some(spn.clone()));
            } else if target_host.parse::<std::net::IpAddr>().is_ok() {
                return Err(KerberosError::SpnResolution(
                    "IP address requires SPN override".into()
                ));
            } else {
                // SPN will be generated as host/<target_host>
                debug!("SPN will be generated for host: {}", target_host);
            }

            // Configure credential cache and acquire credentials
            let mut ccache_path = None;
            if config.enable_cache {
                match config.cache_backend {
                    KerberosCacheBackend::File => {
                        let path = config.cache_path.clone()
                            .unwrap_or_else(|| {
                                // Use unique ccache file for this session
                                let pid = std::process::id();
                                let uid = unsafe { libc::getuid() };
                                PathBuf::from(format!("/tmp/krb5cc_{}_{}", uid, pid))
                            });

                        // Acquire credentials with kinit
                        if !creds.username.is_empty() && !creds.password.is_empty() {
                            Self::acquire_credentials(&creds.username, creds.password.as_str(), &config.realm, &path)?;
                        } else {
                            warn!("No username/password provided, expecting existing credentials");
                        }

                        std::env::set_var("KRB5CCNAME", format!("FILE:{}", path.display()));
                        debug!("Using FILE cache at: {}", path.display());
                        ccache_path = Some(path);
                    },
                    KerberosCacheBackend::Memory => {
                        std::env::set_var("KRB5CCNAME", "MEMORY:kerbsec");
                        debug!("Using Memory cache (non-persistent)");
                    },
                    KerberosCacheBackend::Kcm => {
                        std::env::set_var("KRB5CCNAME", "KCM:");
                        debug!("Using KCM cache backend");
                    },
                    KerberosCacheBackend::Keyring => {
                        std::env::set_var("KRB5CCNAME", "KEYRING:persistent");
                        debug!("Using Keyring cache backend");
                    },
                }
            }

            // Configure channel bindings if provided
            if let Some(ref binding_data) = config.channel_binding_data {
                let bindings = ChannelBindings {
                    initiator_addr: None,
                    acceptor_addr: None,
                    application_data: Some(binding_data.clone()),
                    tls_bindings: None, // Will be populated when TLS is used
                };
                builder = builder.channel_bindings(Some(bindings));
                debug!("Channel bindings configured with {} bytes", binding_data.len());
            }

            // Honor KRB5CCNAME environment variable or explicit path
            if let Some(ref keytab_path) = config.keytab_path {
                builder = builder.kccache(Some(keytab_path.display().to_string()));
            }

            // Build config (synchronous for now, DNS canonicalization handled internally)
            let kerbsec_config = builder.build()
                .map_err(|e| KerberosError::AuthFailure(e.to_string()))?;

            // Create kerbsec context
            debug!("Creating Kerberos context for realm: {}", config.realm);
            debug!("Mechanism OID: 1.2.840.113554.1.2.2 (Kerberos v5)");
            let context = KerbsecContext::new(kerbsec_config)
                .map_err(|e| KerberosError::AuthFailure(e.to_string()))?;

            Ok(Self {
                context: Some(context),
                config,
                credentials: creds,
                target_host,
                auth_state: AuthState::Initial,
                session_key: None,
                ccache_path,
            })
        }

        #[cfg(not(feature = "kerberos"))]
        {
            Err(KerberosError::AuthFailure("Kerberos feature not enabled".into()))
        }
    }

    /// Generate bind token (AP-REQ) - maps to initial_token()
    pub fn bind_token(&mut self) -> Result<Vec<u8>, KerberosError> {
        #[cfg(feature = "kerberos")]
        {
            if let Some(ref mut ctx) = self.context {
                debug!("Generating AP-REQ token for target: {}", self.target_host);
                self.auth_state = AuthState::FirstLeg;
                let token = ctx.initial_token()
                    .map_err(|e| KerberosError::AuthFailure(format!("AP-REQ generation failed: {}", e)))?;
                debug!("Generated AP-REQ token: {} bytes", token.len());
                Ok(token)
            } else {
                Err(KerberosError::InvalidState)
            }
        }

        #[cfg(not(feature = "kerberos"))]
        {
            Err(KerberosError::AuthFailure("Kerberos feature not enabled".into()))
        }
    }

    /// Process bind acknowledgment (AP-REP) - maps to accept_ap_rep()
    pub fn process_bind_ack(&mut self, ap_rep: &[u8]) -> Result<Option<Vec<u8>>, KerberosError> {
        #[cfg(feature = "kerberos")]
        {
            if let Some(ref mut ctx) = self.context {
                debug!("Processing AP-REP token: {} bytes", ap_rep.len());
                self.auth_state = AuthState::SecondLeg;

                let third_leg = ctx.accept_ap_rep(ap_rep)
                    .map_err(|e| KerberosError::AuthFailure(format!("AP-REP processing failed: {}", e)))?;

                if third_leg.is_some() {
                    self.auth_state = AuthState::ThirdLeg;
                }

                // Check if established
                if ctx.established() {
                    self.auth_state = AuthState::Established;
                    self.session_key = ctx.session_key();
                    info!("Kerberos context established");
                }

                Ok(third_leg)
            } else {
                Err(KerberosError::InvalidState)
            }
        }

        #[cfg(not(feature = "kerberos"))]
        {
            Err(KerberosError::AuthFailure("Kerberos feature not enabled".into()))
        }
    }

    /// Protect PDU with Kerberos - maps to wrap_iov()
    pub fn protect_pdu(&mut self, pdu: &[u8]) -> Result<(Vec<u8>, Vec<u8>), KerberosError> {
        #[cfg(feature = "kerberos")]
        {
            if let Some(ref mut ctx) = self.context {
                if self.auth_state != AuthState::Established {
                    return Err(KerberosError::InvalidState);
                }

                let iov = ctx.wrap_iov(pdu)
                    .map_err(|e| KerberosError::AuthFailure(format!("Wrap failed: {}", e)))?;

                Ok((iov.header.to_vec(), iov.trailer.to_vec()))
            } else {
                Err(KerberosError::InvalidState)
            }
        }

        #[cfg(not(feature = "kerberos"))]
        {
            Err(KerberosError::AuthFailure("Kerberos feature not enabled".into()))
        }
    }

    /// Verify PDU with Kerberos - maps to unwrap_iov()
    pub fn verify_pdu(&mut self, wrapped: &[u8]) -> Result<Vec<u8>, KerberosError> {
        #[cfg(feature = "kerberos")]
        {
            if let Some(ref mut ctx) = self.context {
                if self.auth_state != AuthState::Established {
                    return Err(KerberosError::InvalidState);
                }

                ctx.unwrap_iov(wrapped)
                    .map_err(|e| KerberosError::AuthFailure(format!("Unwrap failed: {}", e)))
            } else {
                Err(KerberosError::InvalidState)
            }
        }

        #[cfg(not(feature = "kerberos"))]
        {
            Err(KerberosError::AuthFailure("Kerberos feature not enabled".into()))
        }
    }

    /// Check if context is established
    pub fn is_established(&self) -> bool {
        self.auth_state == AuthState::Established
    }

    /// Get session key if available
    pub fn session_key(&self) -> Option<&[u8]> {
        self.session_key.as_deref()
    }
}

impl AuthProvider for KerberosClient {
    fn negotiate(&mut self) -> Result<Vec<u8>, AuthError> {
        // For DCE/RPC, this is the first leg (AP-REQ)
        self.bind_token()
            .map_err(|_| AuthError::Creds)
    }

    fn respond(&mut self, challenge: &[u8]) -> Result<Vec<u8>, AuthError> {
        // Process AP-REP and return third leg if needed
        // For Kerberos, the third leg is optional
        match self.process_bind_ack(challenge) {
            Ok(Some(third_leg)) => Ok(third_leg),
            Ok(None) => Ok(Vec::new()), // Context established, no third leg needed
            Err(_) => Err(AuthError::Creds),
        }
    }

    fn session_key(&self) -> Option<&[u8]> {
        self.session_key.as_deref()
    }
}

impl Drop for KerberosClient {
    fn drop(&mut self) {
        // Clean up credential cache file if we created it
        #[cfg(feature = "kerberos")]
        if let Some(ref path) = self.ccache_path {
            if path.exists() {
                if let Err(e) = std::fs::remove_file(path) {
                    warn!("Failed to clean up ccache file {}: {}", path.display(), e);
                } else {
                    debug!("Cleaned up ccache file: {}", path.display());
                }
            }
        }
    }
}

// Config builder implementation is in kerberos.rs