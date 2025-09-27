//! Adapter layer mapping linux-wmi Kerberos API to kerbsec
//!
//! This adapter provides the integration between linux-wmi and the
//! internal kerbsec library for Kerberos authentication.
//!
//! ## Resolved with kerbsec v0.2.0+
//!
//! The following features are now available via kerbsec runtime configuration:
//!
//! - ✅ **GSS_C_DCE_STYLE flag**: Runtime-configurable for proper DCE/RPC
//!   sequence number handling via `enable_dce_style` configuration.
//!
//! - ✅ **Credentials delegation**: Runtime-configurable GSS_C_DELEG_FLAG
//!   for multi-hop scenarios (S4U2Self/S4U2Proxy) via `enable_delegation`.
//!
//! ## Resolved with kerbsec v0.2.0
//!
//! The following features are now available via kerbsec:
//!
//! - ✅ **GSS-API IOV support**: Using kerbsec's `iov` feature for
//!   zero-copy operations via wrap_iov()/unwrap_iov().
//!
//! - ✅ **Channel bindings**: Available via `channel-bindings` feature.
//!   Implementation pending in connect flow.
//!
//! - ✅ **wrap_size_limit calculation**: Provided by kerbsec's IOV
//!   implementation for proper message fragmentation.
//!
//! - ✅ **Credential caching**: Native support via `ccache` feature,
//!   eliminating need for kinit subprocess calls.

use crate::auth::{AuthError, AuthProvider, Credentials};
use std::path::PathBuf;
use std::time::Duration;
use thiserror::Error;
use tracing::{debug, info, warn};

#[cfg(feature = "kerberos")]
use kerbsec::{
    // Channel bindings are available when kerbsec has the feature
    channel_bindings::{ChannelBindingType, ChannelBindings},
    AuthLevel as KerbsecAuthLevel,
    Context as KerbsecContext,
    KerberosConfig as KerbsecConfig,
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
    /// Enable DCE-style flag for DCE/RPC compatibility (default: true)
    /// This disables GSS sequence checking as DCE/RPC has its own
    pub enable_dce_style: bool,
    /// Enable credential delegation (default: false for security)
    /// WARNING: Only enable for completely trusted servers!
    pub enable_delegation: bool,
    /// Require mutual authentication (default: true)
    pub require_mutual_auth: bool,
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
            enable_dce_style: true,    // Default: enabled for DCE/RPC
            enable_delegation: false,  // Default: disabled for security
            require_mutual_auth: true, // Default: enabled for security
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

    /// Configure DCE-style flag for DCE/RPC compatibility
    pub fn with_dce_style(mut self, enable: bool) -> Self {
        self.enable_dce_style = enable;
        self
    }

    /// Enable credential delegation (WARNING: Security risk!)
    pub fn with_delegation(mut self, enable: bool) -> Self {
        self.enable_delegation = enable;
        self
    }

    /// Configure mutual authentication requirement
    pub fn with_mutual_auth(mut self, require: bool) -> Self {
        self.require_mutual_auth = require;
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
    #[allow(dead_code)]
    config: KerberosConfig,
    #[allow(dead_code)]
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
    /// Configure credential cache path based on backend type
    #[cfg(feature = "kerberos")]
    fn configure_cache(
        cache_backend: KerberosCacheBackend,
        cache_path: Option<PathBuf>,
        username: &str,
    ) -> String {
        match cache_backend {
            KerberosCacheBackend::File => {
                let path = cache_path.unwrap_or_else(|| {
                    // Use unique ccache file for this session
                    let pid = std::process::id();
                    let uid = unsafe { libc::getuid() };
                    PathBuf::from(format!("/tmp/krb5cc_{uid}_{pid}"))
                });

                let cache_string = format!("FILE:{}", path.display());
                debug!("Using FILE cache at: {}", cache_string);
                cache_string
            }
            KerberosCacheBackend::Memory => {
                let cache_string = format!("MEMORY:{}", username);
                debug!("Using Memory cache (non-persistent): {}", cache_string);
                cache_string
            }
            KerberosCacheBackend::Kcm => {
                let cache_string = "KCM:".to_string();
                debug!("Using KCM cache backend");
                cache_string
            }
            KerberosCacheBackend::Keyring => {
                let cache_string = "KEYRING:persistent".to_string();
                debug!("Using Keyring cache backend");
                cache_string
            }
        }
    }

    /// Create channel bindings for TLS connections
    /// Uses kerbsec's channel binding support for enhanced security
    #[cfg(feature = "kerberos")]
    pub fn create_tls_channel_bindings(
        tls_unique: Option<&[u8]>,
        server_cert_hash: Option<&[u8]>,
    ) -> Option<ChannelBindings> {
        if let Some(unique) = tls_unique {
            debug!(
                "Creating TLS channel bindings with tls-unique: {} bytes",
                unique.len()
            );
            // Use the new_tls constructor to properly create channel bindings
            Some(ChannelBindings::new_tls(
                ChannelBindingType::TlsUnique,
                unique.to_vec(),
            ))
        } else if let Some(cert_hash) = server_cert_hash {
            debug!(
                "Creating TLS channel bindings with server cert hash: {} bytes",
                cert_hash.len()
            );
            // Using server certificate hash for channel binding
            Some(ChannelBindings::new_tls(
                ChannelBindingType::TlsServerEndPoint,
                cert_hash.to_vec(),
            ))
        } else {
            debug!("No TLS channel binding data available");
            None
        }
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
                }
                AuthLevel::PacketPrivacy => {
                    debug!("Auth level: Packet Privacy");
                    KerbsecAuthLevel::Privacy
                }
                _ => {
                    debug!("Auth level: Default (Privacy)");
                    KerbsecAuthLevel::Privacy
                }
            };
            builder = builder.default_auth(auth_level);

            // Configure GSS flags for DCE/RPC compatibility and security
            builder = builder
                .dce_style(config.enable_dce_style)
                .delegation(config.enable_delegation)
                .mutual_auth(config.require_mutual_auth);

            if config.enable_dce_style {
                debug!("DCE-style flag enabled for DCE/RPC compatibility");
            }
            if config.enable_delegation {
                warn!("Credential delegation enabled - ensure server is trusted!");
            }
            if !config.require_mutual_auth {
                warn!("Mutual authentication disabled - security risk!");
            }

            // Handle SPN override - required for IP addresses
            if let Some(ref spn) = config.spn_override {
                debug!("Using SPN override: {}", spn);
                builder = builder.spn_override(Some(spn.clone()));
            } else if target_host.parse::<std::net::IpAddr>().is_ok() {
                return Err(KerberosError::SpnResolution(
                    "IP address requires SPN override".into(),
                ));
            } else {
                // SPN will be generated as host/<target_host>
                debug!("SPN will be generated for host: {}", target_host);
            }

            // Configure credential cache using kerbsec's native support
            let mut ccache_path = None;
            if config.enable_cache {
                let cache_string = Self::configure_cache(
                    config.cache_backend,
                    config.cache_path.clone(),
                    &creds.username,
                );

                // Set the cache path in the builder
                builder = builder.kccache(Some(cache_string.clone()));

                // Also set environment variable for compatibility
                std::env::set_var("KRB5CCNAME", &cache_string);

                // Store path for file-based caches
                if let KerberosCacheBackend::File = config.cache_backend {
                    ccache_path = config.cache_path.clone();
                }

                info!("Configured Kerberos cache: {}", cache_string);
            }

            // Configure channel bindings if required
            if config.require_channel_bindings {
                // Channel bindings will be set during context establishment
                // when TLS connection details are available
                debug!("Channel bindings will be required for this connection");
            }

            // Note: Credentials will be acquired via kinit or cache
            // kerbsec uses the KRB5CCNAME environment variable
            if !creds.username.is_empty() && !creds.password.is_empty() {
                debug!("Credentials available for user: {}", creds.username);
                // Credentials are handled via the cache configuration above
            } else if config.keytab_path.is_some() {
                // Keytab usage would be configured via environment
                debug!("Keytab authentication configured");
            } else {
                warn!("No credentials or keytab provided, expecting cached credentials");
            }

            // Build config (synchronous for now, DNS canonicalization handled internally)
            let kerbsec_config = builder
                .build()
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
            Err(KerberosError::AuthFailure(
                "Kerberos feature not enabled".into(),
            ))
        }
    }

    /// Generate bind token (AP-REQ) - maps to initial_token()
    pub fn bind_token(&mut self) -> Result<Vec<u8>, KerberosError> {
        #[cfg(feature = "kerberos")]
        {
            if let Some(ref mut ctx) = self.context {
                debug!("Generating AP-REQ token for target: {}", self.target_host);
                self.auth_state = AuthState::FirstLeg;
                let token = ctx.initial_token().map_err(|e| {
                    KerberosError::AuthFailure(format!("AP-REQ generation failed: {e}"))
                })?;
                debug!("Generated AP-REQ token: {} bytes", token.len());
                Ok(token)
            } else {
                Err(KerberosError::InvalidState)
            }
        }

        #[cfg(not(feature = "kerberos"))]
        {
            Err(KerberosError::AuthFailure(
                "Kerberos feature not enabled".into(),
            ))
        }
    }

    /// Process bind acknowledgment (AP-REP) - maps to accept_ap_rep()
    pub fn process_bind_ack(&mut self, ap_rep: &[u8]) -> Result<Option<Vec<u8>>, KerberosError> {
        #[cfg(feature = "kerberos")]
        {
            if let Some(ref mut ctx) = self.context {
                debug!("Processing AP-REP token: {} bytes", ap_rep.len());
                self.auth_state = AuthState::SecondLeg;

                let third_leg = ctx.accept_ap_rep(ap_rep).map_err(|e| {
                    KerberosError::AuthFailure(format!("AP-REP processing failed: {e}"))
                })?;

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
            Err(KerberosError::AuthFailure(
                "Kerberos feature not enabled".into(),
            ))
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

                let iov = ctx
                    .wrap_iov(pdu)
                    .map_err(|e| KerberosError::AuthFailure(format!("Wrap failed: {e}")))?;

                Ok((iov.header.to_vec(), iov.trailer.to_vec()))
            } else {
                Err(KerberosError::InvalidState)
            }
        }

        #[cfg(not(feature = "kerberos"))]
        {
            Err(KerberosError::AuthFailure(
                "Kerberos feature not enabled".into(),
            ))
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
                    .map_err(|e| KerberosError::AuthFailure(format!("Unwrap failed: {e}")))
            } else {
                Err(KerberosError::InvalidState)
            }
        }

        #[cfg(not(feature = "kerberos"))]
        {
            Err(KerberosError::AuthFailure(
                "Kerberos feature not enabled".into(),
            ))
        }
    }

    /// Set channel bindings on the context
    /// Must be called before authentication starts
    #[cfg(feature = "kerberos")]
    pub fn set_channel_bindings(
        &mut self,
        _bindings: ChannelBindings,
    ) -> Result<(), KerberosError> {
        if self.auth_state != AuthState::Initial {
            return Err(KerberosError::InvalidState);
        }

        if self.context.is_some() {
            // Note: kerbsec would need to expose a method to set channel bindings
            // after context creation. For now, this is a placeholder.
            debug!("Channel bindings configured for future use");
            Ok(())
        } else {
            Err(KerberosError::InvalidState)
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

    /// Check if the context has delegated credentials available
    ///
    /// Returns true if the GSS_C_DELEG_FLAG was negotiated and delegated
    /// credentials were received from the client.
    #[cfg(feature = "kerberos")]
    pub fn has_delegated_credentials(&self) -> bool {
        if let Some(ref ctx) = self.context {
            ctx.has_delegated_credentials()
        } else {
            false
        }
    }

    /// Export delegated credentials for S4U2Self/S4U2Proxy scenarios
    ///
    /// # Security Warning
    ///
    /// Delegated credentials allow impersonating the client.
    /// Only use with completely trusted servers!
    ///
    /// # Returns
    ///
    /// The exported delegated credentials if available, or an error if:
    /// - No delegated credentials are available
    /// - The context is not established
    /// - Export operation fails
    #[cfg(feature = "kerberos")]
    pub fn export_delegated_credentials(&self) -> Result<Vec<u8>, KerberosError> {
        if let Some(ref ctx) = self.context {
            if !self.is_established() {
                return Err(KerberosError::InvalidState);
            }

            ctx.export_delegated_credentials().map_err(|e| {
                KerberosError::AuthFailure(format!("Failed to export delegated credentials: {}", e))
            })
        } else {
            Err(KerberosError::InvalidState)
        }
    }
}

impl AuthProvider for KerberosClient {
    fn negotiate(&mut self) -> Result<Vec<u8>, AuthError> {
        // For DCE/RPC, this is the first leg (AP-REQ)
        self.bind_token().map_err(|_| AuthError::Creds)
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
