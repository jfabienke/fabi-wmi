//! A logged-in WMI namespace on one host ([`WmiClient`]) and the crate error.
//!
//! Follows the sequence a working reference client uses against Windows
//! (MS-WMI 3.2.3, MS-DCOM 3.2.4): activate CLSID_WbemLevel1Login on port 135,
//! open one TCP connection to the port the activation advertised, and give each
//! interface its own presentation context *and* its own security context at
//! RPC_C_AUTHN_LEVEL_PKT_INTEGRITY (bind or alter_context, then auth3): NTLM, or
//! Kerberos with [`Auth::Kerberos`].
//! Requests carry the target IPID as the object UUID; stubs are signed, not
//! sealed.

use std::time::Duration;

use serde::de::DeserializeOwned;
use thiserror::Error;
use tracing::debug;

use crate::wmi_proto::{
    self, InterfaceRef, WmiProtoError, CLSID_WBEM_LEVEL1_LOGIN, IID_IENUM_WBEM_CLASS_OBJECT,
    IID_IREMUNKNOWN, IID_IWBEM_LEVEL1_LOGIN, IID_IWBEM_SERVICES,
};
#[cfg(feature = "kerberos")]
use fabi_dcerpc::AUTH_LEVEL_PKT_PRIVACY;
use fabi_dcerpc::{
    fault_to_hresult, AuthError, AuthProvider, BoundContext, Credentials, HandshakeStyle,
    NtlmClient, RpcConnection, RpcError, AUTH_LEVEL_PKT_INTEGRITY, RPC_IO_TIMEOUT,
};
use fabi_dcom::{self as dcom, DcomError};
use fabi_wmio::{decode_object, encode_method_in_params, WmioError};

#[cfg(feature = "kerberos")]
use crate::kerberos_adapter::{KerberosClient, KerberosConfig, KerberosError};

/// Everything that can go wrong talking to WMI. [`Error::hresult`] gives the
/// Windows status code when the server reported one.
#[derive(Debug, Error)]
pub enum Error {
    #[error("DCOM activation failed: {0}")]
    Activation(#[from] DcomError),
    #[error("authentication failed: {0}")]
    Auth(#[from] AuthError),
    #[error(transparent)]
    Rpc(#[from] RpcError),
    #[error("WMI call failed: {0}")]
    Wmi(#[from] WmiProtoError),
    #[error("cannot decode WMI object: {0}")]
    Decode(#[from] WmioError),
    #[error("cannot map WMI result: {0}")]
    Deserialize(#[from] serde_json::Error),
    #[error("protocol error: {0}")]
    Protocol(String),
    #[cfg(feature = "kerberos")]
    #[error("Kerberos setup failed: {0}")]
    Kerberos(#[from] KerberosError),
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Error::Rpc(err.into())
    }
}

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

const OPNUM_NTLM_LOGIN: u16 = 6;
const OPNUM_GET_OBJECT: u16 = 6;
const OPNUM_EXEC_QUERY: u16 = 20;
const OPNUM_EXEC_METHOD: u16 = 24;
const OPNUM_ENUM_NEXT: u16 = 4;
const OPNUM_REM_RELEASE: u16 = 5;
/// lTimeout for IEnumWbemClassObject::Next: wait until objects are ready.
const WBEM_INFINITE: i32 = -1;
/// Objects requested per Next call.
const NEXT_BATCH: u32 = 32;

/// An interface bound on the connection: its presentation/security context and
/// the IPID calls are addressed to.
struct BoundInterface {
    ctx: BoundContext,
    ipid: [u8; 16],
}

/// How [`WmiClient`] authenticates the security contexts it creates.
#[derive(Debug, Clone)]
pub enum Auth {
    /// NTLMv2 with a password.
    Ntlm(Credentials),
    /// Kerberos with a ticket from the credential cache (`kinit`). The SPN is
    /// `host/<host>` unless the config overrides it. Activation is sealed where
    /// kerbsec can seal DCE/RPC PDUs (Linux) and signed elsewhere (macOS); WMI
    /// calls are signed either way.
    #[cfg(feature = "kerberos")]
    Kerberos(KerberosConfig),
}

#[cfg(feature = "kerberos")]
fn kerberos_client(host: &str, config: &KerberosConfig) -> Result<KerberosClient, Error> {
    // The ticket comes from the cache, so the client needs no password.
    Ok(KerberosClient::new(
        host,
        config.clone(),
        Credentials::new("", ""),
    )?)
}

impl Auth {
    /// A fresh security context for `host`, which only Kerberos needs (for
    /// the service principal name).
    #[cfg_attr(not(feature = "kerberos"), allow(unused_variables))]
    fn provider(&self, host: &str) -> Result<Box<dyn AuthProvider>, Error> {
        Ok(match self {
            Auth::Ntlm(creds) => Box::new(NtlmClient::new(creds)?),
            #[cfg(feature = "kerberos")]
            Auth::Kerberos(config) => Box::new(kerberos_client(host, config)?),
        })
    }
}

/// The RPC connection to the server's WMI object exporter.
struct WmiConnection {
    rpc: RpcConnection,
    auth: Auth,
    host: String,
}

impl WmiConnection {
    fn open(host: &str, port: u16, auth: &Auth, timeout: Duration) -> Result<Self, Error> {
        let rpc = RpcConnection::connect(host, port, CONNECT_TIMEOUT, timeout)?;
        Ok(Self {
            rpc,
            auth: auth.clone(),
            host: host.to_string(),
        })
    }

    fn set_timeout(&mut self, timeout: Duration) -> Result<(), Error> {
        Ok(self.rpc.set_timeout(timeout)?)
    }

    /// Add a presentation context for `iid` (bind for the first, alter_context
    /// afterwards) and authenticate a fresh security context for it.
    fn bind_interface(
        &mut self,
        name: &'static str,
        iid: &[u8; 16],
        ipid: [u8; 16],
    ) -> Result<BoundInterface, Error> {
        let auth = self.auth.provider(&self.host)?;
        let ctx = self.rpc.bind_context(
            name,
            iid,
            AUTH_LEVEL_PKT_INTEGRITY,
            HandshakeStyle::Auth3,
            auth,
        )?;
        Ok(BoundInterface { ctx, ipid })
    }

    /// Issue one ORPC call and return the reassembled, verified response stub.
    fn call(
        &mut self,
        iface: &mut BoundInterface,
        opnum: u16,
        stub: &[u8],
    ) -> Result<Vec<u8>, Error> {
        Ok(self
            .rpc
            .call(&mut iface.ctx, opnum, Some(&iface.ipid), stub)?)
    }
}

/// `namespace` as the NTLMLogin network path, e.g. `root\cimv2` -> `//./root/cimv2`.
fn namespace_path(namespace: &str) -> String {
    let ns = namespace.replace('\\', "/");
    if ns.starts_with("//") {
        ns
    } else {
        format!("//./{}", ns.trim_start_matches('/'))
    }
}

impl Error {
    /// The HRESULT behind this error, when the server reported one (a failed
    /// WMI/DCOM call or an RPC-level access-denied fault).
    pub fn hresult(&self) -> Option<u32> {
        match self {
            Error::Wmi(WmiProtoError::Hresult(hr)) => Some(*hr),
            Error::Activation(DcomError::AccessDenied) => Some(E_ACCESSDENIED),
            Error::Activation(DcomError::ServerUnavailable) => Some(0x8007_06BA),
            Error::Activation(DcomError::RemoteProcedureCallFailed) => Some(0x8007_06BE),
            Error::Activation(DcomError::Hresult { hr }) => Some(*hr),
            Error::Rpc(RpcError::Fault { status, .. }) => Some(fault_to_hresult(*status)),
            Error::Decode(WmioError::MethodNotFound(_)) => Some(WBEM_E_INVALID_METHOD),
            _ => None,
        }
    }

    /// Whether the connection can no longer be used after this error (I/O
    /// failure, timeout, a protocol desync, or the server no longer knowing
    /// our objects) as opposed to a call that failed cleanly on a healthy
    /// connection.
    pub fn is_connection_lost(&self) -> bool {
        match self {
            Error::Rpc(RpcError::Fault { status, .. }) => *status == RPC_E_DISCONNECTED,
            Error::Wmi(_) | Error::Decode(_) | Error::Deserialize(_) => false,
            _ => true,
        }
    }
}

const E_ACCESSDENIED: u32 = 0x8007_0005;
/// The fault for a call on an IPID the server does not know: it has released
/// the objects behind this connection, so none of its interfaces work any more.
const RPC_E_DISCONNECTED: u32 = 0x8001_0108;
/// What Windows returns for ExecMethod on a method the class does not have.
const WBEM_E_INVALID_METHOD: u32 = 0x8004_102E;

/// Default bound on every network read and write.
pub const DEFAULT_TIMEOUT: Duration = RPC_IO_TIMEOUT;
/// How long releasing references may take when a client is dropped.
const RELEASE_TIMEOUT: Duration = Duration::from_secs(5);

/// A WMI namespace logged in on one host, ready to run queries.
///
/// Holds one connection to the server's object exporter with IWbemServices
/// bound. Queries reuse it. Every interface reference the server hands out is
/// released with IRemUnknown::RemRelease as soon as it is no longer needed,
/// and IWbemServices itself when the client is dropped.
pub struct WmiClient {
    conn: WmiConnection,
    services: BoundInterface,
    services_ref: InterfaceRef,
    rem_unknown: BoundInterface,
    /// The IEnumWbemClassObject presentation/security context, bound on the
    /// first query and reused (with each query's own IPID) afterwards.
    enumerator: Option<BoundInterface>,
    causality_id: [u8; 16],
    /// Set once an I/O or protocol error left the stream in an unknown state.
    broken: bool,
}

impl WmiClient {
    /// Activate WMI on `host`, log in to `namespace` (e.g. `root\\cimv2`),
    /// and bind IWbemServices, with the default network timeout.
    pub fn connect(host: &str, creds: &Credentials, namespace: &str) -> Result<Self, Error> {
        Self::connect_with_timeout(host, creds, namespace, DEFAULT_TIMEOUT)
    }

    /// Like [`connect`](Self::connect); `timeout` bounds each network read and
    /// write on the WMI connection, and each RPC call to four times that.
    pub fn connect_with_timeout(
        host: &str,
        creds: &Credentials,
        namespace: &str,
        timeout: Duration,
    ) -> Result<Self, Error> {
        Self::connect_with(host, &Auth::Ntlm(creds.clone()), namespace, timeout)
    }

    /// Like [`connect_with_timeout`](Self::connect_with_timeout), authenticating
    /// with `auth` (NTLM or Kerberos).
    pub fn connect_with(
        host: &str,
        auth: &Auth,
        namespace: &str,
        timeout: Duration,
    ) -> Result<Self, Error> {
        let (clsid, iid) = (&CLSID_WBEM_LEVEL1_LOGIN, &IID_IWBEM_LEVEL1_LOGIN);
        let (port, activation) = match auth {
            Auth::Ntlm(creds) => dcom::activate(host, creds, clsid, iid)?,
            #[cfg(feature = "kerberos")]
            Auth::Kerberos(config) => {
                // Sealing needs kerbsec's DCE IOV. Without it, activate at packet
                // integrity: the minimum Windows' DCOM hardening accepts, and it
                // needs only MIC tokens, which every GSS-API has.
                let level = if KerberosClient::supports_privacy() {
                    AUTH_LEVEL_PKT_PRIVACY
                } else {
                    AUTH_LEVEL_PKT_INTEGRITY
                };
                dcom::activate_with_level(host, clsid, iid, kerberos_client(host, config)?, level)?
            }
        };
        // The advertised bindings name the server's own view of itself (which
        // may be unreachable behind NAT); keep dialing the address we were given.
        let mut conn = WmiConnection::open(host, port, auth, timeout)?;
        let causality_id = *uuid::Uuid::new_v4().as_bytes();
        let login_ref = InterfaceRef {
            ipid: activation.ipid,
            public_refs: activation.public_refs,
        };

        let mut login =
            conn.bind_interface("IWbemLevel1Login", &IID_IWBEM_LEVEL1_LOGIN, login_ref.ipid)?;
        let resp = conn.call(
            &mut login,
            OPNUM_NTLM_LOGIN,
            &wmi_proto::encode_ntlm_login(&causality_id, &namespace_path(namespace)),
        );
        let mut rem_unknown =
            conn.bind_interface("IRemUnknown", &IID_IREMUNKNOWN, activation.ipid_rem_unknown)?;
        // IWbemLevel1Login is only needed for the login itself.
        let released = release(&mut conn, &mut rem_unknown, &causality_id, &[login_ref]);
        let services_ref = wmi_proto::parse_interface_response(&resp?, &IID_IWBEM_SERVICES)?;
        released?;

        let services =
            conn.bind_interface("IWbemServices", &IID_IWBEM_SERVICES, services_ref.ipid)?;
        Ok(Self {
            conn,
            services,
            services_ref,
            rem_unknown,
            enumerator: None,
            causality_id,
            broken: false,
        })
    }

    /// Change the bound on each network read/write (and on each RPC call, four
    /// times this) for later calls.
    pub fn set_timeout(&mut self, timeout: Duration) -> Result<(), Error> {
        self.conn.set_timeout(timeout)
    }

    /// Whether an earlier error left the connection unusable; reconnect then.
    pub fn is_broken(&self) -> bool {
        self.broken
    }

    /// Run `wql` and return one JSON object per result row.
    pub fn query(&mut self, wql: &str) -> Result<Vec<serde_json::Value>, Error> {
        if self.broken {
            return Err(Error::Protocol(
                "connection was lost by an earlier error; reconnect".into(),
            ));
        }
        let result = self.run_query(wql);
        if let Err(err) = &result {
            self.broken |= err.is_connection_lost();
        }
        result
    }

    /// Run `wql` and deserialize each row into `T` (property names match
    /// field names; use `#[serde(rename = ...)]` or `rename_all` as needed).
    pub fn query_as<T: DeserializeOwned>(&mut self, wql: &str) -> Result<Vec<T>, Error> {
        self.query(wql)?
            .into_iter()
            .map(|row| serde_json::from_value(row).map_err(Error::from))
            .collect()
    }

    /// Execute a CIM method (`method`) on `object_path` (a class name for a
    /// static method such as `"Win32_Process"`, or an instance path such as
    /// `r#"Win32_Process.Handle="1234""#`) with input parameters `in_params`
    /// (a JSON object or `null`) and return the output parameters object.
    pub fn exec_method(
        &mut self,
        object_path: &str,
        method: &str,
        in_params: &serde_json::Value,
    ) -> Result<serde_json::Value, Error> {
        if self.broken {
            return Err(Error::Protocol(
                "connection was lost by an earlier error; reconnect".into(),
            ));
        }
        let result = self.run_exec_method(object_path, method, in_params);
        if let Err(err) = &result {
            self.broken |= err.is_connection_lost();
        }
        result
    }

    /// Execute `method` on `object_path` and deserialize the output parameters
    /// into `T`.
    pub fn exec_method_as<T: DeserializeOwned>(
        &mut self,
        object_path: &str,
        method: &str,
        in_params: &serde_json::Value,
    ) -> Result<T, Error> {
        let out = self.exec_method(object_path, method, in_params)?;
        serde_json::from_value(out).map_err(Error::from)
    }

    fn run_exec_method(
        &mut self,
        object_path: &str,
        method: &str,
        in_params: &serde_json::Value,
    ) -> Result<serde_json::Value, Error> {
        let in_wmio = match in_params {
            serde_json::Value::Null => None,
            serde_json::Value::Object(map) if map.is_empty() => None,
            serde_json::Value::Object(map) => {
                let class_name = class_name_from_path(object_path);
                let class_resp = self.conn.call(
                    &mut self.services,
                    OPNUM_GET_OBJECT,
                    &wmi_proto::encode_get_object(&self.causality_id, class_name, 0),
                )?;
                let class_blob = wmi_proto::parse_single_object_response(&class_resp)?
                    .ok_or(WmiProtoError::Malformed)?;
                encode_method_in_params(&class_blob.data, method, map)?
            }
            _ => {
                return Err(Error::Protocol(
                    "ExecMethod input parameters must be a JSON object or null".into(),
                ))
            }
        };

        let resp = self.conn.call(
            &mut self.services,
            OPNUM_EXEC_METHOD,
            &wmi_proto::encode_exec_method(
                &self.causality_id,
                object_path,
                method,
                0,
                in_wmio.as_deref(),
            ),
        )?;
        match wmi_proto::parse_single_object_response(&resp)? {
            Some(out_blob) => Ok(decode_object(&out_blob.data)?),
            None => Ok(serde_json::json!({})),
        }
    }

    fn run_query(&mut self, wql: &str) -> Result<Vec<serde_json::Value>, Error> {
        let resp = self.conn.call(
            &mut self.services,
            OPNUM_EXEC_QUERY,
            &wmi_proto::encode_exec_query(&self.causality_id, wql, 0),
        )?;
        let enum_ref = wmi_proto::parse_interface_response(&resp, &IID_IENUM_WBEM_CLASS_OBJECT)?;
        let rows = self.enumerate(enum_ref.ipid);
        // Release the enumerator unless the connection itself failed.
        if !matches!(&rows, Err(err) if err.is_connection_lost()) {
            release(
                &mut self.conn,
                &mut self.rem_unknown,
                &self.causality_id,
                &[enum_ref],
            )?;
        }
        rows
    }

    fn enumerate(&mut self, ipid: [u8; 16]) -> Result<Vec<serde_json::Value>, Error> {
        let enumerator = match &mut self.enumerator {
            Some(bound) => bound,
            slot => slot.insert(self.conn.bind_interface(
                "IEnumWbemClassObject",
                &IID_IENUM_WBEM_CLASS_OBJECT,
                ipid,
            )?),
        };
        enumerator.ipid = ipid;
        let mut rows = Vec::new();
        loop {
            let resp = self.conn.call(
                enumerator,
                OPNUM_ENUM_NEXT,
                &wmi_proto::encode_enum_next(&self.causality_id, WBEM_INFINITE, NEXT_BATCH),
            )?;
            let blobs = wmi_proto::parse_next_response(&resp)?;
            let done = blobs.len() < NEXT_BATCH as usize;
            for blob in blobs {
                rows.push(decode_object(&blob.data)?);
            }
            if done {
                return Ok(rows);
            }
        }
    }
}

impl Drop for WmiClient {
    fn drop(&mut self) {
        if self.broken {
            return; // the server reclaims references when pinging stops
        }
        let _ = self.conn.set_timeout(RELEASE_TIMEOUT);
        if let Err(err) = release(
            &mut self.conn,
            &mut self.rem_unknown,
            &self.causality_id,
            &[self.services_ref],
        ) {
            debug!(%err, "releasing IWbemServices failed");
        }
    }
}

/// Release interface references through the OXID's IRemUnknown.
fn release(
    conn: &mut WmiConnection,
    rem_unknown: &mut BoundInterface,
    causality_id: &[u8; 16],
    refs: &[InterfaceRef],
) -> Result<(), Error> {
    let resp = conn.call(
        rem_unknown,
        OPNUM_REM_RELEASE,
        &wmi_proto::encode_rem_release(causality_id, refs),
    )?;
    Ok(wmi_proto::parse_rem_release_response(&resp)?)
}

/// Extract the CIM class name from an object path (e.g. `"Win32_Process"`,
/// `r#"Win32_Process.Handle="1234""#`, or `r#"\\.\root\cimv2:Win32_Process=@"#`).
pub(crate) fn class_name_from_path(object_path: &str) -> &str {
    let after_colon = object_path
        .rsplit_once(':')
        .map_or(object_path, |(_, rest)| rest);
    after_colon
        .split(['.', '='])
        .next()
        .unwrap_or(after_colon)
        .trim()
}

/// Run `wql` in `namespace` on `host` and return one JSON object per result.
/// Connects, queries, and releases everything; use [`WmiClient`] to run
/// several queries over one login.
pub fn query(
    host: &str,
    creds: &Credentials,
    namespace: &str,
    wql: &str,
) -> Result<Vec<serde_json::Value>, Error> {
    WmiClient::connect(host, creds, namespace)?.query(wql)
}

/// Execute `method` on `object_path` in `namespace` on `host` and return the
/// output parameters JSON object. Connects, invokes the method, and releases
/// everything; use [`WmiClient`] to reuse one login across calls.
pub fn exec_method(
    host: &str,
    creds: &Credentials,
    namespace: &str,
    object_path: &str,
    method: &str,
    in_params: &serde_json::Value,
) -> Result<serde_json::Value, Error> {
    WmiClient::connect(host, creds, namespace)?.exec_method(object_path, method, in_params)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn namespace_path_normalizes() {
        assert_eq!(namespace_path(r"root\cimv2"), "//./root/cimv2");
        assert_eq!(namespace_path("root/cimv2"), "//./root/cimv2");
        assert_eq!(namespace_path("//./root/cimv2"), "//./root/cimv2");
        assert_eq!(namespace_path(r"\\.\root\cimv2"), "//./root/cimv2");
    }

    #[test]
    fn class_name_from_path_extracts_class() {
        assert_eq!(class_name_from_path("Win32_Process"), "Win32_Process");
        assert_eq!(
            class_name_from_path(r#"Win32_Process.Handle="1234""#),
            "Win32_Process"
        );
        assert_eq!(
            class_name_from_path(r#"\\WIN-TEST\root\cimv2:Win32_Process.Handle="724""#),
            "Win32_Process"
        );
        assert_eq!(class_name_from_path("MySingleton=@"), "MySingleton");
    }

    #[test]
    fn only_a_fault_for_released_objects_loses_the_connection() {
        let fault = |status| {
            Error::Rpc(RpcError::Fault {
                status,
                did_not_execute: true,
            })
        };
        assert!(fault(RPC_E_DISCONNECTED).is_connection_lost());
        assert!(!fault(5).is_connection_lost()); // access denied
        assert!(!fault(0x8007_06D1).is_connection_lost()); // opnum out of range
        assert!(!Error::Wmi(WmiProtoError::Hresult(0x8004_1010)).is_connection_lost());
        assert!(Error::Protocol("desync".into()).is_connection_lost());
    }
}
