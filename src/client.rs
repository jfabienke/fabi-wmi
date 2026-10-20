//! A logged-in WMI namespace on one host ([`WmiClient`]) and the crate error.
//!
//! Follows the sequence a working reference client uses against Windows
//! (MS-WMI 3.2.3, MS-DCOM 3.2.4): activate CLSID_WbemLevel1Login on port 135,
//! open one TCP connection to the port the activation advertised, and give each
//! interface its own presentation context *and* its own NTLM security context at
//! RPC_C_AUTHN_LEVEL_PKT_INTEGRITY (bind or alter_context, challenge, auth3).
//! Requests carry the target IPID as the object UUID; stubs are signed, not
//! sealed.

use std::io::Write;
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use serde::de::DeserializeOwned;
use thiserror::Error;
use tracing::debug;

use crate::auth::{AuthError, AuthProvider, Credentials};
use crate::dcom::{self, DcomError};
use crate::rpc::{
    build_auth3_pdu, build_bind_pdu, build_signed_request_pdu, fault_to_hresult, is_last_fragment,
    parse_bind_ack, read_pdu, verify_signed_response_pdu, RpcError, AUTH_LEVEL_PKT_INTEGRITY,
    MAX_FRAG, PTYPE_ALTER_CONTEXT, PTYPE_ALTER_CONTEXT_RESP, PTYPE_BIND, PTYPE_BIND_ACK,
    PTYPE_FAULT, PTYPE_RESPONSE, RPC_IO_TIMEOUT,
};
use crate::sspi_ntlm::SspiNtlmClient;
use crate::wmi_proto::{
    self, InterfaceRef, WmiProtoError, IID_IENUM_WBEM_CLASS_OBJECT, IID_IREMUNKNOWN,
    IID_IWBEM_LEVEL1_LOGIN, IID_IWBEM_SERVICES,
};
use crate::wmio::{self, WmioError};

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
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Error::Rpc(err.into())
    }
}

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

const OPNUM_NTLM_LOGIN: u16 = 6;
const OPNUM_EXEC_QUERY: u16 = 20;
const OPNUM_ENUM_NEXT: u16 = 4;
const OPNUM_REM_RELEASE: u16 = 5;
/// lTimeout for IEnumWbemClassObject::Next: wait until objects are ready.
const WBEM_INFINITE: i32 = -1;
/// Objects requested per Next call.
const NEXT_BATCH: u32 = 32;

/// An interface bound on the connection: its presentation context, its own
/// NTLM context, and the IPID calls are addressed to.
struct BoundInterface {
    name: &'static str,
    context_id: u16,
    auth_context_id: u32,
    auth: SspiNtlmClient,
    ipid: [u8; 16],
}

/// The TCP connection to the server's WMI object exporter.
struct WmiConnection {
    stream: TcpStream,
    creds: Credentials,
    target_name: String,
    call_id: u32,
    next_context_id: u16,
    max_xmit: u16,
}

impl WmiConnection {
    fn open(host: &str, port: u16, creds: &Credentials, timeout: Duration) -> Result<Self, Error> {
        let addr = (host, port)
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| Error::Protocol(format!("{host} resolved to no addresses")))?;
        let stream = TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT.min(timeout))?;
        let _ = stream.set_nodelay(true);
        let mut conn = Self {
            stream,
            creds: creds.clone(),
            target_name: format!("host/{host}"),
            call_id: 0,
            next_context_id: 0,
            max_xmit: MAX_FRAG,
        };
        conn.set_timeout(timeout)?;
        Ok(conn)
    }

    fn set_timeout(&mut self, timeout: Duration) -> Result<(), Error> {
        // A zero Duration means "no timeout" to the socket API; never allow it.
        let timeout = Some(timeout.max(Duration::from_millis(1)));
        self.stream.set_read_timeout(timeout)?;
        self.stream.set_write_timeout(timeout)?;
        Ok(())
    }

    fn next_call_id(&mut self) -> u32 {
        self.call_id += 1;
        self.call_id
    }

    /// Add a presentation context for `iid` (bind for the first, alter_context
    /// afterwards) and authenticate a fresh NTLM context for it.
    fn bind_interface(
        &mut self,
        name: &'static str,
        iid: &[u8; 16],
        ipid: [u8; 16],
    ) -> Result<BoundInterface, Error> {
        let mut auth = SspiNtlmClient::new(&self.creds, &self.target_name)?;
        let context_id = self.next_context_id;
        let auth_context_id = u32::from(context_id);
        let (ptype, ack_ptype) = if context_id == 0 {
            (PTYPE_BIND, PTYPE_BIND_ACK)
        } else {
            (PTYPE_ALTER_CONTEXT, PTYPE_ALTER_CONTEXT_RESP)
        };
        let call_id = self.next_call_id();

        let negotiate = auth.negotiate()?;
        self.stream.write_all(&build_bind_pdu(
            ptype,
            call_id,
            context_id,
            iid,
            AUTH_LEVEL_PKT_INTEGRITY,
            auth_context_id,
            &negotiate,
        ))?;
        let ack = parse_bind_ack(&read_pdu(&mut self.stream)?, ack_ptype)?;
        if context_id == 0 {
            self.max_xmit = ack.max_xmit.min(MAX_FRAG);
        }

        let authenticate = auth.respond(&ack.auth_token)?;
        self.stream.write_all(&build_auth3_pdu(
            call_id,
            AUTH_LEVEL_PKT_INTEGRITY,
            auth_context_id,
            &authenticate,
        ))?;
        self.next_context_id += 1;
        debug!(interface = name, context_id, "interface bound");
        Ok(BoundInterface {
            name,
            context_id,
            auth_context_id,
            auth,
            ipid,
        })
    }

    /// Issue one ORPC call and return the reassembled, verified response stub.
    fn call(
        &mut self,
        iface: &mut BoundInterface,
        opnum: u16,
        stub: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let call_id = self.next_call_id();
        let pdu = build_signed_request_pdu(
            &mut iface.auth,
            call_id,
            iface.context_id,
            opnum,
            &iface.ipid,
            stub,
            iface.auth_context_id,
        )?;
        if pdu.len() > usize::from(self.max_xmit) {
            return Err(Error::Protocol(format!(
                "{} request of {} bytes exceeds max_xmit_frag {}; request fragmentation is not implemented",
                iface.name,
                pdu.len(),
                self.max_xmit
            )));
        }
        self.stream.write_all(&pdu)?;

        let mut response = Vec::new();
        loop {
            let frag = read_pdu(&mut self.stream)?;
            let frag_call_id = u32::from_le_bytes(frag[12..16].try_into().unwrap());
            if frag_call_id != call_id {
                return Err(Error::Protocol(format!(
                    "response for call {frag_call_id}, expected {call_id}"
                )));
            }
            if frag[2] != PTYPE_RESPONSE && frag[2] != PTYPE_FAULT {
                return Err(Error::Protocol(format!(
                    "unexpected PDU type 0x{:02x} in response",
                    frag[2]
                )));
            }
            response.extend(verify_signed_response_pdu(&mut iface.auth, &frag)?);
            if is_last_fragment(&frag) {
                break;
            }
        }
        debug!(
            interface = iface.name,
            opnum,
            len = response.len(),
            "call complete"
        );
        tracing::trace!(stub = %hex::encode(&response), "response stub");
        Ok(response)
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
            Error::Wmi(WmiProtoError::Hresult(hr)) | Error::Decode(WmioError::Hresult(hr)) => {
                Some(*hr)
            }
            Error::Activation(DcomError::AccessDenied) => Some(E_ACCESSDENIED),
            Error::Activation(DcomError::ServerUnavailable) => Some(0x8007_06BA),
            Error::Activation(DcomError::RemoteProcedureCallFailed) => Some(0x8007_06BE),
            Error::Activation(DcomError::Hresult { hr }) => Some(*hr),
            Error::Rpc(RpcError::Fault(status)) => Some(fault_to_hresult(*status)),
            _ => None,
        }
    }

    /// Whether the connection can no longer be used after this error (I/O
    /// failure, timeout, or a protocol desync) as opposed to a call that
    /// failed cleanly on a healthy connection.
    pub fn is_connection_lost(&self) -> bool {
        !matches!(
            self,
            Error::Wmi(_)
                | Error::Decode(_)
                | Error::Deserialize(_)
                | Error::Rpc(RpcError::Fault(_))
        )
    }
}

const E_ACCESSDENIED: u32 = 0x8007_0005;

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
    /// write on the WMI connection.
    pub fn connect_with_timeout(
        host: &str,
        creds: &Credentials,
        namespace: &str,
        timeout: Duration,
    ) -> Result<Self, Error> {
        let (port, activation) = dcom::activate_level1_login(host, creds)?;
        // The advertised bindings name the server's own view of itself (which
        // may be unreachable behind NAT); keep dialing the address we were given.
        let mut conn = WmiConnection::open(host, port, creds, timeout)?;
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

    /// Change the bound on each network read/write for later calls.
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
            let batch = wmio::decode_next_response(&resp)?;
            let done = batch.len() < NEXT_BATCH as usize;
            rows.extend(batch);
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
}
