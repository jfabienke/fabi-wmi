use std::sync::{Arc, Mutex};

use serde_json::Value;
use thiserror::Error;

use crate::ndr::{NdrCodec, StubNdrCodec};
use crate::transport::{RpcTransport, StubTransport};

#[derive(Error, Debug)]
pub enum WmiError {
    #[error("ConnectServer failed")]
    Connect,
    #[error("Invalid WQL")]
    Query,
    #[error("Marshal failed")]
    Marshal,
    #[error("Invalid response")]
    Response,
    #[error("Unsupported method {0}.{1}")]
    Method(String, String),
}

#[derive(Clone)]
pub struct IWbemLocator {
    host: String,
    codec: Arc<dyn NdrCodec + Send + Sync>,
    transport: Arc<Mutex<Box<dyn RpcTransport + Send>>>,
}

pub struct IWbemServices {
    namespace: String,
    codec: Arc<dyn NdrCodec + Send + Sync>,
    transport: Arc<Mutex<Box<dyn RpcTransport + Send>>>,
}

impl IWbemLocator {
    #[doc(hidden)]
    pub fn new(host: &str) -> Self {
        Self {
            host: host.to_string(),
            codec: Arc::new(StubNdrCodec),
            transport: Arc::new(Mutex::new(Box::new(StubTransport))),
        }
    }

    pub fn with_components(
        host: &str,
        codec: Arc<dyn NdrCodec + Send + Sync>,
        transport: Arc<Mutex<Box<dyn RpcTransport + Send>>>,
    ) -> Self {
        Self {
            host: host.to_string(),
            codec,
            transport,
        }
    }

    pub fn connect_server(
        &self,
        namespace: &str,
        username: Option<&str>,
        password: Option<&str>,
        domain: Option<&str>,
    ) -> Result<IWbemServices, WmiError> {
        // Use real DCOM activation when credentials are provided
        if let (Some(user), Some(pass)) = (username, password) {
            let config = crate::transport::RealTransportConfig {
                host: self.host.clone(),
                username: Some(user.to_string()),
                password: Some(pass.to_string()),
                domain: domain.map(|s| s.to_string()),
                read_timeout: None,
                write_timeout: None,
            };

            // Validate configuration
            config.validate().map_err(|_| WmiError::Connect)?;

            let creds = crate::auth::Credentials::new(
                user.to_string(),
                pass.to_string(),
                domain.unwrap_or("").to_string(),
                self.host.clone(),
            );

            // Perform DCOM activation to get port and OXID
            let (port, oxid) = crate::dcom::activate_wmi_dcom(&self.host, &creds)
                .map_err(|_| WmiError::Connect)?;

            // Create real transport with OXID
            let transport =
                crate::transport::RealRpcTransport::connect_with_oxid(config, port, oxid)
                    .map_err(|_| WmiError::Connect)?;

            let normalized = if namespace.starts_with("root\\") {
                namespace.to_string()
            } else {
                format!("root\\{namespace}")
            };

            Ok(IWbemServices {
                namespace: normalized,
                codec: Arc::clone(&self.codec),
                transport: Arc::new(Mutex::new(
                    Box::new(transport) as Box<dyn RpcTransport + Send>
                )),
            })
        } else {
            // Fall back to stub transport if no credentials
            let normalized = if namespace.starts_with("root\\") {
                namespace.to_string()
            } else {
                format!("root\\{namespace}")
            };
            println!(
                "ConnectServer to host {} namespace {} (using stub transport)",
                self.host, normalized
            );
            Ok(IWbemServices {
                namespace: normalized,
                codec: Arc::clone(&self.codec),
                transport: Arc::clone(&self.transport),
            })
        }
    }
}

impl IWbemServices {
    pub fn exec_query(&self, wql: &str) -> Result<Vec<Value>, WmiError> {
        const EXEC_QUERY_OPNUM: u16 = 9;
        let request = self
            .codec
            .encode_exec_query("WQL", wql)
            .map_err(|_| WmiError::Marshal)?;

        let mut transport = self.transport.lock().map_err(|_| WmiError::Response)?;
        let response = transport
            .invoke(EXEC_QUERY_OPNUM, &request)
            .map_err(|_| WmiError::Response)?;

        self.codec
            .decode_exec_query(&self.namespace, wql, &response)
            .map_err(|_| WmiError::Query)
    }

    pub fn exec_method(
        &self,
        class: &str,
        method: &str,
        params: &Value,
    ) -> Result<Value, WmiError> {
        const EXEC_METHOD_OPNUM: u16 = 20;
        let class_name = class.to_string();
        let method_name = method.to_string();
        let request = self
            .codec
            .encode_exec_method(class, method, params)
            .map_err(|_| WmiError::Marshal)?;

        let mut transport = self.transport.lock().map_err(|_| WmiError::Response)?;
        let response = transport
            .invoke(EXEC_METHOD_OPNUM, &request)
            .map_err(|_| WmiError::Response)?;

        self.codec
            .decode_exec_method(class, method, &response)
            .map_err(|_| WmiError::Method(class_name, method_name))
    }

    pub fn namespace(&self) -> &str {
        &self.namespace
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn exec_query_supports_known_classes() {
        let locator = IWbemLocator::new("host");
        let services = locator.connect_server("CimV2", None, None, None).unwrap();
        let cpu = services
            .exec_query("SELECT * FROM Win32_Processor")
            .expect("CPU query");
        assert_eq!(cpu.len(), 1);

        let disk = services
            .exec_query("SELECT * FROM Win32_LogicalDisk")
            .expect("Disk query");
        assert_eq!(disk.len(), 1);
    }

    #[test]
    fn exec_query_rejects_malformed_wql() {
        let locator = IWbemLocator::new("host");
        let services = locator.connect_server("CimV2", None, None, None).unwrap();
        let err = services.exec_query("INVALID").unwrap_err();
        assert!(matches!(err, WmiError::Query));
    }

    #[test]
    fn exec_method_returns_error_for_unknown() {
        let locator = IWbemLocator::new("host");
        let services = locator.connect_server("CimV2", None, None, None).unwrap();
        let err = services
            .exec_method("Win32_Process", "Unknown", &json!({}))
            .unwrap_err();
        assert!(matches!(err, WmiError::Method(_, _)));
    }

    #[test]
    fn exec_query_unknown_class_errors() {
        let locator = IWbemLocator::new("host");
        let services = locator.connect_server("CimV2", None, None, None).unwrap();
        let err = services
            .exec_query("SELECT * FROM Win32_Imaginary")
            .unwrap_err();
        assert!(matches!(err, WmiError::Query));
    }

    #[test]
    fn namespace_accessor_returns_current_namespace() {
        let locator = IWbemLocator::new("host");
        let services = locator
            .connect_server("root\\Default", None, None, None)
            .unwrap();
        assert_eq!(services.namespace(), "root\\Default");
    }

    #[test]
    fn locator_accepts_root_prefixed_namespace() {
        let locator = IWbemLocator::new("host");
        let services = locator
            .connect_server("root\\Custom", None, None, None)
            .unwrap();
        assert_eq!(services.namespace(), "root\\Custom");
    }
}
