use thiserror::Error;

#[derive(Error, Debug)]
pub enum DcomError {
    #[error("Endpoint mapper connection failed")]
    Connect,
    #[error("Invalid tower response")]
    Tower,
    #[error("Port resolution failed")]
    Port,
}

/// Resolve the dynamic RPC port for the WMI service.
///
/// The current implementation returns the well-known RPC endpoint (135) as a
/// placeholder until the full endpoint mapper handshake is implemented.
pub fn resolve_wmi_port(_host: &str) -> Result<u16, DcomError> {
    // TODO: Implement MS-EPMR TowerConnectEx to negotiate the IWbemLocator
    // endpoint. Returning 135 keeps the stub usable for local development.
    Ok(135)
}
