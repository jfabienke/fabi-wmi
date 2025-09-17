#![allow(dead_code)]

use thiserror::Error;

use crate::auth::{self, AuthenticateMessage, Credentials, NtlmV2Client};

#[derive(Error, Debug)]
pub enum RpcError {
    #[error("Bind failed")]
    Bind,
    #[error("Auth required")]
    Auth,
    #[error("Invalid PDU")]
    Pdu,
    #[error("Auth error: {0}")]
    AuthFailure(#[from] auth::AuthError),
}

pub struct NtlmBindState {
    pub client: NtlmV2Client,
    pub negotiate_message: Vec<u8>,
}

pub fn start_ntlm_bind(creds: Credentials) -> Result<NtlmBindState, RpcError> {
    let client = NtlmV2Client::new(creds)?;
    let negotiate = client.negotiate_message();
    Ok(NtlmBindState {
        client,
        negotiate_message: negotiate.message,
    })
}

pub fn complete_ntlm_bind(
    client: &mut NtlmV2Client,
    challenge: &[u8],
) -> Result<AuthenticateMessage, RpcError> {
    client.respond_message(challenge).map_err(RpcError::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ntlm_bind_round_trip() {
        let creds = Credentials {
            username: "User".into(),
            password: "Password".into(),
            domain: "Domain".into(),
            workstation: "WORK".into(),
        };
        let mut state = start_ntlm_bind(creds).unwrap();
        assert_eq!(&state.negotiate_message[..8], b"NTLMSSP\0");
        let challenge = crate::auth::sample_type2();
        let auth = complete_ntlm_bind(&mut state.client, &challenge).unwrap();
        assert_eq!(&auth.message[..8], b"NTLMSSP\0");
    }
}
