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
    let mut client = NtlmV2Client::new(creds)?;
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
        let creds = Credentials::new(
            "User".into(),
            "Password".into(),
            "Domain".into(),
            "WORK".into(),
        );
        let mut state = start_ntlm_bind(creds).unwrap();
        assert_eq!(&state.negotiate_message[..8], b"NTLMSSP\0");
        let challenge = crate::auth::sample_type2();
        let auth = complete_ntlm_bind(&mut state.client, &challenge).unwrap();
        assert_eq!(&auth.message[..8], b"NTLMSSP\0");
    }

    #[test]
    fn test_rpc_error_variants() {
        // Test RpcError Display trait implementation
        let bind_err = RpcError::Bind;
        assert!(bind_err.to_string().contains("Bind"));

        let auth_err = RpcError::Auth;
        assert!(auth_err.to_string().contains("Auth"));

        let pdu_err = RpcError::Pdu;
        assert!(pdu_err.to_string().contains("PDU"));

        // Test AuthFailure conversion
        let auth_failure = RpcError::AuthFailure(auth::AuthError::Creds);
        assert!(auth_failure.to_string().contains("Auth error"));
    }

    #[test]
    fn start_ntlm_bind_with_invalid_credentials() {
        // Test start_ntlm_bind with empty credentials
        let invalid_creds = Credentials::new(
            "".into(),
            "".into(),
            "".into(),
            "".into(),
        );

        let result = start_ntlm_bind(invalid_creds);
        assert!(result.is_err());
        // Don't use unwrap_err() to avoid Debug requirement
        if let Err(e) = result {
            assert!(matches!(e, RpcError::AuthFailure(_)));
        }
    }

    #[test]
    fn complete_ntlm_bind_with_invalid_challenge() {
        // Test complete_ntlm_bind with invalid challenge
        let creds = Credentials::new(
            "User".into(),
            "Password".into(),
            "Domain".into(),
            "WORK".into(),
        );
        let mut state = start_ntlm_bind(creds).unwrap();

        // Invalid challenge
        let invalid_challenge = b"invalid";
        let result = complete_ntlm_bind(&mut state.client, invalid_challenge);
        assert!(result.is_err());
        // Don't use unwrap_err() to avoid Debug requirement
        if let Err(e) = result {
            assert!(matches!(e, RpcError::AuthFailure(_)));
        }
    }
}
