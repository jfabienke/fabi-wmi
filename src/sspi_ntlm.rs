//! NTLM authentication and RPC message protection backed by sspi-rs.
//!
//! The handshake tokens go into bind / alter_context PDUs unchanged. For
//! packet-privacy PDUs the header and sec_trailer are passed as
//! SECBUFFER_READONLY_WITH_CHECKSUM data (signed, not encrypted) and the stub
//! as writable data, which is how Windows protects DCE/RPC with NTLM.

use sspi::{
    AuthIdentity, BufferType, ClientRequestFlags, CredentialUse, DataRepresentation,
    EncryptionFlags, Ntlm, SecurityBuffer, SecurityBufferFlags, SecurityBufferRef, SecurityStatus,
    Sspi, SspiImpl, Username,
};

use sspi::ntlm::NtlmConfig;

use crate::auth::{AuthError, AuthProvider, Credentials};

const SIGNATURE_LEN: usize = 16;

pub struct SspiNtlmClient {
    ntlm: Ntlm,
    credentials: <Ntlm as SspiImpl>::CredentialsHandle,
    target_name: String,
}

impl SspiNtlmClient {
    /// `target_name` is the SPN-style name reported in the AUTHENTICATE message
    /// (e.g. `host/server`); NTLM does not use it for key material.
    pub fn new(creds: &Credentials, target_name: &str) -> Result<Self, AuthError> {
        creds.validate()?;
        let domain = (!creds.domain.is_empty()).then_some(creds.domain.as_str());
        let identity = AuthIdentity {
            username: Username::new(&creds.username, domain).map_err(|_| AuthError::Creds)?,
            password: creds.password.as_str().to_owned().into(),
        };
        let mut ntlm = Ntlm::with_config(NtlmConfig::new(local_workstation_name()));
        let acquired = ntlm
            .acquire_credentials_handle()
            .with_credential_use(CredentialUse::Outbound)
            .with_auth_data(&identity)
            .execute(&mut ntlm)
            .map_err(sspi_error)?;
        Ok(Self {
            ntlm,
            credentials: acquired.credentials_handle,
            target_name: target_name.to_owned(),
        })
    }

    fn step(&mut self, input: Option<&[u8]>) -> Result<Vec<u8>, AuthError> {
        let mut input_buffers = vec![SecurityBuffer::new(
            input.map(<[u8]>::to_vec).unwrap_or_default(),
            BufferType::Token,
        )];
        let mut output = vec![SecurityBuffer::new(Vec::new(), BufferType::Token)];
        let mut builder = self
            .ntlm
            .initialize_security_context()
            .with_credentials_handle(&mut self.credentials)
            .with_context_requirements(
                ClientRequestFlags::CONFIDENTIALITY
                    | ClientRequestFlags::INTEGRITY
                    | ClientRequestFlags::ALLOCATE_MEMORY,
            )
            .with_target_data_representation(DataRepresentation::Native)
            .with_target_name(&self.target_name)
            .with_output(&mut output);
        if input.is_some() {
            builder = builder.with_input(&mut input_buffers);
        }
        let result = self
            .ntlm
            .initialize_security_context_impl(&mut builder)
            .map_err(sspi_error)?
            .resolve_to_result()
            .map_err(sspi_error)?;
        if matches!(
            result.status,
            SecurityStatus::CompleteAndContinue | SecurityStatus::CompleteNeeded
        ) {
            self.ntlm
                .complete_auth_token(&mut output)
                .map_err(sspi_error)?;
        }
        Ok(std::mem::take(&mut output[0].buffer))
    }
}

impl AuthProvider for SspiNtlmClient {
    fn negotiate(&mut self) -> Result<Vec<u8>, AuthError> {
        self.step(None)
    }

    fn respond(&mut self, challenge: &[u8]) -> Result<Vec<u8>, AuthError> {
        self.step(Some(challenge))
    }

    fn seal_rpc(
        &mut self,
        header: &[u8],
        stub: &mut [u8],
        sec_trailer: &[u8],
    ) -> Result<Vec<u8>, AuthError> {
        let mut header = header.to_vec();
        let mut sec_trailer = sec_trailer.to_vec();
        let mut signature = [0u8; SIGNATURE_LEN];
        let mut message = [
            SecurityBufferRef::data_buf(&mut header)
                .with_flags(SecurityBufferFlags::SECBUFFER_READONLY_WITH_CHECKSUM),
            SecurityBufferRef::data_buf(stub),
            SecurityBufferRef::data_buf(&mut sec_trailer)
                .with_flags(SecurityBufferFlags::SECBUFFER_READONLY_WITH_CHECKSUM),
            SecurityBufferRef::token_buf(&mut signature),
        ];
        self.ntlm
            .encrypt_message(EncryptionFlags::empty(), &mut message)
            .map_err(sspi_error)?;
        Ok(signature.to_vec())
    }

    fn sign_rpc(
        &mut self,
        header: &[u8],
        stub: &[u8],
        sec_trailer: &[u8],
    ) -> Result<Vec<u8>, AuthError> {
        // Integrity level: every data buffer is READONLY, so sspi signs the
        // whole message without encrypting the stub.
        let mut header = header.to_vec();
        let mut stub = stub.to_vec();
        let mut sec_trailer = sec_trailer.to_vec();
        let mut signature = [0u8; SIGNATURE_LEN];
        let mut message = [
            SecurityBufferRef::data_buf(&mut header)
                .with_flags(SecurityBufferFlags::SECBUFFER_READONLY_WITH_CHECKSUM),
            SecurityBufferRef::data_buf(&mut stub)
                .with_flags(SecurityBufferFlags::SECBUFFER_READONLY_WITH_CHECKSUM),
            SecurityBufferRef::data_buf(&mut sec_trailer)
                .with_flags(SecurityBufferFlags::SECBUFFER_READONLY_WITH_CHECKSUM),
            SecurityBufferRef::token_buf(&mut signature),
        ];
        self.ntlm
            .encrypt_message(EncryptionFlags::empty(), &mut message)
            .map_err(sspi_error)?;
        Ok(signature.to_vec())
    }

    fn verify_rpc(
        &mut self,
        header: &[u8],
        stub: &[u8],
        sec_trailer: &[u8],
        auth_value: &[u8],
    ) -> Result<(), AuthError> {
        let mut header = header.to_vec();
        let mut stub = stub.to_vec();
        let mut sec_trailer = sec_trailer.to_vec();
        let mut signature = auth_value.to_vec();
        let mut message = [
            SecurityBufferRef::data_buf(&mut header)
                .with_flags(SecurityBufferFlags::SECBUFFER_READONLY_WITH_CHECKSUM),
            SecurityBufferRef::data_buf(&mut stub)
                .with_flags(SecurityBufferFlags::SECBUFFER_READONLY_WITH_CHECKSUM),
            SecurityBufferRef::data_buf(&mut sec_trailer)
                .with_flags(SecurityBufferFlags::SECBUFFER_READONLY_WITH_CHECKSUM),
            SecurityBufferRef::token_buf(&mut signature),
        ];
        self.ntlm
            .decrypt_message(&mut message)
            .map_err(sspi_error)?;
        Ok(())
    }

    fn unseal_rpc(
        &mut self,
        header: &[u8],
        stub: &mut [u8],
        sec_trailer: &[u8],
        auth_value: &[u8],
    ) -> Result<(), AuthError> {
        let mut header = header.to_vec();
        let mut sec_trailer = sec_trailer.to_vec();
        let mut signature = auth_value.to_vec();
        let mut message = [
            SecurityBufferRef::data_buf(&mut header)
                .with_flags(SecurityBufferFlags::SECBUFFER_READONLY_WITH_CHECKSUM),
            SecurityBufferRef::data_buf(stub),
            SecurityBufferRef::data_buf(&mut sec_trailer)
                .with_flags(SecurityBufferFlags::SECBUFFER_READONLY_WITH_CHECKSUM),
            SecurityBufferRef::token_buf(&mut signature),
        ];
        self.ntlm
            .decrypt_message(&mut message)
            .map_err(sspi_error)?;
        Ok(())
    }
}

fn sspi_error(err: sspi::Error) -> AuthError {
    AuthError::Protection(err.to_string())
}

/// NetBIOS-style name of this machine for the AUTHENTICATE Workstation field.
fn local_workstation_name() -> String {
    let mut buf = [0u8; 256];
    // SAFETY: buf is valid for buf.len() bytes; gethostname NUL-terminates on success.
    let rc = unsafe { libc::gethostname(buf.as_mut_ptr().cast(), buf.len()) };
    let host = if rc == 0 {
        let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
        String::from_utf8_lossy(&buf[..end]).into_owned()
    } else {
        String::new()
    };
    // Short name only: NetBIOS names stop at the first dot.
    match host.split('.').next().map(str::to_uppercase) {
        Some(name) if !name.is_empty() => name,
        _ => "LINUX-WMI".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpc::{
        build_sealed_request_pdu, build_signed_request_pdu, unseal_response_pdu,
        verify_signed_response_pdu,
    };
    use sspi::ServerRequestFlags;

    struct Server {
        ntlm: Ntlm,
        credentials: <Ntlm as SspiImpl>::CredentialsHandle,
    }

    impl Server {
        fn new(creds: &Credentials) -> Self {
            let identity = AuthIdentity {
                username: Username::new(&creds.username, Some(&creds.domain)).unwrap(),
                password: creds.password.as_str().to_owned().into(),
            };
            let mut ntlm = Ntlm::new();
            let acquired = ntlm
                .acquire_credentials_handle()
                .with_credential_use(CredentialUse::Inbound)
                .with_auth_data(&identity)
                .execute(&mut ntlm)
                .unwrap();
            Self {
                ntlm,
                credentials: acquired.credentials_handle,
            }
        }

        fn accept(&mut self, token: &[u8]) -> Vec<u8> {
            let mut input = vec![SecurityBuffer::new(token.to_vec(), BufferType::Token)];
            let mut output = vec![SecurityBuffer::new(Vec::new(), BufferType::Token)];
            let builder = self
                .ntlm
                .accept_security_context()
                .with_credentials_handle(&mut self.credentials)
                .with_context_requirements(ServerRequestFlags::ALLOCATE_MEMORY)
                .with_target_data_representation(DataRepresentation::Native)
                .with_input(&mut input)
                .with_output(&mut output);
            let result = self
                .ntlm
                .accept_security_context_impl(builder)
                .unwrap()
                .resolve_to_result()
                .unwrap();
            if matches!(
                result.status,
                SecurityStatus::CompleteAndContinue | SecurityStatus::CompleteNeeded
            ) {
                self.ntlm.complete_auth_token(&mut output).unwrap();
            }
            std::mem::take(&mut output[0].buffer)
        }

        /// Decrypt a client request in place using the RPC buffer layout.
        fn open_request(&mut self, pdu: &mut [u8]) {
            let auth_len = u16::from_le_bytes([pdu[10], pdu[11]]) as usize;
            let trailer_at = pdu.len() - auth_len - 8;
            let (head, rest) = pdu.split_at_mut(24);
            let (body, tail) = rest.split_at_mut(trailer_at - 24);
            let (trailer, auth_value) = tail.split_at_mut(8);
            let mut message = [
                SecurityBufferRef::data_buf(head)
                    .with_flags(SecurityBufferFlags::SECBUFFER_READONLY_WITH_CHECKSUM),
                SecurityBufferRef::data_buf(body),
                SecurityBufferRef::data_buf(trailer)
                    .with_flags(SecurityBufferFlags::SECBUFFER_READONLY_WITH_CHECKSUM),
                SecurityBufferRef::token_buf(auth_value),
            ];
            self.ntlm.decrypt_message(&mut message).unwrap();
        }

        /// Verify a signed (integrity) request: 40-byte object header, cleartext
        /// stub, all data buffers READONLY.
        fn verify_signed_request(&mut self, pdu: &mut [u8]) -> Result<(), sspi::Error> {
            let auth_len = u16::from_le_bytes([pdu[10], pdu[11]]) as usize;
            let trailer_at = pdu.len() - auth_len - 8;
            let (head, rest) = pdu.split_at_mut(40);
            let (body, tail) = rest.split_at_mut(trailer_at - 40);
            let (trailer, auth_value) = tail.split_at_mut(8);
            let mut message = [
                SecurityBufferRef::data_buf(head)
                    .with_flags(SecurityBufferFlags::SECBUFFER_READONLY_WITH_CHECKSUM),
                SecurityBufferRef::data_buf(body)
                    .with_flags(SecurityBufferFlags::SECBUFFER_READONLY_WITH_CHECKSUM),
                SecurityBufferRef::data_buf(trailer)
                    .with_flags(SecurityBufferFlags::SECBUFFER_READONLY_WITH_CHECKSUM),
                SecurityBufferRef::token_buf(auth_value),
            ];
            self.ntlm.decrypt_message(&mut message).map(|_| ())
        }

        /// Build a sealed response PDU carrying `stub`.
        fn sealed_response(&mut self, call_id: u32, stub: &[u8]) -> Vec<u8> {
            let pad = (16 - stub.len() % 16) % 16;
            let frag_len = 24 + stub.len() + pad + 8 + 16;
            let mut head = vec![5, 0, 0x02, 0x03, 0x10, 0, 0, 0];
            head.extend_from_slice(&(frag_len as u16).to_le_bytes());
            head.extend_from_slice(&16u16.to_le_bytes());
            head.extend_from_slice(&call_id.to_le_bytes());
            head.extend_from_slice(&(stub.len() as u32).to_le_bytes());
            head.extend_from_slice(&[0, 0, 0, 0]); // p_cont_id, cancel_count, reserved
            let mut body = stub.to_vec();
            body.extend(std::iter::repeat_n(0u8, pad));
            let mut trailer = vec![0x0a, 0x06, pad as u8, 0, 0, 0, 0, 0];
            let mut signature = [0u8; 16];
            let mut message = [
                SecurityBufferRef::data_buf(&mut head)
                    .with_flags(SecurityBufferFlags::SECBUFFER_READONLY_WITH_CHECKSUM),
                SecurityBufferRef::data_buf(&mut body),
                SecurityBufferRef::data_buf(&mut trailer)
                    .with_flags(SecurityBufferFlags::SECBUFFER_READONLY_WITH_CHECKSUM),
                SecurityBufferRef::token_buf(&mut signature),
            ];
            self.ntlm
                .encrypt_message(EncryptionFlags::empty(), &mut message)
                .unwrap();
            [head, body, trailer, signature.to_vec()].concat()
        }

        /// Build a signed (integrity) response PDU carrying a cleartext `stub`.
        fn signed_response(&mut self, call_id: u32, stub: &[u8]) -> Vec<u8> {
            let pad = (4 - stub.len() % 4) % 4;
            let frag_len = 24 + stub.len() + pad + 8 + 16;
            let mut head = vec![5, 0, 0x02, 0x03, 0x10, 0, 0, 0];
            head.extend_from_slice(&(frag_len as u16).to_le_bytes());
            head.extend_from_slice(&16u16.to_le_bytes());
            head.extend_from_slice(&call_id.to_le_bytes());
            head.extend_from_slice(&(stub.len() as u32).to_le_bytes());
            head.extend_from_slice(&[0, 0, 0, 0]);
            let mut body = stub.to_vec();
            body.extend(std::iter::repeat_n(0u8, pad));
            let mut trailer = vec![0x0a, 0x05, pad as u8, 0, 0, 0, 0, 0];
            let mut signature = [0u8; 16];
            let mut message = [
                SecurityBufferRef::data_buf(&mut head)
                    .with_flags(SecurityBufferFlags::SECBUFFER_READONLY_WITH_CHECKSUM),
                SecurityBufferRef::data_buf(&mut body)
                    .with_flags(SecurityBufferFlags::SECBUFFER_READONLY_WITH_CHECKSUM),
                SecurityBufferRef::data_buf(&mut trailer)
                    .with_flags(SecurityBufferFlags::SECBUFFER_READONLY_WITH_CHECKSUM),
                SecurityBufferRef::token_buf(&mut signature),
            ];
            self.ntlm
                .encrypt_message(EncryptionFlags::empty(), &mut message)
                .unwrap();
            [head, body, trailer, signature.to_vec()].concat()
        }
    }

    fn authenticated_pair() -> (SspiNtlmClient, Server) {
        let creds = Credentials::new("Administrator", "Lab-Passw0rd").with_domain("TEST");
        let mut client = SspiNtlmClient::new(&creds, "host/dc01").unwrap();
        let mut server = Server::new(&creds);
        let negotiate = client.negotiate().unwrap();
        let challenge = server.accept(&negotiate);
        let authenticate = client.respond(&challenge).unwrap();
        server.accept(&authenticate);
        (client, server)
    }

    #[test]
    fn sealed_rpc_request_and_response_round_trip() {
        let (mut client, mut server) = authenticated_pair();

        // Two requests in a row: per-direction RC4 state and sequence numbers advance.
        for (call_id, stub) in [
            (3u32, b"first activation stub".to_vec()),
            (4, vec![0xAB; 48]),
        ] {
            let mut pdu = build_sealed_request_pdu(&mut client, call_id, 0, 4, &stub, 0).unwrap();
            assert_eq!(u16::from_le_bytes([pdu[8], pdu[9]]) as usize, pdu.len());
            assert_eq!(
                &pdu[pdu.len() - 24..pdu.len() - 20],
                &[0x0a, 0x06, pdu[pdu.len() - 22], 0]
            );
            assert_ne!(
                &pdu[24..24 + stub.len()],
                &stub[..],
                "stub must be encrypted"
            );
            server.open_request(&mut pdu);
            assert_eq!(&pdu[24..24 + stub.len()], &stub[..]);

            let reply = server.sealed_response(call_id, b"response stub data");
            let plain = unseal_response_pdu(&mut client, &reply).unwrap();
            assert_eq!(&plain[24..24 + 18], b"response stub data");
        }
    }

    #[test]
    fn signed_request_pdu_verifies_and_keeps_stub_cleartext() {
        let (mut client, mut server) = authenticated_pair();
        let ipid = [0x11u8; 16];
        let stub = b"ORPCTHIS and NTLMLogin stub bytes".to_vec();

        let mut pdu = build_signed_request_pdu(&mut client, 2, 0, 6, &ipid, &stub, 0).unwrap();
        // Integrity: the stub travels in cleartext right after the 40-byte header.
        assert_eq!(pdu[3] & 0x80, 0x80, "PFC_OBJECT_UUID set");
        assert_eq!(&pdu[24..40], &ipid, "object IPID present");
        assert_eq!(&pdu[40..40 + stub.len()], &stub[..], "stub is cleartext");
        let sec_trailer_at = pdu.len() - 16 - 8;
        assert_eq!(pdu[sec_trailer_at + 1], 0x05, "auth_level = PKT_INTEGRITY");

        server
            .verify_signed_request(&mut pdu)
            .expect("signature verifies");
    }

    #[test]
    fn signed_response_verifies_and_returns_cleartext_stub() {
        let (mut client, mut server) = authenticated_pair();
        // Client sends a request first so the server's recv seq is aligned.
        let mut req =
            build_signed_request_pdu(&mut client, 2, 0, 6, &[0x11; 16], b"login", 0).unwrap();
        server.verify_signed_request(&mut req).unwrap();

        let stub = b"ORPCTHAT + IWbemServices OBJREF + HRESULT".to_vec();
        let reply = server.signed_response(2, &stub);
        let out = verify_signed_response_pdu(&mut client, &reply).unwrap();
        assert_eq!(out, stub);
    }

    #[test]
    fn tampered_signed_response_is_rejected() {
        let (mut client, mut server) = authenticated_pair();
        let mut req =
            build_signed_request_pdu(&mut client, 2, 0, 6, &[0x11; 16], b"login", 0).unwrap();
        server.verify_signed_request(&mut req).unwrap();
        let mut reply = server.signed_response(2, b"response stub data");
        reply[24] ^= 0x01; // flip a cleartext stub byte
        assert!(verify_signed_response_pdu(&mut client, &reply).is_err());
    }

    #[test]
    fn tampered_signed_request_is_rejected() {
        let (mut client, mut server) = authenticated_pair();
        let mut pdu =
            build_signed_request_pdu(&mut client, 2, 0, 6, &[0x11; 16], b"stub data here!!", 0)
                .unwrap();
        pdu[40] ^= 0x01; // flip a cleartext stub byte
        assert!(server.verify_signed_request(&mut pdu).is_err());
    }

    #[test]
    fn tampered_response_is_rejected() {
        let (mut client, mut server) = authenticated_pair();
        let mut reply = server.sealed_response(3, b"response stub data");
        reply[4] ^= 0x01; // flip a signed (unencrypted) header bit
        assert!(unseal_response_pdu(&mut client, &reply).is_err());
    }
}
