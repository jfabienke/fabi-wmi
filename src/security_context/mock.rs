//! Mock SecurityContext implementation for testing
//!
//! Provides a controllable security context for unit tests without
//! requiring actual Kerberos infrastructure.

use super::{SecurityContext, SecurityError};
use std::collections::VecDeque;

pub struct MockSecurityContext {
    is_complete: bool,
    session_key: Vec<u8>,
    init_tokens: VecDeque<Vec<u8>>,
    expected_inputs: VecDeque<Option<Vec<u8>>>,
    wrap_prefix: Vec<u8>,
    should_fail_at_step: Option<usize>,
    current_step: usize,
}

impl Default for MockSecurityContext {
    fn default() -> Self {
        Self::new()
    }
}

impl MockSecurityContext {
    pub fn new() -> Self {
        Self {
            is_complete: false,
            session_key: vec![0xDE, 0xAD, 0xBE, 0xEF; 16], // 16-byte key
            init_tokens: VecDeque::new(),
            expected_inputs: VecDeque::new(),
            wrap_prefix: vec![0xM0, 0xCK],
            should_fail_at_step: None,
            current_step: 0,
        }
    }

    /// Configure the mock to perform a standard 3-leg DCE handshake
    pub fn configure_dce_handshake(mut self) -> Self {
        // First leg: return AP-REQ
        self.init_tokens.push_back(vec![0x60, 0x81, 0xAA, 0xBB]);
        self.expected_inputs.push_back(None);

        // Second leg: expect AP-REP, return final token
        self.init_tokens.push_back(vec![0x00, 0x01]); // Small final token
        self.expected_inputs.push_back(Some(vec![0x60, 0x82, 0xCC, 0xDD]));

        self
    }

    /// Configure custom behavior for testing
    pub fn with_init_response(mut self, step: usize, token: Vec<u8>) -> Self {
        while self.init_tokens.len() <= step {
            self.init_tokens.push_back(vec![]);
        }
        self.init_tokens[step] = token;
        self
    }

    pub fn expect_input(mut self, step: usize, input: Option<Vec<u8>>) -> Self {
        while self.expected_inputs.len() <= step {
            self.expected_inputs.push_back(None);
        }
        self.expected_inputs[step] = input;
        self
    }

    pub fn with_session_key(mut self, key: Vec<u8>) -> Self {
        self.session_key = key;
        self
    }

    pub fn fail_at_step(mut self, step: usize) -> Self {
        self.should_fail_at_step = Some(step);
        self
    }
}

impl SecurityContext for MockSecurityContext {
    fn init_step(&mut self, input: Option<&[u8]>) -> Result<Vec<u8>, SecurityError> {
        // Check if we should fail at this step
        if Some(self.current_step) == self.should_fail_at_step {
            self.current_step += 1;
            return Err(SecurityError::TokenGeneration(
                format!("Mock failure at step {}", self.current_step - 1)
            ));
        }

        // Verify expected input if configured
        if let Some(expected) = self.expected_inputs.pop_front() {
            match (expected, input) {
                (None, Some(_)) => {
                    return Err(SecurityError::TokenGeneration(
                        "Expected no input, got some".into()
                    ));
                }
                (Some(_), None) => {
                    return Err(SecurityError::TokenGeneration(
                        "Expected input, got none".into()
                    ));
                }
                (Some(exp), Some(inp)) if exp != inp => {
                    return Err(SecurityError::TokenGeneration(
                        format!("Input mismatch at step {}", self.current_step)
                    ));
                }
                _ => {} // Match OK
            }
        }

        // Return configured token or empty
        let token = self.init_tokens.pop_front().unwrap_or_default();

        // Mark complete on last configured step or second step by default
        if self.init_tokens.is_empty() || self.current_step >= 1 {
            self.is_complete = true;
        }

        self.current_step += 1;
        Ok(token)
    }

    fn wrap(&mut self, data: &[u8], _conf_req: bool) -> Result<Vec<u8>, SecurityError> {
        if !self.is_established() {
            return Err(SecurityError::NotEstablished);
        }

        let mut result = self.wrap_prefix.clone();
        result.extend_from_slice(data);
        Ok(result)
    }

    fn unwrap(&mut self, token: &[u8]) -> Result<Vec<u8>, SecurityError> {
        if !self.is_established() {
            return Err(SecurityError::NotEstablished);
        }

        // Strip mock prefix if present
        if token.starts_with(&self.wrap_prefix) {
            Ok(token[self.wrap_prefix.len()..].to_vec())
        } else {
            Ok(token.to_vec())
        }
    }

    fn session_key(&self) -> Option<Vec<u8>> {
        if self.is_complete {
            Some(self.session_key.clone())
        } else {
            None
        }
    }

    fn is_established(&self) -> bool {
        self.is_complete
    }

    fn trailer_size(&self) -> usize {
        16 // Reasonable mock size
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_handshake() {
        let mut ctx = MockSecurityContext::new();

        // Should complete after two steps by default
        let token1 = ctx.init_step(None).unwrap();
        assert!(token1.is_empty()); // Default returns empty

        let token2 = ctx.init_step(Some(&[0x01])).unwrap();
        assert!(token2.is_empty());
        assert!(ctx.is_established());
    }

    #[test]
    fn test_dce_handshake() {
        let mut ctx = MockSecurityContext::new().configure_dce_handshake();

        // First leg: AP-REQ
        let ap_req = ctx.init_step(None).unwrap();
        assert_eq!(ap_req, vec![0x60, 0x81, 0xAA, 0xBB]);
        assert!(!ctx.is_established());

        // Second leg: AP-REP
        let ap_rep = vec![0x60, 0x82, 0xCC, 0xDD];
        let final_token = ctx.init_step(Some(&ap_rep)).unwrap();
        assert_eq!(final_token, vec![0x00, 0x01]);
        assert!(ctx.is_established());
    }

    #[test]
    fn test_wrap_unwrap() {
        let mut ctx = MockSecurityContext::new();

        // Establish first
        let _ = ctx.init_step(None);
        let _ = ctx.init_step(Some(&[0x01]));

        let data = b"test data";
        let wrapped = ctx.wrap(data, true).unwrap();
        assert!(wrapped.starts_with(&[0xM0, 0xCK]));

        let unwrapped = ctx.unwrap(&wrapped).unwrap();
        assert_eq!(unwrapped, data);
    }

    #[test]
    fn test_controlled_failure() {
        let mut ctx = MockSecurityContext::new().fail_at_step(1);

        // First step should succeed
        let _ = ctx.init_step(None).unwrap();

        // Second step should fail
        let result = ctx.init_step(Some(&[0x01]));
        assert!(result.is_err());
    }

    #[test]
    fn test_session_key_after_establishment() {
        let mut ctx = MockSecurityContext::new()
            .with_session_key(vec![0x11, 0x22, 0x33, 0x44]);

        // No key before establishment
        assert!(ctx.session_key().is_none());

        // Establish context
        let _ = ctx.init_step(None);
        let _ = ctx.init_step(Some(&[0x01]));

        // Key available after establishment
        let key = ctx.session_key().unwrap();
        assert_eq!(key, vec![0x11, 0x22, 0x33, 0x44]);
    }
}