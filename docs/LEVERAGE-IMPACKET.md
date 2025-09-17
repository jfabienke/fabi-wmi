Here’s exactly what I found (the key files and functions) so we can port the proven logic straight into our Rust transport:

  ———

  ### 🔍 Where the NTLM signing/sealing happens in Impacket

  1. impacket/ntlm.py
      - SIGNKEY(flags, session_key, usage=b"Client") – derives the signing key using HMAC-MD5 with the “magic” strings.
      - SEALKEY(flags, session_key, usage=b"Client") – derives the sealing key.
      - MAC(flags, sealing_handle, signing_key, seqnum, data) – produces the 16-byte signature block using the signing key, sequence number, and the (already RC4-encrypted) data. It also
  updates the RC4 handle for subsequent calls.
      - SEAL wraps everything for PacketPrivacy – it encrypts the plaintext password with the sealing key and returns (sealed_data, signature).
  2. impacket/dcerpc/v5/rpcrt.py
      - Inside DCERPC_v5:

        self.__clientSigningKey = ntlm.SIGNKEY(self.__flags, self.__sessionKey)
        self.__clientSealingKey = ntlm.SEALKEY(self.__flags, self.__sessionKey)
        cipher = ARC4.new(self.__clientSealingKey)
        self.__clientSealingHandle = cipher.encrypt
      - The method _transport_send calls:

        sealedMessage, signature = ntlm.SEAL(
            self.__flags,
            self.__clientSigningKey,
            self.__clientSealingKey,
            rpc_packet.get_packet()[:-16],  # the PDU header
            plain_data,                      # plaintext stub
            self.__sequence,
            self.__clientSealingHandle)

     This is exactly the versatility we need: under PacketPrivacy, only the stub data gets RC4‑encrypted, but the signature covers the entire PDU (minus the auth trailer).

  ———

  ### ✅ What this means for our Rust implementation

  We don’t need to guess anymore. We have a trusted blueprint for the NTLM message security pipeline:

  1. Derive signing/sealing keys via HMAC-MD5.
  2. Maintain RC4 handles that carry state across calls (Per direction!).
  3. Compute a 16-byte NTLMsignature for every request/response pair, embedding sequence number and CRC32.
  4. Use the same sequence counter for both encrypt and signature (incrementing after each send/receive).

  So the plan is to port the logic from ntlm.SIGNKEY, ntlm.SEALKEY, ntlm.SEAL, and ntlm.MAC into Rust. We can crib directly from those functions to ensure the same behavior. Once that’s
  coded and wired into RealRpcTransport::invoke, we can match the golden PDU exactly.
