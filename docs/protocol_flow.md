# Protocol Flow (High Level)

1. **Session Creation**
   - Relay issues short human-friendly session code
   - Generates random session ID (sid)

2. **Profile Negotiation**
   - Peers exchange supported profiles
   - Highest mutually allowed profile selected
   - Downgrade attempts are rejected

3. **PAKE (SPAKE2)**
   - Password-derived shared secret
   - No password exposure to relay
   - Transcript hashing begins

4. **PAKE Confirmation**
   - Both sides prove possession of K0
   - Short Authentication String (SAS) derivable for UX

5. **Handshake (X25519)**
   - Ephemeral key exchange
   - Transcript-bound master secret
   - Explicit role binding

6. **Key Confirmation**
   - Mutual confirmation of derived keys
   - Prevents unknown key-share attacks

7. **Secure Channel**
   - ChaCha20-Poly1305
   - Directional keys
   - Sequence-number–derived nonces
   - Strong AAD binding (role, transcript, profile)

Each phase is **strictly ordered and state-gated**.
