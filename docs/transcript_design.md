# Transcript Design

TACCV maintains **two directional transcripts**:
- One for messages sent by Alice
- One for messages sent by Bob

Each record includes:
- Protocol version
- Sender role
- Sequence number
- Message kind
- Hash of sanitized payload

Encrypted payloads are **explicitly excluded** to avoid circular dependency.

The final transcript hash is used to:
- Bind PAKE confirmation
- Bind handshake key derivation
- Bind secure channel AAD

Result:  
If *anything* differs between peers, keys will not match.
