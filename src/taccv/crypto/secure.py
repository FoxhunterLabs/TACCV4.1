from __future__ import annotations
from taccv.protocol.constants import PROTO_NAME, PROTO_VERSIONS, ROLE
from taccv.crypto.primitives import sha256, hkdf_sha256

def secure_aad(sid: bytes, profile: str, recon_th: bytes, th: bytes, sender: ROLE, seq2: int) -> bytes:
    versions = PROTO_VERSIONS[profile]
    return b"|".join([
        versions["secure"],
        b"proto=" + PROTO_NAME.encode(),
        b"profile=" + profile.encode(),
        b"sid=" + sid,
        b"recon=" + recon_th,
        b"hs=" + th,
        b"sender=" + sender.encode(),
        b"seq2=" + seq2.to_bytes(8, "big"),
    ])

def require_aead():
    try:
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
        return ChaCha20Poly1305
    except ImportError as e:
        raise RuntimeError("Missing dependency 'cryptography'") from e

# kept here for parity if you extend later
def derive_session_keys(master: bytes, th: bytes, role: ROLE, profile: str):
    base = hkdf_sha256(
        master,
        salt=sha256(f"{profile}|kdf|".encode() + th),
        info=f"{profile}|session|v1".encode(),
        n=64
    )
    k1, k2 = base[:32], base[32:]
    return (k1, k2) if role == "alice" else (k2, k1)
