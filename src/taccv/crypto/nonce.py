from __future__ import annotations
from taccv.crypto.primitives import hkdf_sha256, sha256
from taccv.protocol.constants import ROLE

def derive_nonce_base(master: bytes, sid: bytes, profile: str, role: ROLE) -> bytes:
    return hkdf_sha256(
        master,
        salt=sha256(f"{profile}|nonce-salt|".encode() + sid + b"|" + role.encode()),
        info=f"{profile}|nonce-base|v2".encode(),
        n=12
    )

def build_nonce(nonce_base: bytes, seq2: int) -> bytes:
    seq2_bytes = seq2.to_bytes(8, 'big')
    result = bytearray(nonce_base)
    for i in range(4, 12):
        result[i] ^= seq2_bytes[i - 4]
    return bytes(result)
