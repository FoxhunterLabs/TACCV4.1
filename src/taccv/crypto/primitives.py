from __future__ import annotations
import base64
import hashlib
import hmac
from taccv.protocol.constants import MAX_B64_LENGTH

def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()

def hmac_sha256(k: bytes, b: bytes) -> bytes:
    return hmac.new(k, b, hashlib.sha256).digest()

def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, n: int) -> bytes:
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    out, t = b"", b""
    c = 1
    while len(out) < n:
        t = hmac.new(prk, t + info + bytes([c]), hashlib.sha256).digest()
        out += t
        c += 1
    return out[:n]

def safe_compare(a: bytes, b: bytes, expected_length: int | None = None) -> bool:
    if expected_length and (len(a) != expected_length or len(b) != expected_length):
        return False
    return hmac.compare_digest(a, b)

def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")

def b64d(s: str) -> bytes:
    if len(s) > MAX_B64_LENGTH:
        raise ValueError(f"Base64 too long: {len(s)} > {MAX_B64_LENGTH}")
    return base64.b64decode(s, validate=True)
