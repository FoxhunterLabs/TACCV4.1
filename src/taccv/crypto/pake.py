from __future__ import annotations
import secrets
import time
from typing import Optional
from taccv.crypto.primitives import sha256, hkdf_sha256, hmac_sha256, safe_compare, b64d
from taccv.protocol.constants import ROLE

def require_spake2():
    try:
        from spake2 import SPAKE2_A, SPAKE2_B
        return SPAKE2_A, SPAKE2_B
    except ImportError as e:
        raise RuntimeError("Missing dependency 'spake2'") from e

def validate_bytes_length(data: bytes, name: str, min_len: int, max_len: int | None = None):
    if len(data) < min_len:
        raise ValueError(f"{name} too short: {len(data)} < {min_len}")
    if max_len and len(data) > max_len:
        raise ValueError(f"{name} too long: {len(data)} > {max_len}")

def validate_base64(s: str, name: str, min_bytes: int, max_bytes: int | None = None) -> bytes:
    data = b64d(s)
    validate_bytes_length(data, name, min_bytes, max_bytes)
    return data

def normalize_password(pin: Optional[str], secret_b64: Optional[str]) -> bytes:
    if (pin is None) == (secret_b64 is None):
        raise ValueError("Provide exactly one of --pin or --secret-b64")
    if pin is not None:
        p = pin.strip()
        if not (6 <= len(p) <= 12) or not p.isdigit():
            raise ValueError("PIN must be 6–12 digits")
        return ("PIN:" + p).encode("utf-8")
    s = validate_base64(secret_b64.strip(), "secret-b64", 16)
    return b"SEC:" + s

def pake_init(role: ROLE, password: bytes, sid: bytes, profile: str):
    SPAKE2_A, SPAKE2_B = require_spake2()
    pw_hash = sha256(f"{profile}|pw|".encode() + sid + b"|" + password)
    sp = SPAKE2_A(pw_hash) if role == "alice" else SPAKE2_B(pw_hash)
    out = sp.start()
    return {"role": role, "sp": sp, "msg_out": out, "profile": profile}

def pake_finish_reduced_timing(pake_state: dict, msg_in: bytes, sid: bytes, profile: str) -> bytes:
    SPAKE2_A, SPAKE2_B = require_spake2()

    dummy_pw = bytearray(sha256(b"dummy|" + sid + b"|" + secrets.token_bytes(8)))
    dummy_sp_cls = SPAKE2_A if pake_state["role"] == "alice" else SPAKE2_B
    dummy_sp = dummy_sp_cls(bytes(dummy_pw))
    dummy_sp.start()
    try:
        dummy_sp.finish(msg_in)
    except Exception:
        pass
    for i in range(len(dummy_pw)):
        dummy_pw[i] = 0

    try:
        k = pake_state["sp"].finish(msg_in)
    except Exception:
        time.sleep(0.03)
        raise ValueError("PAKE failed")

    return hkdf_sha256(
        k,
        salt=sha256(f"{profile}|k0-salt|".encode() + sid),
        info=f"{profile}|K0|v1".encode(),
        n=32
    )

def pake_confirm_tag(k0: bytes, sid: bytes, role: ROLE, transcript_hash: bytes, profile: str) -> bytes:
    return hmac_sha256(
        k0,
        f"{profile}|pake-confirm|".encode() + sid + b"|" + role.encode() + b"|" + transcript_hash
    )

def sas6(k0: bytes, sid: bytes, profile: str) -> str:
    v = int.from_bytes(sha256(f"{profile}|sas|".encode() + k0 + sid)[:4], "big") % 1_000_000
    return f"{v:06d}"
