from __future__ import annotations
import secrets
from taccv.crypto.primitives import sha256, hkdf_sha256, hmac_sha256
from taccv.crypto.nonce import derive_nonce_base
from taccv.protocol.constants import ROLE, PROTO_VERSIONS

def require_crypto():
    try:
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        return X25519PrivateKey, X25519PublicKey, Encoding, PublicFormat
    except ImportError as e:
        raise RuntimeError("Missing dependency 'cryptography'") from e

def hs_init(role: ROLE, sid: bytes, profile: str, k0: bytes):
    X25519PrivateKey, _, Encoding, PublicFormat = require_crypto()
    priv = X25519PrivateKey.generate()
    pub = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    nonce = secrets.token_bytes(16)
    return {"role": role, "sid": sid, "profile": profile, "priv": priv, "pub_raw": pub, "nonce": nonce, "k0": k0}

def hs_derive_master(hs_state: dict, peer_pub_raw: bytes, peer_nonce: bytes, recon_th: bytes):
    _, X25519PublicKey, _, _ = require_crypto()
    peer_pub = X25519PublicKey.from_public_bytes(peer_pub_raw)
    ss = hs_state["priv"].exchange(peer_pub)

    if hs_state["role"] == "alice":
        a_pub, a_nonce = hs_state["pub_raw"], hs_state["nonce"]
        b_pub, b_nonce = peer_pub_raw, peer_nonce
    else:
        a_pub, a_nonce = peer_pub_raw, peer_nonce
        b_pub, b_nonce = hs_state["pub_raw"], hs_state["nonce"]

    versions = PROTO_VERSIONS[hs_state["profile"]]
    tr = b"".join([
        versions["handshake"],
        b"|profile=", hs_state["profile"].encode(),
        b"|sid=", hs_state["sid"],
        b"|recon=", recon_th,
        b"|a=", a_pub, a_nonce,
        b"|b=", b_pub, b_nonce,
    ])
    th = sha256(tr)

    salt = sha256(f"{hs_state['profile']}|hs-salt|".encode() + hs_state["k0"] + hs_state["sid"] + recon_th + th)
    master_bytes = hkdf_sha256(ss, salt=salt, info=f"{hs_state['profile']}|master|v1".encode(), n=32)

    confirm_key = hkdf_sha256(
        master_bytes,
        salt=sha256(f"{hs_state['profile']}|confirm-salt|".encode() + th),
        info=f"{hs_state['profile']}|confirm-key|v1".encode(),
        n=32
    )

    nonce_base_send = derive_nonce_base(master_bytes, hs_state["sid"], hs_state["profile"], hs_state["role"])
    nonce_base_recv = derive_nonce_base(master_bytes, hs_state["sid"], hs_state["profile"],
                                       "bob" if hs_state["role"] == "alice" else "alice")

    return {"master": master_bytes, "confirm_key": confirm_key, "th": th,
            "nonce_base_send": nonce_base_send, "nonce_base_recv": nonce_base_recv}

def hs_auth_tag(master: bytes, role: ROLE, th: bytes, profile: str) -> bytes:
    return hmac_sha256(master, f"{profile}|hs-auth|".encode() + role.encode() + b"|" + th)

def hs_confirm_tag(confirm_key: bytes, role: ROLE, th: bytes, profile: str) -> bytes:
    return hmac_sha256(confirm_key, f"{profile}|key-confirm|".encode() + role.encode() + b"|" + th)

def derive_session_keys(master: bytes, th: bytes, role: ROLE, profile: str):
    base = hkdf_sha256(
        master,
        salt=sha256(f"{profile}|kdf|".encode() + th),
        info=f"{profile}|session|v1".encode(),
        n=64
    )
    k1, k2 = base[:32], base[32:]
    return (k1, k2) if role == "alice" else (k2, k1)
