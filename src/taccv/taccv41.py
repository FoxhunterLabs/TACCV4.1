# TACCV4.1 — PAKE-secured pairing over an untrusted relay (Reference Implementation)
# SPAKE2 + X25519 + ChaCha20Poly1305 over untrusted WebSocket relay
# WARNING: This is a reference implementation, not production-ready crypto.

from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import hmac
import json
import secrets
import sys
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Dict, Optional, Literal, List

# =============================
# Dependency Check
# =============================

logger = None  # structlog logger, set in check_dependencies()

def check_dependencies() -> bool:
    """Check for required dependencies."""
    missing = []
    try:
        import websockets  # noqa: F401
    except ImportError:
        missing.append("websockets")

    try:
        import fastapi  # noqa: F401
    except ImportError:
        missing.append("fastapi")

    try:
        import uvicorn  # noqa: F401
    except ImportError:
        missing.append("uvicorn[standard]")

    try:
        import spake2  # noqa: F401
    except ImportError:
        missing.append("spake2")

    try:
        import cryptography  # noqa: F401
    except ImportError:
        missing.append("cryptography")

    try:
        import structlog  # noqa: F401
    except ImportError:
        missing.append("structlog")

    try:
        import pydantic  # noqa: F401
    except ImportError:
        missing.append("pydantic")

    if missing:
        print("ERROR: Missing dependencies:")
        for dep in missing:
            print(f"  - {dep}")
        print("\nInstall with:")
        print(f"pip install {' '.join(missing)}")
        print("\nNote: Install uvicorn with 'standard' extras for better performance")
        return False

    global logger
    import structlog
    logger = structlog.get_logger()
    return True


# =============================
# Configuration & Constants
# =============================

ROLE = Literal["alice", "bob"]
PROTO_NAME = "TACCV"
PROTO_VER = "4.1"

SUPPORTED_PROFILES = ["v41-pake", "v40-pake", "v35-pake"]
MIN_PROFILE = "v40-pake"
DEFAULT_PROFILE = "v41-pake"

PROFILE_RANKS = {
    "v41-pake": 41,
    "v40-pake": 40,
    "v35-pake": 35,
}

PROTO_VERSIONS = {
    "v41-pake": {
        "transcript": b"TACCV41-TRANSCRIPT-1",
        "handshake": b"TACCV41-HS-1",
        "secure": b"TACCV41-SECURE-1",
    },
    "v40-pake": {
        "transcript": b"TACCV40-TRANSCRIPT-1",
        "handshake": b"TACCV40-HS-1",
        "secure": b"TACCV40-SECURE-1",
    },
    "v35-pake": {
        "transcript": b"TACCV35-TRANSCRIPT-1",
        "handshake": b"TACCV35-HS-1",
        "secure": b"TACCV35-SECURE-1",
    },
}

class AbortCode:
    INTERNAL_ERROR = "internal_error"
    PROTOCOL_VIOLATION = "protocol_violation"
    TIMEOUT = "timeout"
    AUTH_FAILED = "auth_failed"
    VERSION_MISMATCH = "version_mismatch"
    PROFILE_MISMATCH = "profile_mismatch"
    PROFILE_DOWNGRADE = "profile_downgrade"
    SEQUENCE_ERROR = "sequence_error"
    CRYPTO_ERROR = "crypto_error"
    INVALID_MESSAGE = "invalid_message"

SESSION_TTL_S = 30 * 60
SESSION_SWEEP_S = 30
MAX_MSG_BYTES = 16 * 1024
MAX_JSON_DEPTH = 10
MAX_JSON_KEYS = 100
MAX_CONNECTIONS_PER_IP = 10
CONNECTION_RATE_LIMIT = 5
TOKENS_PER_MIN = 90
BURST_TOKENS = 30
REQUIRE_SEQ_MONOTONIC = True
MAX_DECRYPT_FAILURES = 10
MAX_B64_LENGTH = 64 * 1024

MSG_TYPES = {"hello", "peer_joined", "peer_left", "error", "ping", "pong", "packet", "relay"}
KINDS = {
    "profile_hello",
    "pake_hello", "pake_confirm",
    "hs_hello", "hs_auth", "hs_confirm",
    "secure_msg",
    "abort",
    "artifact_req", "artifact_resp",
}

# =============================
# Core Security Utilities
# =============================

def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()

def hmac_sha256(k: bytes, b: bytes) -> bytes:
    return hmac.new(k, b, hashlib.sha256).digest()

def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")

def b64d(s: str) -> bytes:
    if len(s) > MAX_B64_LENGTH:
        raise ValueError(f"Base64 too long: {len(s)} > {MAX_B64_LENGTH}")
    return base64.b64decode(s, validate=True)

def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, n: int) -> bytes:
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    out, t = b"", b""
    c = 1
    while len(out) < n:
        t = hmac.new(prk, t + info + bytes([c]), hashlib.sha256).digest()
        out += t
        c += 1
    return out[:n]

def safe_compare(a: bytes, b: bytes, expected_length: int = None) -> bool:
    if expected_length and (len(a) != expected_length or len(b) != expected_length):
        return False
    return hmac.compare_digest(a, b)

def sas6(k0: bytes, sid: bytes, profile: str) -> str:
    v = int.from_bytes(sha256(f"{profile}|sas|".encode() + k0 + sid)[:4], "big") % 1_000_000
    return f"{v:06d}"

def json_dumps_sorted(o: Any) -> str:
    return json.dumps(o, ensure_ascii=False, separators=(",", ":"), sort_keys=True)

def now() -> float:
    return time.time()

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

def validate_bytes_length(data: bytes, name: str, min_len: int, max_len: int = None):
    if len(data) < min_len:
        raise ValueError(f"{name} too short: {len(data)} < {min_len}")
    if max_len and len(data) > max_len:
        raise ValueError(f"{name} too long: {len(data)} > {max_len}")

def validate_base64(s: str, name: str, min_bytes: int, max_bytes: int = None) -> bytes:
    try:
        data = b64d(s)
        validate_bytes_length(data, name, min_bytes, max_bytes)
        return data
    except Exception as e:
        raise ValueError(f"Invalid base64 for {name}: {e}")

def fuzz_resistant_json_loads(s: str) -> Dict:
    if len(s) > MAX_MSG_BYTES * 2:
        raise ValueError("Message too large")

    def object_hook(obj):
        if len(obj) > MAX_JSON_KEYS:
            raise ValueError("Too many JSON keys")
        return obj

    parsed = json.loads(s, object_hook=object_hook)

    def check_depth(obj, depth=0):
        if depth > MAX_JSON_DEPTH:
            raise ValueError("JSON nesting too deep")
        if isinstance(obj, dict):
            for v in obj.values():
                check_depth(v, depth + 1)
        elif isinstance(obj, list):
            for v in obj:
                check_depth(v, depth + 1)

    check_depth(parsed)
    return parsed

def profile_allowed(profile: str) -> bool:
    if profile not in PROFILE_RANKS:
        return False
    return PROFILE_RANKS[profile] >= PROFILE_RANKS[MIN_PROFILE]


# =============================
# Protocol State Machine
# =============================

class Phase(Enum):
    INIT = auto()
    CONNECTED = auto()
    PROFILE_NEGOTIATING = auto()
    PAKE = auto()
    PAKE_DONE = auto()
    HANDSHAKING = auto()
    HANDSHAKE_AUTHED = auto()
    ESTABLISHED = auto()
    ABORTED = auto()


# =============================
# Transcript
# =============================

class Transcript:
    def __init__(self, profile: str):
        self.profile = profile
        versions = PROTO_VERSIONS[profile]
        self.transcript_version = versions["transcript"]
        self._h = {"alice": hashlib.sha256(), "bob": hashlib.sha256()}

    def record(self, sender: ROLE, kind: str, seq: int, payload: Dict[str, Any]) -> None:
        if kind not in KINDS:
            return
        if kind == "profile_hello":
            return

        scrub = dict(payload)
        if kind == "secure_msg":
            scrub.pop("blob_b64", None)
        if "tag_b64" in scrub:
            scrub["tag_b64"] = "[REDACTED]"

        blob = json_dumps_sorted(scrub).encode("utf-8")
        rec = b"|".join([
            self.transcript_version,
            b"msg",
            sender.encode(),
            str(seq).encode(),
            kind.encode(),
            sha256(blob),
        ])
        self._h[sender].update(rec)

    def digest(self) -> bytes:
        return sha256(
            self.transcript_version
            + b"|profile=" + self.profile.encode("utf-8")
            + b"|alice=" + self._h["alice"].digest()
            + b"|bob=" + self._h["bob"].digest()
        )


# =============================
# PAKE (SPAKE2)
# =============================

def require_spake2():
    try:
        from spake2 import SPAKE2_A, SPAKE2_B
        return SPAKE2_A, SPAKE2_B
    except ImportError as e:
        raise RuntimeError("Missing dependency 'spake2'") from e

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

    k0_bytes = hkdf_sha256(
        k,
        salt=sha256(f"{profile}|k0-salt|".encode() + sid),
        info=f"{profile}|K0|v1".encode(),
        n=32
    )
    return k0_bytes

def pake_confirm_tag(k0: bytes, sid: bytes, role: ROLE, transcript_hash: bytes, profile: str) -> bytes:
    return hmac_sha256(
        k0,
        f"{profile}|pake-confirm|".encode() + sid + b"|" + role.encode() + b"|" + transcript_hash
    )


# =============================
# Handshake
# =============================

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


# =============================
# Secure Channel
# =============================

def require_aead():
    try:
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
        return ChaCha20Poly1305
    except ImportError as e:
        raise RuntimeError("Missing dependency 'cryptography'") from e

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


# =============================
# Profile Negotiation
# =============================

def negotiate_profile(my_profiles: List[str], peer_profiles: List[str]) -> str:
    for profile in sorted(my_profiles, key=lambda p: PROFILE_RANKS.get(p, 0), reverse=True):
        if profile in peer_profiles and profile_allowed(profile):
            return profile
    raise ValueError("No mutually supported profile")


# =============================
# Session Management
# =============================

class Session:
    def __init__(self, code: str, sid: bytes):
        self.code = code
        self.sid = sid
        self.created_at = now()
        self.expires_at = self.created_at + SESSION_TTL_S
        self.ws = {"alice": None, "bob": None}
        self.token = {"alice": BURST_TOKENS, "bob": BURST_TOKENS}
        self.token_ts = {"alice": self.created_at, "bob": self.created_at}
        self.peer_seq = {"alice": 0, "bob": 0}
        self.lock = threading.Lock()
        self.stats = {"dropped_packets": 0}

    def is_expired(self) -> bool:
        buffer = 5
        return now() >= (self.expires_at - buffer)

class SessionManager:
    def __init__(self):
        self.sessions: Dict[str, Session] = {}
        self.lock = threading.Lock()
        self.last_sweep = 0.0

    def create(self) -> Session:
        alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
        with self.lock:
            while True:
                code = "".join(secrets.choice(alphabet) for _ in range(8))
                if code not in self.sessions:
                    break
            sid = secrets.token_bytes(16)
            session = Session(code, sid)
            self.sessions[code] = session
            logger.info("session_created", session_code=code)
            return session

    def get(self, code: str) -> Optional[Session]:
        self._sweep_expired()
        with self.lock:
            return self.sessions.get(code)

    def _sweep_expired(self):
        now_time = now()
        if now_time - self.last_sweep < SESSION_SWEEP_S:
            return

        with self.lock:
            expired = [code for code, sess in self.sessions.items() if sess.is_expired()]
            for code in expired:
                self.sessions.pop(code, None)
                logger.info("session_expired", session_code=code)
            self.last_sweep = now_time


# =============================
# Relay Server
# =============================

class RateLimiter:
    def __init__(self):
        self.connections: Dict[str, List[float]] = {}
        self._lock = threading.Lock()

    def allow_connection(self, ip: str) -> bool:
        with self._lock:
            t = now()
            if ip in self.connections:
                conns = [ts for ts in self.connections[ip] if t - ts < 60]
                if not conns:
                    del self.connections[ip]
                else:
                    self.connections[ip] = conns

            conns = self.connections.get(ip, [])

            if len(conns) >= MAX_CONNECTIONS_PER_IP:
                logger.warning("dos_protection", reason="max_connections_per_ip", ip=ip)
                return False

            if len(conns) >= CONNECTION_RATE_LIMIT:
                logger.warning("dos_protection", reason="connection_rate_limit", ip=ip)
                return False

            conns.append(t)
            self.connections[ip] = conns[-MAX_CONNECTIONS_PER_IP:]
            return True

def build_relay_app():
    from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request
    from pydantic import BaseModel

    app = FastAPI(title="TACCV4.1 Relay", version=PROTO_VER)
    session_manager = SessionManager()
    rate_limiter = RateLimiter()

    class SessionCreateResp(BaseModel):
        session_code: str
        session_id_b64: str
        expires_in_s: int

    async def _send(ws: WebSocket, msg_type: str, payload: Any = None):
        msg = {"type": msg_type, "proto": PROTO_NAME, "ver": PROTO_VER}
        if payload is not None:
            msg["payload"] = payload
        await ws.send_text(json_dumps_sorted(msg))

    def _refill_tokens(session: Session, role: ROLE):
        t = now()
        with session.lock:
            last = session.token_ts[role]
            dt = max(0.0, t - last)
            session.token_ts[role] = t
            add = (TOKENS_PER_MIN / 60.0) * dt
            session.token[role] = min(BURST_TOKENS, session.token[role] + add)

    def _take_token(session: Session, role: ROLE) -> bool:
        _refill_tokens(session, role)
        with session.lock:
            if session.token[role] >= 1.0:
                session.token[role] -= 1.0
                return True
        return False

    async def _relay(session: Session, from_role: ROLE, msg: Dict[str, Any]):
        to_role: ROLE = "bob" if from_role == "alice" else "alice"
        with session.lock:
            peer = session.ws.get(to_role)

        if peer:
            relay_msg = {"type": "relay", "payload": {"from": from_role, "msg": msg}, "proto": PROTO_NAME, "ver": PROTO_VER}
            await peer.send_text(json_dumps_sorted(relay_msg))

    @app.post("/session", response_model=SessionCreateResp)
    def create_session():
        session = session_manager.create()
        return SessionCreateResp(session_code=session.code, session_id_b64=b64e(session.sid), expires_in_s=SESSION_TTL_S)

    @app.websocket("/ws/{code}/{role}")
    async def ws_pair(code: str, role: str, websocket: WebSocket, request: Request):
        client_ip = request.client.host if request.client else "unknown"
        if not rate_limiter.allow_connection(client_ip):
            await websocket.close(code=1008)
            return

        if role not in ("alice", "bob"):
            await websocket.accept()
            await _send(websocket, "error", {"error": "role must be alice|bob"})
            await websocket.close(code=1008)
            return

        session = session_manager.get(code)
        if not session:
            await websocket.close(code=1008)
            return

        await websocket.accept()

        with session.lock:
            old_ws = session.ws.get(role)
            session.ws[role] = websocket
            if old_ws:
                session.peer_seq[role] = 0

        if old_ws:
            try:
                await _send(old_ws, "error", {"error": "another connection joined"})
                await old_ws.close(code=1012)
            except Exception:
                pass

        logger.info("client_connected", session_code=code, role=role, ip=client_ip)

        await _send(websocket, "hello", {"session_code": code, "role": role, "session_id_b64": b64e(session.sid), "expires_at": session.expires_at})

        peer_role: ROLE = "bob" if role == "alice" else "alice"
        with session.lock:
            peer_ws = session.ws.get(peer_role)

        if peer_ws:
            await _send(peer_ws, "peer_joined", {"role": role})
            await _send(websocket, "peer_joined", {"role": peer_role})

        try:
            while True:
                raw = await websocket.receive_text()
                raw_bytes = raw.encode("utf-8")

                if len(raw_bytes) > MAX_MSG_BYTES:
                    await _send(websocket, "error", {"error": "message too large"})
                    continue

                if not _take_token(session, role):
                    await _send(websocket, "error", {"error": "rate limit"})
                    continue

                try:
                    msg = fuzz_resistant_json_loads(raw)
                except Exception as e:
                    await _send(websocket, "error", {"error": f"invalid json: {e}"})
                    continue

                if not isinstance(msg, dict):
                    await _send(websocket, "error", {"error": "message must be json object"})
                    continue

                if msg.get("proto") != PROTO_NAME or msg.get("ver") != PROTO_VER:
                    await _send(websocket, "error", {"error": "protocol mismatch"})
                    continue

                msg_type = msg.get("type")
                if msg_type not in MSG_TYPES:
                    await _send(websocket, "error", {"error": f"unknown message type: {msg_type}"})
                    continue

                if msg_type == "ping":
                    await _send(websocket, "pong", {"t": now()})
                    continue

                if msg_type == "packet":
                    payload = msg.get("payload")
                    if not isinstance(payload, dict):
                        await _send(websocket, "error", {"error": "packet payload must be object"})
                        continue

                    kind = payload.get("kind")
                    if kind not in KINDS:
                        await _send(websocket, "error", {"error": f"unknown packet kind: {kind}"})
                        continue

                    if REQUIRE_SEQ_MONOTONIC:
                        seq = payload.get("seq")
                        if not isinstance(seq, int) or seq <= 0:
                            await _send(websocket, "error", {"error": "seq must be positive int"})
                            continue

                        with session.lock:
                            if seq <= session.peer_seq[role]:
                                session.stats["dropped_packets"] += 1
                                continue
                            session.peer_seq[role] = seq

                await _relay(session, role, msg)

        except WebSocketDisconnect:
            logger.info("client_disconnected", session_code=code, role=role, ip=client_ip)
        finally:
            with session.lock:
                if session.ws.get(role) is websocket:
                    session.ws[role] = None

            with session.lock:
                peer_ws = session.ws.get(peer_role)

            if peer_ws:
                try:
                    await _send(peer_ws, "peer_left", {"role": role})
                except Exception:
                    pass

    return app


# =============================
# Client Implementation
# =============================

class ProtocolError(Exception):
    pass

@dataclass
class ClientState:
    role: ROLE
    sid: bytes
    profile: Optional[str] = None
    phase: Phase = Phase.INIT
    seq_out: int = 0
    peer_seq_in: int = 0
    transcript: Optional[Transcript] = None
    recon_th: Optional[bytes] = None
    k0: Optional[bytes] = None
    master: Optional[bytes] = None
    th: Optional[bytes] = None
    nonce_base_send: Optional[bytes] = None
    nonce_base_recv: Optional[bytes] = None
    send_key: Optional[bytes] = None
    recv_key: Optional[bytes] = None
    send_seq2: int = 0
    recv_seq2: int = 0

    peer_pake_confirm: Optional[bytes] = None
    peer_hs_auth: Optional[bytes] = None
    peer_hs_confirm: Optional[bytes] = None

    inbox: Dict[str, List[Dict[str, Any]]] = field(default_factory=lambda: defaultdict(list))
    peer_conn_id: Optional[str] = None

    decrypt_failures: int = 0
    last_decrypt_failure: float = 0.0

    def cleanup(self):
        for field_name in ['k0', 'master', 'send_key', 'recv_key', 'nonce_base_send', 'nonce_base_recv']:
            val = getattr(self, field_name)
            if isinstance(val, bytes):
                setattr(self, field_name, None)
        self.phase = Phase.ABORTED

class WSClient:
    def __init__(self, url: str, session_code: str, role: ROLE, password: bytes):
        self.url = url.rstrip("/")
        self.code = session_code
        self.role = role
        self.peer: ROLE = "bob" if role == "alice" else "alice"
        self.password = password
        self.ws = None
        self.state = ClientState(role=role, sid=b"")
        self._pending: Dict[str, asyncio.Future] = {}
        self._out_of_order_count = 0
        self._pake_state = None
        self._hs_state = None

        self._rx_task: Optional[asyncio.Task] = None
        self._rx_queue: asyncio.Queue = asyncio.Queue()
        self._running = False

    async def connect(self):
        import websockets
        ws_url = f"{self.url}/ws/{self.code}/{self.role}"
        self.ws = await websockets.connect(ws_url)

        self._running = True
        self._rx_task = asyncio.create_task(self._recv_loop())

        msg = await self._wait_for_message(lambda m: m.get("type") == "hello")
        if not msg:
            raise ProtocolError("expected hello")
        if msg.get("proto") != PROTO_NAME or msg.get("ver") != PROTO_VER:
            raise ProtocolError("protocol mismatch")

        payload = msg.get("payload", {})
        self.state.sid = validate_base64(payload["session_id_b64"], "sid", 16, 16)
        self.state.phase = Phase.CONNECTED
        logger.info("client_connected", role=self.role, session=self.code)

    async def _recv_loop(self):
        while self._running and self.ws:
            try:
                raw = await self.ws.recv()
                msg = fuzz_resistant_json_loads(raw)
                if msg.get("proto") != PROTO_NAME or msg.get("ver") != PROTO_VER:
                    logger.error("protocol_mismatch", message=msg)
                    continue
                await self._rx_queue.put(msg)
            except Exception as e:
                if self._running:
                    logger.error("recv_loop_error", error=str(e))
                break

    async def _wait_for_message(self, condition) -> Optional[Dict[str, Any]]:
        start_time = time.time()
        timeout = 30.0
        while self._running and (time.time() - start_time < timeout):
            try:
                msg = await asyncio.wait_for(self._rx_queue.get(), timeout=0.2)
                if condition(msg):
                    return msg
                await self._process_received_message(msg)
            except asyncio.TimeoutError:
                continue
        return None

    def _validate_message_phase(self, kind: str) -> bool:
        phase = self.state.phase
        if kind == "profile_hello":
            return phase in [Phase.CONNECTED, Phase.PROFILE_NEGOTIATING]
        if kind == "pake_hello":
            return phase == Phase.PAKE
        if kind == "pake_confirm":
            return phase in [Phase.PAKE, Phase.PAKE_DONE]
        if kind == "hs_hello":
            return phase == Phase.HANDSHAKING
        if kind in ["hs_auth", "hs_confirm"]:
            return phase in [Phase.HANDSHAKING, Phase.HANDSHAKE_AUTHED]
        if kind == "secure_msg":
            return phase == Phase.ESTABLISHED
        if kind == "abort":
            return True
        return False

    async def _process_received_message(self, msg: Dict[str, Any]):
        msg_type = msg.get("type")
        if msg_type == "relay":
            wrapper = msg.get("payload", {})
            from_role = wrapper.get("from", self.peer)
            peer_msg = wrapper.get("msg", {})
            await self._handle_peer(from_role, peer_msg)
        elif msg_type == "error":
            raise ProtocolError(f"relay error: {msg.get('payload')}")
        elif msg_type == "peer_joined":
            logger.info("peer_connected", role=self.role, peer=self.peer)
            self.state.peer_seq_in = 0
            self.state.peer_conn_id = None
        elif msg_type == "peer_left":
            logger.info("peer_disconnected", role=self.role, peer=self.peer)

    async def _send_raw(self, o: Dict[str, Any]):
        if not self.ws:
            raise ProtocolError("not connected")
        o["proto"] = PROTO_NAME
        o["ver"] = PROTO_VER
        await self.ws.send(json_dumps_sorted(o))

    async def send_packet(self, kind: str, payload: Dict[str, Any], op: str = "req"):
        self.state.seq_out += 1
        seq = self.state.seq_out
        wire_payload = {("rid" if k == "id" else k): v for k, v in payload.items()}
        p = {"kind": kind, "seq": seq, "op": op, **wire_payload}

        if self.state.transcript:
            self.state.transcript.record(self.role, kind, seq, p)

        await self._send_raw({"type": "packet", "payload": p})

    async def request(self, kind: str, payload: Dict[str, Any], timeout: float = 15.0) -> Any:
        req_id = secrets.token_hex(8)
        fut = asyncio.get_event_loop().create_future()
        self._pending[req_id] = fut
        await self.send_packet(kind, {"id": req_id, **payload}, op="req")
        try:
            return await asyncio.wait_for(fut, timeout=timeout)
        except asyncio.TimeoutError:
            self._pending.pop(req_id, None)
            raise ProtocolError(f"Request timeout for {kind}")

    async def abort(self, reason: str, code: str = AbortCode.INTERNAL_ERROR):
        await self.send_packet("abort", {"reason": reason, "code": code})
        self.state.phase = Phase.ABORTED
        raise ProtocolError(f"Aborted: {reason}")

    async def _handle_peer(self, from_role: ROLE, msg: Dict[str, Any]):
        if msg.get("type") != "packet":
            return

        payload = msg.get("payload", {})
        kind = payload.get("kind")
        seq = int(payload.get("seq", 0))
        op = payload.get("op", "req")

        if not self._validate_message_phase(kind):
            await self.abort(f"Message {kind} invalid in phase {self.state.phase}", AbortCode.PROTOCOL_VIOLATION)

        if op not in ("req", "resp"):
            await self.abort(f"Invalid op value: {op}", AbortCode.INVALID_MESSAGE)

        if kind == "profile_hello":
            conn_id = payload.get("conn_id")
            if conn_id and conn_id != self.state.peer_conn_id:
                self.state.peer_conn_id = conn_id
                self.state.peer_seq_in = 0

        if REQUIRE_SEQ_MONOTONIC and seq and seq <= self.state.peer_seq_in:
            self._out_of_order_count += 1
            return
        self.state.peer_seq_in = seq

        if self.state.transcript and kind in KINDS:
            self.state.transcript.record(from_role, kind, seq, payload)

        req_id = payload.get("rid")

        if op == "req" and kind in ["profile_hello", "pake_hello", "hs_hello"]:
            if not req_id:
                await self.abort(f"Request {kind} missing rid", AbortCode.INVALID_MESSAGE)
            await self._handle_request(kind, req_id, payload, from_role)
            return

        if op == "resp":
            if not req_id:
                await self.abort(f"Response {kind} missing rid", AbortCode.INVALID_MESSAGE)
            if req_id in self._pending:
                self._pending.pop(req_id).set_result(payload)
            return

        if kind == "pake_confirm":
            self.state.peer_pake_confirm = validate_base64(payload["tag_b64"], "pake_confirm", 32, 32)
        elif kind == "hs_auth":
            self.state.peer_hs_auth = validate_base64(payload["tag_b64"], "hs_auth", 32, 32)
        elif kind == "hs_confirm":
            self.state.peer_hs_confirm = validate_base64(payload["tag_b64"], "hs_confirm", 32, 32)
        elif kind == "secure_msg":
            await self._handle_secure(from_role, payload)
        elif kind == "abort":
            self.state.phase = Phase.ABORTED
            reason = payload.get("reason", "unknown")
            code = payload.get("code", AbortCode.INTERNAL_ERROR)
            raise ProtocolError(f"peer aborted ({code}): {reason}")

    async def _handle_request(self, kind: str, req_id: str, payload: Dict[str, Any], from_role: ROLE):
        inbox_entry = {
            "rid": req_id,
            "seq": payload.get("seq", 0),
            "kind": kind,
            "from_role": from_role,
            "body": {k: v for k, v in payload.items() if k not in ["rid", "op", "seq", "kind"]}
        }
        if kind in ["pake_hello", "hs_hello"]:
            self.state.inbox[kind].append(inbox_entry)

        response_payload = {}

        if kind == "profile_hello":
            response_payload = {"profiles": SUPPORTED_PROFILES, "min_profile": MIN_PROFILE, "conn_id": secrets.token_hex(8)}
        elif kind == "pake_hello":
            if self._pake_state:
                response_payload = {"msg_b64": b64e(self._pake_state["msg_out"])}
                if self.state.inbox["pake_hello"]:
                    self.state.inbox["pake_hello"].pop(0)
            else:
                return
        elif kind == "hs_hello":
            if self._hs_state:
                response_payload = {"pub_b64": b64e(self._hs_state["pub_raw"]), "nonce_b64": b64e(self._hs_state["nonce"])}
                if self.state.inbox["hs_hello"]:
                    self.state.inbox["hs_hello"].pop(0)
            else:
                return

        await self.send_packet(kind, {"id": req_id, **response_payload}, op="resp")

    async def _check_inbox(self, kind: str) -> Optional[Dict[str, Any]]:
        if self.state.inbox[kind]:
            return self.state.inbox[kind].pop(0)
        return None

    async def _handle_secure(self, from_role: ROLE, payload: Dict[str, Any]):
        if not self.state.recv_key or not self.state.th or not self.state.nonce_base_recv:
            return

        seq2 = int(payload.get("seq2", 0))
        if seq2 <= self.state.recv_seq2:
            return

        ct = validate_base64(payload["blob_b64"], "secure_ct", 17)

        aad = secure_aad(self.state.sid, self.state.profile, self.state.recon_th, self.state.th, from_role, seq2)
        nonce = build_nonce(self.state.nonce_base_recv, seq2)

        ChaCha20Poly1305 = require_aead()
        aead = ChaCha20Poly1305(self.state.recv_key)

        try:
            pt = aead.decrypt(nonce, ct, aad)
        except Exception as e:
            now_time = time.time()
            if now_time - self.state.last_decrypt_failure > 60:
                self.state.decrypt_failures = 0
            self.state.decrypt_failures += 1
            self.state.last_decrypt_failure = now_time
            if self.state.decrypt_failures >= MAX_DECRYPT_FAILURES:
                await self.abort(f"Too many decrypt failures ({self.state.decrypt_failures})", AbortCode.CRYPTO_ERROR)
            logger.warning("decryption_failed", role=self.role, error=str(e), failures=self.state.decrypt_failures)
            return

        self.state.decrypt_failures = 0
        self.state.recv_seq2 = seq2

        try:
            text = pt.decode('utf-8', errors='replace')
            print(f"[{self.role}] <- {from_role} ({seq2}): {text}")
        except Exception:
            print(f"[{self.role}] <- {from_role} ({seq2}): [binary, {len(pt)} bytes]")

    async def close(self):
        self._running = False
        if self._rx_task:
            self._rx_task.cancel()
            try:
                await self._rx_task
            except asyncio.CancelledError:
                pass
        if self.ws:
            try:
                await self.ws.close()
            except Exception:
                pass
            self.ws = None
        self.state.cleanup()

    async def run(self, demo_message: str = ""):
        try:
            await self.connect()
            self.state.phase = Phase.PROFILE_NEGOTIATING

            resp = await self.request("profile_hello", {"profiles": SUPPORTED_PROFILES, "min_profile": MIN_PROFILE, "conn_id": secrets.token_hex(8)})
            peer_profiles = resp.get("profiles", [])
            if not peer_profiles:
                await self.abort("No profiles supported by peer", AbortCode.PROFILE_MISMATCH)

            negotiated = negotiate_profile(SUPPORTED_PROFILES, peer_profiles)
            if not profile_allowed(negotiated):
                await self.abort(f"Profile {negotiated} below minimum security level", AbortCode.PROFILE_DOWNGRADE)

            self.state.profile = negotiated
            self.state.peer_conn_id = resp.get("conn_id")
            logger.info("profile_negotiated", role=self.role, profile=negotiated)

            self.state.transcript = Transcript(profile=negotiated)
            self.state.phase = Phase.PAKE
            self._pake_state = pake_init(self.role, self.password, self.state.sid, negotiated)

            inbox_msg = await self._check_inbox("pake_hello")
            if inbox_msg:
                req_id = inbox_msg.get("rid")
                await self.send_packet("pake_hello", {"id": req_id, "msg_b64": b64e(self._pake_state["msg_out"])}, op="resp")
                peer_msg_b64 = inbox_msg["body"].get("msg_b64")
            else:
                resp = await self.request("pake_hello", {"msg_b64": b64e(self._pake_state["msg_out"])})
                peer_msg_b64 = resp.get("msg_b64")

            if not peer_msg_b64:
                await self.abort("pake_hello missing msg_b64", AbortCode.INVALID_MESSAGE)

            peer_msg = validate_base64(peer_msg_b64, "pake_msg", 32, 64)
            self.state.k0 = pake_finish_reduced_timing(self._pake_state, peer_msg, self.state.sid, negotiated)
            self._pake_state = None

            self.state.recon_th = self.state.transcript.digest()

            my_pake_tag = pake_confirm_tag(self.state.k0, self.state.sid, self.role, self.state.recon_th, negotiated)
            await self.send_packet("pake_confirm", {"tag_b64": b64e(my_pake_tag)})

            for _ in range(100):
                if self.state.peer_pake_confirm is not None:
                    break
                await asyncio.sleep(0.1)
            if self.state.peer_pake_confirm is None:
                await self.abort("PAKE confirmation timeout", AbortCode.TIMEOUT)

            exp_peer_pake = pake_confirm_tag(self.state.k0, self.state.sid, self.peer, self.state.recon_th, negotiated)
            if not safe_compare(exp_peer_pake, self.state.peer_pake_confirm, 32):
                await self.abort("PAKE confirmation mismatch", AbortCode.AUTH_FAILED)

            self.state.phase = Phase.PAKE_DONE
            logger.info("PAKE_SUCCESS", role=self.role, sas6=sas6(self.state.k0, self.state.sid, negotiated))

            self.state.phase = Phase.HANDSHAKING
            self._hs_state = hs_init(self.role, self.state.sid, negotiated, self.state.k0)

            inbox_msg = await self._check_inbox("hs_hello")
            if inbox_msg:
                req_id = inbox_msg.get("rid")
                await self.send_packet("hs_hello", {"id": req_id, "pub_b64": b64e(self._hs_state["pub_raw"]), "nonce_b64": b64e(self._hs_state["nonce"])}, op="resp")
                peer_pub_b64 = inbox_msg["body"].get("pub_b64")
                peer_nonce_b64 = inbox_msg["body"].get("nonce_b64")
            else:
                resp = await self.request("hs_hello", {"pub_b64": b64e(self._hs_state["pub_raw"]), "nonce_b64": b64e(self._hs_state["nonce"])})
                peer_pub_b64 = resp.get("pub_b64")
                peer_nonce_b64 = resp.get("nonce_b64")

            if not peer_pub_b64 or not peer_nonce_b64:
                await self.abort("hs_hello missing fields", AbortCode.INVALID_MESSAGE)

            peer_pub_raw = validate_base64(peer_pub_b64, "hs_pub", 32, 32)
            peer_nonce = validate_base64(peer_nonce_b64, "hs_nonce", 16, 16)

            derived = hs_derive_master(self._hs_state, peer_pub_raw, peer_nonce, self.state.recon_th)
            self.state.master = derived["master"]
            self.state.th = derived["th"]
            self.state.nonce_base_send = derived["nonce_base_send"]
            self.state.nonce_base_recv = derived["nonce_base_recv"]
            self._hs_state = None

            my_hs_tag = hs_auth_tag(self.state.master, self.role, self.state.th, negotiated)
            await self.send_packet("hs_auth", {"tag_b64": b64e(my_hs_tag)})

            for _ in range(100):
                if self.state.peer_hs_auth is not None:
                    break
                await asyncio.sleep(0.1)
            if self.state.peer_hs_auth is None:
                await self.abort("Handshake auth timeout", AbortCode.TIMEOUT)

            exp_peer_hs = hs_auth_tag(self.state.master, self.peer, self.state.th, negotiated)
            if not safe_compare(exp_peer_hs, self.state.peer_hs_auth, 32):
                await self.abort("Handshake auth mismatch", AbortCode.AUTH_FAILED)

            self.state.phase = Phase.HANDSHAKE_AUTHED

            my_confirm_tag = hs_confirm_tag(derived["confirm_key"], self.role, self.state.th, negotiated)
            await self.send_packet("hs_confirm", {"tag_b64": b64e(my_confirm_tag)})

            for _ in range(100):
                if self.state.peer_hs_confirm is not None:
                    break
                await asyncio.sleep(0.1)
            if self.state.peer_hs_confirm is None:
                await self.abort("Key confirmation timeout", AbortCode.TIMEOUT)

            exp_peer_confirm = hs_confirm_tag(derived["confirm_key"], self.peer, self.state.th, negotiated)
            if not safe_compare(exp_peer_confirm, self.state.peer_hs_confirm, 32):
                await self.abort("Key confirmation mismatch", AbortCode.AUTH_FAILED)

            self.state.send_key, self.state.recv_key = derive_session_keys(self.state.master, self.state.th, self.role, negotiated)

            self.state.phase = Phase.ESTABLISHED
            logger.info("ESTABLISHED", role=self.role, profile=negotiated)

            if demo_message:
                await self.send_secure(demo_message)

            while self._running:
                try:
                    msg = await asyncio.wait_for(self._rx_queue.get(), timeout=1.0)
                    await self._process_received_message(msg)
                except asyncio.TimeoutError:
                    continue

        finally:
            await self.close()

    async def send_secure(self, text: str):
        if not self.state.send_key or not self.state.th or not self.state.nonce_base_send:
            raise ProtocolError("Not established")

        self.state.send_seq2 += 1
        seq2 = self.state.send_seq2

        nonce = build_nonce(self.state.nonce_base_send, seq2)
        aad = secure_aad(self.state.sid, self.state.profile, self.state.recon_th, self.state.th, self.role, seq2)

        ChaCha20Poly1305 = require_aead()
        aead = ChaCha20Poly1305(self.state.send_key)
        ct = aead.encrypt(nonce, text.encode("utf-8"), aad)

        await self.send_packet("secure_msg", {"seq2": seq2, "blob_b64": b64e(ct)})
        print(f"[{self.role}] -> {self.peer} ({seq2}): {text}")


# =============================
# Security Self-Check
# =============================

def security_self_check():
    checks = []

    checks.append(("Python >= 3.9", sys.version_info >= (3, 9)))

    try:
        test = [secrets.randbits(16) for _ in range(10)]
        checks.append(("Random source", all(x != 0 for x in test)))
    except Exception:
        checks.append(("Random source", False))

    try:
        require_spake2()
        checks.append(("SPAKE2", True))
    except Exception:
        checks.append(("SPAKE2", False))

    try:
        require_crypto()
        checks.append(("Cryptography", True))
    except Exception:
        checks.append(("Cryptography", False))

    try:
        require_aead()
        checks.append(("AEAD (ChaCha20Poly1305)", True))
    except Exception:
        checks.append(("AEAD (ChaCha20Poly1305)", False))

    try:
        b64d("aW52YWxpZCBwYWRkaW5n")
        checks.append(("Base64 strict decode (valid)", True))
    except Exception:
        checks.append(("Base64 strict decode (valid)", False))

    try:
        b64d("invalid!@#$")
        checks.append(("Base64 strict decode (invalid)", False))
    except ValueError:
        checks.append(("Base64 strict decode (invalid)", True))

    checks.append(("Downgrade protection", profile_allowed("v41-pake") and profile_allowed("v40-pake") and not profile_allowed("v30-pake")))

    all_ok = all(ok for _, ok in checks)
    for name, ok in checks:
        (logger.info if ok else logger.error)("security_check", check=name, status=("OK" if ok else "FAILED"))

    if not all_ok:
        raise RuntimeError("Security self-check failed")
    logger.info("security_self_check_passed")
    return True


# =============================
# Main Entry Point
# =============================

def main():
    if not check_dependencies():
        sys.exit(1)

    import structlog
    structlog.configure(
        processors=[
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.JSONRenderer(),
        ]
    )

    parser = argparse.ArgumentParser(description="TACCV4.1 Secure Pairing Protocol")
    subparsers = parser.add_subparsers(dest="command", required=True)

    relay_parser = subparsers.add_parser("relay", help="Run the untrusted relay server")
    relay_parser.add_argument("--host", default="127.0.0.1")
    relay_parser.add_argument("--port", type=int, default=8000)

    client_parser = subparsers.add_parser("client", help="Run a pairing client")
    client_parser.add_argument("--url", default="ws://localhost:8000")
    client_parser.add_argument("--session", required=True)
    client_parser.add_argument("--role", choices=["alice", "bob"], required=True)

    auth_group = client_parser.add_mutually_exclusive_group(required=True)
    auth_group.add_argument("--pin", help="6-12 digit PIN")
    auth_group.add_argument("--secret-b64", help="Base64 secret (≥16 bytes)")

    client_parser.add_argument("--message", default="Hello from TACCV4.1!")

    subparsers.add_parser("gen-secret", help="Generate a high-entropy secret")
    subparsers.add_parser("check", help="Run security self-check")

    args = parser.parse_args()

    if args.command == "check":
        security_self_check()
        print("✓ Security self-check passed")
        return

    if args.command == "gen-secret":
        secret = secrets.token_bytes(24)
        print(b64e(secret))
        return

    if args.command == "relay":
        security_self_check()
        import uvicorn
        app = build_relay_app()
        logger.info("starting_relay", host=args.host, port=args.port)
        uvicorn.run(app, host=args.host, port=args.port, log_config=None)
        return

    if args.command == "client":
        security_self_check()
        password = normalize_password(args.pin, args.secret_b64)
        client = WSClient(url=args.url, session_code=args.session, role=args.role, password=password)

        print(f"Starting TACCV4.1 client as {args.role} in session {args.session}")
        print("Press Ctrl+C to exit")

        try:
            asyncio.run(client.run(args.message))
        except KeyboardInterrupt:
            logger.info("client_shutdown", reason="keyboard_interrupt")
            print("\nShutting down...")
        except ProtocolError as e:
            logger.error("protocol_error", error=str(e))
            print(f"Protocol error: {e}")
        except Exception as e:
            logger.error("unexpected_error", error=str(e))
            print(f"Unexpected error: {e}")

if __name__ == "__main__":
    main()
