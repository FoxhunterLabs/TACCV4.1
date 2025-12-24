from __future__ import annotations
from typing import Literal

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
