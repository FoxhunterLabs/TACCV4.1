from __future__ import annotations
import secrets
import threading
from typing import Dict, Optional
from taccv.protocol.constants import SESSION_TTL_S, SESSION_SWEEP_S, BURST_TOKENS
from taccv.crypto.primitives import b64e
import time

def now() -> float:
    return time.time()

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
    def __init__(self, logger):
        self.logger = logger
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
            self.logger.info("session_created", session_code=code)
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
                self.logger.info("session_expired", session_code=code)
            self.last_sweep = now_time
