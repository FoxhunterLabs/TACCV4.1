from __future__ import annotations
import hashlib
from typing import Any, Dict
from .constants import KINDS, PROTO_VERSIONS
from .validation import json_dumps_sorted
from taccv.crypto.primitives import sha256

class Transcript:
    def __init__(self, profile: str):
        self.profile = profile
        versions = PROTO_VERSIONS[profile]
        self.transcript_version = versions["transcript"]
        self._h = {"alice": hashlib.sha256(), "bob": hashlib.sha256()}

    def record(self, sender: str, kind: str, seq: int, payload: Dict[str, Any]) -> None:
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
