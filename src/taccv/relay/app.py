from __future__ import annotations
from typing import Any, Dict
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request
from pydantic import BaseModel

from taccv.protocol.constants import (
    PROTO_NAME, PROTO_VER, MSG_TYPES, KINDS, REQUIRE_SEQ_MONOTONIC,
    MAX_MSG_BYTES, TOKENS_PER_MIN, BURST_TOKENS, SESSION_TTL_S,
)
from taccv.protocol.validation import fuzz_resistant_json_loads, json_dumps_sorted
from taccv.crypto.primitives import b64e
from .sessions import SessionManager, Session, now
from .ratelimit import RateLimiter

def build_relay_app(logger):
    app = FastAPI(title="TACCV4.1 Relay", version=PROTO_VER)
    session_manager = SessionManager(logger)
    rate_limiter = RateLimiter(logger)

    class SessionCreateResp(BaseModel):
        session_code: str
        session_id_b64: str
        expires_in_s: int

    async def _send(ws: WebSocket, msg_type: str, payload: Any = None):
        msg = {"type": msg_type, "proto": PROTO_NAME, "ver": PROTO_VER}
        if payload is not None:
            msg["payload"] = payload
        await ws.send_text(json_dumps_sorted(msg))

    def _refill_tokens(session: Session, role: str):
        t = now()
        with session.lock:
            last = session.token_ts[role]
            dt = max(0.0, t - last)
            session.token_ts[role] = t
            add = (TOKENS_PER_MIN / 60.0) * dt
            session.token[role] = min(BURST_TOKENS, session.token[role] + add)

    def _take_token(session: Session, role: str) -> bool:
        _refill_tokens(session, role)
        with session.lock:
            if session.token[role] >= 1.0:
                session.token[role] -= 1.0
                return True
        return False

    async def _relay(session: Session, from_role: str, msg: Dict[str, Any]):
        to_role = "bob" if from_role == "alice" else "alice"
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

        await _send(websocket, "hello", {
            "session_code": code,
            "role": role,
            "session_id_b64": b64e(session.sid),
            "expires_at": session.expires_at,
        })

        peer_role = "bob" if role == "alice" else "alice"
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
