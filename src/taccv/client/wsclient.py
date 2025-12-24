from __future__ import annotations
import asyncio
import secrets
import time
from typing import Any, Dict, Optional

from taccv.protocol.constants import (
    ROLE, PROTO_NAME, PROTO_VER, REQUIRE_SEQ_MONOTONIC,
    MAX_DECRYPT_FAILURES, AbortCode, SUPPORTED_PROFILES, MIN_PROFILE
)
from taccv.protocol.phases import Phase
from taccv.protocol.validation import fuzz_resistant_json_loads, json_dumps_sorted
from taccv.protocol.transcript import Transcript
from taccv.protocol.profiles import negotiate_profile, profile_allowed

from taccv.crypto.primitives import b64e
from taccv.crypto.pake import (
    pake_init, pake_finish_reduced_timing, pake_confirm_tag,
    validate_base64, safe_compare, sas6,
)
from taccv.crypto.handshake import (
    hs_init, hs_derive_master, hs_auth_tag, hs_confirm_tag, derive_session_keys
)
from taccv.crypto.nonce import build_nonce
from taccv.crypto.secure import secure_aad, require_aead

from .errors import ProtocolError
from .state import ClientState

class WSClient:
    def __init__(self, url: str, session_code: str, role: ROLE, password: bytes, logger):
        self.url = url.rstrip("/")
        self.code = session_code
        self.role = role
        self.peer: ROLE = "bob" if role == "alice" else "alice"
        self.password = password
        self.logger = logger

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
        self.logger.info("client_connected", role=self.role, session=self.code)

    async def _recv_loop(self):
        while self._running and self.ws:
            try:
                raw = await self.ws.recv()
                msg = fuzz_resistant_json_loads(raw)
                if msg.get("proto") != PROTO_NAME or msg.get("ver") != PROTO_VER:
                    self.logger.error("protocol_mismatch", message=msg)
                    continue
                await self._rx_queue.put(msg)
            except Exception as e:
                if self._running:
                    self.logger.error("recv_loop_error", error=str(e))
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
            self.logger.info("peer_connected", role=self.role, peer=self.peer)
            self.state.peer_seq_in = 0
            self.state.peer_conn_id = None
        elif msg_type == "peer_left":
            self.logger.info("peer_disconnected", role=self.role, peer=self.peer)

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

        if self.state.transcript and kind:
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
        response_payload = {}
        if kind == "profile_hello":
            response_payload = {"profiles": SUPPORTED_PROFILES, "min_profile": MIN_PROFILE, "conn_id": secrets.token_hex(8)}
        elif kind == "pake_hello":
            if self._pake_state:
                response_payload = {"msg_b64": b64e(self._pake_state["msg_out"])}
            else:
                return
        elif kind == "hs_hello":
            if self._hs_state:
                response_payload = {"pub_b64": b64e(self._hs_state["pub_raw"]), "nonce_b64": b64e(self._hs_state["nonce"])}
            else:
                return
        await self.send_packet(kind, {"id": req_id, **response_payload}, op="resp")

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
            self.logger.warning("decryption_failed", role=self.role, error=str(e), failures=self.state.decrypt_failures)
            return

        self.state.decrypt_failures = 0
        self.state.recv_seq2 = seq2
        try:
            text = pt.decode("utf-8", errors="replace")
            print(f"[{self.role}] <- {from_role} ({seq2}): {text}")
        except Exception:
            print(f"[{self.role}] <- {from_role} ({seq2}): [binary, {len(pt)} bytes]")

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
            self.logger.info("profile_negotiated", role=self.role, profile=negotiated)

            self.state.transcript = Transcript(profile=negotiated)
            self.state.phase = Phase.PAKE
            self._pake_state = pake_init(self.role, self.password, self.state.sid, negotiated)

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
            self.logger.info("PAKE_SUCCESS", role=self.role, sas6=sas6(self.state.k0, self.state.sid, negotiated))

            self.state.phase = Phase.HANDSHAKING
            self._hs_state = hs_init(self.role, self.state.sid, negotiated, self.state.k0)

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

            exp_peer_hs = hs_auth_tag(self.state.master, self.state.role if self.peer == self.state.role else self.peer, self.state.th, negotiated)
            # NOTE: the original expects peer role; keep correct compare:
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
            self.logger.info("ESTABLISHED", role=self.role, profile=negotiated)

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
