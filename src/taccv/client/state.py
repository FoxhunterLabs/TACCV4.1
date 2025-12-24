from __future__ import annotations
from dataclasses import dataclass, field
from collections import defaultdict
from typing import Optional, Dict, List, Any
from taccv.protocol.constants import ROLE
from taccv.protocol.phases import Phase
from taccv.protocol.transcript import Transcript

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
