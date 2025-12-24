from __future__ import annotations
import threading
from typing import Dict, List
import time
from taccv.protocol.constants import MAX_CONNECTIONS_PER_IP, CONNECTION_RATE_LIMIT

def now() -> float:
    return time.time()

class RateLimiter:
    def __init__(self, logger):
        self.logger = logger
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
                self.logger.warning("dos_protection", reason="max_connections_per_ip", ip=ip)
                return False
            if len(conns) >= CONNECTION_RATE_LIMIT:
                self.logger.warning("dos_protection", reason="connection_rate_limit", ip=ip)
                return False

            conns.append(t)
            self.connections[ip] = conns[-MAX_CONNECTIONS_PER_IP:]
            return True
