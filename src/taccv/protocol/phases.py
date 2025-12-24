from enum import Enum, auto

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
