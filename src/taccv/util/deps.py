from __future__ import annotations

def check_dependencies() -> tuple[bool, list[str]]:
    missing = []
    for mod, pipname in [
        ("websockets", "websockets"),
        ("fastapi", "fastapi"),
        ("uvicorn", "uvicorn[standard]"),
        ("spake2", "spake2"),
        ("cryptography", "cryptography"),
        ("structlog", "structlog"),
        ("pydantic", "pydantic"),
    ]:
        try:
            __import__(mod)
        except ImportError:
            missing.append(pipname)
    return (len(missing) == 0, missing)
