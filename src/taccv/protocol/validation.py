from __future__ import annotations
import json
from typing import Any, Dict
from .constants import MAX_MSG_BYTES, MAX_JSON_DEPTH, MAX_JSON_KEYS

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

def json_dumps_sorted(o: Any) -> str:
    return json.dumps(o, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
