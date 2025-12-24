#!/usr/bin/env bash
set -euo pipefail

echo "Starting relay..."
python -m taccv.taccv41 relay --host 127.0.0.1 --port 8000 &
RELAY_PID=$!
sleep 1

echo "Create a session (copy the session_code):"
SESSION_JSON=$(curl -s -X POST http://127.0.0.1:8000/session)
echo "$SESSION_JSON"
SESSION_CODE=$(python - <<'PY'
import json, os, sys
j=json.loads(sys.stdin.read())
print(j["session_code"])
PY <<< "$SESSION_JSON")

PIN="123456"

echo "Launching clients..."
python -m taccv.taccv41 client --url ws://127.0.0.1:8000 --session "$SESSION_CODE" --role alice --pin "$PIN" --message "alice here" &
A_PID=$!
python -m taccv.taccv41 client --url ws://127.0.0.1:8000 --session "$SESSION_CODE" --role bob --pin "$PIN" --message "bob here" &
B_PID=$!

sleep 6

echo "Cleanup..."
kill "$A_PID" "$B_PID" "$RELAY_PID" 2>/dev/null || true
echo "Done."
