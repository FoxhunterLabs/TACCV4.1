#!/usr/bin/env bash
set -euo pipefail
SESSION="${1:-ABCDEFGH}"
PIN="${2:-123456}"
python -m taccv.taccv41 client --url ws://127.0.0.1:8000 --session "$SESSION" --role bob --pin "$PIN" --message "hello from bob"
