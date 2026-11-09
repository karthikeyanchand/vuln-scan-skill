#!/usr/bin/env bash
# Serve Antares-1B locally on Apple Silicon with an OpenAI-compatible
# /v1/completions endpoint on 127.0.0.1:8000. Leave this running in its own terminal.
#
# Bound to localhost on purpose: the code you scan is sent to this server.
set -euo pipefail

MODEL_DIR="${ANTARES_MODEL_DIR:-$HOME/models/antares-1b-mlx}"
PORT="${ANTARES_PORT:-8000}"

if [[ ! -d "$MODEL_DIR" ]]; then
  echo "No model at $MODEL_DIR. Run ./setup/setup_mac.sh --model first." >&2
  exit 1
fi

echo "Serving $MODEL_DIR on http://127.0.0.1:$PORT/v1/completions (Ctrl+C to stop)"
exec mlx_lm.server --model "$MODEL_DIR" --host 127.0.0.1 --port "$PORT"
