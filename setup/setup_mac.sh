#!/usr/bin/env bash
# One-time setup for the vuln-scan workshop on an Apple Silicon Mac (M1 or later).
#
#   ./setup/setup_mac.sh            scanners + Antares CLI + MLX
#   ./setup/setup_mac.sh --model    also download and convert Antares-1B (needs approved HF access)
#
# Safe to run more than once.
set -euo pipefail

MODEL_DIR="${ANTARES_MODEL_DIR:-$HOME/models/antares-1b-mlx}"
HF_REPO="${ANTARES_HF_REPO:-fdtn-ai/antares-1b}"

say() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }

if [[ "$(uname -s)" != "Darwin" || "$(uname -m)" != "arm64" ]]; then
  echo "This script targets Apple Silicon macOS. On Linux with a GPU, serve Antares with vLLM instead (see README)." >&2
  exit 1
fi

command -v brew >/dev/null || { echo "Install Homebrew first: https://brew.sh" >&2; exit 1; }

say "Scanners: semgrep, gitleaks, ripgrep, tree, uv, node"
brew install semgrep gitleaks ripgrep tree uv node

say "Python tools (isolated with uv): pip-audit, Antares CLI, MLX LM, Hugging Face CLI"
uv tool install --upgrade pip-audit
uv tool install --upgrade cisco-antares-cli
uv tool install --upgrade mlx-lm
uv tool install --upgrade "huggingface_hub[cli]"
uv tool update-shell >/dev/null 2>&1 || true

say "Antares profile"
mkdir -p "$HOME/.antares"
PROFILE="$HOME/.antares/profiles.toml"
if grep -q '^\[profiles.local-mlx\]' "$PROFILE" 2>/dev/null; then
  echo "profile 'local-mlx' already exists in $PROFILE (left unchanged)"
else
  sed "s#__MODEL_DIR__#$MODEL_DIR#g" "$(dirname "$0")/profiles.toml.example" >> "$PROFILE"
  echo "added profile 'local-mlx' to $PROFILE"
fi

if [[ "${1:-}" == "--model" ]]; then
  say "Antares-1B weights -> MLX ($MODEL_DIR)"
  echo "The official weights are gated. Request access on https://huggingface.co/$HF_REPO first,"
  echo "then log in with a read token when prompted."
  hf auth whoami >/dev/null 2>&1 || hf auth login
  if [[ -d "$MODEL_DIR" ]]; then
    echo "$MODEL_DIR already exists, skipping conversion"
  else
    mkdir -p "$(dirname "$MODEL_DIR")"
    # Convert the OFFICIAL checkpoint locally rather than trusting a third-party re-upload.
    mlx_lm.convert --hf-path "$HF_REPO" --mlx-path "$MODEL_DIR"
  fi
fi

say "Done. Next:"
cat <<EOF
  1. Start the model server (separate terminal):  ./setup/serve_antares_mlx.sh
  2. Check everything:                            ./setup/check_setup.sh
  3. In your project, ask Codex:                  \$vuln-scan scan ./path/to/repo
EOF
