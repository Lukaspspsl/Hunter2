#!/usr/bin/env bash
# Hunter 2 — start llama.cpp server on a RunPod GPU pod.
#
# Usage:
#   ssh into the pod, drop this file at /workspace/runpod_start.sh,
#   chmod +x it, run it. The Gemma4 26B Q4_K_M weights are expected
#   at /workspace/models/ (upload once via scp or `runpodctl send`).
#
# After the server boots, set on Railway:
#   RUNPOD_POD_IP = <pod public IP>
#   LLM_BASE_URL  = http://${RUNPOD_POD_IP}:8090/v1
set -euo pipefail

MODEL_PATH="${MODEL_PATH:-/workspace/models/gemma-4-26B-A4B-it-UD-Q4_K_M.gguf}"
PORT="${PORT:-8090}"
CTX_SIZE="${CTX_SIZE:-65536}"
N_GPU_LAYERS="${N_GPU_LAYERS:-99}"
PARALLEL="${PARALLEL:-4}"

if [[ ! -f "$MODEL_PATH" ]]; then
    echo "model not found at $MODEL_PATH — upload first" >&2
    exit 1
fi

cd /workspace
echo "starting llama-server on :${PORT} with ${MODEL_PATH}"
exec ./llama-server \
    --model "$MODEL_PATH" \
    --host 0.0.0.0 \
    --port "$PORT" \
    --ctx-size "$CTX_SIZE" \
    --n-gpu-layers "$N_GPU_LAYERS" \
    --parallel "$PARALLEL"
