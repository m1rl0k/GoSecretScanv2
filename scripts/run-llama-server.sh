#!/bin/bash
# Launch a llama.cpp HTTP server inside Docker using the downloaded Granite model.

set -euo pipefail

MODEL_PATH=${MODEL_PATH:-.gosecretscanner/models/granite-4.0-micro.Q4_K_M.gguf}
PORT=${PORT:-8080}
CTX_SIZE=${CTX_SIZE:-2048}
IMAGE=${LLAMA_CPP_IMAGE:-ghcr.io/ggerganov/llama.cpp:full}

if [ ! -f "$MODEL_PATH" ]; then
  echo "Model not found at $MODEL_PATH. Run scripts/download-models.sh first or set MODEL_PATH." >&2
  exit 1
fi

MODEL_DIR=$(cd "$(dirname "$MODEL_PATH")" && pwd)
MODEL_FILE=$(basename "$MODEL_PATH")

set -x
exec docker run --rm \
  -p "${PORT}:8080" \
  -v "${MODEL_DIR}:/models" \
  "$IMAGE" \
  ./server -m "/models/${MODEL_FILE}" --host 0.0.0.0 --port 8080 --ctx-size "${CTX_SIZE}" --no-warmup --log-disable
