#!/bin/bash
# Launch a llama.cpp HTTP server inside Docker using the downloaded Granite model.

set -euo pipefail

MODEL_PATH=${MODEL_PATH:-.gosecretscanner/models/granite-4.0-micro.Q4_K_M.gguf}
HOST_PORT=${PORT:-8080}
SERVER_PORT=${SERVER_PORT:-8080}
CONTAINER_PORT=${CONTAINER_PORT:-$SERVER_PORT}
CTX_SIZE=${CTX_SIZE:-2048}
IMAGE=${LLAMA_CPP_IMAGE:-ghcr.io/ggerganov/llama.cpp:full}
DETACH=${DETACH:-false}
CONTAINER_NAME=${CONTAINER_NAME:-gosecretscanner-llm}
HOST_NETWORK=${HOST_NETWORK:-false}

if [ ! -f "$MODEL_PATH" ]; then
  echo "Model not found at $MODEL_PATH. Run scripts/download-models.sh first or set MODEL_PATH." >&2
  exit 1
fi

MODEL_DIR=$(cd "$(dirname "$MODEL_PATH")" && pwd)
MODEL_FILE=$(basename "$MODEL_PATH")

DOCKER_ARGS=("-v" "${MODEL_DIR}:/models")

if [ "$HOST_NETWORK" = "true" ]; then
  DOCKER_ARGS+=("--network" "host")
  CONTAINER_PORT=$SERVER_PORT
else
  DOCKER_ARGS+=("-p" "${HOST_PORT}:${CONTAINER_PORT}")
fi

SERVER_CMD=(./server -m "/models/${MODEL_FILE}" --host 0.0.0.0 --port "${SERVER_PORT}" --ctx-size "${CTX_SIZE}" --no-warmup --log-disable)

set -x
if [ "$DETACH" = "true" ]; then
  docker run -d --rm \
    --name "${CONTAINER_NAME}" \
    "${DOCKER_ARGS[@]}" \
    "$IMAGE" \
    "${SERVER_CMD[@]}"
else
  exec docker run --rm \
    "${DOCKER_ARGS[@]}" \
    "$IMAGE" \
    "${SERVER_CMD[@]}"
fi
