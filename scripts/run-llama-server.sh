#!/bin/bash
# Launch a llama.cpp HTTP server in Docker with correct networking and readiness checks.

set -euo pipefail

# Config
MODEL_PATH=${MODEL_PATH:-.gosecretscanner/models/granite-4.0-micro-Q4_K_M.gguf}
HOST_IP=${HOST_IP:-127.0.0.1}
HOST_PORT=${PORT:-8080}
SERVER_PORT=${SERVER_PORT:-8080}
CONTAINER_PORT=${CONTAINER_PORT:-$SERVER_PORT}
CTX_SIZE=${CTX_SIZE:-2048}
IMAGE=${LLAMA_CPP_IMAGE:-ghcr.io/ggerganov/llama.cpp:server}
DETACH=${DETACH:-false}
CONTAINER_NAME=${CONTAINER_NAME:-gosecretscanner-llm}
HOST_NETWORK=${HOST_NETWORK:-false}
WAIT_READY=${WAIT_READY:-true}
HEALTH_PATH=${HEALTH_PATH:-/health}
WAIT_RETRIES=${WAIT_RETRIES:-60}
WAIT_SLEEP=${WAIT_SLEEP:-2}

if ! command -v docker >/dev/null 2>&1; then
  echo "docker not found in PATH" >&2
  exit 1
fi

# Resolve model path robustly (accept common naming mistakes)
if [ ! -f "$MODEL_PATH" ]; then
  # Try hyphen/dot variant swap around "micro"
  alt_path=$(echo "$MODEL_PATH" | sed 's/micro\.Q/micro-Q/')
  if [ -f "$alt_path" ]; then
    echo "Note: Using model at $alt_path (corrected filename variant)"
    MODEL_PATH="$alt_path"
  else
    # Try to auto-discover in default model dir
    default_dir=".gosecretscanner/models"
    if [ -d "$default_dir" ]; then
      candidate=$(ls -1 "$default_dir"/granite-4.0-micro-*.gguf 2>/dev/null | grep -E 'Q4_K_M|Q4_1|Q4_0|Q3_K_M' | head -n1 || true)
      if [ -n "$candidate" ] && [ -f "$candidate" ]; then
        echo "Note: Auto-discovered model: $candidate"
        MODEL_PATH="$candidate"
      fi
    fi
  fi
fi

if [ ! -f "$MODEL_PATH" ]; then
  echo "Model not found at $MODEL_PATH. Run scripts/download-models.sh first or set MODEL_PATH." >&2
  exit 1
fi

MODEL_DIR=$(cd "$(dirname "$MODEL_PATH")" && pwd)
MODEL_FILE=$(basename "$MODEL_PATH")

# Prepare docker args
DOCKER_ARGS=("-v" "${MODEL_DIR}:/models:ro")

if [ "$HOST_NETWORK" = "true" ]; then
  DOCKER_ARGS+=("--network" "host")
  CONTAINER_PORT=$SERVER_PORT
  ENDPOINT="http://127.0.0.1:${SERVER_PORT}"
else
  DOCKER_ARGS+=("-p" "${HOST_IP}:${HOST_PORT}:${CONTAINER_PORT}")
  ENDPOINT="http://${HOST_IP}:${HOST_PORT}"
fi

# Remove old container with same name if present
docker rm -f "${CONTAINER_NAME}" >/dev/null 2>&1 || true

# Command to run inside container (entrypoint is already /app/llama-server)
SERVER_CMD=(-m "/models/${MODEL_FILE}" --host 0.0.0.0 --port "${SERVER_PORT}" -c "${CTX_SIZE}")

set -x
if [ "$DETACH" = "true" ]; then
  docker run -d --rm \
    --name "${CONTAINER_NAME}" \
    "${DOCKER_ARGS[@]}" \
    "$IMAGE" \
    "${SERVER_CMD[@]}"
  set +x

  if [ "$WAIT_READY" = "true" ]; then
    echo "Waiting for llama.cpp server at ${ENDPOINT}${HEALTH_PATH} ..."
    for i in $(seq 1 "$WAIT_RETRIES"); do
      if curl -fsS "${ENDPOINT}${HEALTH_PATH}" >/dev/null 2>&1; then
        echo "Ready: ${ENDPOINT}"
        # Export to GitHub Actions environment if available
        if [ -n "${GITHUB_ENV:-}" ]; then
          echo "GOSECRETSCANNER_LLM_SERVER=${ENDPOINT}" >> "$GITHUB_ENV"
        fi
        echo "LLM_ENDPOINT=${ENDPOINT}"
        exit 0
      fi
      sleep "$WAIT_SLEEP"
    done
    echo "Server did not become ready in time"
    docker ps -a || true
    docker logs --tail=200 "${CONTAINER_NAME}" || true
    exit 1
  else
    echo "Started: ${ENDPOINT}"
  fi
else
  # Foreground mode
  exec docker run --rm \
    --name "${CONTAINER_NAME}" \
    "${DOCKER_ARGS[@]}" \
    "$IMAGE" \
    "${SERVER_CMD[@]}"
fi
