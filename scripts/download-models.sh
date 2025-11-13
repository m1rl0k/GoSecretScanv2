#!/bin/bash
# Script to download AI models for GoSecretScanv2

set -e

MODELS_DIR="${MODELS_DIR:-.gosecretscanner/models}"
CACHE_DIR="${HOME}/.cache/gosecretscanner"

echo "=== GoSecretScanv2 Model Downloader ==="
echo ""

# Create directories
mkdir -p "$MODELS_DIR"
mkdir -p "$CACHE_DIR"

# Granite 4.0 Micro GGUF
GRANITE_URL="https://huggingface.co/ibm-granite/granite-4.0-micro-GGUF/resolve/main/granite-4.0-micro.Q4_K_M.gguf"
GRANITE_FILE="$MODELS_DIR/granite-4.0-micro.Q4_K_M.gguf"

if [ -f "$GRANITE_FILE" ]; then
    echo "✓ Granite 4.0 Micro model already downloaded"
else
    echo "Downloading Granite 4.0 Micro (~450MB)..."
    if command -v curl &> /dev/null; then
        curl -L "$GRANITE_URL" -o "$GRANITE_FILE" --progress-bar
    elif command -v wget &> /dev/null; then
        wget "$GRANITE_URL" -O "$GRANITE_FILE" --show-progress
    else
        echo "Error: Neither curl nor wget found. Please install one of them."
        exit 1
    fi
    echo "✓ Granite 4.0 Micro downloaded"
fi

# BGE Embeddings Model (Optional - for future use)
# For now, we use hash-based embeddings
echo ""
echo "Note: Using hash-based embeddings (no download needed)"
echo "To enable BGE embeddings, download BAAI/bge-small-en-v1.5 ONNX model"

echo ""
echo "=== Download Complete ==="
echo "Models directory: $MODELS_DIR"
echo ""
echo "To use the LLM verification:"
echo "  export GOSECRETSCANNER_LLM_ENABLED=true"
echo "  export GOSECRETSCANNER_MODEL_PATH=$GRANITE_FILE"
echo ""
echo "Or use the --llm flag:"
echo "  ./gosecretscanner --llm --model-path=$GRANITE_FILE"
