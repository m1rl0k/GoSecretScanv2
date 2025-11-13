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

# Granite 4.0 Micro GGUF (default: Q4_K_M ~2.1GB)
REPO="ibm-granite/granite-4.0-micro-GGUF"
FILENAME="${FILENAME:-granite-4.0-micro-Q4_K_M.gguf}"
GRANITE_URL="https://huggingface.co/${REPO}/resolve/main/${FILENAME}"
GRANITE_FILE="$MODELS_DIR/${FILENAME}"

# If present and non-empty, assume OK
if [ -s "$GRANITE_FILE" ]; then
    echo "✓ Granite model already present: $GRANITE_FILE"
else
    echo "Downloading $FILENAME (this can be ~2.1GB; ensure your CI has cache or enough space)..."
    tmp_file="${GRANITE_FILE}.partial"

    # Build curl headers/args
    CURL_ARGS=("-L" "--fail" "--retry" "5" "--retry-delay" "2" "--progress-bar")
    if [ -n "${HF_TOKEN:-}" ]; then
        CURL_ARGS+=("-H" "Authorization: Bearer ${HF_TOKEN}")
    fi

    if command -v curl >/dev/null 2>&1; then
        curl "${CURL_ARGS[@]}" -o "$tmp_file" "$GRANITE_URL"
    elif command -v wget >/dev/null 2>&1; then
        WGET_ARGS=("--tries=5" "--timeout=30" "--show-progress")
        if [ -n "${HF_TOKEN:-}" ]; then
            WGET_ARGS+=("--header=Authorization: Bearer ${HF_TOKEN}")
        fi
        wget "${WGET_ARGS[@]}" "$GRANITE_URL" -O "$tmp_file"
    else
        echo "Error: Neither curl nor wget found. Please install one of them."
        exit 1
    fi

    # Basic validation: non-empty and GGUF magic
    if [ ! -s "$tmp_file" ]; then
        echo "Error: Downloaded file is empty. URL may be wrong or gated." >&2
        rm -f "$tmp_file"
        exit 1
    fi
    magic=$(head -c 4 "$tmp_file" | tr -d '\0') || magic=""
    if [ "${magic}" != "GGUF" ]; then
        echo "Error: File does not look like GGUF (magic='${magic}'). Check URL or HF_TOKEN." >&2
        echo "First bytes:"; xxd -l 16 "$tmp_file" || true
        rm -f "$tmp_file"
        exit 1
    fi

    mv -f "$tmp_file" "$GRANITE_FILE"
    echo "✓ Downloaded: $GRANITE_FILE ($(du -h "$GRANITE_FILE" | cut -f1))"
fi

# BGE Embeddings Model (ONNX)
echo ""
echo "Downloading BGE-small-en-v1.5 ONNX model (~100MB)..."

BGE_MODEL_URL="https://huggingface.co/BAAI/bge-small-en-v1.5/resolve/main/onnx/model.onnx"
BGE_TOKENIZER_URL="https://huggingface.co/BAAI/bge-small-en-v1.5/resolve/main/tokenizer.json"
BGE_MODEL_FILE="$MODELS_DIR/bge-small-en-v1.5.onnx"
BGE_TOKENIZER_FILE="$MODELS_DIR/bge-tokenizer.json"

if [ -s "$BGE_MODEL_FILE" ] && [ -s "$BGE_TOKENIZER_FILE" ]; then
    echo "✓ BGE model and tokenizer already present"
else
    echo "Downloading BGE ONNX model..."
    tmp_model="${BGE_MODEL_FILE}.partial"
    tmp_tokenizer="${BGE_TOKENIZER_FILE}.partial"

    CURL_ARGS=("-L" "--fail" "--retry" "5" "--retry-delay" "2" "--progress-bar")
    if [ -n "${HF_TOKEN:-}" ]; then
        CURL_ARGS+=("-H" "Authorization: Bearer ${HF_TOKEN}")
    fi

    if command -v curl >/dev/null 2>&1; then
        curl "${CURL_ARGS[@]}" -o "$tmp_model" "$BGE_MODEL_URL"
        curl "${CURL_ARGS[@]}" -o "$tmp_tokenizer" "$BGE_TOKENIZER_URL"
    elif command -v wget >/dev/null 2>&1; then
        WGET_ARGS=("--tries=5" "--timeout=30" "--show-progress")
        if [ -n "${HF_TOKEN:-}" ]; then
            WGET_ARGS+=("--header=Authorization: Bearer ${HF_TOKEN}")
        fi
        wget "${WGET_ARGS[@]}" "$BGE_MODEL_URL" -O "$tmp_model"
        wget "${WGET_ARGS[@]}" "$BGE_TOKENIZER_URL" -O "$tmp_tokenizer"
    else
        echo "Error: Neither curl nor wget found."
        exit 1
    fi

    if [ ! -s "$tmp_model" ] || [ ! -s "$tmp_tokenizer" ]; then
        echo "Error: Downloaded files are empty."
        rm -f "$tmp_model" "$tmp_tokenizer"
        exit 1
    fi

    mv -f "$tmp_model" "$BGE_MODEL_FILE"
    mv -f "$tmp_tokenizer" "$BGE_TOKENIZER_FILE"
    echo "✓ Downloaded BGE model: $BGE_MODEL_FILE ($(du -h "$BGE_MODEL_FILE" | cut -f1))"
    echo "✓ Downloaded BGE tokenizer: $BGE_TOKENIZER_FILE"
fi

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
