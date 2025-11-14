# GoSecretScanv2

GoSecretScanv2 is a fast secret scanner for code. It uses deterministic patterns with entropy and light context. LLM verification is optional.

## Overview

- Detects credentials, API keys, private keys, and connection strings
- CLI and GitHub Actions support
- Sensible defaults; no services required
- Optional local LLM verification for triage


### Optional: LLM verification

```bash
./scripts/download-models.sh
./scripts/run-llama-server.sh   # exposes http://localhost:8080
./gosecretscanner --llm

# Optionally point to a remote/local endpoint
export GOSECRETSCANNER_LLM_ENDPOINT=http://localhost:8080
```

## Installation

### From Source

```bash
git clone https://github.com/m1rl0k/GoSecretScanv2.git
cd GoSecretScanv2
go build -o gosecretscanner main.go
```

### Using Go Install

```bash
go install github.com/m1rl0k/GoSecretScanv2@latest
```

### Using Docker

```bash
# Build the Docker image
docker build -t gosecretscanner .

# Run the scanner on current directory
docker run --rm -v $(pwd):/workspace gosecretscanner

# Run on a specific directory
docker run --rm -v /path/to/scan:/workspace gosecretscanner

```

### GitHub Actions

Action inputs (when using `enable-llm`):

- `enable-llm`: set to `'true'` to download Granite, launch llama.cpp via Docker, and run the scan with `--llm`.
- `model-path`: overrides the GGUF path (relative to the action directory by default).
- `llm-endpoint` / `llm-port`: control how the scanner reaches the llama.cpp HTTP server.
- `llama-image`: change the Docker image used to serve Granite (default `ghcr.io/ggerganov/llama.cpp:full`).
- `manage-llm-server`: set to `'false'` when your workflow spins up the llama.cpp container via `services:` (as shown below).

Example workflow step:

```yaml
      - name: Run GoSecretScan Action with LLM
        uses: ./
        with:
          scan-path: '.'
          fail-on-secrets: 'false'
          enable-llm: 'true'
          llm-port: '8080'
          manage-llm-server: 'false'
```

## Usage

Navigate to the directory you want to scan and run:

```bash
cd /path/to/your/project
./gosecretscanner
```

The scanner will:
1. Recursively scan all files in the current directory
2. Skip `.git` and `node_modules` directories
3. Report any secrets found with file location and line numbers
4. Exit with code 1 if secrets are found, 0 otherwise



## Integration with CI/CD

### Pre-commit Hook

Add to `.git/hooks/pre-commit`:

```bash
#!/bin/bash
./gosecretscanner
if [ $? -ne 0 ]; then
    echo "Secret scan failed! Please remove secrets before committing."
    exit 1
fi
```

### GitHub Actions

The repository also exposes a reusable GitHub Action for CI pipelines:

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  secret-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      # Use GoSecretScan as a reusable action
      - name: Run Secret Scanner
        uses: m1rl0k/GoSecretScanv2@main
        with:
          scan-path: '.'
          fail-on-secrets: 'true'
```


## Development

### Building

```bash
go build -o gosecretscanner main.go
```

### Running Tests

```bash
go test ./...
```

### Code Formatting

```bash
gofmt -w .
```


## Current Limitations

- Binary files are not automatically filtered.
- Configuration files for custom settings are not yet supported.
- Custom patterns require code changes.
- Allowlists/whitelists must currently be handled outside the tool.

## Contributing

Contributions are welcome via pull requests.

## License

This project is licensed under the MIT License; see [LICENSE](LICENSE) for details.

## Support

Please open an issue on [GitHub](https://github.com/m1rl0k/GoSecretScanv2/issues) for bugs or feature requests.
