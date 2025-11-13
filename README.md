# GoSecretScanv2

A fast, concurrent security scanner that detects secrets, API keys, credentials, and security vulnerabilities in your source code.

## Features

- **70+ Detection Patterns**: Comprehensive regex patterns for detecting:
  - Cloud provider credentials (AWS, Azure, GCP)
  - API keys and tokens (GitHub, Slack, JWT)
  - Private keys (SSH, RSA, PGP)
  - Database connection strings
  - Basic authentication credentials
  - Security vulnerabilities (XSS, SQL injection patterns)

- **High Performance**:
  - Pre-compiled regex patterns for fast scanning
  - Concurrent file processing using goroutines
  - Thread-safe operations with proper synchronization

- **Easy to Use**:
  - Zero configuration required
  - Color-coded terminal output
  - Automatic recursive directory scanning

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

### Example Output

```
------------------------------------------------------------------------
Secrets found:
File: /path/to/file.go (Secret)
Line Number: 42
Type: (?i)_(AWS_Key):[\\s'\"=]A[KS]IA[0-9A-Z]{16}[\\s'\"]
Line: const awsKey = "AKIAIOSFODNN7EXAMPLE"

------------------------------------------------------------------------
2 secrets found. Please review and remove them before committing your code.
```

## Detected Patterns

### Cloud Provider Credentials

- **AWS**:
  - Access Key IDs (AKIA...)
  - Secret Access Keys
  - STS Tokens

- **Azure**:
  - Client IDs and Secrets
  - Tenant IDs
  - Subscription IDs
  - Access Keys

- **Google Cloud Platform**:
  - API Keys (AIza...)
  - Application Credentials
  - Service Account Keys
  - Client IDs and Secrets

### Private Keys

- SSH Private Keys
- RSA Private Keys
- PGP Private Keys
- Generic Private Keys (PEM format)

### Authentication & Secrets

- Basic Authentication tokens
- API Keys
- Bearer tokens
- JWT tokens
- Passwords and credentials
- Database connection strings

### Security Vulnerabilities

- Cross-Site Scripting (XSS) patterns
- SQL Injection patterns
- Hardcoded IP addresses
- S3 Bucket URLs

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

```yaml
name: Secret Scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Set up Go
        uses: actions/setup-go@v4
        with:
          go-version: '1.24'

      - name: Install GoSecretScanv2
        run: go install github.com/m1rl0k/GoSecretScanv2@latest

      - name: Run Secret Scanner
        run: gosecretscanner
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

## How It Works

1. **Pattern Compilation**: On startup, all regex patterns are pre-compiled for optimal performance
2. **Directory Walking**: Uses `filepath.Walk` to recursively traverse the directory tree
3. **Concurrent Scanning**: Each file is scanned in a separate goroutine for parallel processing
4. **Thread-Safe Results**: Uses mutex locks to safely collect results from concurrent scans
5. **Pattern Matching**: Each line is checked against all compiled patterns
6. **Result Reporting**: Findings are displayed with file location, line number, and pattern type

## Performance Considerations

- **Pre-compiled Patterns**: Regex patterns are compiled once at startup, not on every match
- **Concurrent Processing**: Multiple files are scanned simultaneously using goroutines
- **Smart Ignoring**: Automatically skips `.git` and `node_modules` directories
- **Memory Efficient**: Streams file contents line-by-line rather than loading entire files

## Limitations

- Currently scans all file types (including binaries)
- No configuration file support yet
- No custom pattern support without code modification
- No allowlist/whitelist for false positives

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Inspired by tools like gitleaks, truffleHog, and git-secrets
- Built with Go's powerful standard library

## Roadmap

- [ ] Configuration file support (YAML/JSON)
- [ ] Custom pattern definitions
- [ ] Multiple output formats (JSON, SARIF)
- [ ] Allowlist/whitelist support
- [ ] Binary file detection and skipping
- [ ] Interactive mode for reviewing findings
- [ ] Entropy-based detection for unknown secrets
- [ ] Docker image for easy deployment

## Support

For bugs and feature requests, please open an issue on [GitHub](https://github.com/m1rl0k/GoSecretScanv2/issues).
