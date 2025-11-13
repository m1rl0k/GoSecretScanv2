package main

import (
	"bufio"
	"flag"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"

	"github.com/m1rl0k/GoSecretScanv2/pkg/verification"
)

const (
	ResetColor       = "\033[0m"
	RedColor         = "\033[31m"
	GreenColor       = "\033[32m"
	YellowColor      = "\033[33m"
	SeparatorLine    = "------------------------------------------------------------------------"
	maxFileSizeBytes = 5 * 1024 * 1024 // 5MB cap to skip huge/binary blobs
)

var (
	secretPatterns = []string{
		`(?i)_(Private_Key):[-]{5}BEGIN\\s(?:[DR]SA|OPENSSH|EC|PGP)\\sPRIVATE\\sKEY(?:\\sBLOCK)?[-]{5}`,
		`(?i)_(AWS_Key):[\\s'\"=]A[KS]IA[0-9A-Z]{16}[\\s'\"]`,
		`(?i)_(AWS_Key_line_end):[\\s=]A[KS]IA[0-9A-Z]{16}$`,
		`(?i)_(Slack_token):xox[pboa]-[0-9]{11,12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32}`,
		`(?i)_(Basic_Auth):Authorization:\\sBasic\\s(?:[a-zA-Z0-9\\+/]{4})*(?:[a-zA-Z0-9\\+/]{3}=|[a-zA-Z0-9\\+/]{2}==)?(?:$|[\\s;'\"])`,
		`(?i)_(Basic_Auth_Only_Pattern):Basic\\s(?:[a-zA-Z0-9\\+/]{4})*(?:[a-zA-Z0-9\\+/]{3}=|[a-zA-Z0-9\\+/]{2}==)?(?:$|[\\s;'\"])`,
		`(?i)(aws_secret_access_key|aws_access_key_id|password|pass|passwd|user|username|key|apikey|accesskey|secret)[\\s\\r\\n]*=[\\s\\r\\n]*('[^']*'|\"[^\"]*\")`,
		`(?i)(client_id|client_secret|subscription_id|tenant_id|access_key|account_key|primary_access_key|secondary_access_key)[\\s\\r\\n]*=[\\s\\r\\n]*('[^']*'|\"[^\"]*\")`,
		`(?i)provider\\s*\"azurerm\"\\s*{\\s*features\\s*{\\s*}\\s*subscription_id\\s*=\\s*\"([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})\"\\s*tenant_id\\s*=\\s*\"([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})\"\\s*client_id\\s*=\\s*\"([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})\"\\s*client_secret\\s*=\\s*\"([^\\s]+)\"\\s*}`,
		`(?i)(api|app|client)_?(key|id|secret)(\s*[:=]\s*|\s*['"])([\w\-\/+]{10,})(\s*['"])`,
		`(?i)(username|password)\s*=\s*('[^']*'|\"[^\"]*\")`,
		`(?i)aws_access_key_id\s*=\s*"AKIA[0-9A-Z]{16}"`,
		`(?i)aws_secret_access_key\s*=\s*"[0-9a-zA-Z/+]{40}"`,
		`(?i)api_key(?:\s*[:=]\s*|\s*["'\s])?([a-zA-Z0-9_\-]{32,})`,
		`(?i)password(?:\s*[:=]\s*|\s*["'\s])?([a-zA-Z0-9!@#$%^&*()_+]{8,})`,
		`(?i)azure_client_(?:id|secret)\s*=\s*"[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}"`,
		`(?i)azure_tenant_id\s*=\s*"[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}"`,
		`(?i)azure_subscription_id\s*=\s*"[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}"`,
		`(?i)google_application_credentials\s*=\s*"([a-zA-Z0-9\-]+\.json)"`,
		`(?i)google_client_(?:id|secret)\s*=\s*"([0-9]{12}-[a-zA-Z0-9_]{32})"`,
		`(?i)google_project(?:\s*[:=]\s*|\s*["'\s])?([a-z][a-z0-9-]{4,28}[a-z0-9])`,
		`(?i)google_credentials(?:\s*[:=]\s*|\s*["'\s])?([a-zA-Z0-9\-]+\.json)"`,
		`(?i)private_key(?:_id)?\s*=\s*"([0-9a-f]{64})"`,
		`(?i)client_email\s*=\s*"([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[A-Z]{2,})"`,
		`(?i)client_id\s*=\s*"([0-9]{12}-[a-zA-Z0-9_]{32})"`,
		`(?i)client_secret\s*=\s*"([a-zA-Z0-9_]{24})"`,
		`(?i)client_x509_cert_url\s*=\s*"(https://[a-z0-9\-]+\.googleusercontent\.com/[^"']{1,200})"`,
		`(?i)token_uri\s*=\s*"(https://(?:accounts\.)?google\.com/o/oauth2/token)"`,
		`(?i)auth_uri\s*=\s*"(https://(?:accounts\.)?google\.com/o/oauth2/auth)"`,
		`(?i)_(AWS_STS_Token):FQoG.*[^\\w]`,                                                                                               // AWS Security Token Service (STS) token
		`(?i)_(AWS_Access_Key_ID):[^\\w]AKIA[0-9A-Z]{16}[^\\w]`,                                                                           // AWS access key ID
		`(?i)_(API_Key):[^\\w]Bearer [0-9a-f]{32}`,                                                                                        // API key
		`(?i)_(AWS_Secret_Key):[\\s'\"=]AKIA[0-9A-Z]{16}[\\s'\"$]`,                                                                        // AWS secret access key
		`(?i)_(Basic_Auth2):Authorization:\\sBasic\\s(?:[a-zA-Z0-9\\+/]{4})*(?:[a-zA-Z0-9\\+/]{3}=|[a-zA-Z0-9\\+/]{2}==)?(?:$|[\\s;'\"])`, // Basic auth token
		`(?i)_(SSH_Key):-{5}BEGIN\\s(?:[DR]SA|OPENSSH|EC|PGP)\\sPRIVATE\\sKEY(?:\\sBLOCK)?-{5}`,                                           // SSH private key
		`(?i)_(RSA_Key):-{5}BEGIN\\sRSA\\sPRIVATE\\sKEY(?:\\sBLOCK)?-{5}`,                                                                 // RSA private key
		`(?i)_(Private_Key):-----BEGIN PRIVATE KEY-----[^-]+-----END PRIVATE KEY-----`,                                                    // Private key
		`(?i)_(PGP_Private_Key):-----BEGIN PGP PRIVATE KEY BLOCK----[^-]+-----END PGP PRIVATE KEY BLOCK-----`,                             // PGP private key
		`(?i)_(GCP_API_Key):[^\\w]AIza[0-9A-Za-z_-]{35}[^\\w]`,                                                                            // Google Cloud Platform (GCP) API key
		`(?i)_(SecretsAWS):[^\\w](aws_secret_access_key|aws_access_key_id|password|pass|passwd|user|username|key|apikey|accesskey|secret)[\\s\\r\\n]*=[\\s\\r\\n]*('[^']*'|\"[^\"]*\")[^\\w]`,
		`(?i)_(SecretsAZURE):[^\\w](client_id|client_secret|subscription_id|tenant_id|access_key|account_key|primary_access_key|secondary_access_key)[\\s\\r\\n]*=[\\s\\r\\n]*('[^']*'|\"[^\"]*\")[^\\w]`, // Azure secret
		`(?i)_(GitHub_API_Token):[^\\w]ghp_[A-Za-z0-9_]{30,40}`, // GitHub API token
		`(?i)_(Keys):(?:(?:a(?:ws|ccess|p(?:i|p(?:lication)?)))|private|se(?:nsitive|cret))[\\s_-]?key\\s{1,20}[=:]{1,2}\\s{0,20}['\"]?(?:[^\\sa-z;'\",\\/._-][a-z0-9!?$)=<\/>%@#*&{}_^-]{0,1000})[\\s;'\",]`,
		`(?i)_(Keys_no_space):(?:(?:a(?:ws|ccess|p(?:i|p(?:lication)?)))|private|se(?:nsitive|cret))[\\s_-]?key[=:]{1,2}\\s{0,20}['\"]?(?:[^\\sa-z;',\\/._-][a-z0-9!?$)=<\/>%@#*&{}_^-]{0,1000})[\\s;',]`,
		`(?i)_(Password_Generic_with_quotes):(?:(?:pass(?:w(?:or)?d)?)|(?:p(?:s)?w(?:r)?d)|secret)['\"]?\\s{0,20}[=:]{1,3}\\s{0,20}[@]?['\"]([^\\sa-z;'\",\\/._-][a-z0-9!?$)=<\/>%@#*&{}_^-]{0,45})['\"]`,
		`(?i)_(Password_equal_no_quotes):(?:(?:pass(?:w(?:or)?d)?)|(?:p(?:s)?w(?:r)?d)|secret)\s{0,20}[=]\s{0,20}([a-z0-9!?$)=<\/>%@#*&{}_^-]{0,45}[^\\sa-z;',\\/._-][a-z0-9!?$)=<\/>%@#*&{}_^-]{0,45})(?:(?:<\/)|[\s;',]|$)`,
		`(?i)_(Password_value):(?:(?:pass(?:w(?:or)?d)?)|(?:p(?:s)?w(?:r)?d)|secret).{0,10}value[=]['\"]([^\\sa-z;'\",\\/._-][a-z0-9!?$)=<\/>%@#*&{}_^-]{0,45})['\"]`,
		`(?i)_(Password_primary):(?:(?:pass(?:w(?:or)?d)?)|(?:p(?:s)?w(?:r)?d)|secret)\\sprimary[=]['\"]([^\\sa-z;'\",\\/._-][a-z0-9!?$)=<\/>%@#*&{}_^-]{0,45})(?:['"\\s;,\"]|$)`,
		`(?i)encryPublicKey\s*=\s*\"([A-Za-z0-9+/=\r\n]+)\"`,
		`(?i)decryPrivateKey\s*=\s*\"([A-Za-z0-9+/=\r\n]+)\"`,
		`(?i)_(GCP_API_Key2):\\bAIza[0-9A-Za-z_-]{29,45}\\b`,
		`(?i)_(Stripe_Secret):\\bsk_(?:live|test)_[0-9A-Za-z]{24,}\\b`,
		`(?i)_(Slack_Token_Generic):\\bxox(?:p|b|o|a|r)-[0-9A-Za-z-]{10,}\\b`,
		`(?i)_(Private_Key_Begin):^-{5}BEGIN\\sPRIVATE\\sKEY-{5}`,
		`(?i)_(DB_URI_With_Creds):\\b(?:postgres|mysql|mariadb|mongodb|redis)://[^:\\s]+:[^@\\s]+@[^/\\s]+`,
		`(?i)_(AWS_AKIA):\\bAKIA[0-9A-Z]{16}\\b`,
		`(?i)_(GitHub_PAT):\\bghp_[A-Za-z0-9]{30,}\\b`,
	}
	// Pre-compiled regex patterns for performance
	compiledPatterns []*regexp.Regexp

	bracePlaceholderPattern   = regexp.MustCompile(`\$\{[^}]+\}`)
	percentPlaceholderPattern = regexp.MustCompile(`%[A-Za-z0-9_]+%`)
	dollarPlaceholderPattern  = regexp.MustCompile(`\$[A-Z0-9_]+`)
)

type Secret struct {
	File       string
	LineNumber int
	Line       string
	Type       string
	Confidence string  // low, medium, high, critical
	Entropy    float64 // Shannon entropy of the matched secret
	Context    string  // Additional context (e.g., "test file", "comment", "variable")
}

var (
	// CLI flags
	enableLLM           = flag.Bool("llm", false, "Enable LLM-powered verification")
	modelPath           = flag.String("model-path", ".gosecretscanner/models/granite-4.0-micro-Q4_K_M.gguf", "Path to LLM model")
	embeddingsPath      = flag.String("embeddings-path", "", "Path to embeddings models directory (defaults to .gosecretscanner/models)")
	dbPath              = flag.String("db-path", ".gosecretscanner/findings.db", "Path to vector store database")
	similarityThreshold = flag.Float64("similarity", 0.8, "Similarity threshold for vector search")
	keepVectorStore     = flag.Bool("keep-vector-store", false, "Keep the vector store database after the run")
	llmEndpoint         = flag.String("llm-endpoint", "http://localhost:8080", "LLM server endpoint (llama.cpp HTTP API)")
)

func init() {
	additionalPatterns := AdditionalSecretPatterns()
	secretPatterns = append(secretPatterns, additionalPatterns...)

	// Pre-compile all regex patterns for performance
	compiledPatterns = make([]*regexp.Regexp, len(secretPatterns))
	for i, pattern := range secretPatterns {
		compiledPatterns[i] = regexp.MustCompile(pattern)
	}
}

func main() {
	// Parse CLI flags
	flag.Parse()

	// Initialize verification pipeline if LLM is enabled
	var pipeline *verification.Pipeline
	if *enableLLM {
		config := &verification.Config{
			Enabled:             true,
			DBPath:              *dbPath,
			ModelPath:           *modelPath,
			EmbeddingsPath:      *embeddingsPath,
			SimilarityThreshold: float32(*similarityThreshold),
			EphemeralStore:      !*keepVectorStore,
			LLMEndpoint:         *llmEndpoint,
		}

		var err error
		pipeline, err = verification.NewPipeline(config)
		if err != nil {
			fmt.Printf("%sWarning: Failed to initialize LLM pipeline: %v%s\n", YellowColor, err, ResetColor)
			fmt.Printf("%sContinuing with standard detection only...%s\n\n", YellowColor, ResetColor)
			pipeline = nil
		} else {
			fmt.Printf("%sLLM verification enabled%s\n\n", GreenColor, ResetColor)
			defer pipeline.Close()
		}
	}

	dir, err := os.Getwd()
	if err != nil {
		fmt.Println("Error getting current working directory:", err)
		os.Exit(1)
	}

	var secretsFound []Secret
	var wg sync.WaitGroup
	var mu sync.Mutex

	// Bounded worker pool for stable scanning on large repos
	workers := runtime.NumCPU() * 4
	if workers < 8 {
		workers = 8
	}
	if workers > 64 {
		workers = 64
	}
	sem := make(chan struct{}, workers)

	err = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			if shouldIgnoreDir(path) {
				return filepath.SkipDir
			}
			return nil
		}
		if shouldIgnoreFile(info) {
			return nil
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(p string) {
			defer func() { <-sem; wg.Done() }()
			secrets, err := scanFileForSecrets(p, pipeline)
			if err != nil {
				fmt.Printf("Error scanning file %s: %v\n", p, err)
				return
			}
			mu.Lock()
			secretsFound = append(secretsFound, secrets...)
			mu.Unlock()
		}(path)
		return nil
	})
	if err != nil {
		fmt.Println("Error walking the directory:", err)
		os.Exit(1)
	}

	wg.Wait()

	if len(secretsFound) > 0 {
		fmt.Printf("\n%s%s%s\n", YellowColor, SeparatorLine, ResetColor)
		fmt.Printf("%sSecrets found:%s\n", RedColor, ResetColor)

		// Group by confidence level
		critical := []Secret{}
		high := []Secret{}
		medium := []Secret{}

		for _, secret := range secretsFound {
			switch secret.Confidence {
			case "critical":
				critical = append(critical, secret)
			case "high":
				high = append(high, secret)
			case "medium":
				medium = append(medium, secret)
			}
		}

		// Display critical findings first
		if len(critical) > 0 {
			fmt.Printf("\n%s=== CRITICAL FINDINGS ===%s\n", RedColor, ResetColor)
			for _, secret := range critical {
				displaySecret(secret)
			}
		}

		// Then high confidence
		if len(high) > 0 {
			fmt.Printf("\n%s=== HIGH CONFIDENCE ===%s\n", RedColor, ResetColor)
			for _, secret := range high {
				displaySecret(secret)
			}
		}

		// Then medium confidence
		if len(medium) > 0 {
			fmt.Printf("\n%s=== MEDIUM CONFIDENCE ===%s\n", YellowColor, ResetColor)
			for _, secret := range medium {
				displaySecret(secret)
			}
		}

		fmt.Printf("\n%s%s\n", YellowColor, SeparatorLine)
		fmt.Printf("%sSummary: %d secrets found (Critical: %d, High: %d, Medium: %d)%s\n",
			RedColor, len(secretsFound), len(critical), len(high), len(medium), ResetColor)
		fmt.Printf("%sPlease review and remove them before committing your code.%s\n", RedColor, ResetColor)
		os.Exit(1)
	} else {
		fmt.Printf("%sNo secrets found.%s\n", GreenColor, ResetColor)
	}
}

func displaySecret(secret Secret) {
	confidenceColor := YellowColor
	if secret.Confidence == "critical" || secret.Confidence == "high" {
		confidenceColor = RedColor
	}

	fmt.Printf("\n%sFile:%s %s\n", YellowColor, ResetColor, secret.File)
	fmt.Printf("%sLine Number:%s %d\n", YellowColor, ResetColor, secret.LineNumber)
	fmt.Printf("%sConfidence:%s %s%s%s (Entropy: %.2f)\n",
		YellowColor, ResetColor, confidenceColor, strings.ToUpper(secret.Confidence), ResetColor, secret.Entropy)
	fmt.Printf("%sContext:%s %s\n", YellowColor, ResetColor, secret.Context)
	fmt.Printf("%sPattern:%s %s\n", YellowColor, ResetColor, secret.Type)
	fmt.Printf("%sLine:%s %s\n", YellowColor, ResetColor, secret.Line)
}

func scanFileForSecrets(path string, pipeline *verification.Pipeline) ([]Secret, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	// Increase buffer size to handle large lines (e.g., minified files)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024) // 1MB max token size

	lineNumber := 1
	var secrets []Secret

	for scanner.Scan() {
		line := scanner.Text()

		// Skip lines that are clearly regex pattern definitions
		if isRegexPatternLine(line) {
			lineNumber++
			continue
		}

		for index, re := range compiledPatterns {
			match := re.FindStringSubmatch(line)

			if len(match) > 0 {
				secretType := "Secret"
				if index >= len(secretPatterns)-len(AdditionalSecretPatterns()) {
					secretType = "Additional Secret"
				}

				// Extract the actual matched secret for analysis
				matchedSecret := match[0]
				// Prefer the most secret-looking capture group instead of the first (some patterns use a label group)
				if len(match) > 1 {
					best := ""
					bestEntropy := -1.0
					for i := 1; i < len(match); i++ {
						cand := strings.TrimSpace(match[i])
						if cand == "" {
							continue
						}
						ent := calculateEntropy(cand)
						if ent > bestEntropy || (math.Abs(ent-bestEntropy) < 0.01 && len(cand) > len(best)) {
							bestEntropy = ent
							best = cand
						}
					}
					if best != "" {
						matchedSecret = best
					}
				}

				// Calculate entropy of the matched secret
				entropy := calculateEntropy(matchedSecret)

				// Detect context of the finding
				context := detectContext(path, line)

				// Calculate confidence based on entropy and context
				confidence := calculateConfidence(matchedSecret, entropy, context, secretPatterns[index])

				// Use LLM verification if available
				if pipeline != nil && confidence != "low" {
					result, err := pipeline.VerifyFinding(
						path,
						lineNumber,
						line,
						secretPatterns[index],
						matchedSecret,
						entropy,
						context,
						confidence,
					)

					if err == nil {
						// Update confidence based on LLM verification
						confidence = result.Confidence

						// Only report if LLM confirms it's a real secret
						if result.IsRealSecret {
							secrets = append(secrets, Secret{
								File:       fmt.Sprintf("%s (%s) [LLM: %s]", path, secretType, result.Reasoning),
								LineNumber: lineNumber,
								Line:       line,
								Type:       secretPatterns[index],
								Confidence: confidence,
								Entropy:    entropy,
								Context:    context,
							})
						}
					} else {
						// Fall back to non-LLM if verification fails
						if confidence != "low" {
							secrets = append(secrets, Secret{
								File:       fmt.Sprintf("%s (%s)", path, secretType),
								LineNumber: lineNumber,
								Line:       line,
								Type:       secretPatterns[index],
								Confidence: confidence,
								Entropy:    entropy,
								Context:    context,
							})
						}
					}
				} else if confidence != "low" {
					// No LLM pipeline or low confidence - use standard detection
					secrets = append(secrets, Secret{
						File:       fmt.Sprintf("%s (%s)", path, secretType),
						LineNumber: lineNumber,
						Line:       line,
						Type:       secretPatterns[index],
						Confidence: confidence,
						Entropy:    entropy,
						Context:    context,
					})
				}
				break
			}
		}
		lineNumber++
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return secrets, nil
}

func AdditionalSecretPatterns() []string {
	vulnerabilityPatterns := []string{
		// Add your additional regex patterns here
		`(?i)(<\s*script\b[^>]*>(.*?)<\s*/\s*script\s*>)`,                      // Cross-site scripting (XSS)
		`(?i)(\b(?:or|and)\b\s*[\w-]*\s*=\s*[\w-]*\s*\b(?:or|and)\b\s*[^\s]+)`, // SQL injection
		`(?i)(['"\s]exec(?:ute)?\s*[(\s]*\s*@\w+\s*)`,                          // SQL injection (EXEC, EXECUTE)
		`(?i)(['"\s]union\s*all\s*select\s*[\w\s,]+(?:from|into|where)\s*\w+)`, // SQL injection (UNION ALL SELECT)
		`(?i)example_pattern_1\s*=\s*"([a-zA-Z0-9\-]+\.example)"`,
		`(?i)example_pattern_2\s*=\s*"([0-9]{12}-[a-zA-Z0-9_]{32})"`,
		// Private SSH keys
		`-----BEGIN\sRSA\sPRIVATE\sKEY-----[\s\S]+-----END\sRSA\sPRIVATE\sKEY-----`,
		// S3 Bucket URLs
		`(?i)s3\.amazonaws\.com/[\w\-\.]+`,
		// Note: IP address pattern removed - too many false positives in docs/examples
		// If needed, filter reserved IPs (127.0.0.1, RFC1918) before reporting
		// Basic Authentication credentials
		`(?i)(?:http|https)://\w+:\w+@[\w\-\.]+`,
		// JWT tokens
		`(?i)ey(?:J[a-zA-Z0-9_-]+)[.](?:[a-zA-Z0-9_-]+)[.](?:[a-zA-Z0-9_-]+)`,
		// Connection strings (such as database connections)
		`(?i)(?:Server|Host)=([\w\.-]+);\s*(?:Port|Database|User\s*ID|Password)=([^;\s]+)(?:;\s*(?:Port|Database|User\s*ID|Password)=([^;\s]+))*`,
		// Path traversal attempts
		// `(\.\./|\.\.\\)`,
		// Open redirects
		// `(?i)(?:(?:https?|ftp)://|%3A%2F%2F)[^\s&]+(?:\s|%20)*(?:\b(?:and|or)\b\s*[\w-]*\s*=\s*[\w-]*\s*\b(?:and|or)\b\s*[^\s]+)?`,
		// UPLOAD MISCONFIG
		//`(?i)enctype\s*=\s*['"]multipart/form-data['"]`,
		// Headers
		//`(?i)<(title|head)>`,
		`(?i)encryPublicKey\s*=\s*"([^"]*)"`,
		`(?i)decryPrivateKey\s*=\s*"([^"]*)"`,
	}
	return vulnerabilityPatterns
}

func isRegexPatternLine(line string) bool {
	// Skip lines that contain regex pattern definitions (backtick-quoted strings with regex)
	// Common in source code defining patterns
	trimmed := regexp.MustCompile(`^\s+`).ReplaceAllString(line, "")

	// Check if line is a regex pattern definition (starts with backtick or contains backtick with regex chars)
	if regexp.MustCompile("^`.*(?:\\(\\?i\\)|\\\\s|\\\\d|\\[|\\]|\\{|\\}|\\||\\^|\\$).*`").MatchString(trimmed) {
		return true
	}

	return false
}

func shouldIgnoreDir(path string) bool {
	base := filepath.Base(path)
	switch base {
	case ".git", "node_modules", "vendor", ".gosecretscanner", "dist", "build", ".venv", "venv", "__pycache__", "coverage", ".idea", ".vscode":
		return true
	}
	return false
}

func shouldIgnoreFile(info os.FileInfo) bool {
	if info.Size() > maxFileSizeBytes {
		return true
	}

	name := strings.ToLower(info.Name())
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".svg", ".ico",
		".mp3", ".mp4", ".mov", ".avi", ".mkv", ".wav",
		".zip", ".gz", ".tgz", ".tar", ".rar", ".7z",
		".pdf", ".doc", ".docx", ".ppt", ".pptx",
		".dll", ".exe", ".so", ".dylib", ".bin", ".dat", ".class", ".jar",
		".ttf", ".otf", ".woff", ".woff2",
		".psd", ".xcf", ".sketch", ".ai":
		return true
	}

	// Skip obvious minified bundles
	if strings.HasSuffix(name, ".min.js") || strings.HasSuffix(name, ".min.css") {
		return true
	}

	return false
}

// calculateEntropy calculates Shannon entropy of a string
// Higher entropy indicates more randomness (likely a real secret)
func calculateEntropy(s string) float64 {
	if len(s) == 0 {
		return 0.0
	}

	// Count character frequencies
	freq := make(map[rune]int)
	for _, char := range s {
		freq[char]++
	}

	// Calculate Shannon entropy
	var entropy float64
	length := float64(len(s))

	for _, count := range freq {
		p := float64(count) / length
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}

	return entropy
}

// detectContext analyzes the line and file to determine context
func detectContext(path, line string) string {
	pathLower := strings.ToLower(path)
	lineLower := strings.ToLower(line)
	lineUpper := strings.ToUpper(line)

	// Test file detection (treat real test scaffolding as tests; do not down-rank examples/demo)
	testPatterns := []string{"test", "spec", "mock", "fixture"}
	for _, pattern := range testPatterns {
		if strings.Contains(pathLower, pattern) {
			return "test_file"
		}
	}

	// Comment detection (avoid misclassifying '*' in code as a comment)
	trimmed := strings.TrimSpace(line)
	if strings.HasPrefix(trimmed, "//") ||
		strings.HasPrefix(trimmed, "#") ||
		strings.Contains(line, "/*") ||
		strings.Contains(line, "*/") ||
		strings.Contains(line, "<!--") ||
		strings.Contains(line, "-->") {
		return "comment"
	}

	// Documentation detection
	if strings.Contains(lineLower, "example") || strings.Contains(lineLower, "documentation") {
		return "documentation"
	}

	// Environment variable placeholder detection (restrict to ${VAR}, %VAR%, or $VAR)
	if bracePlaceholderPattern.MatchString(line) ||
		percentPlaceholderPattern.MatchString(lineUpper) ||
		dollarPlaceholderPattern.MatchString(lineUpper) {
		return "placeholder"
	}

	// Configuration template detection
	if strings.Contains(line, "YOUR_") || strings.Contains(line, "REPLACE_") ||
		strings.Contains(line, "INSERT_") || strings.Contains(line, "CHANGE_ME") {
		return "template"
	}

	return "code"
}

// calculateConfidence determines confidence level based on multiple factors
func calculateConfidence(match string, entropy float64, context string, patternType string) string {
	// Start with base score
	score := 50

	// Entropy scoring (high entropy = likely real secret)
	if entropy > 4.5 {
		score += 30
	} else if entropy > 4.0 {
		score += 20
	} else if entropy > 3.5 {
		score += 10
	} else {
		score -= 10 // Low entropy = likely false positive
	}

	// Context scoring
	switch context {
	case "comment":
		score -= 30
	case "documentation":
		score -= 35
	case "placeholder":
		score -= 50
	case "template":
		score -= 45
	case "code":
		score += 10 // Actual code is more likely to have real secrets
	}

	// Pattern-specific adjustments
	if strings.Contains(patternType, "AWS_Key") || strings.Contains(patternType, "Private_Key") {
		score += 15 // Cloud keys and private keys are critical
	}

	// Convert score to confidence level
	if score >= 80 {
		return "critical"
	} else if score >= 60 {
		return "high"
	} else if score >= 40 {
		return "medium"
	}
	return "low"
}
