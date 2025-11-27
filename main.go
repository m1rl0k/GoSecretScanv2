package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"

	"github.com/m1rl0k/GoSecretScanv2/pkg/baseline"
	"github.com/m1rl0k/GoSecretScanv2/pkg/config"
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
	// Comprehensive secret patterns - organized by provider/type
	// Patterns are ordered from most specific to most generic to minimize false positives
	secretPatterns = []string{
		// ===== CLOUD PROVIDERS =====
		// AWS
		`AKIA[0-9A-Z]{16}`, // AWS Access Key ID
		`ABIA[0-9A-Z]{16}`, // AWS STS Service Bearer Token
		`ACCA[0-9A-Z]{16}`, // AWS Context-specific credentials
		`ASIA[0-9A-Z]{16}`, // AWS Temporary (STS) Access Key
		`(?i)aws_?secret_?access_?key["'\s:=]+[A-Za-z0-9/+=]{40}`, // AWS Secret Access Key
		`(?i)aws_?session_?token["'\s:=]+[A-Za-z0-9/+=]{100,}`,    // AWS Session Token
		// GCP / Google
		`AIza[0-9A-Za-z_-]{35}`,                                 // Google API Key
		`(?i)google_?api_?key["'\s:=]+AIza[0-9A-Za-z_-]{35}`,    // Google API Key with label
		`[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com`, // Google OAuth Client ID
		`ya29\.[0-9A-Za-z_-]+`,                                  // Google OAuth Access Token
		// Azure
		`(?i)azure[_-]?(?:client|tenant|subscription)[_-]?(?:id|secret)["'\s:=]+[0-9a-f-]{36}`, // Azure IDs
		`(?i)(?:DefaultEndpointsProtocol|AccountName|AccountKey)=[^;\s"']+`,                    // Azure Storage Connection String
		`(?i)SharedAccessSignature=sv=[^;\s"']+`,                                               // Azure SAS Token
		// IBM Cloud
		`(?i)ibm[_-]?(?:api[_-]?key|cloud[_-]?key)["'\s:=]+[A-Za-z0-9_-]{44}`, // IBM Cloud API Key
		// Alibaba Cloud
		`LTAI[0-9A-Za-z]{20}`, // Alibaba Cloud Access Key ID
		// DigitalOcean
		`dop_v1_[0-9a-f]{64}`, // DigitalOcean Personal Access Token
		`doo_v1_[0-9a-f]{64}`, // DigitalOcean OAuth Token
		// Linode
		`(?i)linode[_-]?(?:api[_-]?)?token["'\s:=]+[0-9a-f]{64}`, // Linode API Token
		// Vultr
		`(?i)vultr[_-]?api[_-]?key["'\s:=]+[A-Z0-9]{36}`, // Vultr API Key
		// Heroku
		`(?i)heroku[_-]?api[_-]?key["'\s:=]+[0-9a-f-]{36}`,             // Heroku API Key
		`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`, // Heroku OAuth Token (UUID format)

		// ===== VERSION CONTROL =====
		// GitHub
		`ghp_[A-Za-z0-9]{36}`,                        // GitHub Personal Access Token
		`gho_[A-Za-z0-9]{36}`,                        // GitHub OAuth Access Token
		`ghu_[A-Za-z0-9]{36}`,                        // GitHub User-to-Server Token
		`ghs_[A-Za-z0-9]{36}`,                        // GitHub Server-to-Server Token
		`ghr_[A-Za-z0-9]{36}`,                        // GitHub Refresh Token
		`github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}`, // GitHub Fine-grained PAT
		// GitLab
		`glpat-[A-Za-z0-9_-]{20}`,    // GitLab Personal Access Token
		`glptt-[A-Za-z0-9_-]{40}`,    // GitLab Pipeline Trigger Token
		`GR1348941[A-Za-z0-9_-]{20}`, // GitLab Runner Token
		// Bitbucket
		`(?i)bitbucket[_-]?(?:api[_-]?)?(?:key|token|secret)["'\s:=]+[A-Za-z0-9]{32}`, // Bitbucket tokens

		// ===== CI/CD =====
		// CircleCI
		`(?i)circle[_-]?(?:ci[_-]?)?token["'\s:=]+[0-9a-f]{40}`, // CircleCI Token
		// Travis CI
		`(?i)travis[_-]?(?:ci[_-]?)?token["'\s:=]+[A-Za-z0-9]{22}`, // Travis CI Token
		// Jenkins
		`(?i)jenkins[_-]?(?:api[_-]?)?token["'\s:=]+[0-9a-f]{32,34}`, // Jenkins API Token
		// Drone CI
		`(?i)drone[_-]?token["'\s:=]+[A-Za-z0-9]{32}`, // Drone CI Token

		// ===== PAYMENT PROCESSORS =====
		// Stripe
		`sk_live_[0-9a-zA-Z]{24,}`, // Stripe Live Secret Key
		`sk_test_[0-9a-zA-Z]{24,}`, // Stripe Test Secret Key
		`rk_live_[0-9a-zA-Z]{24,}`, // Stripe Live Restricted Key
		`rk_test_[0-9a-zA-Z]{24,}`, // Stripe Test Restricted Key
		`pk_live_[0-9a-zA-Z]{24,}`, // Stripe Live Publishable Key
		`pk_test_[0-9a-zA-Z]{24,}`, // Stripe Test Publishable Key
		`whsec_[0-9a-zA-Z]{32,}`,   // Stripe Webhook Secret
		// Square
		`sq0atp-[0-9A-Za-z_-]{22}`, // Square Access Token
		`sq0csp-[0-9A-Za-z_-]{43}`, // Square OAuth Secret
		`EAAAE[A-Za-z0-9]{59}`,     // Square Production Application Secret
		// PayPal
		`(?i)paypal[_-]?(?:client[_-]?)?secret["'\s:=]+[A-Za-z0-9]{32,}`, // PayPal Secret
		// Braintree
		`(?i)braintree[_-]?(?:private[_-]?)?key["'\s:=]+[a-f0-9]{32}`, // Braintree Private Key

		// ===== COMMUNICATION =====
		// Slack
		`xoxp-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[a-z0-9]{32}`,              // Slack User Token
		`xoxb-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{20,}`,                       // Slack Bot Token
		`xoxa-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{20,}`,                       // Slack App Token
		`xoxr-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{20,}`,                       // Slack Refresh Token
		`https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+`, // Slack Webhook URL
		// Discord
		`(?i)discord[_-]?(?:bot[_-]?)?token["'\s:=]+[MN][A-Za-z0-9]{23,}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27}`, // Discord Bot Token
		`https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+`,                                      // Discord Webhook URL
		// Twilio
		`AC[0-9a-f]{32}`, // Twilio Account SID
		`SK[0-9a-f]{32}`, // Twilio API Key SID
		`(?i)twilio[_-]?auth[_-]?token["'\s:=]+[0-9a-f]{32}`, // Twilio Auth Token
		// Telegram
		`[0-9]{8,10}:[A-Za-z0-9_-]{35}`, // Telegram Bot Token
		// SendGrid
		`SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}`, // SendGrid API Key
		// Mailgun
		`key-[0-9a-zA-Z]{32}`, // Mailgun API Key
		`(?i)mailgun[_-]?api[_-]?key["'\s:=]+key-[0-9a-zA-Z]{32}`, // Mailgun API Key with label
		// Mailchimp
		`[0-9a-f]{32}-us[0-9]{1,2}`, // Mailchimp API Key
		// Postmark
		`(?i)postmark[_-]?(?:api[_-]?)?(?:token|key)["'\s:=]+[0-9a-f-]{36}`, // Postmark API Token

		// ===== DATABASES =====
		`(?i)(?:mongodb|mongo)(?:\+srv)?://[^:\s]+:[^@\s]+@[^\s/]+`,       // MongoDB Connection String
		`(?i)postgres(?:ql)?://[^:\s]+:[^@\s]+@[^\s/]+`,                   // PostgreSQL Connection String
		`(?i)mysql://[^:\s]+:[^@\s]+@[^\s/]+`,                             // MySQL Connection String
		`(?i)redis://[^:\s]*:[^@\s]+@[^\s/]+`,                             // Redis Connection String (with auth)
		`(?i)amqp://[^:\s]+:[^@\s]+@[^\s/]+`,                              // RabbitMQ Connection String
		`(?i)(?:jdbc:)?(?:mysql|postgresql|oracle|sqlserver)://[^;\s"']+`, // JDBC Connection Strings

		// ===== PACKAGE MANAGERS =====
		`npm_[A-Za-z0-9]{36}`,                                        // npm Access Token
		`(?i)_auth\s*=\s*[A-Za-z0-9+/=]{50,}`,                        // npm _auth token (base64)
		`pypi-[A-Za-z0-9_-]{50,}`,                                    // PyPI API Token
		`rubygems_[0-9a-f]{48}`,                                      // RubyGems API Key
		`(?i)gem[_-]?(?:host[_-]?)?api[_-]?key["'\s:=]+[0-9a-f]{48}`, // RubyGems with label
		`GOPRIVATE.*token.*[A-Za-z0-9_-]{40}`,                        // Go private module token
		`nuget[_-]?api[_-]?key["'\s:=]+[a-z0-9-]{36}`,                // NuGet API Key

		// ===== CONTAINER REGISTRIES =====
		`(?i)docker[_-]?(?:hub[_-]?)?(?:password|token)["'\s:=]+[A-Za-z0-9_-]{36,}`, // Docker Hub
		`(?i)(?:ghcr|gcr|acr|ecr)[_-]?token["'\s:=]+[A-Za-z0-9_-]{36,}`,             // Container registry tokens

		// ===== MONITORING / ANALYTICS =====
		// Datadog
		`(?i)(?:datadog|dd)[_-]?api[_-]?key["'\s:=]+[a-f0-9]{32}`, // Datadog API Key
		`(?i)(?:datadog|dd)[_-]?app[_-]?key["'\s:=]+[a-f0-9]{40}`, // Datadog App Key
		// New Relic
		`NRAK-[A-Z0-9]{27}`, // New Relic API Key
		`(?i)new[_-]?relic[_-]?license[_-]?key["'\s:=]+[a-f0-9]{40}`, // New Relic License Key
		// Sentry
		`https://[a-f0-9]{32}@(?:o[0-9]+\.)?ingest\.sentry\.io/[0-9]+`, // Sentry DSN
		// PagerDuty
		`(?i)pagerduty[_-]?(?:api[_-]?)?(?:token|key)["'\s:=]+[A-Za-z0-9+_-]{20}`, // PagerDuty Token
		// Splunk
		`(?i)splunk[_-]?(?:hec[_-]?)?token["'\s:=]+[0-9a-f-]{36}`, // Splunk HEC Token

		// ===== AUTHENTICATION =====
		// Auth0
		`(?i)auth0[_-]?(?:client[_-]?)?secret["'\s:=]+[A-Za-z0-9_-]{32,}`, // Auth0 Client Secret
		// Okta
		`(?i)okta[_-]?(?:api[_-]?)?token["'\s:=]+[A-Za-z0-9_-]{42}`, // Okta API Token
		// Firebase
		`(?i)firebase[_-]?(?:api[_-]?)?key["'\s:=]+AIza[0-9A-Za-z_-]{35}`, // Firebase API Key
		`AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}`,                         // Firebase Cloud Messaging Token

		// ===== CRYPTOGRAPHIC KEYS =====
		`-----BEGIN\s(?:RSA\s)?PRIVATE\sKEY-----`,   // RSA Private Key
		`-----BEGIN\sOPENSSH\sPRIVATE\sKEY-----`,    // OpenSSH Private Key
		`-----BEGIN\sEC\sPRIVATE\sKEY-----`,         // EC Private Key
		`-----BEGIN\sPGP\sPRIVATE\sKEY\sBLOCK-----`, // PGP Private Key
		`-----BEGIN\sDSA\sPRIVATE\sKEY-----`,        // DSA Private Key
		`-----BEGIN\sENCRYPTED\sPRIVATE\sKEY-----`,  // Encrypted Private Key

		// ===== JWT / OAUTH =====
		`eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`,  // JWT Token
		`(?i)bearer\s+[A-Za-z0-9_-]{20,}\.?[A-Za-z0-9_-]*\.?[A-Za-z0-9_-]*`, // Bearer Token
		`(?i)oauth[_-]?(?:access[_-]?)?token["'\s:=]+[A-Za-z0-9_-]{20,}`,    // OAuth Access Token

		// ===== MISC SERVICES =====
		// Shopify
		`shppa_[a-f0-9]{32}`, // Shopify Private App Password
		`shpat_[a-f0-9]{32}`, // Shopify Access Token
		`shpss_[a-f0-9]{32}`, // Shopify Shared Secret
		// Atlassian
		`(?i)atlassian[_-]?api[_-]?token["'\s:=]+[A-Za-z0-9]{24}`, // Atlassian API Token
		// Airtable
		`(?i)airtable[_-]?api[_-]?key["'\s:=]+key[A-Za-z0-9]{14}`, // Airtable API Key
		// Asana
		`(?i)asana[_-]?(?:access[_-]?)?token["'\s:=]+[0-9]/[0-9]{16}:[A-Za-z0-9]{32}`, // Asana Token
		// Zendesk
		`(?i)zendesk[_-]?api[_-]?token["'\s:=]+[A-Za-z0-9]{40}`, // Zendesk API Token
		// Intercom
		`(?i)intercom[_-]?(?:access[_-]?)?token["'\s:=]+dG9[A-Za-z0-9+/=]+`, // Intercom Access Token (base64)
		// Dropbox
		`sl\.[A-Za-z0-9_-]{130,}`, // Dropbox Access Token
		// Box
		`(?i)box[_-]?(?:access[_-]?)?token["'\s:=]+[A-Za-z0-9]{32}`, // Box Access Token
		// Cloudflare
		`(?i)cloudflare[_-]?(?:api[_-]?)?(?:token|key)["'\s:=]+[A-Za-z0-9_-]{37,}`, // Cloudflare API Token
		// Netlify
		`(?i)netlify[_-]?(?:access[_-]?)?token["'\s:=]+[A-Za-z0-9_-]{40,}`, // Netlify Token
		// Vercel
		`(?i)vercel[_-]?(?:access[_-]?)?token["'\s:=]+[A-Za-z0-9]{24}`, // Vercel Token
		// Supabase
		`sbp_[a-f0-9]{40}`, // Supabase Service Key
		`eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`, // Supabase JWT (specific header)
		// Linear
		`lin_api_[A-Za-z0-9]{40}`, // Linear API Key
		// Notion
		`secret_[A-Za-z0-9]{43}`, // Notion Integration Token
		// Figma
		`figd_[A-Za-z0-9_-]{40,}`, // Figma Personal Access Token
		// OpenAI
		`sk-[A-Za-z0-9]{48}`, // OpenAI API Key
		// Anthropic
		`sk-ant-[A-Za-z0-9_-]{80,}`, // Anthropic API Key
		// Hugging Face
		`hf_[A-Za-z0-9]{34}`, // Hugging Face Token
		// Replicate
		`r8_[A-Za-z0-9]{40}`, // Replicate API Token
		// Mapbox
		`pk\.[A-Za-z0-9]{60,}`, // Mapbox Public Key
		`sk\.[A-Za-z0-9]{60,}`, // Mapbox Secret Key
		// Algolia
		`(?i)algolia[_-]?(?:admin[_-]?)?api[_-]?key["'\s:=]+[a-f0-9]{32}`, // Algolia Admin API Key
		// Segment
		`(?i)segment[_-]?(?:write[_-]?)?key["'\s:=]+[A-Za-z0-9]{32}`, // Segment Write Key
		// Mixpanel
		`(?i)mixpanel[_-]?(?:api[_-]?)?(?:token|secret)["'\s:=]+[a-f0-9]{32}`, // Mixpanel Token
		// Amplitude
		`(?i)amplitude[_-]?api[_-]?key["'\s:=]+[a-f0-9]{32}`, // Amplitude API Key
		// LaunchDarkly
		`(?i)launchdarkly[_-]?(?:sdk[_-]?)?key["'\s:=]+sdk-[a-f0-9-]{36}`, // LaunchDarkly SDK Key

		// ===== GENERIC HIGH-SIGNAL PATTERNS =====
		`(?i)(?:api|app|application)[_-]?key["'\s:=]+[A-Za-z0-9_-]{20,}`,      // Generic API Key
		`(?i)(?:api|app|application)[_-]?secret["'\s:=]+[A-Za-z0-9_-]{20,}`,   // Generic API Secret
		`(?i)secret[_-]?key["'\s:=]+[A-Za-z0-9_-]{20,}`,                       // Generic Secret Key
		`(?i)access[_-]?token["'\s:=]+[A-Za-z0-9_-]{20,}`,                     // Generic Access Token
		`(?i)auth[_-]?token["'\s:=]+[A-Za-z0-9_-]{20,}`,                       // Generic Auth Token
		`(?i)private[_-]?key["'\s:=]+[A-Za-z0-9_-]{20,}`,                      // Generic Private Key
		`(?i)signing[_-]?(?:key|secret)["'\s:=]+[A-Za-z0-9_-]{20,}`,           // Signing Key/Secret
		`(?i)encryption[_-]?key["'\s:=]+[A-Za-z0-9_-]{16,}`,                   // Encryption Key
		`(?i)(?:master|root)[_-]?(?:key|password|secret)["'\s:=]+[^\s"']{8,}`, // Master/Root credentials
		`(?i)password["'\s:=]+[^\s"']{8,64}`,                                  // Generic Password assignment

		// ===== URLS WITH CREDENTIALS =====
		`(?i)https?://[^:\s]+:[^@\s]+@[^\s/]+`, // URL with embedded credentials
	}
	// Pre-compiled regex patterns for performance
	compiledPatterns []*regexp.Regexp

	bracePlaceholderPattern   = regexp.MustCompile(`\$\{[^}]+\}`)
	percentPlaceholderPattern = regexp.MustCompile(`%[A-Za-z0-9_]+%`)
	dollarPlaceholderPattern  = regexp.MustCompile(`\$[A-Z0-9_]+`)

	// Pre-compiled pattern for detecting regex definition lines (to skip self-matches)
	regexLinePattern = regexp.MustCompile("^\\s*`.*(?:\\(\\?i\\)|\\\\s|\\\\d|\\[|\\]|\\{|\\}|\\||\\^|\\$).*`")
)

const ruleIDFmt = "pattern-%d"

type Secret struct {
	File               string  `json:"-"`
	FilePath           string  `json:"file"`
	LineNumber         int     `json:"line"`
	Line               string  `json:"line_text"`
	Match              string  `json:"match"`
	RuleID             string  `json:"rule_id"`
	Type               string  `json:"pattern"`
	Confidence         string  `json:"confidence"` // low, medium, high, critical
	Entropy            float64 `json:"entropy"`    // Shannon entropy of the matched secret
	Context            string  `json:"context"`    // Additional context (e.g., "test file", "comment", "variable")
	Verified           bool    `json:"verified"`
	VerificationReason string  `json:"verification_reason,omitempty"`
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

	outputFormat   = flag.String("output", "text", "Output format: text, json, or sarif")
	redactOutput   = flag.Bool("redact", true, "Redact secret values in output")
	modeFlag       = flag.String("mode", "detect", "Mode: detect, protect, or report")
	failOn         = flag.String("fail-on", "low", "Minimum confidence to treat as a failure: low, medium, high, critical")
	includeGlobs   = flag.String("include-glob", "", "Comma-separated glob patterns to include (relative paths)")
	excludeGlobs   = flag.String("exclude-glob", "", "Comma-separated glob patterns to exclude (relative paths)")
	includeExts    = flag.String("include-ext", "", "Comma-separated list of file extensions to include (e.g. .go,.py)")
	maxFileSizeCli = flag.Int64("max-file-size", maxFileSizeBytes, "Maximum file size to scan in bytes")
	configPath     = flag.String("config", "", "Path to config file (default: .gosecretscanner.json in repo root)")
	baselinePath   = flag.String("baseline", "", "Path to baseline file for suppressing known findings")
	updateBaseline = flag.Bool("update-baseline", false, "Update the baseline file with current findings")
	baselineReason = flag.String("baseline-reason", "", "Reason for adding findings to baseline (used with --update-baseline)")

	// Git history scanning flags (git history is scanned by default)
	noGitHistory  = flag.Bool("no-git-history", false, "Skip scanning git commit history")
	gitMaxCommits = flag.Int("git-max-commits", 0, "Maximum number of commits to scan (0 = all, scans entire history)")
	gitRef        = flag.String("git-ref", "HEAD", "Git ref to start scanning from")
	gitSinceDate  = flag.String("git-since", "", "Only scan commits after this date (e.g., 2024-01-01)")

	// Derived settings from flags
	maxFileSizeLimit int64 = maxFileSizeBytes
	includeGlobList  []string
	excludeGlobList  []string
	includeExtList   []string

	// Loaded configuration
	compiledConfig *config.CompiledConfig

	// Loaded baseline
	loadedBaseline *baseline.Baseline
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

	// Apply max file size override
	if *maxFileSizeCli > 0 {
		maxFileSizeLimit = *maxFileSizeCli
	}

	// Parse include/exclude globs and extensions
	if *includeGlobs != "" {
		for _, p := range strings.Split(*includeGlobs, ",") {
			if trimmed := strings.TrimSpace(p); trimmed != "" {
				includeGlobList = append(includeGlobList, filepath.ToSlash(trimmed))
			}
		}
	}
	if *excludeGlobs != "" {
		for _, p := range strings.Split(*excludeGlobs, ",") {
			if trimmed := strings.TrimSpace(p); trimmed != "" {
				excludeGlobList = append(excludeGlobList, filepath.ToSlash(trimmed))
			}
		}
	}
	if *includeExts != "" {
		for _, e := range strings.Split(*includeExts, ",") {
			trimmed := strings.TrimSpace(e)
			if trimmed == "" {
				continue
			}
			if !strings.HasPrefix(trimmed, ".") {
				trimmed = "." + trimmed
			}
			includeExtList = append(includeExtList, strings.ToLower(trimmed))
		}
	}

	// Get working directory for config loading
	dir, err := os.Getwd()
	if err != nil {
		fmt.Println("Error getting current working directory:", err)
		os.Exit(1)
	}

	// Load configuration
	cfg, err := config.Load(*configPath, dir)
	if err != nil {
		fmt.Printf("%sError loading config: %v%s\n", RedColor, err, ResetColor)
		os.Exit(1)
	}

	compiledConfig, err = cfg.Compile()
	if err != nil {
		fmt.Printf("%sError compiling config: %v%s\n", RedColor, err, ResetColor)
		os.Exit(1)
	}

	// Apply config overrides for max file size if not overridden via CLI
	if *maxFileSizeCli == maxFileSizeBytes && compiledConfig.GetMaxFileSize() != maxFileSizeBytes {
		maxFileSizeLimit = compiledConfig.GetMaxFileSize()
	}

	// Merge config allowlist paths with CLI exclude globs
	for _, p := range cfg.Allowlist.Paths {
		excludeGlobList = append(excludeGlobList, filepath.ToSlash(p))
	}

	// Helper to print status messages (stderr for JSON/SARIF, stdout for text)
	outFmt := *outputFormat
	statusPrint := func(format string, args ...interface{}) {
		if outFmt == "json" || outFmt == "sarif" {
			fmt.Fprintf(os.Stderr, format, args...)
		} else {
			fmt.Printf(format, args...)
		}
	}

	// Load baseline ONLY if explicitly specified via --baseline flag
	// Baseline is opt-in - by default we report ALL findings
	loadedBaseline = baseline.New()
	if *baselinePath != "" {
		loadedBaseline, err = baseline.Load(*baselinePath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%sError loading baseline: %v%s\n", RedColor, err, ResetColor)
			os.Exit(1)
		}
		if loadedBaseline.Count() > 0 {
			statusPrint("%sLoaded baseline with %d known findings (will be suppressed)%s\n", YellowColor, loadedBaseline.Count(), ResetColor)
		}
	}

	// Initialize verification pipeline if LLM is enabled
	var pipeline *verification.Pipeline
	if *enableLLM {
		pipelineConfig := &verification.Config{
			Enabled:             true,
			DBPath:              *dbPath,
			ModelPath:           *modelPath,
			EmbeddingsPath:      *embeddingsPath,
			SimilarityThreshold: float32(*similarityThreshold),
			EphemeralStore:      !*keepVectorStore,
			LLMEndpoint:         *llmEndpoint,
		}

		pipeline, err = verification.NewPipeline(pipelineConfig)
		if err != nil {
			statusPrint("%sWarning: Failed to initialize LLM pipeline: %v%s\n", YellowColor, err, ResetColor)
			statusPrint("%sContinuing with standard detection only...%s\n\n", YellowColor, ResetColor)
			pipeline = nil
		} else {
			statusPrint("%sLLM verification enabled%s\n\n", GreenColor, ResetColor)
			defer pipeline.Close()
		}
	}

	var secretsFound []Secret
	var historySecrets []Secret

	// Check if we're in a git repo
	isGitRepo := false
	if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
		isGitRepo = true
	}

	// PHASE 1: Scan current working directory files (with LLM verification if enabled)
	statusPrint("Phase 1: Scanning current files...\n")
	{
		// Normal file system scanning
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

			rel, relErr := filepath.Rel(dir, path)
			if relErr != nil {
				rel = path
			}
			rel = filepath.ToSlash(rel)

			if info.IsDir() {
				if shouldIgnoreDir(path) || shouldSkipDirByUserFilters(rel) {
					return filepath.SkipDir
				}
				return nil
			}

			if shouldIgnoreFile(info) {
				return nil
			}

			if shouldSkipFileByUserFilters(rel, info) {
				return nil
			}

			wg.Add(1)
			sem <- struct{}{}
			go func(absPath, relPath string) {
				defer func() { <-sem; wg.Done() }()
				secrets, err := scanFileForSecrets(absPath, relPath, pipeline)
				if err != nil {
					fmt.Printf("Error scanning file %s: %v\n", absPath, err)
					return
				}
				mu.Lock()
				secretsFound = append(secretsFound, secrets...)
				mu.Unlock()
			}(path, rel)
			return nil
		})
		if err != nil {
			fmt.Println("Error walking the directory:", err)
			os.Exit(1)
		}

		wg.Wait()
	}
	statusPrint("Found %d potential secrets in current files\n", len(secretsFound))

	// PHASE 2: Scan git history (no LLM - can't access file content at old commits)
	// Git history scanning is ON by default. Use --no-git-history to skip.
	if isGitRepo && !*noGitHistory {
		statusPrint("\nPhase 2: Scanning git history...\n")
		var err error
		historySecrets, err = scanGitHistory(dir, *gitMaxCommits, *gitRef, *gitSinceDate, nil) // nil pipeline = no LLM
		if err != nil {
			statusPrint("%sWarning: Git history scan failed: %v%s\n", YellowColor, err, ResetColor)
		} else {
			statusPrint("Found %d potential secrets in git history\n", len(historySecrets))
			secretsFound = append(secretsFound, historySecrets...)
		}
	} else if !isGitRepo {
		statusPrint("\nSkipping git history scan (not a git repository)\n")
	} else if *noGitHistory {
		statusPrint("\nSkipping git history scan (--no-git-history)\n")
	}

	statusPrint("\nTotal: %d potential secrets found\n\n", len(secretsFound))

	// Apply config-based filtering (allowlists, disabled rules, entropy threshold)
	secretsFound = filterSecretsByConfig(secretsFound, compiledConfig)

	// Apply baseline filtering (suppress known findings)
	secretsFound = filterSecretsByBaseline(secretsFound, loadedBaseline)

	// Update baseline if requested
	if *updateBaseline {
		outputPath := *baselinePath
		if outputPath == "" {
			outputPath = filepath.Join(dir, baseline.DefaultBaselineFile)
		}

		// Add all current findings to baseline
		for _, s := range secretsFound {
			entry := baseline.CreateEntry(s.FilePath, s.LineNumber, s.RuleID, s.Match, *baselineReason)
			loadedBaseline.Add(entry)
		}

		if err := loadedBaseline.Save(outputPath); err != nil {
			fmt.Printf("%sError saving baseline: %v%s\n", RedColor, err, ResetColor)
			os.Exit(1)
		}
		fmt.Printf("%sBaseline updated: %s (%d entries)%s\n", GreenColor, outputPath, loadedBaseline.Count(), ResetColor)
	}

	mode := strings.ToLower(*modeFlag)
	if mode != "detect" && mode != "protect" && mode != "report" {
		mode = "detect"
	}

	output := strings.ToLower(*outputFormat)
	redact := *redactOutput

	// Determine the failure threshold from --fail-on
	failThreshold := 1
	switch strings.ToLower(*failOn) {
	case "critical":
		failThreshold = 4
	case "high":
		failThreshold = 3
	case "medium":
		failThreshold = 2
	case "low":
		failThreshold = 1
	}

	// Decide whether this run should be considered a failure
	shouldFail := false
	for _, s := range secretsFound {
		if confidenceScore(s.Confidence) >= failThreshold {
			shouldFail = true
			break
		}
	}

	// For JSON/SARIF modes, print a summary to stderr so it shows in CI logs
	if (output == "json" || output == "sarif") && len(secretsFound) > 0 {
		fmt.Fprintf(os.Stderr, "\n--- Secrets Found (%d) ---\n\n", len(secretsFound))
		for i, s := range secretsFound {
			r := maybeRedactSecret(s, redact)

			// Truncate match for display
			match := r.Match
			if len(match) > 60 {
				match = match[:57] + "..."
			}

			fmt.Fprintf(os.Stderr, "  #%d\n", i+1)
			fmt.Fprintf(os.Stderr, "    File:       %s\n", r.FilePath)
			fmt.Fprintf(os.Stderr, "    Line:       %d\n", r.LineNumber)
			fmt.Fprintf(os.Stderr, "    Confidence: %s\n", strings.ToUpper(r.Confidence))
			fmt.Fprintf(os.Stderr, "    Match:      %s\n", match)
			if r.Verified {
				fmt.Fprintf(os.Stderr, "    Verified:   YES (LLM)\n")
			}
			if r.VerificationReason != "" {
				fmt.Fprintf(os.Stderr, "    Reason:     %s\n", r.VerificationReason)
			}
			fmt.Fprintf(os.Stderr, "\n")
		}
	}

	switch output {
	case "json":
		out := make([]Secret, len(secretsFound))
		for i, s := range secretsFound {
			out[i] = maybeRedactSecret(s, redact)
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(out); err != nil {
			fmt.Fprintf(os.Stderr, "failed to encode JSON output: %v\n", err)
		}
	case "sarif":
		if err := emitSarif(secretsFound, redact); err != nil {
			fmt.Fprintf(os.Stderr, "failed to encode SARIF output: %v\n", err)
		}
	default:
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
					displaySecret(maybeRedactSecret(secret, redact))
				}
			}

			// Then high confidence
			if len(high) > 0 {
				fmt.Printf("\n%s=== HIGH CONFIDENCE ===%s\n", RedColor, ResetColor)
				for _, secret := range high {
					displaySecret(maybeRedactSecret(secret, redact))
				}
			}

			// Then medium confidence
			if len(medium) > 0 {
				fmt.Printf("\n%s=== MEDIUM CONFIDENCE ===%s\n", YellowColor, ResetColor)
				for _, secret := range medium {
					displaySecret(maybeRedactSecret(secret, redact))
				}
			}

			fmt.Printf("\n%s%s\n", YellowColor, SeparatorLine)
			fmt.Printf("%sSummary: %d secrets found (Critical: %d, High: %d, Medium: %d)%s\n",
				RedColor, len(secretsFound), len(critical), len(high), len(medium), ResetColor)
			fmt.Printf("%sPlease review and remove them before committing your code.%s\n", RedColor, ResetColor)
		} else {
			fmt.Printf("%sNo secrets found.%s\n", GreenColor, ResetColor)
		}
	}

	// Mode/reporting based exit codes
	if mode == "report" {
		os.Exit(0)
	}

	if shouldFail && len(secretsFound) > 0 {
		os.Exit(1)
	}

	os.Exit(0)
}

func displaySecret(secret Secret) {
	confidenceColor := YellowColor
	if secret.Confidence == "critical" || secret.Confidence == "high" {
		confidenceColor = RedColor
	}

	fmt.Printf("\n%s───────────────────────────────────────────────────────%s\n", YellowColor, ResetColor)
	fmt.Printf("%sFile:%s %s\n", YellowColor, ResetColor, secret.File)
	fmt.Printf("%sLine Number:%s %d\n", YellowColor, ResetColor, secret.LineNumber)
	fmt.Printf("%sConfidence:%s %s%s%s (Entropy: %.2f)\n",
		YellowColor, ResetColor, confidenceColor, strings.ToUpper(secret.Confidence), ResetColor, secret.Entropy)
	fmt.Printf("%sContext:%s %s\n", YellowColor, ResetColor, secret.Context)
	fmt.Printf("%sPattern:%s %s\n", YellowColor, ResetColor, secret.Type)
	fmt.Printf("%sLine:%s %s\n", YellowColor, ResetColor, secret.Line)
	if secret.Verified {
		fmt.Printf("%sVerified:%s YES (LLM)\n", YellowColor, ResetColor)
	}
	if secret.VerificationReason != "" {
		fmt.Printf("%sReason:%s %s\n", YellowColor, ResetColor, secret.VerificationReason)
	}
}

func maybeRedactSecret(s Secret, redact bool) Secret {
	if !redact {
		return s
	}

	redacted := s

	if redacted.Match != "" {
		redacted.Match = "****REDACTED****"
	}

	if redacted.Line != "" && s.Match != "" {
		redacted.Line = strings.ReplaceAll(redacted.Line, s.Match, "****REDACTED****")
	}

	return redacted
}

func confidenceScore(level string) int {
	switch strings.ToLower(level) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

// Minimal SARIF 2.1.0 structures and encoder

type sarifReport struct {
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name string `json:"name"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level,omitempty"`
	Message   sarifMessage    `json:"message"`
	Locations []sarifLocation `json:"locations,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           *sarifRegion          `json:"region,omitempty"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine,omitempty"`
}

func emitSarif(secrets []Secret, redact bool) error {
	results := make([]sarifResult, 0, len(secrets))
	for _, s := range secrets {
		rs := maybeRedactSecret(s, redact)

		level := "warning"
		switch strings.ToLower(rs.Confidence) {
		case "critical", "high":
			level = "error"
		case "medium":
			level = "warning"
		case "low":
			level = "note"
		}

		ruleID := rs.RuleID
		if ruleID == "" {
			ruleID = rs.Type
		}

		result := sarifResult{
			RuleID: ruleID,
			Level:  level,
			Message: sarifMessage{
				Text: fmt.Sprintf("Potential secret detected (%s)", rs.Type),
			},
		}

		location := sarifLocation{
			PhysicalLocation: sarifPhysicalLocation{
				ArtifactLocation: sarifArtifactLocation{URI: rs.FilePath},
				Region:           &sarifRegion{StartLine: rs.LineNumber},
			},
		}
		result.Locations = []sarifLocation{location}

		results = append(results, result)
	}

	report := sarifReport{
		Version: "2.1.0",
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{Name: "GoSecretScanv2"},
				},
				Results: results,
			},
		},
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}

// filterSecretsByConfig removes findings that match config allowlists or disabled rules.
func filterSecretsByConfig(secrets []Secret, cc *config.CompiledConfig) []Secret {
	if cc == nil {
		return secrets
	}

	minEntropy := cc.GetMinEntropy()
	var filtered []Secret

	for _, s := range secrets {
		// Skip if path is in allowlist
		if !cc.IsPathAllowed(s.FilePath) {
			continue
		}

		// Skip if secret value is in allowlist
		if cc.IsSecretAllowed(s.Match) {
			continue
		}

		// Skip if rule is disabled
		if cc.IsRuleDisabled(s.RuleID) {
			continue
		}

		// Skip if entropy is below threshold (unless it's a high-confidence pattern)
		if s.Entropy < minEntropy && s.Confidence != "critical" && s.Confidence != "high" {
			continue
		}

		filtered = append(filtered, s)
	}

	return filtered
}

// filterSecretsByBaseline removes findings that are in the baseline.
func filterSecretsByBaseline(secrets []Secret, b *baseline.Baseline) []Secret {
	if b == nil || b.Count() == 0 {
		return secrets
	}

	var filtered []Secret
	for _, s := range secrets {
		if !b.IsBaselined(s.FilePath, s.RuleID, s.Match) {
			filtered = append(filtered, s)
		}
	}

	return filtered
}

// GitCommit represents a commit in git history.
type GitCommit struct {
	Hash    string
	Author  string
	Date    string
	Message string
}

// scanGitHistory scans git commit history for secrets.
func scanGitHistory(repoDir string, maxCommits int, ref, sinceDate string, pipeline *verification.Pipeline) ([]Secret, error) {
	// Get list of commits
	args := []string{"log", "--format=%H|%an|%ai|%s", ref}
	if maxCommits > 0 {
		args = append(args, fmt.Sprintf("-n%d", maxCommits))
	}
	if sinceDate != "" {
		args = append(args, "--since="+sinceDate)
	}

	cmd := exec.Command("git", args...)
	cmd.Dir = repoDir
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git log failed: %w", err)
	}

	var commits []GitCommit
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "|", 4)
		if len(parts) < 4 {
			continue
		}
		commits = append(commits, GitCommit{
			Hash:    parts[0],
			Author:  parts[1],
			Date:    parts[2],
			Message: parts[3],
		})
	}

	var allSecrets []Secret
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Use worker pool for parallel commit scanning
	workers := runtime.NumCPU() * 2
	if workers < 4 {
		workers = 4
	}
	sem := make(chan struct{}, workers)

	for _, commit := range commits {
		wg.Add(1)
		sem <- struct{}{}
		go func(c GitCommit) {
			defer wg.Done()
			defer func() { <-sem }()

			secrets, err := scanCommitDiff(repoDir, c, pipeline)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Warning: failed to scan commit %s: %v\n", c.Hash[:8], err)
				return
			}

			if len(secrets) > 0 {
				mu.Lock()
				allSecrets = append(allSecrets, secrets...)
				mu.Unlock()
			}
		}(commit)
	}

	wg.Wait()
	return allSecrets, nil
}

// scanCommitDiff scans the diff of a single commit for secrets.
func scanCommitDiff(repoDir string, commit GitCommit, pipeline *verification.Pipeline) ([]Secret, error) {
	// Get the diff for this commit
	cmd := exec.Command("git", "show", "--format=", "--unified=0", commit.Hash)
	cmd.Dir = repoDir
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	return scanDiffContent(out, commit, pipeline)
}

// scanDiffContent scans diff output for secrets.
func scanDiffContent(diffData []byte, commit GitCommit, pipeline *verification.Pipeline) ([]Secret, error) {
	var secrets []Secret
	var currentFile string
	lineNum := 0

	scanner := bufio.NewScanner(bytes.NewReader(diffData))
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	for scanner.Scan() {
		line := scanner.Text()

		// Track current file from diff headers
		if strings.HasPrefix(line, "+++ b/") {
			currentFile = strings.TrimPrefix(line, "+++ b/")
			lineNum = 0
			continue
		}

		// Track line numbers from @@ headers
		if strings.HasPrefix(line, "@@") {
			// Parse @@ -old,count +new,count @@
			parts := strings.Split(line, " ")
			for _, p := range parts {
				if strings.HasPrefix(p, "+") && !strings.HasPrefix(p, "+++") {
					numPart := strings.TrimPrefix(p, "+")
					if idx := strings.Index(numPart, ","); idx > 0 {
						numPart = numPart[:idx]
					}
					fmt.Sscanf(numPart, "%d", &lineNum)
					break
				}
			}
			continue
		}

		// Only scan added lines (lines starting with +)
		if !strings.HasPrefix(line, "+") || strings.HasPrefix(line, "+++") {
			if strings.HasPrefix(line, "+") {
				lineNum++
			}
			continue
		}

		// Remove the leading + for scanning
		content := strings.TrimPrefix(line, "+")
		lineNum++

		// Scan this line for secrets
		for i, pattern := range compiledPatterns {
			if pattern.MatchString(content) {
				match := pattern.FindString(content)
				entropy := calculateEntropy(match)
				context := detectContext(currentFile, content)
				confidence := calculateConfidence(match, entropy, context, secretPatterns[i])

				secret := Secret{
					File:       currentFile,
					FilePath:   fmt.Sprintf("%s@%s", currentFile, commit.Hash[:8]),
					LineNumber: lineNum,
					Line:       content,
					Match:      match,
					RuleID:     fmt.Sprintf("pattern-%d", i),
					Type:       secretPatterns[i],
					Confidence: confidence,
					Entropy:    entropy,
					Context:    fmt.Sprintf("%s (commit: %s by %s)", context, commit.Hash[:8], commit.Author),
				}

				// Note: LLM verification is skipped for git history scanning
				// because we don't have access to the full file content at that commit.
				// The finding is still reported with the pattern-based confidence.

				secrets = append(secrets, secret)
				break // One match per line
			}
		}
	}

	return secrets, scanner.Err()
}

func scanFileForSecrets(absPath, relPath string, pipeline *verification.Pipeline) ([]Secret, error) {
	file, err := os.Open(absPath)
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
	seenLines := make(map[int]bool) // Track which lines already have findings to avoid duplicates

	for scanner.Scan() {
		line := scanner.Text()

		// Skip lines that are clearly regex pattern definitions
		if isRegexPatternLine(line) {
			lineNumber++
			continue
		}

		// Skip if we already found a secret on this line (avoid duplicates from overlapping patterns)
		if seenLines[lineNumber] {
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
				context := detectContext(relPath, line)

				// Calculate confidence based on entropy and context
				confidence := calculateConfidence(matchedSecret, entropy, context, secretPatterns[index])

				// Use LLM verification if available
				if pipeline != nil && confidence != "low" {
					result, err := pipeline.VerifyFinding(
						relPath,
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

						// LLM is advisory-only: attach reasoning but do not suppress regex hits.
						secrets = append(secrets, Secret{
							File:               fmt.Sprintf("%s (%s) [LLM: %s]", relPath, secretType, result.Reasoning),
							FilePath:           relPath,
							LineNumber:         lineNumber,
							Line:               line,
							Match:              matchedSecret,
							RuleID:             fmt.Sprintf(ruleIDFmt, index),
							Type:               secretPatterns[index],
							Confidence:         confidence,
							Entropy:            entropy,
							Context:            context,
							Verified:           result.IsRealSecret,
							VerificationReason: result.Reasoning,
						})
						seenLines[lineNumber] = true
					} else {
						// Fall back to non-LLM if verification fails
						if confidence != "low" {
							secrets = append(secrets, Secret{
								File:       fmt.Sprintf("%s (%s)", relPath, secretType),
								FilePath:   relPath,
								LineNumber: lineNumber,
								Line:       line,
								Match:      matchedSecret,
								RuleID:     fmt.Sprintf(ruleIDFmt, index),
								Type:       secretPatterns[index],
								Confidence: confidence,
								Entropy:    entropy,
								Context:    context,
							})
							seenLines[lineNumber] = true
						}
					}
				} else if confidence != "low" {
					// No LLM pipeline or low confidence - use standard detection
					secrets = append(secrets, Secret{
						File:       fmt.Sprintf("%s (%s)", relPath, secretType),
						FilePath:   relPath,
						LineNumber: lineNumber,
						Line:       line,
						Match:      matchedSecret,
						RuleID:     fmt.Sprintf(ruleIDFmt, index),
						Type:       secretPatterns[index],
						Confidence: confidence,
						Entropy:    entropy,
						Context:    context,
					})
					seenLines[lineNumber] = true
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
	// Additional patterns that complement the core set - focus on less common services
	return []string{
		// S3 Bucket URLs (may indicate misconfiguration)
		`(?i)s3\.amazonaws\.com/[\w\-\.]+`,
		// Windows/ADO connection strings
		`(?i)(?:Server|Host|Data\s*Source)=([\w\.-]+);\s*(?:Port|Database|Initial\s*Catalog|User\s*ID|Password)=([^;\s]+)`,
		// Fastly API Token
		`(?i)fastly[_-]?(?:api[_-]?)?(?:token|key)["'\s:=]+[A-Za-z0-9_-]{32}`,
		// Contentful
		`(?i)contentful[_-]?(?:access[_-]?)?token["'\s:=]+[A-Za-z0-9_-]{43,}`,
		// Prismic
		`(?i)prismic[_-]?(?:api[_-]?)?(?:token|key)["'\s:=]+[A-Za-z0-9_-]{40,}`,
		// Sanity
		`(?i)sanity[_-]?(?:api[_-]?)?token["'\s:=]+sk[A-Za-z0-9]{60,}`,
		// Hasura
		`(?i)hasura[_-]?(?:admin[_-]?)?secret["'\s:=]+[A-Za-z0-9_-]{32,}`,
		// Supabase (service role key pattern)
		`(?i)supabase[_-]?(?:service[_-]?)?key["'\s:=]+eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`,
		// PlanetScale
		`pscale_tkn_[A-Za-z0-9_-]{43}`,
		// Turso
		`(?i)turso[_-]?(?:auth[_-]?)?token["'\s:=]+[A-Za-z0-9_-]{40,}`,
		// Upstash
		`(?i)upstash[_-]?redis[_-]?rest[_-]?token["'\s:=]+[A-Za-z0-9_=-]{40,}`,
		// Convex
		`(?i)convex[_-]?deploy[_-]?key["'\s:=]+prod:[A-Za-z0-9_-]{40,}`,
		// Railway
		`(?i)railway[_-]?token["'\s:=]+[A-Za-z0-9_-]{36,}`,
		// Render
		`(?i)render[_-]?api[_-]?key["'\s:=]+rnd_[A-Za-z0-9]{24,}`,
		// Fly.io
		`(?i)fly[_-]?(?:api[_-]?)?token["'\s:=]+[A-Za-z0-9_-]{43}`,
		// Deno Deploy
		`(?i)deno[_-]?deploy[_-]?token["'\s:=]+[A-Za-z0-9_-]{40,}`,
		// Expo
		`(?i)expo[_-]?(?:access[_-]?)?token["'\s:=]+[A-Za-z0-9_-]{40,}`,
		// Snyk
		`(?i)snyk[_-]?(?:api[_-]?)?token["'\s:=]+[0-9a-f-]{36}`,
		// Codecov
		`(?i)codecov[_-]?token["'\s:=]+[0-9a-f-]{36}`,
		// Coveralls
		`(?i)coveralls[_-]?(?:repo[_-]?)?token["'\s:=]+[A-Za-z0-9]{32,}`,
		// SonarQube/SonarCloud
		`(?i)sonar[_-]?(?:token|login)["'\s:=]+[a-f0-9]{40}`,
		// Terraform Cloud
		`(?i)(?:tfc|terraform)[_-]?token["'\s:=]+[A-Za-z0-9]{14}\.[A-Za-z0-9]{14}\.[A-Za-z0-9]{21,}`,
		// HashiCorp Vault
		`(?i)vault[_-]?token["'\s:=]+(?:hvs\.|s\.)[A-Za-z0-9_-]{24,}`,
		// Doppler
		`dp\.(?:ct|pt|st)\.[A-Za-z0-9]{40,}`,
		// 1Password
		`ops_[A-Za-z0-9]{43}`,
		// LastPass
		`(?i)lastpass[_-]?(?:api[_-]?)?(?:key|token)["'\s:=]+[A-Za-z0-9]{32,}`,
		// Pulumi
		`pul-[A-Za-z0-9]{40}`,
		// Weights & Biases (wandb)
		`(?i)wandb[_-]?api[_-]?key["'\s:=]+[a-f0-9]{40}`,
		// Comet ML
		`(?i)comet[_-]?api[_-]?key["'\s:=]+[A-Za-z0-9]{40}`,
		// Neptune AI
		`(?i)neptune[_-]?api[_-]?token["'\s:=]+eyJ[A-Za-z0-9_-]+`,
		// Roboflow
		`(?i)roboflow[_-]?api[_-]?key["'\s:=]+[A-Za-z0-9]{40,}`,
		// Pinecone
		`(?i)pinecone[_-]?api[_-]?key["'\s:=]+[a-f0-9-]{36}`,
		// Weaviate
		`(?i)weaviate[_-]?api[_-]?key["'\s:=]+[A-Za-z0-9_-]{40,}`,
		// Qdrant
		`(?i)qdrant[_-]?api[_-]?key["'\s:=]+[A-Za-z0-9_-]{32,}`,
		// Milvus
		`(?i)milvus[_-]?(?:api[_-]?)?token["'\s:=]+[A-Za-z0-9_-]{32,}`,
		// Cohere
		`(?i)cohere[_-]?api[_-]?key["'\s:=]+[A-Za-z0-9]{40}`,
		// Mistral AI
		`(?i)mistral[_-]?api[_-]?key["'\s:=]+[A-Za-z0-9]{32}`,
		// Together AI
		`(?i)together[_-]?api[_-]?key["'\s:=]+[a-f0-9]{64}`,
		// Groq
		`gsk_[A-Za-z0-9]{52}`,
		// Perplexity
		`pplx-[A-Za-z0-9]{48}`,
		// ElevenLabs
		`(?i)elevenlabs[_-]?api[_-]?key["'\s:=]+[a-f0-9]{32}`,
		// AssemblyAI
		`(?i)assemblyai[_-]?api[_-]?key["'\s:=]+[a-f0-9]{32}`,
		// Deepgram
		`(?i)deepgram[_-]?api[_-]?key["'\s:=]+[a-f0-9]{40}`,
		// Rev AI
		`(?i)rev[_-]?(?:ai[_-]?)?(?:access[_-]?)?token["'\s:=]+[A-Za-z0-9_-]{40,}`,
		// Bannerbear
		`bb_(?:live|test)_[A-Za-z0-9]{32}`,
		// imgix
		`(?i)imgix[_-]?(?:api[_-]?)?(?:key|token)["'\s:=]+[A-Za-z0-9_-]{32,}`,
		// Cloudinary
		`(?i)cloudinary[_-]?(?:api[_-]?)?secret["'\s:=]+[A-Za-z0-9_-]{27}`,
		// Uploadcare
		`(?i)uploadcare[_-]?(?:secret[_-]?)?key["'\s:=]+[a-f0-9]{20}`,
		// Imgbb
		`(?i)imgbb[_-]?api[_-]?key["'\s:=]+[a-f0-9]{32}`,
		// Tenor
		`(?i)tenor[_-]?api[_-]?key["'\s:=]+[A-Z0-9]{16}`,
		// Giphy
		`(?i)giphy[_-]?api[_-]?key["'\s:=]+[A-Za-z0-9]{32}`,
	}
}

func isRegexPatternLine(line string) bool {
	// Skip lines that contain regex pattern definitions (backtick-quoted strings with regex)
	// Common in source code defining patterns
	trimmed := strings.TrimLeft(line, " \t")

	// Check if line is a regex pattern definition (starts with backtick or contains backtick with regex chars)
	return regexLinePattern.MatchString(trimmed)
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
	if info.Size() > maxFileSizeLimit {
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

func matchAnyGlob(relPath string, patterns []string) bool {
	for _, p := range patterns {
		if p == "" {
			continue
		}
		// Try matching on full relative path
		if ok, _ := filepath.Match(p, relPath); ok {
			return true
		}
		// Also try matching on just the basename for simple patterns
		if ok, _ := filepath.Match(p, filepath.Base(relPath)); ok {
			return true
		}
		// Support "dir/*" style: check if pattern prefix matches path segments
		if strings.HasSuffix(p, "/*") {
			prefix := strings.TrimSuffix(p, "/*")
			if strings.HasPrefix(relPath, prefix+"/") || relPath == prefix {
				return true
			}
		}
	}
	return false
}

func shouldSkipDirByUserFilters(relPath string) bool {
	if len(excludeGlobList) > 0 && matchAnyGlob(relPath, excludeGlobList) {
		return true
	}
	return false
}

func shouldSkipFileByUserFilters(relPath string, info os.FileInfo) bool {
	if len(includeGlobList) > 0 && !matchAnyGlob(relPath, includeGlobList) {
		return true
	}

	if len(excludeGlobList) > 0 && matchAnyGlob(relPath, excludeGlobList) {
		return true
	}

	if len(includeExtList) > 0 {
		name := strings.ToLower(info.Name())
		ext := strings.ToLower(filepath.Ext(name))
		matched := false
		for _, e := range includeExtList {
			if ext == e {
				matched = true
				break
			}
		}
		if !matched {
			return true
		}
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
	lineUpper := strings.ToUpper(line)

	// Documentation/examples should not be treated as real secrets
	docExts := []string{".md", ".rst", ".adoc", ".txt"}
	for _, ext := range docExts {
		if strings.HasSuffix(pathLower, ext) {
			return "documentation"
		}
	}
	if strings.Contains(pathLower, "/docs/") || strings.Contains(pathLower, "\\docs\\") {
		return "documentation"
	}

	// Test file detection: only treat real test scaffolding as tests
	base := filepath.Base(pathLower)
	if strings.HasSuffix(base, "_test.go") ||
		strings.HasSuffix(base, "_test.ts") ||
		strings.HasSuffix(base, "_test.tsx") ||
		strings.HasSuffix(base, "_test.js") ||
		strings.HasSuffix(base, "_test.jsx") ||
		strings.HasSuffix(base, ".spec.ts") ||
		strings.HasSuffix(base, ".spec.tsx") ||
		strings.HasSuffix(base, ".spec.js") ||
		strings.HasSuffix(base, ".spec.jsx") {
		return "test_file"
	}

	if strings.Contains(pathLower, "/test/") || strings.Contains(pathLower, "/tests/") ||
		strings.Contains(pathLower, "\\test\\") || strings.Contains(pathLower, "\\tests\\") {
		return "test_file"
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
