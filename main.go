package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sync"
)

const (
	ResetColor    = "\033[0m"
	RedColor      = "\033[31m"
	GreenColor    = "\033[32m"
	YellowColor   = "\033[33m"
	SeparatorLine = "------------------------------------------------------------------------"
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
    `(?i)_(AWS_STS_Token):FQoG.*[^\\w]`, // AWS Security Token Service (STS) token
    `(?i)_(AWS_Access_Key_ID):[^\\w]AKIA[0-9A-Z]{16}[^\\w]`, // AWS access key ID
    `(?i)_(API_Key):[^\\w]Bearer [0-9a-f]{32}`, // API key
    `(?i)_(AWS_Secret_Key):[\\s'\"=]AKIA[0-9A-Z]{16}[\\s'\"$]`, // AWS secret access key
    `(?i)_(Basic_Auth2):Authorization:\\sBasic\\s(?:[a-zA-Z0-9\\+/]{4})*(?:[a-zA-Z0-9\\+/]{3}=|[a-zA-Z0-9\\+/]{2}==)?(?:$|[\\s;'\"])`, // Basic auth token
    `(?i)_(SSH_Key):-{5}BEGIN\\s(?:[DR]SA|OPENSSH|EC|PGP)\\sPRIVATE\\sKEY(?:\\sBLOCK)?-{5}`, // SSH private key
    `(?i)_(RSA_Key):-{5}BEGIN\\sRSA\\sPRIVATE\\sKEY(?:\\sBLOCK)?-{5}`, // RSA private key
    `(?i)_(Private_Key):-----BEGIN PRIVATE KEY-----[^-]+-----END PRIVATE KEY-----`, // Private key
    `(?i)_(PGP_Private_Key):-----BEGIN PGP PRIVATE KEY BLOCK----[^-]+-----END PGP PRIVATE KEY BLOCK-----`, // PGP private key
    `(?i)_(GCP_API_Key):[^\\w]AIza[0-9A-Za-z_-]{35}[^\\w]`, // Google Cloud Platform (GCP) API key
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
	}
	// Pre-compiled regex patterns for performance
	compiledPatterns []*regexp.Regexp
)

type Secret struct {
	File       string
	LineNumber int
	Line       string
	Type       string
}

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
	dir, err := os.Getwd()
	if err != nil {
		fmt.Println("Error getting current working directory:", err)
		os.Exit(1)
	}

	var secretsFound []Secret
	var wg sync.WaitGroup
	var mu sync.Mutex

	err = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && !shouldIgnore(path) {
			wg.Add(1)
			go func(p string) {
				defer wg.Done()
				secrets, err := scanFileForSecrets(p)
				if err != nil {
					fmt.Printf("Error scanning file %s: %v\n", p, err)
					return
				}
				mu.Lock()
				secretsFound = append(secretsFound, secrets...)
				mu.Unlock()
			}(path)
		}
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
		for _, secret := range secretsFound {
			fmt.Printf("%sFile:%s %s\n%sLine Number:%s %d\n%sType:%s %s\n%sLine:%s %s\n\n", YellowColor, ResetColor, secret.File, YellowColor, ResetColor, secret.LineNumber, YellowColor, ResetColor, secret.Type, YellowColor, ResetColor, secret.Line)
		}
		fmt.Printf("%s%s\n", YellowColor, SeparatorLine)
		fmt.Printf("%s%d secrets found. Please review and remove them before committing your code.%s\n", RedColor, len(secretsFound), ResetColor)
		os.Exit(1)
	} else {
		fmt.Printf("%sNo secrets found.%s\n", GreenColor, ResetColor)
	}
}
func scanFileForSecrets(path string) ([]Secret, error) {
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
				secrets = append(secrets, Secret{
					File:       fmt.Sprintf("%s (%s)", path, secretType),
					LineNumber: lineNumber,
					Line:       line,
					Type:       secretPatterns[index],
				})
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
		`(?i)(<\s*script\b[^>]*>(.*?)<\s*/\s*script\s*>)`,                          // Cross-site scripting (XSS)
		`(?i)(\b(?:or|and)\b\s*[\w-]*\s*=\s*[\w-]*\s*\b(?:or|and)\b\s*[^\s]+)`,     // SQL injection
		`(?i)(['"\s]exec(?:ute)?\s*[(\s]*\s*@\w+\s*)`,                             // SQL injection (EXEC, EXECUTE)
		`(?i)(['"\s]union\s*all\s*select\s*[\w\s,]+(?:from|into|where)\s*\w+)`,    // SQL injection (UNION ALL SELECT)
		`(?i)example_pattern_1\s*=\s*"([a-zA-Z0-9\-]+\.example)"`,
		`(?i)example_pattern_2\s*=\s*"([0-9]{12}-[a-zA-Z0-9_]{32})"`,
		// Private SSH keys
		`-----BEGIN\sRSA\sPRIVATE\sKEY-----[\s\S]+-----END\sRSA\sPRIVATE\sKEY-----`,
		// S3 Bucket URLs
		`(?i)s3\.amazonaws\.com/[\w\-\.]+`,
		// Hardcoded IP addresses
		`\b(?:\d{1,3}\.){3}\d{1,3}\b`,
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

func shouldIgnore(path string) bool {
	ignorePatterns := []string{
		`^\.git($|/)`, // ignore .git directory and its contents
		`node_modules`,
		// Add more ignore patterns if needed
	}
	for _, pattern := range ignorePatterns {
		if matched, _ := regexp.MatchString(pattern, path); matched {
			return true
		}
	}
	return false
}