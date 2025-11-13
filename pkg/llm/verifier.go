package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	defaultLLMEndpoint = "http://localhost:8080"
	llamaAPIRoute      = "/v1/chat/completions"
	llmRequestTimeout  = 180 * time.Second // Increased for Granite model which can be slow, especially for large repos
)

// VerificationResult represents the LLM's verification result
type VerificationResult struct {
	IsRealSecret   bool   `json:"is_real_secret"`
	Confidence     string `json:"confidence"`
	Reasoning      string `json:"reasoning"`
	Recommendation string `json:"recommendation"`
}

// CodeContext provides context for LLM verification
type CodeContext struct {
	FilePath        string
	Language        string
	Function        string
	SurroundingCode string
	Imports         []string
	IsTest          bool
}

// Finding represents a secret finding
type Finding struct {
	FilePath    string
	LineNumber  int
	Line        string
	PatternType string
	Match       string
	Entropy     float64
	Context     string
	Confidence  string
}

// LLMVerifier handles LLM-based verification
type LLMVerifier struct {
	enabled  bool
	model    string
	endpoint string
	client   *http.Client
	sem      chan struct{}
}

// NewLLMVerifier creates a new LLM verifier
func NewLLMVerifier(modelPath string, endpoint string, enabled bool) (*LLMVerifier, error) {
	if !enabled {
		return &LLMVerifier{enabled: false}, nil
	}

	if modelPath == "" {
		return nil, fmt.Errorf("model path is required when LLM verification is enabled")
	}

	// Check if model exists locally so users get fast feedback when running the bundled server
	if _, err := os.Stat(modelPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("model not found at %s: %w", modelPath, err)
	}

	if endpoint == "" {
		endpoint = defaultLLMEndpoint
	}

	endpoint = strings.TrimSuffix(endpoint, "/")

	return &LLMVerifier{
		enabled:  true,
		model:    modelPath,
		endpoint: endpoint,
		client: &http.Client{
			Timeout: llmRequestTimeout,
		},
		sem: make(chan struct{}, 1),
	}, nil
}

// Verify verifies if a finding is a real secret
func (v *LLMVerifier) Verify(finding *Finding, context *CodeContext) (*VerificationResult, error) {
	if !v.enabled {
		// Fall back to heuristic verification
		return v.heuristicVerify(finding, context), nil
	}

	// Build prompt
	prompt := v.buildPrompt(finding, context)

	if v.endpoint == "" || v.client == nil {
		return v.heuristicVerify(finding, context), nil
	}

	result, err := v.invokeLLM(prompt)
	if err != nil {
		fmt.Printf("Warning: LLM verification failed, falling back to heuristics: %v\n", err)
		return v.heuristicVerify(finding, context), nil
	}

	return result, nil
}

// buildPrompt creates the prompt for the LLM
func (v *LLMVerifier) buildPrompt(finding *Finding, context *CodeContext) string {
	return fmt.Sprintf(`You are a security expert analyzing code for secrets.

Context:
- File: %s
- Language: %s
- Function: %s
- Line: %d
- Is Test File: %v

Code snippet:
`+"```"+`
%s
`+"```"+`

Pattern detected: %s
Matched value: %s
Entropy: %.2f
Context type: %s
Initial confidence: %s

Question: Is this a real secret that should be reported, or a false positive?

Consider:
1. Is the value hardcoded or from an environment variable?
2. Is this in a test file or production code?
3. Is the entropy high enough to be a real secret?
4. Could this be example/template code?
5. Is the pattern in a sensitive location?
6. Are there indicators this is a placeholder (YOUR_, REPLACE_, etc.)?

Answer with JSON only:
{
  "is_real_secret": true/false,
  "confidence": "low"/"medium"/"high"/"critical",
  "reasoning": "brief explanation",
  "recommendation": "what to do"
}`,
		context.FilePath,
		context.Language,
		context.Function,
		finding.LineNumber,
		context.IsTest,
		context.SurroundingCode,
		finding.PatternType,
		finding.Match,
		finding.Entropy,
		finding.Context,
		finding.Confidence,
	)
}

type chatRequest struct {
	Model       string        `json:"model"`
	Messages    []chatMessage `json:"messages"`
	Temperature float32       `json:"temperature"`
	TopP        float32       `json:"top_p"`
	MaxTokens   int           `json:"max_tokens"`
	Stream      bool          `json:"stream"`
}

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatResponse struct {
	Choices []struct {
		Message chatMessage `json:"message"`
	} `json:"choices"`
}

func (v *LLMVerifier) invokeLLM(prompt string) (*VerificationResult, error) {
	// Limit concurrent LLM calls to avoid timeouts on small CI runners
	if v.sem != nil {
		v.sem <- struct{}{}
		defer func() { <-v.sem }()
	}

	reqBody := chatRequest{
		Model: v.model,
		Messages: []chatMessage{
			{Role: "system", Content: "You are a senior application security engineer. Respond with JSON only."},
			{Role: "user", Content: prompt},
		},
		Temperature: 0.1,
		TopP:        0.9,
		MaxTokens:   128,
		Stream:      false,
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal LLM request: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), llmRequestTimeout)
	defer cancel()

	endpoint := v.endpoint + llamaAPIRoute
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to build LLM request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := v.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("LLM request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("LLM server returned status %s", resp.Status)
	}

	var completion chatResponse
	if err := json.NewDecoder(resp.Body).Decode(&completion); err != nil {
		return nil, fmt.Errorf("failed to decode LLM response: %w", err)
	}

	if len(completion.Choices) == 0 {
		return nil, fmt.Errorf("LLM response contained no choices")
	}

	content := strings.TrimSpace(completion.Choices[0].Message.Content)
	if content == "" {
		return nil, fmt.Errorf("LLM response content is empty")
	}

	// Strip markdown code blocks if present (Granite often wraps JSON in ```json ... ```)
	content = strings.TrimPrefix(content, "```json")
	content = strings.TrimPrefix(content, "```")
	content = strings.TrimSuffix(content, "```")
	content = strings.TrimSpace(content)

	// Use parseResponse to extract JSON even if there's extra text
	result, err := v.parseResponse(content)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal LLM JSON: %w", err)
	}

	return result, nil
}

// heuristicVerify provides rule-based verification as fallback
func (v *LLMVerifier) heuristicVerify(finding *Finding, context *CodeContext) *VerificationResult {
	isReal := true
	confidence := finding.Confidence
	reasoning := []string{}

	// Test file check
	if context.IsTest {
		isReal = false
		reasoning = append(reasoning, "Found in test file")
		confidence = "low"
	}

	// Documentation files are generally examples; lower severity/ignore
	lowerPath := strings.ToLower(finding.FilePath)
	if strings.HasSuffix(lowerPath, ".md") || strings.HasSuffix(lowerPath, ".rst") || strings.Contains(lowerPath, "/docs/") {
		isReal = false
		reasoning = append(reasoning, "Found in documentation")
		confidence = "low"
	}

	// Placeholder detection
	line := strings.ToUpper(finding.Line)
	if strings.Contains(line, "YOUR_") ||
		strings.Contains(line, "REPLACE_") ||
		strings.Contains(line, "EXAMPLE_") ||
		strings.Contains(line, "CHANGE_ME") ||
		strings.Contains(line, "INSERT_") {
		isReal = false
		reasoning = append(reasoning, "Contains placeholder text")
		confidence = "low"
	}

	// Environment variable pattern
	if strings.Contains(finding.Line, "os.Getenv") ||
		strings.Contains(finding.Line, "process.env") ||
		strings.Contains(finding.Line, "${") ||
		strings.Contains(finding.Line, "%") {
		isReal = false
		reasoning = append(reasoning, "Uses environment variable pattern")
	}

	// Low entropy check
	if finding.Entropy < 3.0 {
		isReal = false
		reasoning = append(reasoning, fmt.Sprintf("Low entropy (%.2f)", finding.Entropy))
		confidence = "low"
	}

	// High entropy in production code
	if finding.Entropy > 4.5 && !context.IsTest && finding.Context == "code" {
		isReal = true
		reasoning = append(reasoning, fmt.Sprintf("High entropy (%.2f) in production code", finding.Entropy))
		confidence = "critical"
	}

	// Comment check
	if finding.Context == "comment" || finding.Context == "documentation" {
		isReal = false
		reasoning = append(reasoning, "Found in comment or documentation")
		confidence = "low"
	}

	recommendation := "Review and remove if confirmed as secret"
	if !isReal {
		recommendation = "Likely false positive, but verify manually"
	}

	return &VerificationResult{
		IsRealSecret:   isReal,
		Confidence:     confidence,
		Reasoning:      strings.Join(reasoning, "; "),
		Recommendation: recommendation,
	}
}

// BatchVerify verifies multiple findings in a batch
func (v *LLMVerifier) BatchVerify(findings []*Finding, contexts []*CodeContext) ([]*VerificationResult, error) {
	if len(findings) != len(contexts) {
		return nil, fmt.Errorf("findings and contexts must have same length")
	}

	results := make([]*VerificationResult, len(findings))
	for i := range findings {
		result, err := v.Verify(findings[i], contexts[i])
		if err != nil {
			return nil, err
		}
		results[i] = result
	}

	return results, nil
}

// parseResponse parses the LLM's JSON response
func (v *LLMVerifier) parseResponse(response string) (*VerificationResult, error) {
	// Extract JSON from response
	start := strings.Index(response, "{")
	end := strings.LastIndex(response, "}")

	if start == -1 || end == -1 {
		return nil, fmt.Errorf("no JSON found in response")
	}

	jsonStr := response[start : end+1]

	var result VerificationResult
	if err := json.Unmarshal([]byte(jsonStr), &result); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %w", err)
	}

	return &result, nil
}

// Close releases resources
func (v *LLMVerifier) Close() error {
	// Future: Clean up llama.cpp context
	return nil
}
