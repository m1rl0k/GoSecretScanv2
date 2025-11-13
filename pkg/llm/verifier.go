package llm

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
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
	enabled   bool
	modelPath string
	// Future: Add llama.cpp context here
}

// NewLLMVerifier creates a new LLM verifier
func NewLLMVerifier(modelPath string, enabled bool) (*LLMVerifier, error) {
	if !enabled {
		return &LLMVerifier{enabled: false}, nil
	}

	// Check if model exists
	if _, err := os.Stat(modelPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("model not found at %s: %w", modelPath, err)
	}

	// Future: Initialize llama.cpp here

	return &LLMVerifier{
		enabled:   true,
		modelPath: modelPath,
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

	// Future: Call llama.cpp here
	// For now, use heuristic
	_ = prompt
	return v.heuristicVerify(finding, context), nil
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
