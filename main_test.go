package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testPath = "pkg/service/foo.go"

func TestDetectContext(t *testing.T) {
	cases := []struct {
		name string
		path string
		line string
		want string
	}{
		{"test file detection", "pkg/service/foo_test.go", "secret := \"foo\"", "test_file"},
		{"comment line", testPath, "// TODO: handle", "comment"},
		{"placeholder brace", testPath, "token := \"${API_KEY}\"", "placeholder"},
		{"placeholder percent", testPath, "set %API_KEY%", "placeholder"},
		{"placeholder dollar", testPath, "token := \"$SECRET_TOKEN\"", "placeholder"},
		{"code with percent formatting", testPath, "fmt.Printf(\"token=%s\", token)", "code"},
		{"pointer code not comment", testPath, "value := foo * bar", "code"},
		{"markdown documentation", "docs/setup.md", "Example TOKEN=foo", "documentation"},
		{"readme file", "README.md", "Set API_KEY=foo", "documentation"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := detectContext(tc.path, tc.line)
			if got != tc.want {
				t.Fatalf("detectContext(%q, %q) = %q, want %q", tc.path, tc.line, got, tc.want)
			}
		})
	}
}

// Regression test: the demo file should have all fake secrets detected by the core scanner
// without relying on the LLM pipeline.
func TestDemoSecretsDetected(t *testing.T) {
	relPath := filepath.Join("examples", "demo_secrets", "demo_app.py")
	absPath := relPath // In test context, relative path works as abs

	secrets, err := scanFileForSecrets(absPath, relPath, nil)
	if err != nil {
		t.Fatalf("scanFileForSecrets error: %v", err)
	}

	expected := []string{
		"AKIAIOSFODNN7EXAMPLE",
		"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		"ghp_1234567890abcdef1234567890abcdef1234",
		"AIzaSyA1234567890abcdefGHIJKLMNOPQRSTUV123",
		"sk_live_51M8c7uExampleExampleExample0000",
		"xoxb-123456789012-1234567890123-ABCDEFGHIJKLMNOPQRSTUV",
		"-----BEGIN PRIVATE KEY-----",
		"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
		"P@ssw0rd123!",
		"password123",
	}

	found := make(map[string]bool)
	for _, s := range secrets {
		for _, marker := range expected {
			if strings.Contains(s.Line, marker) {
				found[marker] = true
			}
		}
	}

	for _, marker := range expected {
		if !found[marker] {
			t.Errorf("expected secret containing %q to be detected", marker)
		}
	}
}

// Basic negative test: a plain text file with no obvious secrets should not produce findings.
func TestNoFalsePositivesOnSafeFile(t *testing.T) {
	dir := t.TempDir()
	absPath := filepath.Join(dir, "safe.txt")
	relPath := "safe.txt"
	content := "this file intentionally contains no secrets, just some example code and configuration values"

	if err := os.WriteFile(absPath, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	secrets, err := scanFileForSecrets(absPath, relPath, nil)
	if err != nil {
		t.Fatalf("scanFileForSecrets error: %v", err)
	}

	if len(secrets) != 0 {
		t.Fatalf("expected no secrets, got %d", len(secrets))
	}
}

func TestMaybeRedactSecret(t *testing.T) {
	s := Secret{
		FilePath:   "src/app.py",
		LineNumber: 10,
		Line:       "api_key = \"sk_live_abc123xyz789\"",
		Match:      "sk_live_abc123xyz789",
		RuleID:     "pattern-0",
		Confidence: "high",
	}

	// Without redaction
	noRedact := maybeRedactSecret(s, false)
	if noRedact.Match != s.Match {
		t.Errorf("expected Match to remain %q, got %q", s.Match, noRedact.Match)
	}
	if noRedact.Line != s.Line {
		t.Errorf("expected Line to remain unchanged, got %q", noRedact.Line)
	}

	// With redaction
	redacted := maybeRedactSecret(s, true)
	if redacted.Match != "****REDACTED****" {
		t.Errorf("expected Match to be redacted, got %q", redacted.Match)
	}
	if !strings.Contains(redacted.Line, "****REDACTED****") {
		t.Errorf("expected Line to contain redacted marker, got %q", redacted.Line)
	}
	if strings.Contains(redacted.Line, "sk_live_abc123xyz789") {
		t.Errorf("Line should not contain the raw secret after redaction")
	}
}

func TestConfidenceScore(t *testing.T) {
	cases := []struct {
		level string
		want  int
	}{
		{"critical", 4},
		{"high", 3},
		{"medium", 2},
		{"low", 1},
		{"CRITICAL", 4}, // case insensitive
		{"unknown", 0},
	}
	for _, tc := range cases {
		got := confidenceScore(tc.level)
		if got != tc.want {
			t.Errorf("confidenceScore(%q) = %d, want %d", tc.level, got, tc.want)
		}
	}
}

func TestMatchAnyGlob(t *testing.T) {
	cases := []struct {
		path     string
		patterns []string
		want     bool
	}{
		{"vendor/github.com/foo", []string{"vendor/*"}, true},
		{"vendor", []string{"vendor/*"}, true},
		{"src/vendor/lib", []string{"vendor/*"}, false}, // only matches top-level vendor
		{"test.go", []string{"*.go"}, true},
		{"src/app/test.go", []string{"*.go"}, true}, // matches basename
		{"README.md", []string{"*.txt", "*.md"}, true},
		{"main.py", []string{"*.go"}, false},
	}
	for _, tc := range cases {
		got := matchAnyGlob(tc.path, tc.patterns)
		if got != tc.want {
			t.Errorf("matchAnyGlob(%q, %v) = %v, want %v", tc.path, tc.patterns, got, tc.want)
		}
	}
}
