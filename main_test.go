package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDetectContext(t *testing.T) {
	cases := []struct {
		name string
		path string
		line string
		want string
	}{
		{"test file detection", "pkg/service/foo_test.go", "secret := \"foo\"", "test_file"},
		{"comment line", "pkg/service/foo.go", "// TODO: handle", "comment"},
		{"placeholder brace", "pkg/service/foo.go", "token := \"${API_KEY}\"", "placeholder"},
		{"placeholder percent", "pkg/service/foo.go", "set %API_KEY%", "placeholder"},
		{"placeholder dollar", "pkg/service/foo.go", "token := \"$SECRET_TOKEN\"", "placeholder"},
		{"code with percent formatting", "pkg/service/foo.go", "fmt.Printf(\"token=%s\", token)", "code"},
		{"pointer code not comment", "pkg/service/foo.go", "value := foo * bar", "code"},
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
	path := filepath.Join("examples", "demo_secrets", "demo_app.py")

	secrets, err := scanFileForSecrets(path, nil)
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
	path := filepath.Join(dir, "safe.txt")
	content := "this file intentionally contains no secrets, just some example code and configuration values"

	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	secrets, err := scanFileForSecrets(path, nil)
	if err != nil {
		t.Fatalf("scanFileForSecrets error: %v", err)
	}

	if len(secrets) != 0 {
		t.Fatalf("expected no secrets, got %d", len(secrets))
	}
}
