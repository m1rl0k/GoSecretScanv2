package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.General.MinEntropy != 3.0 {
		t.Errorf("expected min_entropy 3.0, got %f", cfg.General.MinEntropy)
	}

	if cfg.General.MaxFileSize != 5*1024*1024 {
		t.Errorf("expected max_file_size 5MB, got %d", cfg.General.MaxFileSize)
	}

	if len(cfg.Rules) != 0 {
		t.Errorf("expected no rules, got %d", len(cfg.Rules))
	}
}

func TestLoadFromFile(t *testing.T) {
	dir := t.TempDir()
	configFile := filepath.Join(dir, "config.json")

	content := `{
		"general": {
			"min_entropy": 4.0,
			"max_file_size": 1048576
		},
		"rules": [
			{
				"id": "test-rule",
				"pattern": "test-[0-9]+",
				"enabled": true
			}
		],
		"allowlist": {
			"paths": ["vendor/*"],
			"secrets": ["secret123"],
			"rule_ids": ["pattern-0"]
		}
	}`

	if err := os.WriteFile(configFile, []byte(content), 0o644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	cfg, err := Load(configFile, dir)
	if err != nil {
		t.Fatalf("Load error: %v", err)
	}

	if cfg.General.MinEntropy != 4.0 {
		t.Errorf("expected min_entropy 4.0, got %f", cfg.General.MinEntropy)
	}

	if len(cfg.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(cfg.Rules))
	}

	if cfg.Rules[0].ID != "test-rule" {
		t.Errorf("expected rule ID 'test-rule', got %q", cfg.Rules[0].ID)
	}

	if len(cfg.Allowlist.Paths) != 1 || cfg.Allowlist.Paths[0] != "vendor/*" {
		t.Errorf("expected paths ['vendor/*'], got %v", cfg.Allowlist.Paths)
	}
}

func TestLoadDefaultFile(t *testing.T) {
	dir := t.TempDir()
	defaultFile := filepath.Join(dir, DefaultConfigFile)

	content := `{"general": {"min_entropy": 5.0}}`
	if err := os.WriteFile(defaultFile, []byte(content), 0o644); err != nil {
		t.Fatalf("failed to write default config: %v", err)
	}

	cfg, err := Load("", dir)
	if err != nil {
		t.Fatalf("Load error: %v", err)
	}

	if cfg.General.MinEntropy != 5.0 {
		t.Errorf("expected min_entropy 5.0 from default file, got %f", cfg.General.MinEntropy)
	}
}

func TestLoadNoFile(t *testing.T) {
	dir := t.TempDir()

	cfg, err := Load("", dir)
	if err != nil {
		t.Fatalf("Load error: %v", err)
	}

	// Should return default config
	if cfg.General.MinEntropy != 3.0 {
		t.Errorf("expected default min_entropy 3.0, got %f", cfg.General.MinEntropy)
	}
}

func TestCompiledConfig(t *testing.T) {
	cfg := &Config{
		General: GeneralConfig{MinEntropy: 3.5},
		Rules: []RuleConfig{
			{ID: "custom-1", Pattern: "custom-[0-9]+", Enabled: true},
			{ID: "custom-2", Pattern: "disabled-pattern", Enabled: false},
		},
		Allowlist: AllowlistConfig{
			Paths:       []string{"vendor/*"},
			Secrets:     []string{"allowed-secret"},
			Regexes:     []string{"(?i)example"},
			RuleIDs:     []string{"pattern-5"},
			PathRegexes: []string{`.*\.md$`},
		},
	}

	cc, err := cfg.Compile()
	if err != nil {
		t.Fatalf("Compile error: %v", err)
	}

	// Only enabled rules should be compiled
	if len(cc.CustomPatterns) != 1 {
		t.Errorf("expected 1 compiled pattern, got %d", len(cc.CustomPatterns))
	}

	// Test path allowlist
	if cc.IsPathAllowed("vendor/foo.go") {
		t.Error("vendor/foo.go should NOT be allowed (matches vendor/*)")
	}
	if !cc.IsPathAllowed("src/main.go") {
		t.Error("src/main.go should be allowed")
	}
	if cc.IsPathAllowed("docs/README.md") {
		t.Error("docs/README.md should NOT be allowed (matches *.md regex)")
	}

	// Test secret allowlist
	if !cc.IsSecretAllowed("allowed-secret") {
		t.Error("'allowed-secret' should be allowed (exact match)")
	}
	if !cc.IsSecretAllowed("this-is-example-key") {
		t.Error("'this-is-example-key' should be allowed (matches regex)")
	}
	if cc.IsSecretAllowed("real-secret-123") {
		t.Error("'real-secret-123' should NOT be allowed")
	}

	// Test rule disabled
	if !cc.IsRuleDisabled("pattern-5") {
		t.Error("pattern-5 should be disabled")
	}
	if cc.IsRuleDisabled("pattern-1") {
		t.Error("pattern-1 should NOT be disabled")
	}
}
