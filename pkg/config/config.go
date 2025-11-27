// Package config provides configuration loading and management for GoSecretScanv2.
package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
)

// DefaultConfigFile is the default config file name looked for in the repo root.
const DefaultConfigFile = ".gosecretscanner.json"

// Config represents the full scanner configuration.
type Config struct {
	General   GeneralConfig   `json:"general"`
	Rules     []RuleConfig    `json:"rules"`
	Allowlist AllowlistConfig `json:"allowlist"`
}

// GeneralConfig contains general scanner settings.
type GeneralConfig struct {
	MinEntropy  float64 `json:"min_entropy"`   // Minimum entropy threshold (default: 3.0)
	MaxFileSize int64   `json:"max_file_size"` // Max file size in bytes (default: 5MB)
}

// RuleConfig defines a custom detection rule.
type RuleConfig struct {
	ID          string   `json:"id"`                    // Unique rule identifier
	Pattern     string   `json:"pattern"`               // Regex pattern
	Description string   `json:"description,omitempty"` // Human-readable description
	Tags        []string `json:"tags,omitempty"`        // Categorization tags
	MinEntropy  float64  `json:"min_entropy,omitempty"` // Override global entropy threshold
	Enabled     bool     `json:"enabled"`               // Whether rule is active
	Confidence  string   `json:"confidence,omitempty"`  // Default confidence level
}

// AllowlistConfig defines patterns/paths to exclude from findings.
type AllowlistConfig struct {
	Paths       []string `json:"paths"`        // Glob patterns for paths to ignore
	Secrets     []string `json:"secrets"`      // Exact secret values to ignore
	Regexes     []string `json:"regexes"`      // Regex patterns for secrets to ignore
	RuleIDs     []string `json:"rule_ids"`     // Rule IDs to disable entirely
	PathRegexes []string `json:"path_regexes"` // Regex patterns for paths to ignore
	Files       []string `json:"files"`        // Exact file names to ignore
}

// CompiledConfig holds pre-compiled regexes for performance.
type CompiledConfig struct {
	Config           *Config
	CustomPatterns   []*regexp.Regexp
	AllowlistRegexes []*regexp.Regexp
	PathRegexes      []*regexp.Regexp
	AllowedSecrets   map[string]bool
	DisabledRules    map[string]bool
}

// DefaultConfig returns a config with sensible defaults.
func DefaultConfig() *Config {
	return &Config{
		General: GeneralConfig{
			MinEntropy:  3.0,
			MaxFileSize: 5 * 1024 * 1024, // 5MB
		},
		Rules:     []RuleConfig{},
		Allowlist: AllowlistConfig{},
	}
}

// Load reads config from the specified path, or looks for DefaultConfigFile in dir.
// Returns default config if no file is found.
func Load(configPath, repoRoot string) (*Config, error) {
	// If explicit path given, use it
	if configPath != "" {
		return loadFromFile(configPath)
	}

	// Otherwise look for default config in repo root
	defaultPath := filepath.Join(repoRoot, DefaultConfigFile)
	if _, err := os.Stat(defaultPath); err == nil {
		return loadFromFile(defaultPath)
	}

	// No config file found, return defaults
	return DefaultConfig(), nil
}

func loadFromFile(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	cfg := DefaultConfig()
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}

// Compile pre-compiles all regex patterns for performance.
func (c *Config) Compile() (*CompiledConfig, error) {
	cc := &CompiledConfig{
		Config:         c,
		AllowedSecrets: make(map[string]bool),
		DisabledRules:  make(map[string]bool),
	}

	// Compile custom rule patterns
	for _, rule := range c.Rules {
		if !rule.Enabled {
			continue
		}
		re, err := regexp.Compile(rule.Pattern)
		if err != nil {
			return nil, err
		}
		cc.CustomPatterns = append(cc.CustomPatterns, re)
	}

	// Compile allowlist regexes
	for _, pattern := range c.Allowlist.Regexes {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, err
		}
		cc.AllowlistRegexes = append(cc.AllowlistRegexes, re)
	}

	// Compile path regexes
	for _, pattern := range c.Allowlist.PathRegexes {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, err
		}
		cc.PathRegexes = append(cc.PathRegexes, re)
	}

	// Build allowed secrets set
	for _, secret := range c.Allowlist.Secrets {
		cc.AllowedSecrets[secret] = true
	}

	// Build disabled rules set
	for _, ruleID := range c.Allowlist.RuleIDs {
		cc.DisabledRules[ruleID] = true
	}

	return cc, nil
}

// IsPathAllowed checks if a path should be scanned (not in allowlist).
func (cc *CompiledConfig) IsPathAllowed(relPath string) bool {
	// Check exact file matches
	base := filepath.Base(relPath)
	for _, f := range cc.Config.Allowlist.Files {
		if f == base || f == relPath {
			return false
		}
	}

	// Check glob patterns
	for _, pattern := range cc.Config.Allowlist.Paths {
		if matched, _ := filepath.Match(pattern, relPath); matched {
			return false
		}
		if matched, _ := filepath.Match(pattern, base); matched {
			return false
		}
	}

	// Check path regexes
	for _, re := range cc.PathRegexes {
		if re.MatchString(relPath) {
			return false
		}
	}

	return true
}

// IsSecretAllowed checks if a specific secret value should be ignored.
func (cc *CompiledConfig) IsSecretAllowed(secret string) bool {
	// Check exact matches
	if cc.AllowedSecrets[secret] {
		return true
	}

	// Check regex matches
	for _, re := range cc.AllowlistRegexes {
		if re.MatchString(secret) {
			return true
		}
	}

	return false
}

// IsRuleDisabled checks if a rule ID is disabled.
func (cc *CompiledConfig) IsRuleDisabled(ruleID string) bool {
	return cc.DisabledRules[ruleID]
}

// GetMinEntropy returns the effective minimum entropy threshold.
func (cc *CompiledConfig) GetMinEntropy() float64 {
	if cc.Config.General.MinEntropy > 0 {
		return cc.Config.General.MinEntropy
	}
	return 3.0 // Default
}

// GetMaxFileSize returns the effective maximum file size.
func (cc *CompiledConfig) GetMaxFileSize() int64 {
	if cc.Config.General.MaxFileSize > 0 {
		return cc.Config.General.MaxFileSize
	}
	return 5 * 1024 * 1024 // 5MB default
}

// GetEnabledRules returns all enabled custom rules.
func (cc *CompiledConfig) GetEnabledRules() []RuleConfig {
	var rules []RuleConfig
	for _, rule := range cc.Config.Rules {
		if rule.Enabled {
			rules = append(rules, rule)
		}
	}
	return rules
}
