// Package baseline provides functionality to track and suppress known findings.
package baseline

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"sort"
)

// DefaultBaselineFile is the default baseline file name.
const DefaultBaselineFile = ".gosecretscanner-baseline.json"

// Entry represents a single finding in the baseline.
type Entry struct {
	Fingerprint string `json:"fingerprint"`      // Unique identifier for this finding
	FilePath    string `json:"file"`             // Relative file path
	LineNumber  int    `json:"line"`             // Original line number (may drift)
	RuleID      string `json:"rule_id"`          // Rule that triggered this finding
	SecretHash  string `json:"secret_hash"`      // SHA256 of the secret value (for verification)
	Reason      string `json:"reason,omitempty"` // Why this was baselined (optional)
}

// Baseline holds all known/accepted findings.
type Baseline struct {
	Version string  `json:"version"`
	Entries []Entry `json:"entries"`

	// Lookup map for quick fingerprint matching (not serialized)
	lookup map[string]bool
}

// New creates an empty baseline.
func New() *Baseline {
	return &Baseline{
		Version: "1.0",
		Entries: []Entry{},
		lookup:  make(map[string]bool),
	}
}

// Load reads a baseline from the specified file.
// Returns an empty baseline if the file doesn't exist.
func Load(path string) (*Baseline, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return New(), nil
		}
		return nil, err
	}

	b := New()
	if err := json.Unmarshal(data, b); err != nil {
		return nil, err
	}

	// Build lookup map
	b.lookup = make(map[string]bool)
	for _, e := range b.Entries {
		b.lookup[e.Fingerprint] = true
	}

	return b, nil
}

// Save writes the baseline to the specified file.
func (b *Baseline) Save(path string) error {
	// Sort entries for consistent output
	sort.Slice(b.Entries, func(i, j int) bool {
		if b.Entries[i].FilePath != b.Entries[j].FilePath {
			return b.Entries[i].FilePath < b.Entries[j].FilePath
		}
		return b.Entries[i].LineNumber < b.Entries[j].LineNumber
	})

	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0o644)
}

// Fingerprint generates a unique identifier for a finding.
// The fingerprint is based on: file path, rule ID, and the secret value.
// Line numbers are NOT included since they drift as code changes.
func Fingerprint(filePath, ruleID, secretValue string) string {
	h := sha256.New()
	h.Write([]byte(filePath))
	h.Write([]byte(":"))
	h.Write([]byte(ruleID))
	h.Write([]byte(":"))
	h.Write([]byte(secretValue))
	return hex.EncodeToString(h.Sum(nil))[:32] // Use first 32 chars (128 bits)
}

// SecretHash generates a hash of the secret value for verification.
func SecretHash(secretValue string) string {
	h := sha256.Sum256([]byte(secretValue))
	return hex.EncodeToString(h[:])[:16] // Use first 16 chars
}

// Add adds a new entry to the baseline.
func (b *Baseline) Add(entry Entry) {
	if b.lookup == nil {
		b.lookup = make(map[string]bool)
	}
	if !b.lookup[entry.Fingerprint] {
		b.Entries = append(b.Entries, entry)
		b.lookup[entry.Fingerprint] = true
	}
}

// Contains checks if a fingerprint is in the baseline.
func (b *Baseline) Contains(fingerprint string) bool {
	if b.lookup == nil {
		return false
	}
	return b.lookup[fingerprint]
}

// IsBaselined checks if a finding (by path, rule, secret) is in the baseline.
func (b *Baseline) IsBaselined(filePath, ruleID, secretValue string) bool {
	fp := Fingerprint(filePath, ruleID, secretValue)
	return b.Contains(fp)
}

// Count returns the number of entries in the baseline.
func (b *Baseline) Count() int {
	return len(b.Entries)
}

// CreateEntry creates a baseline entry from finding details.
func CreateEntry(filePath string, lineNumber int, ruleID, secretValue, reason string) Entry {
	return Entry{
		Fingerprint: Fingerprint(filePath, ruleID, secretValue),
		FilePath:    filePath,
		LineNumber:  lineNumber,
		RuleID:      ruleID,
		SecretHash:  SecretHash(secretValue),
		Reason:      reason,
	}
}
