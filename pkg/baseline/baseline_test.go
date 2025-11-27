package baseline

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFingerprint(t *testing.T) {
	fp1 := Fingerprint("src/app.go", "pattern-0", "secret123")
	fp2 := Fingerprint("src/app.go", "pattern-0", "secret123")
	fp3 := Fingerprint("src/app.go", "pattern-1", "secret123")
	fp4 := Fingerprint("src/other.go", "pattern-0", "secret123")

	// Same inputs should produce same fingerprint
	if fp1 != fp2 {
		t.Errorf("identical inputs should produce same fingerprint: %q vs %q", fp1, fp2)
	}

	// Different rule ID should produce different fingerprint
	if fp1 == fp3 {
		t.Error("different rule IDs should produce different fingerprints")
	}

	// Different file should produce different fingerprint
	if fp1 == fp4 {
		t.Error("different files should produce different fingerprints")
	}

	// Fingerprint should be 32 chars (128 bits hex)
	if len(fp1) != 32 {
		t.Errorf("expected 32-char fingerprint, got %d", len(fp1))
	}
}

func TestSecretHash(t *testing.T) {
	h1 := SecretHash("my-secret-key")
	h2 := SecretHash("my-secret-key")
	h3 := SecretHash("different-secret")

	if h1 != h2 {
		t.Error("same secret should produce same hash")
	}

	if h1 == h3 {
		t.Error("different secrets should produce different hashes")
	}

	if len(h1) != 16 {
		t.Errorf("expected 16-char hash, got %d", len(h1))
	}
}

func TestNewBaseline(t *testing.T) {
	b := New()

	if b.Version != "1.0" {
		t.Errorf("expected version 1.0, got %q", b.Version)
	}

	if len(b.Entries) != 0 {
		t.Errorf("expected empty entries, got %d", len(b.Entries))
	}

	if b.Count() != 0 {
		t.Errorf("expected count 0, got %d", b.Count())
	}
}

func TestAddAndContains(t *testing.T) {
	b := New()

	entry := CreateEntry("src/app.go", 10, "pattern-0", "secret123", "known test secret")
	b.Add(entry)

	if b.Count() != 1 {
		t.Errorf("expected count 1, got %d", b.Count())
	}

	if !b.Contains(entry.Fingerprint) {
		t.Error("baseline should contain added fingerprint")
	}

	if !b.IsBaselined("src/app.go", "pattern-0", "secret123") {
		t.Error("IsBaselined should return true for added finding")
	}

	if b.IsBaselined("src/app.go", "pattern-0", "different-secret") {
		t.Error("IsBaselined should return false for different secret")
	}

	// Adding duplicate should not increase count
	b.Add(entry)
	if b.Count() != 1 {
		t.Errorf("duplicate add should not increase count, got %d", b.Count())
	}
}

func TestSaveAndLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "baseline.json")

	// Create and save baseline
	b1 := New()
	b1.Add(CreateEntry("file1.go", 10, "rule-1", "secret1", "reason1"))
	b1.Add(CreateEntry("file2.go", 20, "rule-2", "secret2", "reason2"))

	if err := b1.Save(path); err != nil {
		t.Fatalf("Save error: %v", err)
	}

	// Load baseline
	b2, err := Load(path)
	if err != nil {
		t.Fatalf("Load error: %v", err)
	}

	if b2.Count() != 2 {
		t.Errorf("expected 2 entries after load, got %d", b2.Count())
	}

	if !b2.IsBaselined("file1.go", "rule-1", "secret1") {
		t.Error("loaded baseline should contain first entry")
	}

	if !b2.IsBaselined("file2.go", "rule-2", "secret2") {
		t.Error("loaded baseline should contain second entry")
	}
}

func TestLoadNonExistent(t *testing.T) {
	b, err := Load("/nonexistent/path/baseline.json")
	if err != nil {
		t.Fatalf("Load should not error for nonexistent file: %v", err)
	}

	if b.Count() != 0 {
		t.Errorf("expected empty baseline for nonexistent file, got %d entries", b.Count())
	}
}

func TestLoadInvalid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "invalid.json")

	if err := os.WriteFile(path, []byte("not valid json"), 0o644); err != nil {
		t.Fatalf("WriteFile error: %v", err)
	}

	_, err := Load(path)
	if err == nil {
		t.Error("Load should error for invalid JSON")
	}
}
