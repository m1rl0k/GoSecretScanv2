package vectorstore

import "testing"

func TestSanitizeSnippet(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		if got := sanitizeSnippet("", true); got != "" {
			t.Fatalf("expected empty string, got %q", got)
		}
	})

	t.Run("ephemeral truncates and is deterministic", func(t *testing.T) {
		first := sanitizeSnippet("super-secret", true)
		second := sanitizeSnippet("super-secret", true)
		if first != second {
			t.Fatalf("expected deterministic hash, got %q and %q", first, second)
		}
		if len(first) != len("sha256:")+16 {
			t.Fatalf("expected truncated hash length, got %q", first)
		}
	})

	t.Run("persistent keeps full hash", func(t *testing.T) {
		got := sanitizeSnippet("super-secret", false)
		if len(got) != len("sha256:")+64 {
			t.Fatalf("expected full hash length, got %q", got)
		}
	})
}
