package main

import "testing"

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
