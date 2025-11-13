package parser

import (
	"path/filepath"
	"strings"
)

// ParsedCode represents parsed code structure
type ParsedCode struct {
	Language    string
	Functions   []string
	Strings     []string
	Variables   []string
	Comments    []string
	IsTest      bool
	Imports     []string
}

// CodeParser handles code parsing
type CodeParser struct {
	enabled bool
}

// NewCodeParser creates a new code parser
func NewCodeParser(enabled bool) *CodeParser {
	return &CodeParser{
		enabled: enabled,
	}
}

// ParseFile parses a file and extracts code structure
func (p *CodeParser) ParseFile(filePath string, content []byte) (*ParsedCode, error) {
	if !p.enabled {
		return p.basicParse(filePath, content), nil
	}

	// Future: Use tree-sitter here
	return p.basicParse(filePath, content), nil
}

// basicParse provides basic parsing without tree-sitter
func (p *CodeParser) basicParse(filePath string, content []byte) *ParsedCode {
	ext := strings.ToLower(filepath.Ext(filePath))
	language := detectLanguage(ext)

	lines := strings.Split(string(content), "\n")

	parsed := &ParsedCode{
		Language:  language,
		Functions: []string{},
		Strings:   []string{},
		Variables: []string{},
		Comments:  []string{},
		IsTest:    isTestFile(filePath),
		Imports:   []string{},
	}

	// Simple heuristic parsing
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Detect functions
		if strings.Contains(trimmed, "func ") ||
		   strings.Contains(trimmed, "def ") ||
		   strings.Contains(trimmed, "function ") {
			parsed.Functions = append(parsed.Functions, trimmed)
		}

		// Detect imports
		if strings.HasPrefix(trimmed, "import ") ||
		   strings.HasPrefix(trimmed, "from ") ||
		   strings.HasPrefix(trimmed, "require(") {
			parsed.Imports = append(parsed.Imports, trimmed)
		}
	}

	return parsed
}

func detectLanguage(ext string) string {
	languages := map[string]string{
		".go":   "go",
		".py":   "python",
		".js":   "javascript",
		".ts":   "typescript",
		".java": "java",
		".c":    "c",
		".cpp":  "cpp",
		".rs":   "rust",
		".rb":   "ruby",
		".php":  "php",
		".sh":   "bash",
		".yaml": "yaml",
		".yml":  "yaml",
		".json": "json",
	}

	if lang, ok := languages[ext]; ok {
		return lang
	}
	return "unknown"
}

func isTestFile(path string) bool {
	lower := strings.ToLower(path)
	return strings.Contains(lower, "test") ||
		strings.Contains(lower, "spec") ||
		strings.Contains(lower, "_test.") ||
		strings.Contains(lower, ".test.")
}

// GetContext extracts context around a line number
func (p *CodeParser) GetContext(content []byte, lineNum int, contextLines int) string {
	lines := strings.Split(string(content), "\n")

	start := lineNum - contextLines - 1
	if start < 0 {
		start = 0
	}

	end := lineNum + contextLines
	if end > len(lines) {
		end = len(lines)
	}

	return strings.Join(lines[start:end], "\n")
}
