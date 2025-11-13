package verification

import (
	"fmt"
	"os"
	"time"

	"github.com/m1rl0k/GoSecretScanv2/pkg/embeddings"
	"github.com/m1rl0k/GoSecretScanv2/pkg/llm"
	"github.com/m1rl0k/GoSecretScanv2/pkg/parser"
	"github.com/m1rl0k/GoSecretScanv2/pkg/vectorstore"
)

// Pipeline orchestrates the verification process
type Pipeline struct {
	parser              *parser.CodeParser
	embeddings          *embeddings.EmbeddingGenerator
	vectorStore         *vectorstore.VectorStore
	llmVerifier         *llm.LLMVerifier
	enabled             bool
	similarityThreshold float32
}

// Config holds pipeline configuration
type Config struct {
	Enabled             bool
	DBPath              string
	ModelPath           string
	SimilarityThreshold float32
	EphemeralStore      bool
}

// NewPipeline creates a new verification pipeline
func NewPipeline(config *Config) (*Pipeline, error) {
	if !config.Enabled {
		return &Pipeline{enabled: false}, nil
	}

	// Initialize components
	codeParser := parser.NewCodeParser(config.Enabled)

	embeddingGen := embeddings.NewEmbeddingGenerator(config.Enabled)

	vectorStore, err := vectorstore.NewVectorStore(config.DBPath, config.Enabled, config.EphemeralStore)
	if err != nil {
		return nil, fmt.Errorf("failed to create vector store: %w", err)
	}

	llmVerifier, err := llm.NewLLMVerifier(config.ModelPath, config.Enabled)
	if err != nil {
		// LLM is optional, can fall back to heuristics
		llmVerifier = &llm.LLMVerifier{}
	}

	return &Pipeline{
		parser:              codeParser,
		embeddings:          embeddingGen,
		vectorStore:         vectorStore,
		llmVerifier:         llmVerifier,
		enabled:             true,
		similarityThreshold: config.SimilarityThreshold,
	}, nil
}

// VerifyFinding verifies a single finding
func (p *Pipeline) VerifyFinding(
	filePath string,
	lineNumber int,
	line string,
	patternType string,
	match string,
	entropy float64,
	context string,
	confidence string,
) (*llm.VerificationResult, error) {
	if !p.enabled {
		return &llm.VerificationResult{
			IsRealSecret:   true,
			Confidence:     confidence,
			Reasoning:      "Verification pipeline disabled",
			Recommendation: "Review manually",
		}, nil
	}

	// Read file content
	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	// Parse code
	parsed, err := p.parser.ParseFile(filePath, content)
	if err != nil {
		return nil, fmt.Errorf("failed to parse file: %w", err)
	}

	// Create code context
	codeContext := &llm.CodeContext{
		FilePath:        filePath,
		Language:        parsed.Language,
		Function:        p.findFunction(parsed, lineNumber),
		SurroundingCode: p.parser.GetContext(content, lineNumber, 5),
		Imports:         parsed.Imports,
		IsTest:          parsed.IsTest,
	}

	// Create finding
	finding := &llm.Finding{
		FilePath:    filePath,
		LineNumber:  lineNumber,
		Line:        line,
		PatternType: patternType,
		Match:       match,
		Entropy:     entropy,
		Context:     context,
		Confidence:  confidence,
	}

	// Generate embedding
	embedding, err := p.embeddings.Generate(line)
	if err != nil {
		return nil, fmt.Errorf("failed to generate embedding: %w", err)
	}

	// Search for similar findings
	similar, err := p.vectorStore.Search(embedding, 10, p.similarityThreshold)
	if err != nil {
		return nil, fmt.Errorf("failed to search vector store: %w", err)
	}

	// If we have similar verified findings, use their results
	if len(similar) > 0 {
		for _, s := range similar {
			if s.Verified {
				// Found a similar verified finding
				return &llm.VerificationResult{
					IsRealSecret:   true,
					Confidence:     s.Confidence,
					Reasoning:      fmt.Sprintf("Similar to previously verified finding in %s", s.FilePath),
					Recommendation: "Review and remove",
				}, nil
			}
		}
	}

	// Verify with LLM
	result, err := p.llmVerifier.Verify(finding, codeContext)
	if err != nil {
		return nil, fmt.Errorf("failed to verify with LLM: %w", err)
	}

	// Store the finding in vector store
	storeFinding := &vectorstore.Finding{
		FilePath:    filePath,
		LineNumber:  lineNumber,
		CodeSnippet: line,
		Embedding:   embedding,
		PatternType: patternType,
		Entropy:     entropy,
		Confidence:  result.Confidence,
		Verified:    result.IsRealSecret,
		Timestamp:   time.Now().Unix(),
	}

	if err := p.vectorStore.Store(storeFinding); err != nil {
		// Non-fatal error, just log
		fmt.Printf("Warning: failed to store finding: %v\n", err)
	}

	return result, nil
}

// findFunction finds the function containing the given line number
func (p *Pipeline) findFunction(parsed *parser.ParsedCode, lineNumber int) string {
	// Simple heuristic - return first function if any
	if len(parsed.Functions) > 0 {
		return parsed.Functions[0]
	}
	return "unknown"
}

// Close releases pipeline resources
func (p *Pipeline) Close() error {
	if p.vectorStore != nil {
		if err := p.vectorStore.Close(); err != nil {
			return err
		}
	}

	if p.llmVerifier != nil {
		if err := p.llmVerifier.Close(); err != nil {
			return err
		}
	}

	return nil
}
