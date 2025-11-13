package embeddings

import (
	"fmt"
	"math"
	"os"
	"path/filepath"

	ort "github.com/yalue/onnxruntime_go"
	"github.com/sugarme/tokenizer"
	"github.com/sugarme/tokenizer/pretrained"
)

// EmbeddingGenerator generates embeddings for text using BGE model
type EmbeddingGenerator struct {
	enabled   bool
	dimension int
	session   *ort.AdvancedSession
	tokenizer *tokenizer.Tokenizer
	modelPath string
}

// NewEmbeddingGenerator creates a new embedding generator
func NewEmbeddingGenerator(enabled bool) *EmbeddingGenerator {
	return &EmbeddingGenerator{
		enabled:   enabled,
		dimension: 384, // BGE-small dimension
	}
}

// Initialize loads the ONNX model and tokenizer
func (e *EmbeddingGenerator) Initialize(modelsDir string) error {
	if !e.enabled {
		return nil
	}

	// Initialize ONNX runtime
	if err := ort.InitializeEnvironment(); err != nil {
		return fmt.Errorf("failed to initialize ONNX runtime: %w", err)
	}

	// Load BGE model
	modelPath := filepath.Join(modelsDir, "bge-small-en-v1.5.onnx")
	if _, err := os.Stat(modelPath); os.IsNotExist(err) {
		return fmt.Errorf("BGE model not found at %s. Run scripts/download-models.sh", modelPath)
	}

	e.modelPath = modelPath

	// Create ONNX session
	session, err := ort.NewAdvancedSession(modelPath,
		[]string{"input_ids", "attention_mask", "token_type_ids"},
		[]string{"last_hidden_state"},
		nil)
	if err != nil {
		return fmt.Errorf("failed to create ONNX session: %w", err)
	}
	e.session = session

	// Load tokenizer
	tokenizerPath := filepath.Join(modelsDir, "bge-tokenizer.json")
	if _, err := os.Stat(tokenizerPath); os.IsNotExist(err) {
		return fmt.Errorf("BGE tokenizer not found at %s. Run scripts/download-models.sh", tokenizerPath)
	}

	tk, err := pretrained.FromFile(tokenizerPath)
	if err != nil {
		return fmt.Errorf("failed to load tokenizer: %w", err)
	}
	e.tokenizer = tk

	return nil
}

// Generate creates an embedding vector for the given text
func (e *EmbeddingGenerator) Generate(text string) ([]float32, error) {
	if !e.enabled || e.session == nil || e.tokenizer == nil {
		// Fall back to simple hash if not initialized
		return e.simpleHash(text), nil
	}

	// Tokenize input
	encoding, err := e.tokenizer.EncodeSingle(text)
	if err != nil {
		return nil, fmt.Errorf("failed to tokenize: %w", err)
	}

	ids := encoding.GetIds()
	attentionMask := encoding.GetAttentionMask()
	tokenTypeIds := encoding.GetTypeIds()

	// Prepare input tensors
	inputIDs := make([]int64, len(ids))
	for i, id := range ids {
		inputIDs[i] = int64(id)
	}

	attention := make([]int64, len(attentionMask))
	for i, mask := range attentionMask {
		attention[i] = int64(mask)
	}

	tokenTypes := make([]int64, len(tokenTypeIds))
	for i, typeID := range tokenTypeIds {
		tokenTypes[i] = int64(typeID)
	}

	// Create input shape [1, sequence_length]
	shape := ort.NewShape(1, int64(len(inputIDs)))

	inputIDsTensor, err := ort.NewTensor(shape, inputIDs)
	if err != nil {
		return nil, fmt.Errorf("failed to create input IDs tensor: %w", err)
	}
	defer inputIDsTensor.Destroy()

	attentionTensor, err := ort.NewTensor(shape, attention)
	if err != nil {
		return nil, fmt.Errorf("failed to create attention mask tensor: %w", err)
	}
	defer attentionTensor.Destroy()

	tokenTypesTensor, err := ort.NewTensor(shape, tokenTypes)
	if err != nil {
		return nil, fmt.Errorf("failed to create token types tensor: %w", err)
	}
	defer tokenTypesTensor.Destroy()

	// Run inference
	outputs, err := e.session.Run([]ort.ArbitraryTensor{
		inputIDsTensor,
		attentionTensor,
		tokenTypesTensor,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to run ONNX inference: %w", err)
	}
	defer outputs[0].Destroy()

	// Extract embeddings (CLS token pooling - first token)
	outputData := outputs[0].GetData().([]float32)

	// The output shape is [batch_size, sequence_length, hidden_dim]
	// We take the CLS token (first token) embedding
	embedding := outputData[:e.dimension]

	// Normalize the embedding
	return normalize(embedding), nil
}

// simpleHash creates a deterministic pseudo-embedding using hashing (fallback)
func (e *EmbeddingGenerator) simpleHash(text string) []float32 {
	// Use the same hash-based approach as before for fallback
	embedding := make([]float32, e.dimension)

	// Simple character-based hashing
	for i := 0; i < e.dimension; i++ {
		val := 0.0
		for j, c := range text {
			val += float64(c) * math.Sin(float64(i+j))
		}
		embedding[i] = float32(math.Sin(val))
	}

	return normalize(embedding)
}

// normalize normalizes a vector to unit length
func normalize(vec []float32) []float32 {
	var sum float32
	for _, v := range vec {
		sum += v * v
	}

	norm := float32(math.Sqrt(float64(sum)))
	if norm == 0 {
		return vec
	}

	normalized := make([]float32, len(vec))
	for i, v := range vec {
		normalized[i] = v / norm
	}

	return normalized
}

// CosineSimilarity calculates cosine similarity between two vectors
func CosineSimilarity(a, b []float32) (float32, error) {
	if len(a) != len(b) {
		return 0, fmt.Errorf("vectors must have the same dimension")
	}

	var dotProduct, normA, normB float32
	for i := range a {
		dotProduct += a[i] * b[i]
		normA += a[i] * a[i]
		normB += b[i] * b[i]
	}

	if normA == 0 || normB == 0 {
		return 0, nil
	}

	return dotProduct / (float32(math.Sqrt(float64(normA))) * float32(math.Sqrt(float64(normB)))), nil
}

// Dimension returns the embedding dimension
func (e *EmbeddingGenerator) Dimension() int {
	return e.dimension
}

// Close releases resources
func (e *EmbeddingGenerator) Close() error {
	if e.session != nil {
		if err := e.session.Destroy(); err != nil {
			return err
		}
	}
	return nil
}
