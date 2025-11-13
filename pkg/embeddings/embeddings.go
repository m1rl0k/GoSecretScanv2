package embeddings

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math"
)

// EmbeddingGenerator generates embeddings for text
type EmbeddingGenerator struct {
	enabled   bool
	dimension int
}

// NewEmbeddingGenerator creates a new embedding generator
func NewEmbeddingGenerator(enabled bool) *EmbeddingGenerator {
	return &EmbeddingGenerator{
		enabled:   enabled,
		dimension: 384, // BGE-small dimension
	}
}

// Generate creates an embedding vector for the given text
func (e *EmbeddingGenerator) Generate(text string) ([]float32, error) {
	if !e.enabled {
		return e.simpleHash(text), nil
	}

	// Future: Use BAAI BGE model here via ONNX runtime
	return e.simpleHash(text), nil
}

// simpleHash creates a deterministic pseudo-embedding using hashing
// This is a placeholder until we integrate the actual BGE model
func (e *EmbeddingGenerator) simpleHash(text string) []float32 {
	embedding := make([]float32, e.dimension)

	// Use SHA256 to create a deterministic hash
	hash := sha256.Sum256([]byte(text))

	// Convert hash bytes to float32 values
	for i := 0; i < e.dimension; i++ {
		// Use different parts of the hash with different seeds
		byteIdx := (i * 4) % len(hash)
		val := binary.BigEndian.Uint32(hash[byteIdx:])

		// Normalize to [-1, 1] range
		embedding[i] = float32(val)/float32(math.MaxUint32)*2.0 - 1.0
	}

	// Normalize the vector
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
