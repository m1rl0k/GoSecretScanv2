package embeddings

import (
	"fmt"
	"math"
	"os"
	"path/filepath"

	"github.com/sugarme/tokenizer"
	"github.com/sugarme/tokenizer/pretrained"
	ort "github.com/yalue/onnxruntime_go"
)

// EmbeddingGenerator generates embeddings for text using BGE model
type EmbeddingGenerator struct {
	enabled       bool
	dimension     int
	maxSeqLength  int
	session       *ort.AdvancedSession
	tokenizer     *tokenizer.Tokenizer
	modelPath     string
	inputIDs      *ort.Tensor[int64]
	attentionMask *ort.Tensor[int64]
	tokenTypeIDs  *ort.Tensor[int64]
	outputTensor  *ort.Tensor[float32]
}

// NewEmbeddingGenerator creates a new embedding generator
func NewEmbeddingGenerator(enabled bool) *EmbeddingGenerator {
	return &EmbeddingGenerator{
		enabled:      enabled,
		dimension:    384, // BGE-small dimension
		maxSeqLength: 512, // BERT max sequence length
	}
}

// Initialize loads the ONNX model and tokenizer
func (e *EmbeddingGenerator) Initialize(modelsDir string) error {
	if !e.enabled {
		return nil
	}

	// Set ONNX Runtime library path
	// Try both the versioned and symlinked names
	libPaths := []string{
		filepath.Join(modelsDir, "libonnxruntime.dylib"),        // macOS symlink
		filepath.Join(modelsDir, "libonnxruntime.1.22.0.dylib"), // macOS versioned
		filepath.Join(modelsDir, "libonnxruntime.1.20.1.dylib"), // macOS old version
		filepath.Join(modelsDir, "libonnxruntime.so"),           // Linux symlink
		filepath.Join(modelsDir, "libonnxruntime.so.1.22.0"),    // Linux versioned
		filepath.Join(modelsDir, "libonnxruntime.so.1.20.1"),    // Linux old version
	}

	libFound := false
	for _, libPath := range libPaths {
		if _, err := os.Stat(libPath); err == nil {
			ort.SetSharedLibraryPath(libPath)
			libFound = true
			break
		}
	}

	if !libFound {
		return fmt.Errorf("ONNX Runtime library not found in %s. Run scripts/download-models.sh", modelsDir)
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

	// Load tokenizer first (needed for session creation)
	tokenizerPath := filepath.Join(modelsDir, "bge-tokenizer.json")
	if _, err := os.Stat(tokenizerPath); os.IsNotExist(err) {
		return fmt.Errorf("BGE tokenizer not found at %s. Run scripts/download-models.sh", tokenizerPath)
	}

	tk, err := pretrained.FromFile(tokenizerPath)
	if err != nil {
		return fmt.Errorf("failed to load tokenizer: %w", err)
	}
	e.tokenizer = tk

	// Pre-allocate tensors with fixed shape [1, maxSeqLength]
	shape := ort.NewShape(1, int64(e.maxSeqLength))

	// Create input tensors (will be filled with data on each call)
	e.inputIDs, err = ort.NewEmptyTensor[int64](shape)
	if err != nil {
		return fmt.Errorf("failed to create input IDs tensor: %w", err)
	}

	e.attentionMask, err = ort.NewEmptyTensor[int64](shape)
	if err != nil {
		return fmt.Errorf("failed to create attention mask tensor: %w", err)
	}

	e.tokenTypeIDs, err = ort.NewEmptyTensor[int64](shape)
	if err != nil {
		return fmt.Errorf("failed to create token type IDs tensor: %w", err)
	}

	// Create output tensor [1, maxSeqLength, dimension]
	outputShape := ort.NewShape(1, int64(e.maxSeqLength), int64(e.dimension))
	e.outputTensor, err = ort.NewEmptyTensor[float32](outputShape)
	if err != nil {
		return fmt.Errorf("failed to create output tensor: %w", err)
	}

	// Create ONNX session with pre-allocated tensors
	session, err := ort.NewAdvancedSession(modelPath,
		[]string{"input_ids", "attention_mask", "token_type_ids"},
		[]string{"last_hidden_state"},
		[]ort.Value{e.inputIDs, e.attentionMask, e.tokenTypeIDs},
		[]ort.Value{e.outputTensor},
		nil)
	if err != nil {
		return fmt.Errorf("failed to create ONNX session: %w", err)
	}
	e.session = session

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

	// Get tensor data slices
	inputData := e.inputIDs.GetData()
	attentionData := e.attentionMask.GetData()
	tokenTypeData := e.tokenTypeIDs.GetData()

	// Clear tensors (fill with zeros)
	for i := range inputData {
		inputData[i] = 0
		attentionData[i] = 0
		tokenTypeData[i] = 0
	}

	// Fill tensors with tokenized data (pad or truncate to maxSeqLength)
	seqLen := len(ids)
	if seqLen > e.maxSeqLength {
		seqLen = e.maxSeqLength
	}

	for i := 0; i < seqLen; i++ {
		inputData[i] = int64(ids[i])
		attentionData[i] = int64(attentionMask[i])
		tokenTypeData[i] = int64(tokenTypeIds[i])
	}

	// Run inference
	err = e.session.Run()
	if err != nil {
		return nil, fmt.Errorf("failed to run ONNX inference: %w", err)
	}

	// Extract embeddings (CLS token pooling - first token)
	// Output shape is [1, maxSeqLength, dimension]
	// CLS token is at position 0
	outputData := e.outputTensor.GetData()

	// Extract CLS token embedding (first dimension elements)
	embedding := make([]float32, e.dimension)
	copy(embedding, outputData[:e.dimension])

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

	// Destroy tensors
	if e.inputIDs != nil {
		e.inputIDs.Destroy()
	}
	if e.attentionMask != nil {
		e.attentionMask.Destroy()
	}
	if e.tokenTypeIDs != nil {
		e.tokenTypeIDs.Destroy()
	}
	if e.outputTensor != nil {
		e.outputTensor.Destroy()
	}

	return nil
}
