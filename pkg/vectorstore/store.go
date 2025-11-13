package vectorstore

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"

	_ "github.com/mattn/go-sqlite3"
)

// Finding represents a secret finding with its embedding
type Finding struct {
	ID          int64
	FilePath    string
	LineNumber  int
	CodeSnippet string
	Embedding   []float32
	PatternType string
	Entropy     float64
	Confidence  string
	Verified    bool
	Timestamp   int64
}

// VectorStore handles storage and retrieval of embeddings
type VectorStore struct {
	db        *sql.DB
	enabled   bool
	dbPath    string
	ephemeral bool
}

// NewVectorStore creates a new vector store
func NewVectorStore(dbPath string, enabled bool, ephemeral bool) (*VectorStore, error) {
	if !enabled {
		return &VectorStore{enabled: false, dbPath: dbPath, ephemeral: ephemeral}, nil
	}

	// Create directory if it doesn't exist
	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create directory: %w", err)
	}

	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	store := &VectorStore{
		db:        db,
		enabled:   true,
		dbPath:    dbPath,
		ephemeral: ephemeral,
	}

	if err := store.initialize(); err != nil {
		return nil, err
	}

	return store, nil
}

// initialize creates the necessary tables
func (vs *VectorStore) initialize() error {
	schema := `
	CREATE TABLE IF NOT EXISTS findings (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		file_path TEXT NOT NULL,
		line_number INTEGER NOT NULL,
		code_snippet TEXT NOT NULL,
		embedding TEXT NOT NULL,
		pattern_type TEXT NOT NULL,
		entropy REAL NOT NULL,
		confidence TEXT NOT NULL,
		verified BOOLEAN DEFAULT 0,
		timestamp INTEGER NOT NULL,
		UNIQUE(file_path, line_number, pattern_type)
	);

	CREATE INDEX IF NOT EXISTS idx_file_path ON findings(file_path);
	CREATE INDEX IF NOT EXISTS idx_confidence ON findings(confidence);
	CREATE INDEX IF NOT EXISTS idx_verified ON findings(verified);
	CREATE INDEX IF NOT EXISTS idx_timestamp ON findings(timestamp);
	`

	_, err := vs.db.Exec(schema)
	return err
}

// Store saves a finding with its embedding
func (vs *VectorStore) Store(finding *Finding) error {
	if !vs.enabled {
		return nil
	}

	embeddingJSON, err := json.Marshal(finding.Embedding)
	if err != nil {
		return fmt.Errorf("failed to marshal embedding: %w", err)
	}

	query := `
	INSERT OR REPLACE INTO findings (
		file_path, line_number, code_snippet, embedding,
		pattern_type, entropy, confidence, verified, timestamp
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	sanitizedSnippet := sanitizeSnippet(finding.CodeSnippet, vs.ephemeral)

	result, err := vs.db.Exec(query,
		finding.FilePath,
		finding.LineNumber,
		sanitizedSnippet,
		string(embeddingJSON),
		finding.PatternType,
		finding.Entropy,
		finding.Confidence,
		finding.Verified,
		finding.Timestamp,
	)

	if err != nil {
		return fmt.Errorf("failed to store finding: %w", err)
	}

	id, _ := result.LastInsertId()
	finding.ID = id

	return nil
}

// Search finds similar findings using cosine similarity
func (vs *VectorStore) Search(embedding []float32, topK int, threshold float32) ([]*Finding, error) {
	if !vs.enabled {
		return []*Finding{}, nil
	}

	query := `
	SELECT id, file_path, line_number, code_snippet, embedding,
	       pattern_type, entropy, confidence, verified, timestamp
	FROM findings
	`

	rows, err := vs.db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to query findings: %w", err)
	}
	defer rows.Close()

	type scoredFinding struct {
		finding    *Finding
		similarity float32
	}

	var candidates []scoredFinding

	for rows.Next() {
		var finding Finding
		var embeddingJSON string

		err := rows.Scan(
			&finding.ID,
			&finding.FilePath,
			&finding.LineNumber,
			&finding.CodeSnippet,
			&embeddingJSON,
			&finding.PatternType,
			&finding.Entropy,
			&finding.Confidence,
			&finding.Verified,
			&finding.Timestamp,
		)
		if err != nil {
			continue
		}

		// Unmarshal embedding
		if err := json.Unmarshal([]byte(embeddingJSON), &finding.Embedding); err != nil {
			continue
		}

		// Calculate similarity
		similarity := cosineSimilarity(embedding, finding.Embedding)

		if similarity >= threshold {
			candidates = append(candidates, scoredFinding{
				finding:    &finding,
				similarity: similarity,
			})
		}
	}

	// Sort by similarity (descending)
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].similarity > candidates[j].similarity
	})

	// Return top K
	var results []*Finding
	for i := 0; i < topK && i < len(candidates); i++ {
		results = append(results, candidates[i].finding)
	}

	return results, nil
}

// MarkVerified marks a finding as verified
func (vs *VectorStore) MarkVerified(id int64, verified bool) error {
	if !vs.enabled {
		return nil
	}

	query := `UPDATE findings SET verified = ? WHERE id = ?`
	_, err := vs.db.Exec(query, verified, id)
	return err
}

// Close closes the database connection
func (vs *VectorStore) Close() error {
	if vs.db != nil {
		if err := vs.db.Close(); err != nil {
			return err
		}
	}

	if vs.enabled && vs.ephemeral && vs.dbPath != "" {
		if err := os.Remove(vs.dbPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}

	return nil
}

// cosineSimilarity calculates cosine similarity between two vectors
func cosineSimilarity(a, b []float32) float32 {
	if len(a) != len(b) || len(a) == 0 {
		return 0
	}

	var dot, normA, normB float64
	for i := range a {
		ai := float64(a[i])
		bi := float64(b[i])
		dot += ai * bi
		normA += ai * ai
		normB += bi * bi
	}

	denom := math.Sqrt(normA) * math.Sqrt(normB)
	if denom == 0 {
		return 0
	}
	return float32(dot / denom)
}

func sanitizeSnippet(snippet string, ephemeral bool) string {
	if snippet == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(snippet))
	encoded := hex.EncodeToString(sum[:])
	if ephemeral {
		return "sha256:" + encoded[:16]
	}
	return "sha256:" + encoded
}
