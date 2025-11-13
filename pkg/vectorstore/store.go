package vectorstore

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

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
	db      *sql.DB
	enabled bool
}

// NewVectorStore creates a new vector store
func NewVectorStore(dbPath string, enabled bool) (*VectorStore, error) {
	if !enabled {
		return &VectorStore{enabled: false}, nil
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
		db:      db,
		enabled: true,
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

	result, err := vs.db.Exec(query,
		finding.FilePath,
		finding.LineNumber,
		finding.CodeSnippet,
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
	for i := 0; i < len(candidates)-1; i++ {
		for j := i + 1; j < len(candidates); j++ {
			if candidates[j].similarity > candidates[i].similarity {
				candidates[i], candidates[j] = candidates[j], candidates[i]
			}
		}
	}

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
		return vs.db.Close()
	}
	return nil
}

// cosineSimilarity calculates cosine similarity between two vectors
func cosineSimilarity(a, b []float32) float32 {
	if len(a) != len(b) {
		return 0
	}

	var dotProduct, normA, normB float32
	for i := range a {
		dotProduct += a[i] * b[i]
		normA += a[i] * a[i]
		normB += b[i] * b[i]
	}

	if normA == 0 || normB == 0 {
		return 0
	}

	return dotProduct / (float32(normA) * float32(normB))
}
