# GoSecretScanv2 - LLM-Powered Architecture

## Vision

Transform GoSecretScanv2 into the world's most advanced secret scanner by combining:
- Traditional regex pattern matching
- Shannon entropy analysis
- Context-aware detection
- **Tree-sitter code parsing**
- **Semantic embeddings (BAAI BGE)**
- **LLM verification (Llama.cpp)**
- **Vector search (SQLite-VSS)**

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    GoSecretScanv2 Pipeline                   │
└─────────────────────────────────────────────────────────────┘

  ┌─────────────┐
  │  Git Diff   │  ← Track changed files only
  │  Detection  │
  └──────┬──────┘
         │
         ▼
  ┌─────────────┐
  │ Tree-sitter │  ← Parse code structure
  │   Parsing   │  ← Understand syntax
  └──────┬──────┘
         │
         ▼
  ┌─────────────┐
  │   Regex     │  ← Pattern matching (70+ patterns)
  │  Detection  │  ← Fast pre-filter
  └──────┬──────┘
         │
         ▼
  ┌─────────────┐
  │  Entropy &  │  ← Shannon entropy
  │  Context    │  ← Context detection
  └──────┬──────┘
         │
         ▼ (medium+ confidence findings)
         │
  ┌─────────────┐
  │   BGE       │  ← Generate embeddings
  │ Embeddings  │  ← Semantic vectors
  └──────┬──────┘
         │
         ▼
  ┌─────────────┐
  │  Vector     │  ← SQLite-VSS storage
  │  Search     │  ← Similarity search
  └──────┬──────┘
         │
         ▼
  ┌─────────────┐
  │  Context    │  ← Batch similar findings
  │  Batching   │  ← Gather surrounding code
  └──────┬──────┘
         │
         ▼
  ┌─────────────┐
  │  LLM        │  ← Llama.cpp inference
  │ Verification│  ← Verify: Real or False Positive?
  └──────┬──────┘
         │
         ▼
  ┌─────────────┐
  │   Final     │  ← Only verified secrets
  │   Report    │  ← <1% false positive rate
  └─────────────┘
```

## Component Details

### 1. Tree-sitter Integration

**Purpose**: Parse code to understand structure and syntax

**Languages Supported**:
- Go, Python, JavaScript, TypeScript
- Java, C, C++, Rust
- Ruby, PHP, Bash, YAML, JSON

**Benefits**:
- Extract only code (skip comments intelligently)
- Identify function names, variable names
- Understand string literals vs identifiers
- Detect test functions automatically

**Implementation**:
```go
// pkg/parser/treesitter.go
type CodeParser struct {
    language *sitter.Language
    parser   *sitter.Parser
}

func (p *CodeParser) ParseFile(content []byte) (*ParsedCode, error) {
    tree, _ := p.parser.ParseCtx(ctx, nil, content)

    return &ParsedCode{
        Functions:    extractFunctions(tree),
        Strings:      extractStrings(tree),
        Variables:    extractVariables(tree),
        Comments:     extractComments(tree),
        IsTest:       isTestFile(tree),
    }, nil
}
```

### 2. BAAI BGE Embeddings

**Model**: BAAI/bge-small-en-v1.5 (133MB, very fast)

**Purpose**: Convert code snippets to semantic vectors

**Why BGE**:
- Fast inference (10-100ms per snippet)
- Small model size (runs in GitHub Actions)
- State-of-the-art quality for semantic search
- Optimized for English text and code

**Implementation**:
```go
// pkg/embeddings/bge.go
type EmbeddingGenerator struct {
    modelPath string
}

func (e *EmbeddingGenerator) Generate(text string) ([]float32, error) {
    // Use onnxruntime-go for fast inference
    // Or use a REST API to a local server
    embedding := runBGEModel(text)
    return embedding, nil
}
```

### 3. SQLite Vector Store

**Technology**: SQLite with sqlite-vss extension

**Purpose**: Store and search embeddings

**Schema**:
```sql
CREATE TABLE code_embeddings (
    id INTEGER PRIMARY KEY,
    file_path TEXT,
    line_number INTEGER,
    code_snippet TEXT,
    embedding BLOB,  -- 384-dim float32 vector
    pattern_type TEXT,
    entropy REAL,
    confidence TEXT,
    verified BOOLEAN,
    timestamp INTEGER
);

CREATE INDEX idx_embeddings ON code_embeddings USING vss(embedding);
```

**Benefits**:
- Fast similarity search (k-NN)
- Find similar findings across codebase
- Track historical patterns
- Lightweight (no external database)

### 4. Llama.cpp Integration

**Model**: IBM Granite-4.0-Micro (GGUF, Q4_K_M quantization)

**Size**: ~450MB Q4 quantized (perfect for CI/CD)

**Why Granite 4.0 Micro**:
- Specifically trained for code understanding
- Excellent instruction following despite small size
- Very fast inference on CPU (~100-200 tokens/sec)
- Fits easily in GitHub Actions (7GB RAM limit)
- Open-source Apache 2.0 license
- Better code analysis than general LLMs
- Lower memory footprint than larger models

**Purpose**: LLM verification of findings

**Prompt Template**:
```
You are a security expert analyzing code for secrets.

Context:
- File: auth.py
- Language: Python
- Function: connect_database()
- Line 42

Code snippet:
```python
def connect_database():
    # Database connection
    conn_str = "postgresql://user:password123@localhost/db"
    return connect(conn_str)
```

Pattern detected: (?i)password(?:\s*[:=]\s*|\s*["'\s])?([a-zA-Z0-9!@#$%^&*()_+]{8,})
Match: "password123"
Entropy: 3.2
Context: code

Question: Is this a real secret that should be reported, or a false positive?

Consider:
1. Is the value hardcoded or from an environment variable?
2. Is this in a test file or production code?
3. Is the entropy high enough to be a real secret?
4. Could this be example/template code?
5. Is the pattern in a sensitive location?

Answer with JSON:
{
  "is_real_secret": true/false,
  "confidence": "low"/"medium"/"high"/"critical",
  "reasoning": "...",
  "recommendation": "..."
}
```

**Implementation**:
```go
// pkg/llm/verification.go
type LLMVerifier struct {
    modelPath string
    ctx       *llama.Context
}

func (v *LLMVerifier) Verify(finding *Finding, context *CodeContext) (*VerificationResult, error) {
    prompt := buildPrompt(finding, context)
    response := v.ctx.Predict(prompt)

    result := parseResponse(response)
    return result, nil
}
```

### 5. Semantic Search Pipeline

**Workflow**:

1. **Generate Embedding** for each finding
2. **Search Vector Store** for similar patterns
3. **Batch Similar Findings** together
4. **Send to LLM** with full context

**Benefits**:
- Reduce LLM calls (batch similar findings)
- Learn from historical patterns
- Identify patterns across codebase
- Consistent verification for similar code

**Implementation**:
```go
// pkg/semantic/search.go
func (s *SemanticSearcher) FindSimilar(finding *Finding) ([]*Finding, error) {
    embedding := s.embeddings.Generate(finding.Line)

    similar := s.vectorStore.Search(embedding, topK=10, threshold=0.8)

    return similar, nil
}
```

### 6. Context Batching System

**Purpose**: Gather surrounding code for LLM context

**Strategy**:
- Extract 5-10 lines before/after finding
- Include function signature
- Add file-level context (imports, etc.)
- Batch similar findings together

**Implementation**:
```go
// pkg/context/batcher.go
type ContextBatcher struct {
    parser *CodeParser
}

func (b *ContextBatcher) GatherContext(finding *Finding) (*CodeContext, error) {
    parsed := b.parser.ParseFile(finding.FilePath)

    return &CodeContext{
        Function:        findFunction(parsed, finding.LineNumber),
        SurroundingCode: extractLines(finding.FilePath, finding.LineNumber-5, finding.LineNumber+5),
        Imports:         parsed.Imports,
        IsTest:          parsed.IsTest,
    }, nil
}
```

## Performance Considerations

### GitHub Actions Compatibility

**Resource Constraints**:
- 7GB RAM available
- 2-core CPU
- 14GB disk space
- Max 6 hours runtime

**Our Usage**:
- BGE model: ~300MB RAM
- TinyLlama: ~1GB RAM
- SQLite: ~100MB disk
- Total: ~1.5GB RAM, ~500MB disk ✅

### Optimization Strategies

1. **Lazy Loading**:
   - Only load LLM if medium+ confidence findings exist
   - Cache embeddings in SQLite

2. **Parallel Processing**:
   - Generate embeddings in parallel
   - Batch LLM calls (up to 10 findings)

3. **Caching**:
   - Cache verified findings in SQLite
   - Skip re-verification of unchanged files

4. **Incremental Scanning**:
   - Use git diff to only scan changed files
   - Build Merkle tree of file hashes

## Implementation Phases

### Phase 1: Foundation (Week 1)
- [x] Basic entropy and context detection (DONE)
- [ ] Tree-sitter integration
- [ ] Language detection

### Phase 2: Embeddings (Week 2)
- [ ] BGE embedding generation
- [ ] SQLite vector store setup
- [ ] Semantic search implementation

### Phase 3: LLM Integration (Week 3)
- [ ] Llama.cpp Go bindings
- [ ] Model download and quantization
- [ ] Prompt engineering
- [ ] Verification pipeline

### Phase 4: Optimization (Week 4)
- [ ] Git diff integration
- [ ] Caching and incremental scanning
- [ ] Performance tuning
- [ ] GitHub Actions optimization

### Phase 5: Testing & Release (Week 5)
- [ ] Comprehensive testing
- [ ] Benchmark vs gitleaks/truffleHog
- [ ] Documentation
- [ ] Public release

## Expected Results

### Accuracy

- **False Positive Rate**: <1% (vs gitleaks ~10-20%)
- **True Positive Rate**: >99%
- **Verification Confidence**: 95%+

### Performance

- **Small Repo (<1000 files)**: 2-5 minutes
- **Medium Repo (1000-10k files)**: 5-15 minutes
- **Large Repo (>10k files)**: 15-30 minutes

### GitHub Actions Cost

- Free tier: ✅ (within limits)
- Parallel jobs: ✅ (can parallelize)
- Caching: ✅ (cache models and vectors)

## Competitive Advantage

| Feature | GoSecretScanv2 | Gitleaks | TruffleHog | Advantage |
|---------|----------------|----------|------------|-----------|
| **LLM Verification** | ✅ | ❌ | ❌ | Revolutionary |
| **Semantic Search** | ✅ | ❌ | ❌ | Better clustering |
| **Tree-sitter Parsing** | ✅ | ❌ | ❌ | Language-aware |
| **Entropy Analysis** | ✅ | ⚠️ | ✅ | Enhanced |
| **Context Batching** | ✅ | ❌ | ❌ | Efficient |
| **Vector Storage** | ✅ | ❌ | ❌ | Historical learning |
| **False Positive Rate** | <1% | ~15% | ~10% | 10-15x better |
| **GitHub Actions** | ✅ | ✅ | ✅ | Optimized |

## Technical Stack

```
Language: Go 1.21+
Parsing: tree-sitter/tree-sitter-go
Embeddings: BAAI/bge-small-en-v1.5 (ONNX runtime)
Vector Store: SQLite + sqlite-vss
LLM: TinyLlama-1.1B (via llama.cpp)
CI/CD: GitHub Actions
```

## Next Steps

1. Implement tree-sitter integration
2. Add BGE embedding generation
3. Set up SQLite vector store
4. Integrate llama.cpp
5. Build verification pipeline
6. Optimize for GitHub Actions
7. Benchmark and tune

This architecture will make GoSecretScanv2 the most accurate and intelligent
secret scanner available, with industry-leading precision and minimal false
positives.
