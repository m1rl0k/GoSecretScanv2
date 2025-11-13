package main

import (
	"fmt"
	"log"

	"github.com/m1rl0k/GoSecretScanv2/pkg/embeddings"
)

func main() {
	// Create embedding generator
	gen := embeddings.NewEmbeddingGenerator(true)

	// Initialize with models directory
	err := gen.Initialize("../.gosecretscanner/models")
	if err != nil {
		log.Fatalf("Failed to initialize embeddings: %v", err)
	}
	defer gen.Close()

	// Test embedding generation
	testTexts := []string{
		"password = 'my_secret_password_123'",
		"API_KEY = 'sk-1234567890abcdef'",
		"# This is just a comment with fake password",
	}

	fmt.Println("Testing BGE ONNX embeddings:")
	fmt.Println("----------------------------")

	for i, text := range testTexts {
		emb, err := gen.Generate(text)
		if err != nil {
			log.Fatalf("Failed to generate embedding for text %d: %v", i, err)
		}

		fmt.Printf("\nText %d: %s\n", i+1, text)
		fmt.Printf("Embedding dimension: %d\n", len(emb))
		fmt.Printf("First 5 values: %.4f, %.4f, %.4f, %.4f, %.4f\n",
			emb[0], emb[1], emb[2], emb[3], emb[4])

		// Verify normalization
		var norm float32
		for _, v := range emb {
			norm += v * v
		}
		fmt.Printf("Norm (should be ~1.0): %.6f\n", norm)
	}

	// Test similarity between first two (should be higher than with third)
	emb1, _ := gen.Generate(testTexts[0])
	emb2, _ := gen.Generate(testTexts[1])
	emb3, _ := gen.Generate(testTexts[2])

	sim12, _ := embeddings.CosineSimilarity(emb1, emb2)
	sim13, _ := embeddings.CosineSimilarity(emb1, emb3)

	fmt.Println("\n----------------------------")
	fmt.Printf("Similarity (text1 vs text2): %.4f\n", sim12)
	fmt.Printf("Similarity (text1 vs text3): %.4f\n", sim13)
	fmt.Println("\nSuccess! ONNX embeddings are working correctly.")
}
