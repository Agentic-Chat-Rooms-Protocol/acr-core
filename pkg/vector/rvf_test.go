package vector

import (
	"encoding/json"
	"math"
	"math/bits"
	"path/filepath"
	"testing"
)

func TestRvfStoreSerialization(t *testing.T) {
	dim := 4
	store := NewRvfStore(dim)

	meta1, _ := json.Marshal(map[string]string{"type": "message", "sender": "agent-1"})
	meta2, _ := json.Marshal(map[string]string{"type": "memory", "sender": "agent-2"})

	_ = store.Upsert(RvfRecord{
		ID:     "msg-1",
		Vector: []float32{1.0, 0.0, 0.5, -0.2},
		Meta:   meta1,
	})
	_ = store.Upsert(RvfRecord{
		ID:     "msg-2",
		Vector: []float32{-0.8, 0.2, -0.1, 0.9},
		Meta:   meta2,
	})

	if store.Len() != 2 {
		t.Fatalf("Expected 2 records, got %d", store.Len())
	}

	// Serialize
	data, err := store.ToBytes()
	if err != nil {
		t.Fatalf("ToBytes failed: %v", err)
	}

	// Deserialize
	loaded, err := FromBytes(data)
	if err != nil {
		t.Fatalf("FromBytes failed: %v", err)
	}

	if loaded.Dim() != dim || loaded.Len() != 2 {
		t.Fatalf("Loaded store mismatch: dim=%d, len=%d", loaded.Dim(), loaded.Len())
	}

	rec1 := loaded.Records()[0]
	if rec1.ID != "msg-1" || len(rec1.Vector) != dim {
		t.Fatalf("Loaded record 1 mismatch: %+v", rec1)
	}
	if rec1.Vector[0] != 1.0 || rec1.Vector[1] != 0.0 {
		t.Fatalf("Vector values altered during serialization: %+v", rec1.Vector)
	}

	// Save and load file
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "test.rvf")
	if err := store.SaveToFile(filePath); err != nil {
		t.Fatalf("SaveToFile failed: %v", err)
	}

	fromFile, err := LoadFromFile(filePath)
	if err != nil {
		t.Fatalf("LoadFromFile failed: %v", err)
	}
	if fromFile.Len() != 2 {
		t.Fatalf("LoadFromFile length mismatch")
	}
}

func TestRvfStoreSearch(t *testing.T) {
	dim := 3
	store := NewRvfStore(dim)

	_ = store.Upsert(RvfRecord{ID: "x", Vector: []float32{1.0, 0.0, 0.0}, Meta: []byte("{}")})
	_ = store.Upsert(RvfRecord{ID: "y", Vector: []float32{0.0, 1.0, 0.0}, Meta: []byte("{}")})
	_ = store.Upsert(RvfRecord{ID: "diag", Vector: []float32{0.7071, 0.7071, 0.0}, Meta: []byte("{}")})

	hits, err := store.Search([]float32{1.0, 0.0, 0.0}, 2)
	if err != nil {
		t.Fatalf("Search failed: %v", err)
	}

	if len(hits) != 2 {
		t.Fatalf("Expected 2 hits, got %d", len(hits))
	}
	if hits[0].ID != "x" || math.Abs(float64(hits[0].Score-1.0)) > 1e-4 {
		t.Fatalf("Top hit should be 'x' with score 1.0, got ID=%s, score=%f", hits[0].ID, hits[0].Score)
	}
	if hits[1].ID != "diag" {
		t.Fatalf("Second hit should be 'diag', got ID=%s", hits[1].ID)
	}
}

func TestLshIndexSearch(t *testing.T) {
	dim := 8
	store := NewRvfStore(dim)

	v1 := []float32{1.0, 0.0, 0.5, -0.2, 0.8, -0.5, 0.3, 0.1}
	v2 := []float32{0.99, 0.01, 0.49, -0.19, 0.81, -0.49, 0.31, 0.09} // very close to v1
	v3 := []float32{-1.0, 0.0, -0.5, 0.2, -0.8, 0.5, -0.3, -0.1}      // opposite of v1

	_ = store.Upsert(RvfRecord{ID: "v1", Vector: v1, Meta: []byte("{}")})
	_ = store.Upsert(RvfRecord{ID: "v2", Vector: v2, Meta: []byte("{}")})
	_ = store.Upsert(RvfRecord{ID: "v3", Vector: v3, Meta: []byte("{}")})

	index := BuildLshIndex(store)

	sig1 := index.ComputeSignature(v1)
	sig2 := index.ComputeSignature(v2)
	sig3 := index.ComputeSignature(v3)

	hamming12 := bits.OnesCount64(sig1 ^ sig2)
	hamming13 := bits.OnesCount64(sig1 ^ sig3)

	// Invariant: close vectors must have very small Hamming distance, opposite must be large
	if hamming12 > 5 {
		t.Fatalf("LSH failed: close vectors should have small Hamming distance, got %d", hamming12)
	}
	if hamming13 < 50 {
		t.Fatalf("LSH failed: inverted vectors should have large Hamming distance, got %d", hamming13)
	}

	// Approximate ANN search
	hits, err := index.Search(store, v1, 2, 2)
	if err != nil {
		t.Fatalf("LSH search failed: %v", err)
	}

	if len(hits) != 2 {
		t.Fatalf("Expected 2 hits, got %d", len(hits))
	}
	if hits[0].ID != "v1" {
		t.Fatalf("Top hit must be v1 itself, got %s", hits[0].ID)
	}
	if hits[1].ID != "v2" {
		t.Fatalf("Second hit must be v2, got %s", hits[1].ID)
	}
}
