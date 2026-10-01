package vector

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/bits"
	"os"
	"sort"
)

var (
	MagicRVF       = [8]byte{'A', 'G', 'B', 'B', 'S', 'R', 'V', 'F'}
	VersionRVF     = uint16(1)
	ErrBadMagic    = errors.New("invalid RVF magic bytes")
	ErrBadVersion  = errors.New("unsupported RVF version")
	ErrDimMismatch = errors.New("vector dimension mismatch")
)

// RvfRecord represents a single vector record in an RVF store.
type RvfRecord struct {
	ID     string          `json:"id"`
	Vector []float32       `json:"vector"`
	Meta   json.RawMessage `json:"meta"`
}

// RvfHit represents a scored search hit.
type RvfHit struct {
	ID    string          `json:"id"`
	Score float32         `json:"score"`
	Meta  json.RawMessage `json:"meta"`
}

// RvfStore provides an in-memory vector store with deterministic .rvf binary serialization.
type RvfStore struct {
	dim     int
	records []RvfRecord
}

// NewRvfStore constructs an empty RvfStore with vector dimension dim.
func NewRvfStore(dim int) *RvfStore {
	return &RvfStore{
		dim:     dim,
		records: make([]RvfRecord, 0),
	}
}

func (s *RvfStore) Dim() int {
	return s.dim
}

func (s *RvfStore) Len() int {
	return len(s.records)
}

func (s *RvfStore) Records() []RvfRecord {
	return s.records
}

// Upsert adds or updates a record. Returns an error if the vector dimension does not match.
func (s *RvfStore) Upsert(rec RvfRecord) error {
	if len(rec.Vector) != s.dim {
		return fmt.Errorf("%w: expected %d, got %d", ErrDimMismatch, s.dim, len(rec.Vector))
	}
	if len(rec.Meta) == 0 {
		rec.Meta = json.RawMessage("{}")
	}

	for i, r := range s.records {
		if r.ID == rec.ID {
			s.records[i] = rec
			return nil
		}
	}

	s.records = append(s.records, rec)
	return nil
}

// Cosine computes the cosine similarity between two vectors.
func Cosine(a, b []float32, normA float32) float32 {
	var dot float32
	var normB float32
	for i := range a {
		dot += a[i] * b[i]
		normB += b[i] * b[i]
	}
	denom := normA * float32(math.Sqrt(float64(normB)))
	if denom <= 0.0 {
		return 0.0
	}
	sim := dot / denom
	if sim > 1.0 {
		return 1.0
	}
	if sim < -1.0 {
		return -1.0
	}
	return sim
}

func VectorNorm(v []float32) float32 {
	var sum float32
	for _, val := range v {
		sum += val * val
	}
	return float32(math.Sqrt(float64(sum)))
}

// Search performs exact brute-force cosine similarity search for topK nearest records.
func (s *RvfStore) Search(query []float32, topK int) ([]RvfHit, error) {
	if len(query) != s.dim {
		return nil, fmt.Errorf("%w: expected %d, got %d", ErrDimMismatch, s.dim, len(query))
	}

	qNorm := VectorNorm(query)
	hits := make([]RvfHit, len(s.records))
	for i, r := range s.records {
		score := Cosine(query, r.Vector, qNorm)
		hits[i] = RvfHit{
			ID:    r.ID,
			Score: score,
			Meta:  r.Meta,
		}
	}

	sort.Slice(hits, func(i, j int) bool {
		return hits[i].Score > hits[j].Score
	})

	if topK > len(hits) {
		topK = len(hits)
	}
	return hits[:topK], nil
}

// ToBytes serializes the store to the agentbbs.rvf.v1 binary format.
func (s *RvfStore) ToBytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Magic: 8 bytes
	if _, err := buf.Write(MagicRVF[:]); err != nil {
		return nil, err
	}
	// Version: u16 LE
	if err := binary.Write(buf, binary.LittleEndian, VersionRVF); err != nil {
		return nil, err
	}
	// Dim: u32 LE
	if err := binary.Write(buf, binary.LittleEndian, uint32(s.dim)); err != nil {
		return nil, err
	}
	// Count: u32 LE
	if err := binary.Write(buf, binary.LittleEndian, uint32(len(s.records))); err != nil {
		return nil, err
	}

	for _, r := range s.records {
		idBytes := []byte(r.ID)
		// id_len: u16 LE
		if err := binary.Write(buf, binary.LittleEndian, uint16(len(idBytes))); err != nil {
			return nil, err
		}
		// id: id_len bytes
		if _, err := buf.Write(idBytes); err != nil {
			return nil, err
		}

		metaBytes := []byte(r.Meta)
		if len(metaBytes) == 0 {
			metaBytes = []byte("{}")
		}
		// meta_len: u32 LE
		if err := binary.Write(buf, binary.LittleEndian, uint32(len(metaBytes))); err != nil {
			return nil, err
		}
		// meta: meta_len bytes
		if _, err := buf.Write(metaBytes); err != nil {
			return nil, err
		}

		// vector: dim * f32 LE
		for _, f := range r.Vector {
			if err := binary.Write(buf, binary.LittleEndian, f); err != nil {
				return nil, err
			}
		}
	}

	return buf.Bytes(), nil
}

// FromBytes parses an RvfStore from agentbbs.rvf.v1 binary data.
func FromBytes(data []byte) (*RvfStore, error) {
	reader := bytes.NewReader(data)

	var magic [8]byte
	if err := binary.Read(reader, binary.LittleEndian, &magic); err != nil {
		return nil, err
	}
	if magic != MagicRVF {
		return nil, ErrBadMagic
	}

	var version uint16
	if err := binary.Read(reader, binary.LittleEndian, &version); err != nil {
		return nil, err
	}
	if version != VersionRVF {
		return nil, fmt.Errorf("%w: got %d", ErrBadVersion, version)
	}

	var dim uint32
	if err := binary.Read(reader, binary.LittleEndian, &dim); err != nil {
		return nil, err
	}

	var count uint32
	if err := binary.Read(reader, binary.LittleEndian, &count); err != nil {
		return nil, err
	}

	store := NewRvfStore(int(dim))
	for i := uint32(0); i < count; i++ {
		var idLen uint16
		if err := binary.Read(reader, binary.LittleEndian, &idLen); err != nil {
			return nil, err
		}
		idBytes := make([]byte, idLen)
		if _, err := reader.Read(idBytes); err != nil {
			return nil, err
		}

		var metaLen uint32
		if err := binary.Read(reader, binary.LittleEndian, &metaLen); err != nil {
			return nil, err
		}
		metaBytes := make([]byte, metaLen)
		if _, err := reader.Read(metaBytes); err != nil {
			return nil, err
		}

		vec := make([]float32, dim)
		for d := uint32(0); d < dim; d++ {
			if err := binary.Read(reader, binary.LittleEndian, &vec[d]); err != nil {
				return nil, err
			}
		}

		store.records = append(store.records, RvfRecord{
			ID:     string(idBytes),
			Vector: vec,
			Meta:   json.RawMessage(metaBytes),
		})
	}

	return store, nil
}

// SaveToFile writes the RVF store to a local file.
func (s *RvfStore) SaveToFile(filePath string) error {
	data, err := s.ToBytes()
	if err != nil {
		return err
	}
	return os.WriteFile(filePath, data, 0644)
}

// LoadFromFile loads an RVF store from a local file.
func LoadFromFile(filePath string) (*RvfStore, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	return FromBytes(data)
}

// LshIndex represents a 64-hyperplane sign random-projection index over an RvfStore.
type LshIndex struct {
	planes [][]float32 // 64 planes, each dim long
	sigs   []uint64    // one 64-bit signature per store record
	dim    int
}

// SplitMix64 pseudo-random generator for reproducible deterministic hyperplane weights.
func splitmix64(state *uint64) uint64 {
	*state += 0x9E3779B97F4A7C15
	z := *state
	z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9
	z = (z ^ (z >> 27)) * 0x94D049BB133111EB
	return z ^ (z >> 31)
}

func generateLshPlanes(dim int, bitsCount int, seed uint64) [][]float32 {
	s := seed
	planes := make([][]float32, bitsCount)
	for b := 0; b < bitsCount; b++ {
		plane := make([]float32, dim)
		for d := 0; d < dim; d++ {
			u := float32(splitmix64(&s)>>11) / float32(uint64(1)<<53)
			plane[d] = u*2.0 - 1.0
		}
		planes[b] = plane
	}
	return planes
}

func computeLshSig(planes [][]float32, v []float32) uint64 {
	var sig uint64
	for i, p := range planes {
		var dot float32
		for d := range p {
			dot += p[d] * v[d]
		}
		if dot >= 0.0 {
			sig |= 1 << i
		}
	}
	return sig
}

// BuildLshIndex builds a 64-hyperplane sign projection LSH index over the store.
func BuildLshIndex(store *RvfStore) *LshIndex {
	planes := generateLshPlanes(store.dim, 64, 0xA9E52026C0FFEE01)
	sigs := make([]uint64, len(store.records))
	for i, r := range store.records {
		sigs[i] = computeLshSig(planes, r.Vector)
	}
	return &LshIndex{
		planes: planes,
		sigs:   sigs,
		dim:    store.dim,
	}
}

// ComputeSignature computes the 64-bit LSH signature for an arbitrary vector.
func (idx *LshIndex) ComputeSignature(v []float32) uint64 {
	return computeLshSig(idx.planes, v)
}

// Search performs approximate nearest neighbor search:
// 1. Prunes to maxCandidates records with smallest Hamming distance to query LSH signature.
// 2. Performs exact cosine re-ranking on those candidates.
// 3. Degrades gracefully to exact search if the index is stale.
func (idx *LshIndex) Search(store *RvfStore, query []float32, topK int, maxCandidates int) ([]RvfHit, error) {
	if len(query) != idx.dim {
		return nil, fmt.Errorf("%w: expected %d, got %d", ErrDimMismatch, idx.dim, len(query))
	}
	if len(idx.sigs) != len(store.records) {
		// Index is stale; fallback to exact scan for correctness
		return store.Search(query, topK)
	}

	qSig := computeLshSig(idx.planes, query)

	type candidate struct {
		index   int
		hamming int
	}
	candidates := make([]candidate, len(store.records))
	for i, sig := range idx.sigs {
		candidates[i] = candidate{
			index:   i,
			hamming: bits.OnesCount64(sig ^ qSig),
		}
	}

	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].hamming < candidates[j].hamming
	})

	limit := maxCandidates
	if limit < topK {
		limit = topK
	}
	if limit > len(candidates) {
		limit = len(candidates)
	}
	candidates = candidates[:limit]

	qNorm := VectorNorm(query)
	hits := make([]RvfHit, len(candidates))
	for i, c := range candidates {
		rec := store.records[c.index]
		score := Cosine(query, rec.Vector, qNorm)
		hits[i] = RvfHit{
			ID:    rec.ID,
			Score: score,
			Meta:  rec.Meta,
		}
	}

	sort.Slice(hits, func(i, j int) bool {
		return hits[i].Score > hits[j].Score
	})

	if topK > len(hits) {
		topK = len(hits)
	}
	return hits[:topK], nil
}
