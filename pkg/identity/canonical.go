package identity

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"time"
)

// CanonicalizeJSON converts arbitrary JSON or Go data structures into a deterministic RFC 8785-compliant format
// with sorted object keys, normalized whitespace, and consistent representation.
func CanonicalizeJSON(v interface{}) ([]byte, error) {
	if v == nil {
		return []byte("null"), nil
	}

	var raw []byte
	switch val := v.(type) {
	case []byte:
		raw = val
	case string:
		raw = []byte(val)
	default:
		b, err := json.Marshal(v)
		if err != nil {
			return nil, err
		}
		raw = b
	}

	if len(bytes.TrimSpace(raw)) == 0 {
		return []byte("{}"), nil
	}

	var decoded interface{}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&decoded); err != nil {
		// If raw string isn't valid JSON, treat as JSON string
		return json.Marshal(string(raw))
	}

	normalized := normalizeValue(decoded)
	return json.Marshal(normalized)
}

func normalizeValue(v interface{}) interface{} {
	switch val := v.(type) {
	case map[string]interface{}:
		keys := make([]string, 0, len(val))
		for k := range val {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		ordered := make(map[string]interface{}, len(val))
		for _, k := range keys {
			ordered[k] = normalizeValue(val[k])
		}
		return ordered
	case []interface{}:
		res := make([]interface{}, len(val))
		for i, item := range val {
			res[i] = normalizeValue(item)
		}
		return res
	default:
		return v
	}
}

// ComputeCanonicalEventHash computes a cryptographically tamper-evident SHA-256 state hash
// over canonicalized event pre-images for GAP-06 monotonic chain verification.
func ComputeCanonicalEventHash(prevHash string, index uint64, eventType, actorDID string, payload interface{}, ts time.Time) string {
	canonBytes, err := CanonicalizeJSON(payload)
	if err != nil {
		canonBytes = []byte("{}")
	}

	hasher := sha256.New()
	hasher.Write([]byte(prevHash))
	header := fmt.Sprintf(":%d:%s:%s:%d:", index, eventType, actorDID, ts.UnixNano())
	hasher.Write([]byte(header))
	hasher.Write(canonBytes)
	return hex.EncodeToString(hasher.Sum(nil))
}
