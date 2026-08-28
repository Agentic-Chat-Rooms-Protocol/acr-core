package identity

import (
	"testing"
	"time"
)

func TestCanonicalizeJSON(t *testing.T) {
	// Two logically identical JSON strings with different key orders and whitespace
	json1 := `{"z": 100, "a": "test", "m": [3, 2, 1], "sub": {"k2": true, "k1": false}}`
	json2 := `{"a": "test", "sub": {"k1": false, "k2": true}, "m": [3, 2, 1], "z": 100}`

	c1, err1 := CanonicalizeJSON(json1)
	if err1 != nil {
		t.Fatalf("CanonicalizeJSON failed for json1: %v", err1)
	}

	c2, err2 := CanonicalizeJSON(json2)
	if err2 != nil {
		t.Fatalf("CanonicalizeJSON failed for json2: %v", err2)
	}

	if string(c1) != string(c2) {
		t.Fatalf("Canonical JSON mismatch:\nC1: %s\nC2: %s", string(c1), string(c2))
	}
}

func TestComputeCanonicalEventHash_Determinism(t *testing.T) {
	ts := time.Unix(1724790000, 123456789).UTC()
	prevHash := "0000000000000000000000000000000000000000000000000000000000000000"

	payload1 := `{"rationale": "Throughput bottleneck exceeds 450ms P99 threshold", "vote": "DISSENT"}`
	payload2 := `{"vote": "DISSENT", "rationale": "Throughput bottleneck exceeds 450ms P99 threshold"}`

	h1 := ComputeCanonicalEventHash(prevHash, 1, "VOTE_DISSENT_RECORDED", "did:key:z6Mkdissent", payload1, ts)
	h2 := ComputeCanonicalEventHash(prevHash, 1, "VOTE_DISSENT_RECORDED", "did:key:z6Mkdissent", payload2, ts)

	if h1 != h2 {
		t.Fatalf("Hashes must match for semantically identical payloads regardless of key ordering:\nH1: %s\nH2: %s", h1, h2)
	}

	// Tamper test: altering 1 char changes hash
	payloadTampered := `{"vote": "DISSENT", "rationale": "Throughput bottleneck exceeds 451ms P99 threshold"}`
	hTampered := ComputeCanonicalEventHash(prevHash, 1, "VOTE_DISSENT_RECORDED", "did:key:z6Mkdissent", payloadTampered, ts)

	if h1 == hTampered {
		t.Fatalf("Tampered payload produced colliding hash: %s", h1)
	}
}
