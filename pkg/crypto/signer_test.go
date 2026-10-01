package crypto

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestBlake3Hash(t *testing.T) {
	msg := []byte("acr-protocol-test")
	h1 := Blake3Hash(msg)
	h2 := Blake3Hash(msg)
	if h1 != h2 {
		t.Fatalf("BLAKE3 hash is non-deterministic")
	}
	hexStr := Blake3Hex(msg)
	if hexStr != hex.EncodeToString(h1[:]) {
		t.Fatalf("BLAKE3 hex mismatch: %s vs %s", hexStr, hex.EncodeToString(h1[:]))
	}

	// Known BLAKE3 empty string test vector:
	// af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262
	emptyHex := Blake3Hex([]byte(""))
	expectedEmpty := "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
	if emptyHex != expectedEmpty {
		t.Fatalf("BLAKE3 empty vector mismatch: got %s, expected %s", emptyHex, expectedEmpty)
	}
}

func TestCompose(t *testing.T) {
	header := "agentbbs.test.v1"
	p1 := []byte("foo")
	p2 := []byte("bar")
	out := Compose(header, p1, p2)
	expected := "agentbbs.test.v1\n3:foo\n3:bar\n"
	if string(out) != expected {
		t.Fatalf("Compose mismatch: got %q, expected %q", string(out), expected)
	}
}

func TestEd25519SignVerify(t *testing.T) {
	pub, priv, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair failed: %v", err)
	}

	msg := []byte("deliberation-payload-to-sign")
	sig := Sign(priv, msg)
	if !Verify(pub, msg, sig) {
		t.Fatalf("Ed25519 signature verification failed")
	}

	// Tampered message
	tamperedMsg := []byte("deliberation-payload-to-sign-tampered")
	if Verify(pub, tamperedMsg, sig) {
		t.Fatalf("Verification should have failed on tampered message")
	}

	// Tampered signature
	corruptedSig := bytes.Clone(sig)
	corruptedSig[0] ^= 0xFF
	if Verify(pub, msg, corruptedSig) {
		t.Fatalf("Verification should have failed on corrupted signature")
	}

	// Hex helpers
	pubHex := hex.EncodeToString(pub)
	sigHex := SignHex(priv, msg)
	ok, err := VerifyHex(pubHex, msg, sigHex)
	if err != nil || !ok {
		t.Fatalf("VerifyHex failed: ok=%v, err=%v", ok, err)
	}
}
