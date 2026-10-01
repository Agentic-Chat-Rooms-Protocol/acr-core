package identity

import (
	"crypto/ed25519"
	"encoding/hex"
	"testing"
	"time"

	"acr-core/pkg/crypto"
)

func TestRotationLinkDualSignAndVerify(t *testing.T) {
	pub1, priv1, err := crypto.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair 1 failed: %v", err)
	}
	pub2, priv2, err := crypto.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair 2 failed: %v", err)
	}

	ts := time.Now().UTC()
	link, err := SignRotationLink(priv1, priv2, ts)
	if err != nil {
		t.Fatalf("SignRotationLink failed: %v", err)
	}

	if err := link.Verify(); err != nil {
		t.Fatalf("RotationLink verification failed: %v", err)
	}

	// Tamper predecessor signature
	badLink := *link
	badLink.PredecessorSig = hex.EncodeToString(make([]byte, 64))
	if err := badLink.Verify(); err == nil {
		t.Fatalf("Verify should have failed on corrupted predecessor signature")
	}

	// Tamper successor signature
	badLink2 := *link
	badLink2.SuccessorSig = hex.EncodeToString(make([]byte, 64))
	if err := badLink2.Verify(); err == nil {
		t.Fatalf("Verify should have failed on corrupted successor signature")
	}

	// Self-referential link
	selfLink, err := SignRotationLink(priv1, priv1, ts)
	if err != nil {
		t.Fatalf("Sign self link failed: %v", err)
	}
	if err := selfLink.Verify(); err == nil {
		t.Fatalf("Verify should have failed on self-referential rotation link")
	}

	_ = pub1
	_ = pub2
}

func TestRotationChainTraversal(t *testing.T) {
	// Build a chain of 4 keys: K0 -> K1 -> K2 -> K3
	privs := make([]ed25519.PrivateKey, 4)
	pubs := make([]string, 4)
	for i := 0; i < 4; i++ {
		pub, priv, err := crypto.GenerateKeypair()
		if err != nil {
			t.Fatalf("GenerateKeypair %d failed: %v", i, err)
		}
		privs[i] = priv
		pubs[i] = hex.EncodeToString(pub)
	}

	chain := NewRotationChain()
	ts := time.Now().UTC()

	// Link K0 -> K1
	l0, _ := SignRotationLink(privs[0], privs[1], ts)
	if err := chain.Add(*l0); err != nil {
		t.Fatalf("Add l0 failed: %v", err)
	}

	// Link K1 -> K2
	l1, _ := SignRotationLink(privs[1], privs[2], ts)
	if err := chain.Add(*l1); err != nil {
		t.Fatalf("Add l1 failed: %v", err)
	}

	// Link K2 -> K3
	l2, _ := SignRotationLink(privs[2], privs[3], ts)
	if err := chain.Add(*l2); err != nil {
		t.Fatalf("Add l2 failed: %v", err)
	}

	// Resolve tests
	if chain.Resolve(pubs[0]) != pubs[3] {
		t.Fatalf("Expected %s to resolve to %s, got %s", pubs[0], pubs[3], chain.Resolve(pubs[0]))
	}
	if chain.Resolve(pubs[1]) != pubs[3] {
		t.Fatalf("Expected %s to resolve to %s, got %s", pubs[1], pubs[3], chain.Resolve(pubs[1]))
	}
	if chain.Resolve(pubs[2]) != pubs[3] {
		t.Fatalf("Expected %s to resolve to %s, got %s", pubs[2], pubs[3], chain.Resolve(pubs[2]))
	}
	if chain.Resolve(pubs[3]) != pubs[3] {
		t.Fatalf("Expected unrotated %s to resolve to itself, got %s", pubs[3], chain.Resolve(pubs[3]))
	}

	// Unknown key resolves to itself
	unknownPub, _, _ := crypto.GenerateKeypair()
	unknownHex := hex.EncodeToString(unknownPub)
	if chain.Resolve(unknownHex) != unknownHex {
		t.Fatalf("Unknown key should resolve to itself")
	}
}

func TestRotationChainCycleGuard(t *testing.T) {
	pub1, priv1, _ := crypto.GenerateKeypair()
	pub2, priv2, _ := crypto.GenerateKeypair()
	h1 := hex.EncodeToString(pub1)
	h2 := hex.EncodeToString(pub2)

	chain := NewRotationChain()
	ts := time.Now().UTC()

	l1, _ := SignRotationLink(priv1, priv2, ts)
	l2, _ := SignRotationLink(priv2, priv1, ts)
	_ = chain.Add(*l1)
	_ = chain.Add(*l2)

	// Should not enter infinite loop
	res := chain.Resolve(h1)
	if res != h1 && res != h2 {
		t.Fatalf("Cycle resolution returned unexpected key: %s", res)
	}
}
