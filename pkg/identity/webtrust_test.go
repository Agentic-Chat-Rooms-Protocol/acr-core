package identity

import (
	"crypto/ed25519"
	"encoding/hex"
	"testing"
	"time"

	"acr-core/pkg/crypto"
)

func TestEndorsementSignAndVerify(t *testing.T) {
	pubA, privA, _ := crypto.GenerateKeypair()
	pubB, _, _ := crypto.GenerateKeypair()

	now := time.Now().UTC()
	e, err := SignEndorsement(privA, pubB, now)
	if err != nil {
		t.Fatalf("SignEndorsement failed: %v", err)
	}

	if err := e.Verify(); err != nil {
		t.Fatalf("Endorsement verification failed: %v", err)
	}

	// Tampered subject
	tampered := *e
	tampered.Subject = hex.EncodeToString(pubA)
	if err := tampered.Verify(); err == nil {
		t.Fatalf("Verify should fail on tampered subject")
	}
}

func TestWebOfTrustBFS(t *testing.T) {
	// A -> B -> C -> D
	privs := make([]ed25519.PrivateKey, 4)
	pubs := make([]string, 4)
	for i := 0; i < 4; i++ {
		pub, priv, _ := crypto.GenerateKeypair()
		privs[i] = priv
		pubs[i] = hex.EncodeToString(pub)
	}

	wot := NewWebOfTrust()
	now := time.Now().UTC()

	// Endorsements: 0->1, 1->2, 2->3
	pub1, _ := hex.DecodeString(pubs[1])
	e0, _ := SignEndorsement(privs[0], pub1, now)
	wot.Add(*e0)

	pub2, _ := hex.DecodeString(pubs[2])
	e1, _ := SignEndorsement(privs[1], pub2, now)
	wot.Add(*e1)

	pub3, _ := hex.DecodeString(pubs[3])
	e2, _ := SignEndorsement(privs[2], pub3, now)
	wot.Add(*e2)

	roots := []string{pubs[0]}

	// Depth 1: only B (pubs[1])
	d1 := wot.TrustedFrom(roots, 1)
	if len(d1) != 1 || d1[pubs[1]] != 1 {
		t.Fatalf("Expected only B at depth 1, got %+v", d1)
	}

	// Depth 2: B at 1, C at 2
	d2 := wot.TrustedFrom(roots, 2)
	if len(d2) != 2 || d2[pubs[1]] != 1 || d2[pubs[2]] != 2 {
		t.Fatalf("Expected B=1, C=2 at depth 2, got %+v", d2)
	}

	// Depth 3: B=1, C=2, D=3
	d3 := wot.TrustedFrom(roots, 3)
	if len(d3) != 3 || d3[pubs[3]] != 3 {
		t.Fatalf("Expected D=3 at depth 3, got %+v", d3)
	}

	// Depth check with IsTrusted
	if !wot.IsTrusted(pubs[3], roots, 3) {
		t.Fatalf("Expected D to be trusted at depth 3")
	}
	if wot.IsTrusted(pubs[3], roots, 2) {
		t.Fatalf("Expected D not to be trusted at depth 2")
	}
}

func TestWebOfTrustRotationInheritance(t *testing.T) {
	// Root -> OldKey
	// OldKey -> NewKey (Rotation)
	rootPub, rootPriv, _ := crypto.GenerateKeypair()
	oldPub, oldPriv, _ := crypto.GenerateKeypair()
	newPub, newPriv, _ := crypto.GenerateKeypair()

	rootHex := hex.EncodeToString(rootPub)
	oldHex := hex.EncodeToString(oldPub)
	newHex := hex.EncodeToString(newPub)

	now := time.Now().UTC()
	wot := NewWebOfTrust()
	endorsement, _ := SignEndorsement(rootPriv, oldPub, now)
	wot.Add(*endorsement)

	chain := NewRotationChain()
	rotLink, _ := SignRotationLink(oldPriv, newPriv, now)
	chain.Add(*rotLink)

	roots := []string{rootHex}

	// Direct check on oldHex is true in WoT
	if !wot.IsTrusted(oldHex, roots, 2) {
		t.Fatalf("Old key should be directly trusted")
	}

	// Direct check on newHex is false in WoT
	if wot.IsTrusted(newHex, roots, 2) {
		t.Fatalf("New key should not be directly trusted without rotation resolution")
	}

	// Rotation-aware check should succeed because oldHex was endorsed
	if !wot.IsTrustedVia(newHex, roots, 2, chain) {
		t.Fatalf("New key should inherit trust from old key via rotation chain")
	}
}
