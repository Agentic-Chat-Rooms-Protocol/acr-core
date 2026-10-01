package identity

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"acr-core/pkg/crypto"
)

// RotationLink represents a dual-signed link binding a retired predecessor key
// to an active successor key.
type RotationLink struct {
	Predecessor    string    `json:"predecessor"`
	Successor      string    `json:"successor"`
	Timestamp      time.Time `json:"timestamp"`
	PredecessorSig string    `json:"predecessor_sig"`
	SuccessorSig   string    `json:"successor_sig"`
}

// SigningBytes constructs the canonical length-prefixed bytes for a rotation link.
func (r *RotationLink) SigningBytes() []byte {
	tsStr := r.Timestamp.UTC().Format(time.RFC3339Nano)
	return crypto.Compose(
		"agentbbs.rotation.v1",
		[]byte(r.Predecessor),
		[]byte(r.Successor),
		[]byte(tsStr),
	)
}

// SignRotationLink constructs and dual-signs a RotationLink using the predecessor
// and successor Ed25519 private keys.
func SignRotationLink(oldPriv ed25519.PrivateKey, newPriv ed25519.PrivateKey, ts time.Time) (*RotationLink, error) {
	oldPub := oldPriv.Public().(ed25519.PublicKey)
	newPub := newPriv.Public().(ed25519.PublicKey)

	oldHex := hex.EncodeToString(oldPub)
	newHex := hex.EncodeToString(newPub)

	link := &RotationLink{
		Predecessor: oldHex,
		Successor:   newHex,
		Timestamp:   ts.UTC(),
	}

	bytesToSign := link.SigningBytes()
	link.PredecessorSig = crypto.SignHex(oldPriv, bytesToSign)
	link.SuccessorSig = crypto.SignHex(newPriv, bytesToSign)

	return link, nil
}

// Verify validates that both predecessor and successor signatures are cryptographically
// authentic and that the link is not self-referential.
func (r *RotationLink) Verify() error {
	if r.Predecessor == "" || r.Successor == "" {
		return errors.New("predecessor and successor must not be empty")
	}
	if r.Predecessor == r.Successor {
		return errors.New("self-referential rotation link: predecessor and successor are identical")
	}

	signingBytes := r.SigningBytes()

	ok, err := crypto.VerifyHex(r.Predecessor, signingBytes, r.PredecessorSig)
	if err != nil || !ok {
		return fmt.Errorf("invalid predecessor signature: %w", err)
	}

	ok, err = crypto.VerifyHex(r.Successor, signingBytes, r.SuccessorSig)
	if err != nil || !ok {
		return fmt.Errorf("invalid successor signature: %w", err)
	}

	return nil
}

// RotationChain tracks verified rotation links and resolves retired keys to active successors.
type RotationChain struct {
	next map[string]string // predecessor -> successor
}

// NewRotationChain creates a new empty RotationChain.
func NewRotationChain() *RotationChain {
	return &RotationChain{
		next: make(map[string]string),
	}
}

// Add verifies a RotationLink and adds it to the chain. First-write wins per predecessor.
func (c *RotationChain) Add(link RotationLink) error {
	if err := link.Verify(); err != nil {
		return err
	}
	if _, exists := c.next[link.Predecessor]; !exists {
		c.next[link.Predecessor] = link.Successor
	}
	return nil
}

// Resolve follows predecessor -> successor links up to a maximum depth of 64 transitions,
// with cycle detection. If the key has not been rotated, returns keyHex itself.
func (c *RotationChain) Resolve(keyHex string) string {
	curr := keyHex
	seen := make(map[string]bool)

	for i := 0; i < 64; i++ {
		if seen[curr] {
			break // Cycle detected; terminate at last seen
		}
		seen[curr] = true

		nextKey, ok := c.next[curr]
		if !ok {
			break
		}
		curr = nextKey
	}

	return curr
}
