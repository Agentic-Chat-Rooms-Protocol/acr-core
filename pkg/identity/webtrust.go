package identity

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"acr-core/pkg/crypto"
)

// Endorsement represents an Ed25519-signed statement vouching for a peer node.
type Endorsement struct {
	Endorser  string    `json:"endorser"`
	Subject   string    `json:"subject"`
	CreatedAt time.Time `json:"created_at"`
	Signature string    `json:"signature"`
}

// SigningBytes constructs the canonical length-prefixed bytes for an endorsement.
func (e *Endorsement) SigningBytes() []byte {
	tsStr := e.CreatedAt.UTC().Format(time.RFC3339Nano)
	return crypto.Compose(
		"agentbbs.endorsement.v1",
		[]byte(e.Endorser),
		[]byte(e.Subject),
		[]byte(tsStr),
	)
}

// SignEndorsement signs an endorsement under the endorser's private key.
func SignEndorsement(endorserPriv ed25519.PrivateKey, subjectPub ed25519.PublicKey, createdAt time.Time) (*Endorsement, error) {
	endorserPub := endorserPriv.Public().(ed25519.PublicKey)
	e := &Endorsement{
		Endorser:  hex.EncodeToString(endorserPub),
		Subject:   hex.EncodeToString(subjectPub),
		CreatedAt: createdAt.UTC(),
	}

	signingBytes := e.SigningBytes()
	e.Signature = crypto.SignHex(endorserPriv, signingBytes)
	return e, nil
}

// Verify checks the endorsement's cryptographic signature against the endorser's public key.
func (e *Endorsement) Verify() error {
	if e.Endorser == "" || e.Subject == "" {
		return errors.New("endorser and subject must not be empty")
	}
	signingBytes := e.SigningBytes()
	ok, err := crypto.VerifyHex(e.Endorser, signingBytes, e.Signature)
	if err != nil || !ok {
		return fmt.Errorf("invalid endorsement signature: %w", err)
	}
	return nil
}

// WebOfTrust represents a directed endorsement graph supporting bounded BFS traversal.
type WebOfTrust struct {
	edges map[string][]string // endorser -> subjects
}

// NewWebOfTrust initializes an empty WebOfTrust graph.
func NewWebOfTrust() *WebOfTrust {
	return &WebOfTrust{
		edges: make(map[string][]string),
	}
}

// Add verifies an endorsement and adds the directed edge endorser -> subject.
func (w *WebOfTrust) Add(e Endorsement) error {
	if err := e.Verify(); err != nil {
		return err
	}

	subjects := w.edges[e.Endorser]
	for _, s := range subjects {
		if s == e.Subject {
			return nil // Already present
		}
	}

	w.edges[e.Endorser] = append(subjects, e.Subject)
	return nil
}

// TrustedFrom executes a bounded BFS from roots along endorsement edges.
// Returns a map of reachable nodes and their shortest trust distance in [1, maxDepth].
// Roots themselves are not returned in the result map.
func (w *WebOfTrust) TrustedFrom(roots []string, maxDepth int) map[string]int {
	depthMap := make(map[string]int)
	if maxDepth <= 0 || len(roots) == 0 {
		return depthMap
	}

	rootSet := make(map[string]bool)
	type queueItem struct {
		node  string
		depth int
	}
	var queue []queueItem

	for _, r := range roots {
		rootSet[r] = true
		queue = append(queue, queueItem{node: r, depth: 0})
	}

	for len(queue) > 0 {
		curr := queue[0]
		queue = queue[1:]

		if curr.depth >= maxDepth {
			continue
		}

		subjects := w.edges[curr.node]
		for _, s := range subjects {
			if rootSet[s] {
				continue
			}

			nd := curr.depth + 1
			prevDepth, exists := depthMap[s]
			if !exists || nd < prevDepth {
				depthMap[s] = nd
				queue = append(queue, queueItem{node: s, depth: nd})
			}
		}
	}

	return depthMap
}

// IsTrusted returns true if node is reachable from roots within maxDepth.
func (w *WebOfTrust) IsTrusted(node string, roots []string, maxDepth int) bool {
	trusted := w.TrustedFrom(roots, maxDepth)
	_, ok := trusted[node]
	return ok
}

// IsTrustedVia evaluates transitive trust considering key rotation history.
// An active key inherits endorsements granted to any of its predecessors.
func (w *WebOfTrust) IsTrustedVia(node string, roots []string, maxDepth int, chain *RotationChain) bool {
	if w.IsTrusted(node, roots, maxDepth) {
		return true
	}
	if chain == nil {
		return false
	}

	targetResolved := chain.Resolve(node)
	trusted := w.TrustedFrom(roots, maxDepth)

	for trustedNode := range trusted {
		if chain.Resolve(trustedNode) == targetResolved {
			return true
		}
	}

	return false
}
