package governance

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"acr-core/pkg/crypto"
)

// Verdict defines an operator's authorization choice on an ActionProposal.
type Verdict string

const (
	VerdictApprove Verdict = "approve"
	VerdictReject  Verdict = "reject"
)

// ActionProposal represents an agent's proposal to take a side-effectful action.
type ActionProposal struct {
	ActionID  string    `json:"action_id"`
	Kind      string    `json:"kind"`
	Summary   string    `json:"summary"`
	Proposer  string    `json:"proposer"`
	Board     string    `json:"board"`
	CreatedAt time.Time `json:"created_at"`
}

// NewActionProposal builds an ActionProposal and computes its deterministic BLAKE3 content-addressed action_id.
func NewActionProposal(kind, summary, proposer, board string, createdAt time.Time) *ActionProposal {
	tsStr := createdAt.UTC().Format(time.RFC3339Nano)
	canonicalBytes := crypto.Compose(
		"agentbbs.approval.v1",
		[]byte(kind),
		[]byte(summary),
		[]byte(proposer),
		[]byte(board),
		[]byte(tsStr),
	)

	actionID := crypto.Blake3Hex(canonicalBytes)
	return &ActionProposal{
		ActionID:  actionID,
		Kind:      kind,
		Summary:   summary,
		Proposer:  proposer,
		Board:     board,
		CreatedAt: createdAt.UTC(),
	}
}

// SignedDecision represents an Ed25519-signed decision on an ActionProposal.
type SignedDecision struct {
	ActionID  string    `json:"action_id"`
	Verdict   Verdict   `json:"verdict"`
	Reason    string    `json:"reason"`
	Decider   string    `json:"decider"`
	DecidedAt time.Time `json:"decided_at"`
	Signature string    `json:"signature"`
}

// SigningBytes constructs the canonical bytes for a decision.
func (d *SignedDecision) SigningBytes() []byte {
	tsStr := d.DecidedAt.UTC().Format(time.RFC3339Nano)
	return crypto.Compose(
		"agentbbs.approval.v1",
		[]byte(d.ActionID),
		[]byte(d.Verdict),
		[]byte(d.Reason),
		[]byte(d.Decider),
		[]byte(tsStr),
	)
}

// SignDecision constructs and signs a decision using deciderPriv.
func SignDecision(deciderPriv ed25519.PrivateKey, actionID string, verdict Verdict, reason string, decidedAt time.Time) (*SignedDecision, error) {
	deciderPub := deciderPriv.Public().(ed25519.PublicKey)
	d := &SignedDecision{
		ActionID:  actionID,
		Verdict:   verdict,
		Reason:    reason,
		Decider:   hex.EncodeToString(deciderPub),
		DecidedAt: decidedAt.UTC(),
	}

	signingBytes := d.SigningBytes()
	d.Signature = crypto.SignHex(deciderPriv, signingBytes)
	return d, nil
}

// Verify checks the Ed25519 signature of the decision against decider's public key.
func (d *SignedDecision) Verify() error {
	if d.ActionID == "" || d.Decider == "" || d.Signature == "" {
		return errors.New("decision fields must not be empty")
	}
	signingBytes := d.SigningBytes()
	ok, err := crypto.VerifyHex(d.Decider, signingBytes, d.Signature)
	if err != nil || !ok {
		return fmt.Errorf("invalid decision signature: %w", err)
	}
	return nil
}

// ApprovalGate tracks signed decisions and evaluates authorization with fail-closed veto enforcement.
type ApprovalGate struct {
	decisions []SignedDecision
}

// NewApprovalGate creates an empty ApprovalGate.
func NewApprovalGate() *ApprovalGate {
	return &ApprovalGate{
		decisions: make([]SignedDecision, 0),
	}
}

// Record verifies and stores a SignedDecision. Forged decisions are rejected.
func (g *ApprovalGate) Record(d SignedDecision) error {
	if err := d.Verify(); err != nil {
		return err
	}
	g.decisions = append(g.decisions, d)
	return nil
}

// DecisionsFor returns all verified decisions for actionID.
func (g *ApprovalGate) DecisionsFor(actionID string) []SignedDecision {
	var result []SignedDecision
	for _, d := range g.decisions {
		if d.ActionID == actionID {
			result = append(result, d)
		}
	}
	return result
}

// IsAuthorized evaluates whether actionID is authorized:
// - At least one verified Approve from an allowed decider.
// - Zero Reject verdicts from any allowed decider (any veto immediately denies authorization: fail-closed).
// - Empty allowed list authorizes nothing.
func (g *ApprovalGate) IsAuthorized(actionID string, allowedDeciders []string) bool {
	if len(allowedDeciders) == 0 {
		return false
	}

	allowedSet := make(map[string]bool)
	for _, a := range allowedDeciders {
		allowedSet[a] = true
	}

	approved := false
	for _, d := range g.decisions {
		if d.ActionID == actionID && allowedSet[d.Decider] {
			if d.Verdict == VerdictReject {
				return false // Immediate fail-closed veto wins
			}
			if d.Verdict == VerdictApprove {
				approved = true
			}
		}
	}

	return approved
}
