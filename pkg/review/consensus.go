package review

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"time"
)

// ConsensusEngine signs and verifies MergeDecisionEnvelopes using Ed25519.
// It reuses acr-core's existing DID keypair infrastructure.
type ConsensusEngine struct {
	agentDID   string
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
}

// NewConsensusEngine constructs a ConsensusEngine with a fresh ephemeral keypair.
// In production, pass in the daemon's long-lived DID private key instead.
func NewConsensusEngine(agentDID string, privateKey ed25519.PrivateKey) *ConsensusEngine {
	pub, ok := privateKey.Public().(ed25519.PublicKey)
	if !ok {
		panic("consensus: invalid private key")
	}
	return &ConsensusEngine{
		agentDID:   agentDID,
		privateKey: privateKey,
		publicKey:  pub,
	}
}

// NewEphemeralConsensusEngine generates a throw-away keypair (useful for tests / sandbox).
func NewEphemeralConsensusEngine(agentDID string) (*ConsensusEngine, error) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, fmt.Errorf("consensus: keygen: %w", err)
	}
	return &ConsensusEngine{
		agentDID:   agentDID,
		privateKey: priv,
		publicKey:  pub,
	}, nil
}

// SignEnvelope appends this engine's verdict to the envelope and signs it.
// The signature covers SHA256 of the canonical envelope JSON (before this verdict).
func (ce *ConsensusEngine) SignEnvelope(env *MergeDecisionEnvelope) error {
	canonical, err := marshalEnvelope(env)
	if err != nil {
		return fmt.Errorf("consensus: canonical marshal: %w", err)
	}
	digest := sha256.Sum256([]byte(canonical))
	sig := ed25519.Sign(ce.privateKey, digest[:])
	env.Verdicts = append(env.Verdicts, Verdict{
		AgentDID:  ce.agentDID,
		Decision:  "APPROVE",
		Signature: base64.StdEncoding.EncodeToString(sig),
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	})
	return nil
}

// VerifyVerdict verifies a single verdict's Ed25519 signature against the
// canonical envelope (without this verdict appended).
func VerifyVerdict(env *MergeDecisionEnvelope, verdictIdx int, pubKey ed25519.PublicKey) (bool, error) {
	// Build envelope state before this verdict was appended
	snapshot := &MergeDecisionEnvelope{
		StackID:   env.StackID,
		Repo:      env.Repo,
		PRIDs:     env.PRIDs,
		CommitSHA: env.CommitSHA,
		Quorum:    env.Quorum,
		Timestamp: env.Timestamp,
		Verdicts:  env.Verdicts[:verdictIdx],
	}
	canonical, err := marshalEnvelope(snapshot)
	if err != nil {
		return false, fmt.Errorf("consensus verify: %w", err)
	}
	digest := sha256.Sum256([]byte(canonical))
	sig, err := base64.StdEncoding.DecodeString(env.Verdicts[verdictIdx].Signature)
	if err != nil {
		return false, fmt.Errorf("consensus verify: decode sig: %w", err)
	}
	return ed25519.Verify(pubKey, digest[:], sig), nil
}

// QuorumReached returns true when at least threshold APPROVE verdicts are present.
func QuorumReached(env *MergeDecisionEnvelope, threshold int) bool {
	count := 0
	for _, v := range env.Verdicts {
		if v.Decision == "APPROVE" {
			count++
		}
	}
	return count >= threshold
}
