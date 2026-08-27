package identity

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// GenerateChallengeNonce returns a cryptographically secure random nonce for challenge-response.
func GenerateChallengeNonce() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}
	return hex.EncodeToString(bytes), nil
}

// ValidateDID checks if a DID string matches supported DID schemes (did:key or did:web).
func ValidateDID(did string) bool {
	if !strings.HasPrefix(did, "did:") {
		return false
	}
	parts := strings.Split(did, ":")
	if len(parts) < 3 {
		return false
	}
	method := parts[1]
	return method == "key" || method == "web"
}

// ComputeEventHash computes a deterministic SHA-256 state hash chaining from prevHash.
func ComputeEventHash(prevHash string, index uint64, eventType, actorDID string, payload string, ts time.Time) string {
	hasher := sha256.New()
	hasher.Write([]byte(prevHash))
	hasher.Write([]byte(fmt.Sprintf(":%d:%s:%s:%d:", index, eventType, actorDID, ts.UnixNano())))
	hasher.Write([]byte(payload))
	return hex.EncodeToString(hasher.Sum(nil))
}

// CheckCapabilityScope verifies if an agent's capability VC permits a target action.
func CheckCapabilityScope(capabilities []string, targetAction string) bool {
	for _, cap := range capabilities {
		if cap == "*" || cap == targetAction {
			return true
		}
		// Prefix matching e.g. "chat.*" matches "chat.message.send"
		if strings.HasSuffix(cap, ".*") {
			prefix := strings.TrimSuffix(cap, ".*")
			if strings.HasPrefix(targetAction, prefix) {
				return true
			}
		}
	}
	return false
}
