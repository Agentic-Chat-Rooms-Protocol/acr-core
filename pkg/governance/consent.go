package governance

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"
)

var (
	ErrConsentChallengeMissing = errors.New("CONSENT_CHALLENGE_MISSING_OR_CONSUMED")
	ErrConsentChallengeExpired = errors.New("CONSENT_CHALLENGE_EXPIRED")
	ErrConsentHashMismatch     = errors.New("CONSENT_HASH_MISMATCH")
	ErrConsentActionMismatch   = errors.New("CONSENT_ACTION_MISMATCH")
	ErrConsentResourceMismatch = errors.New("CONSENT_RESOURCE_MISMATCH")
	ErrStaleResourceVersion    = errors.New("STALE_RESOURCE_VERSION")
	ErrPolicyRevisionOutdated  = errors.New("POLICY_REVISION_OUTDATED")
	ErrConsentExpired          = errors.New("CONSENT_EXPIRED")
	ErrConsentQuotaExhausted   = errors.New("CONSENT_QUOTA_EXHAUSTED")
	ErrConsentSignatureInvalid = errors.New("CONSENT_SIGNATURE_INVALID")
)

type ConsentScopeBinding struct {
	RequestCanonicalHash string `json:"request_canonical_hash"`
	ActionType           string `json:"action_type"`
	TargetResourceURI    string `json:"target_resource_uri"`
	ResourceVersion      string `json:"resource_version"`
	PolicyRevision       string `json:"policy_revision"`
}

type ConsentTemporalLimits struct {
	IssuedAt             time.Time `json:"issued_at"`
	ExpiresAt            time.Time `json:"expires_at"`
	MaxInvocations       int       `json:"max_invocations"`
	RemainingInvocations int       `json:"remaining_invocations"`
}

// PasskeyConsentEnvelope binds a verified operator's cryptographic consent
// to the exact request hash, action type, resource URI, resource version,
// policy revision, expiration, and invocation limit (Extension 5).
type PasskeyConsentEnvelope struct {
	ProtocolVersion        string                `json:"protocol_version"`
	ConsentID              string                `json:"consent_id"`
	OperatorDID            string                `json:"operator_did"`
	WebAuthnCredentialID   string                `json:"webauthn_credential_id"`
	ScopeBinding           ConsentScopeBinding   `json:"scope_binding"`
	TemporalAndUsageLimits ConsentTemporalLimits `json:"temporal_and_usage_limits"`
	ChallengeNonce         string                `json:"challenge_nonce"`
	UserVerified           bool                  `json:"user_verified"`
	Signature              string                `json:"signature"`
}

type pendingConsentChallenge struct {
	nonce     string
	expiresAt time.Time
}

type consentSessionGrant struct {
	consentID            string
	remainingInvocations int
	expiresAt            time.Time
}

// ConsentChallengeStore manages single-use ephemeral challenges with atomic
// pre-verification consumption (takeChallenge deletes before verification)
// and durable multi-invocation session grants (Extension 5).
type ConsentChallengeStore struct {
	mu         sync.Mutex
	challenges map[string]pendingConsentChallenge
	sessions   map[string]consentSessionGrant
}

func NewConsentChallengeStore() *ConsentChallengeStore {
	return &ConsentChallengeStore{
		challenges: make(map[string]pendingConsentChallenge),
		sessions:   make(map[string]consentSessionGrant),
	}
}

func (s *ConsentChallengeStore) IssueChallenge(ttl time.Duration, now time.Time) (string, error) {
	if ttl <= 0 {
		ttl = 120 * time.Second
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	nonce := hex.EncodeToString(b)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.challenges[nonce] = pendingConsentChallenge{
		nonce:     nonce,
		expiresAt: now.UTC().Add(ttl),
	}
	return nonce, nil
}

// TakeChallenge atomically deletes the challenge record before checking expiry,
// guaranteeing single-use consumption even if downstream verification fails.
func (s *ConsentChallengeStore) TakeChallenge(nonce string, now time.Time) error {
	s.mu.Lock()
	ch, exists := s.challenges[nonce]
	delete(s.challenges, nonce)
	s.mu.Unlock()

	if !exists || nonce == "" {
		return ErrConsentChallengeMissing
	}
	if !now.UTC().Before(ch.expiresAt) {
		return ErrConsentChallengeExpired
	}
	return nil
}

// CanonicalConsentBytes computes the deterministic length-prefixed domain-separated
// byte payload signed by the operator's passkey/Ed25519 key (defeating boundary-sliding collisions).
func CanonicalConsentBytes(
	reqHash, actionType, targetURI, resourceVer, policyRev string,
	expiresAt time.Time,
	maxInvocations int,
	nonce string,
) []byte {
	expStr := expiresAt.UTC().Format(time.RFC3339Nano)
	maxStr := fmt.Sprintf("%d", maxInvocations)
	fields := []string{
		reqHash,
		actionType,
		targetURI,
		resourceVer,
		policyRev,
		expStr,
		maxStr,
		nonce,
	}
	out := "acr.consent.passkey.v1\n"
	for _, f := range fields {
		out += fmt.Sprintf("%d:%s\n", len(f), f)
	}
	return []byte(out)
}

func HashCanonicalRequest(rawPayload string) string {
	sum := sha256.Sum256([]byte(rawPayload))
	return hex.EncodeToString(sum[:])
}

func MintPasskeyConsentEnvelope(
	privKey ed25519.PrivateKey,
	operatorDID, credentialID string,
	scope ConsentScopeBinding,
	issuedAt, expiresAt time.Time,
	maxInvocations int,
	nonce string,
) (*PasskeyConsentEnvelope, error) {
	if maxInvocations <= 0 {
		maxInvocations = 1
	}
	msg := CanonicalConsentBytes(
		scope.RequestCanonicalHash,
		scope.ActionType,
		scope.TargetResourceURI,
		scope.ResourceVersion,
		scope.PolicyRevision,
		expiresAt,
		maxInvocations,
		nonce,
	)
	sig := ed25519.Sign(privKey, msg)
	idSum := sha256.Sum256(msg)
	return &PasskeyConsentEnvelope{
		ProtocolVersion:      "acr.consent.passkey.v1",
		ConsentID:            hex.EncodeToString(idSum[:]),
		OperatorDID:          operatorDID,
		WebAuthnCredentialID: credentialID,
		ScopeBinding:         scope,
		TemporalAndUsageLimits: ConsentTemporalLimits{
			IssuedAt:             issuedAt.UTC(),
			ExpiresAt:            expiresAt.UTC(),
			MaxInvocations:       maxInvocations,
			RemainingInvocations: maxInvocations,
		},
		ChallengeNonce: nonce,
		UserVerified:   true,
		Signature:      hex.EncodeToString(sig),
	}, nil
}

// VerifyAndConsumeConsent validates the challenge (burning it atomically first),
// checks all request/resource/policy/TTL/quota invariants, verifies the cryptographic
// signature, and decrements RemainingInvocations (supporting both single-use and bounded
// multi-invocation ConsentSessionGrants).
func VerifyAndConsumeConsent(
	store *ConsentChallengeStore,
	env *PasskeyConsentEnvelope,
	pubKey ed25519.PublicKey,
	expectedReqHash, expectedAction, expectedTargetURI, currentResourceVer, currentPolicyRev string,
	now time.Time,
) error {
	if env == nil {
		return ErrConsentSignatureInvalid
	}

	isSubsequentSessionCall := false
	if store != nil {
		store.mu.Lock()
		grant, hasGrant := store.sessions[env.ConsentID]
		store.mu.Unlock()
		if hasGrant {
			isSubsequentSessionCall = true
			if grant.remainingInvocations <= 0 {
				return ErrConsentQuotaExhausted
			}
		} else {
			if err := store.TakeChallenge(env.ChallengeNonce, now); err != nil {
				return err
			}
		}
	}

	if !env.UserVerified {
		return ErrConsentSignatureInvalid
	}
	if env.TemporalAndUsageLimits.RemainingInvocations <= 0 {
		return ErrConsentQuotaExhausted
	}
	if !now.UTC().Before(env.TemporalAndUsageLimits.ExpiresAt.UTC()) {
		return ErrConsentExpired
	}
	if env.ScopeBinding.RequestCanonicalHash != expectedReqHash {
		return ErrConsentHashMismatch
	}
	if env.ScopeBinding.ActionType != expectedAction {
		return ErrConsentActionMismatch
	}
	if env.ScopeBinding.TargetResourceURI != expectedTargetURI {
		return ErrConsentResourceMismatch
	}
	if env.ScopeBinding.ResourceVersion != currentResourceVer {
		return ErrStaleResourceVersion
	}
	if env.ScopeBinding.PolicyRevision != currentPolicyRev {
		return ErrPolicyRevisionOutdated
	}

	msg := CanonicalConsentBytes(
		env.ScopeBinding.RequestCanonicalHash,
		env.ScopeBinding.ActionType,
		env.ScopeBinding.TargetResourceURI,
		env.ScopeBinding.ResourceVersion,
		env.ScopeBinding.PolicyRevision,
		env.TemporalAndUsageLimits.ExpiresAt,
		env.TemporalAndUsageLimits.MaxInvocations,
		env.ChallengeNonce,
	)
	sigBytes, err := hex.DecodeString(env.Signature)
	if err != nil || len(pubKey) != ed25519.PublicKeySize || !ed25519.Verify(pubKey, msg, sigBytes) {
		return ErrConsentSignatureInvalid
	}

	env.TemporalAndUsageLimits.RemainingInvocations--

	if store != nil && env.TemporalAndUsageLimits.MaxInvocations > 1 {
		store.mu.Lock()
		if !isSubsequentSessionCall {
			store.sessions[env.ConsentID] = consentSessionGrant{
				consentID:            env.ConsentID,
				remainingInvocations: env.TemporalAndUsageLimits.MaxInvocations - 1,
				expiresAt:            env.TemporalAndUsageLimits.ExpiresAt.UTC(),
			}
		} else {
			g := store.sessions[env.ConsentID]
			g.remainingInvocations--
			store.sessions[env.ConsentID] = g
		}
		store.mu.Unlock()
	}

	return nil
}

