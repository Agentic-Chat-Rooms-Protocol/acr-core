package governance

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"acr-core/pkg/models"
)

func TestPasskeyConsentEnvelopeAndTamperRejection(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	store := NewConsentChallengeStore()
	now := time.Now().UTC().Truncate(time.Second)

	payloadP1 := `{"action":"transfer_budget","amount_usd":500,"destination":"acc_engineering_42"}`
	reqHashP1 := HashCanonicalRequest(payloadP1)

	scope := ConsentScopeBinding{
		RequestCanonicalHash: reqHashP1,
		ActionType:           "transfer_budget",
		TargetResourceURI:    "consensus-main",
		ResourceVersion:      "v1.4.0",
		PolicyRevision:       "pol_rev_8a9f",
	}

	// Baseline: valid consent succeeds and consumes challenge atomically
	nonce1, _ := store.IssueChallenge(2*time.Minute, now)
	env1, err := MintPasskeyConsentEnvelope(
		priv,
		"did:key:z6MkOperator",
		"cred-fido2-01",
		scope,
		now,
		now.Add(2*time.Minute),
		1,
		nonce1,
	)
	if err != nil {
		t.Fatalf("mint consent: %v", err)
	}

	if err := VerifyAndConsumeConsent(
		store,
		env1,
		pub,
		reqHashP1,
		"transfer_budget",
		"consensus-main",
		"v1.4.0",
		"pol_rev_8a9f",
		now.Add(10*time.Second),
	); err != nil {
		t.Fatalf("expected baseline consent to pass, got: %v", err)
	}
	if env1.TemporalAndUsageLimits.RemainingInvocations != 0 {
		t.Fatalf("expected remaining invocations 0, got %d", env1.TemporalAndUsageLimits.RemainingInvocations)
	}

	// Replay with same challenge nonce must fail immediately (already consumed)
	if err := VerifyAndConsumeConsent(
		store,
		env1,
		pub,
		reqHashP1,
		"transfer_budget",
		"consensus-main",
		"v1.4.0",
		"pol_rev_8a9f",
		now.Add(11*time.Second),
	); !errors.Is(err, ErrConsentChallengeMissing) {
		t.Fatalf("expected ErrConsentChallengeMissing on replay, got: %v", err)
	}

	// Tamper Test A: Parameter mutation (amount_usd 500 -> 5000) -> CONSENT_HASH_MISMATCH, and burns challenge
	nonceA, _ := store.IssueChallenge(2*time.Minute, now)
	envA, _ := MintPasskeyConsentEnvelope(priv, "did:key:z6MkOperator", "cred-fido2-01", scope, now, now.Add(2*time.Minute), 1, nonceA)
	payloadP2 := `{"action":"transfer_budget","amount_usd":5000,"destination":"acc_engineering_42"}`
	reqHashP2 := HashCanonicalRequest(payloadP2)
	if err := VerifyAndConsumeConsent(store, envA, pub, reqHashP2, "transfer_budget", "consensus-main", "v1.4.0", "pol_rev_8a9f", now); !errors.Is(err, ErrConsentHashMismatch) {
		t.Fatalf("expected ErrConsentHashMismatch on mutated payload, got: %v", err)
	}
	// Verify challenge nonceA was atomically burned even though verification failed
	if err := store.TakeChallenge(nonceA, now); !errors.Is(err, ErrConsentChallengeMissing) {
		t.Fatalf("expected challenge to be burned on failed verification, got: %v", err)
	}

	// Tamper Test B: Resource version advanced (v1.4.0 -> v1.4.1) -> STALE_RESOURCE_VERSION
	nonceB, _ := store.IssueChallenge(2*time.Minute, now)
	envB, _ := MintPasskeyConsentEnvelope(priv, "did:key:z6MkOperator", "cred-fido2-01", scope, now, now.Add(2*time.Minute), 1, nonceB)
	if err := VerifyAndConsumeConsent(store, envB, pub, reqHashP1, "transfer_budget", "consensus-main", "v1.4.1", "pol_rev_8a9f", now); !errors.Is(err, ErrStaleResourceVersion) {
		t.Fatalf("expected ErrStaleResourceVersion, got: %v", err)
	}

	// Tamper Test C: Policy revision updated (pol_rev_8a9f -> pol_rev_8a9g) -> POLICY_REVISION_OUTDATED
	nonceC, _ := store.IssueChallenge(2*time.Minute, now)
	envC, _ := MintPasskeyConsentEnvelope(priv, "did:key:z6MkOperator", "cred-fido2-01", scope, now, now.Add(2*time.Minute), 1, nonceC)
	if err := VerifyAndConsumeConsent(store, envC, pub, reqHashP1, "transfer_budget", "consensus-main", "v1.4.0", "pol_rev_8a9g", now); !errors.Is(err, ErrPolicyRevisionOutdated) {
		t.Fatalf("expected ErrPolicyRevisionOutdated, got: %v", err)
	}

	// Tamper Test D: Expired TTL -> CONSENT_EXPIRED
	nonceD, _ := store.IssueChallenge(5*time.Minute, now)
	envD, _ := MintPasskeyConsentEnvelope(priv, "did:key:z6MkOperator", "cred-fido2-01", scope, now, now.Add(30*time.Second), 1, nonceD)
	if err := VerifyAndConsumeConsent(store, envD, pub, reqHashP1, "transfer_budget", "consensus-main", "v1.4.0", "pol_rev_8a9f", now.Add(31*time.Second)); !errors.Is(err, ErrConsentExpired) {
		t.Fatalf("expected ErrConsentExpired, got: %v", err)
	}

	// Multi-Invocation Test E: MaxInvocations = 2 burns challenge on first call and tracks ConsentSessionGrant on second call
	nonceE, _ := store.IssueChallenge(5*time.Minute, now)
	envE, err := MintPasskeyConsentEnvelope(priv, "did:key:z6MkOperator", "cred-fido2-01", scope, now, now.Add(2*time.Minute), 2, nonceE)
	if err != nil {
		t.Fatalf("mint multi-invocation consent: %v", err)
	}
	if err := VerifyAndConsumeConsent(store, envE, pub, reqHashP1, "transfer_budget", "consensus-main", "v1.4.0", "pol_rev_8a9f", now.Add(5*time.Second)); err != nil {
		t.Fatalf("expected invocation 1 of 2 to pass, got: %v", err)
	}
	if envE.TemporalAndUsageLimits.RemainingInvocations != 1 {
		t.Fatalf("expected remaining invocations 1 after first call, got %d", envE.TemporalAndUsageLimits.RemainingInvocations)
	}
	// Challenge nonceE is already burned after call 1
	if err := store.TakeChallenge(nonceE, now.Add(5*time.Second)); !errors.Is(err, ErrConsentChallengeMissing) {
		t.Fatalf("expected challenge to be burned on first invocation, got: %v", err)
	}
	// Second invocation with same ConsentID succeeds via ConsentSessionGrant
	if err := VerifyAndConsumeConsent(store, envE, pub, reqHashP1, "transfer_budget", "consensus-main", "v1.4.0", "pol_rev_8a9f", now.Add(10*time.Second)); err != nil {
		t.Fatalf("expected invocation 2 of 2 to pass via session grant, got: %v", err)
	}
	if envE.TemporalAndUsageLimits.RemainingInvocations != 0 {
		t.Fatalf("expected remaining invocations 0 after second call, got %d", envE.TemporalAndUsageLimits.RemainingInvocations)
	}
	// Third invocation fails with ErrConsentQuotaExhausted
	if err := VerifyAndConsumeConsent(store, envE, pub, reqHashP1, "transfer_budget", "consensus-main", "v1.4.0", "pol_rev_8a9f", now.Add(15*time.Second)); !errors.Is(err, ErrConsentQuotaExhausted) {
		t.Fatalf("expected ErrConsentQuotaExhausted on third invocation, got: %v", err)
	}
}

func TestResolveEscalationRejectsUnsignedAndEnforcesConsent(t *testing.T) {
	gov := NewEngine(nil, nil)
	_, err := gov.RequestEscalation(models.Escalation{
		ID:            "esc-consent-01",
		RequestingDID: "did:key:z6MkAgent",
		AgentName:     "DeployAgent",
		RoomID:        "consensus-main",
		Action:        "k8s.deploy.prod",
		RiskLevel:     "CRITICAL",
		Payload:       `{"cluster":"prod-east","replicas":5}`,
	})
	if err != nil {
		t.Fatalf("request escalation: %v", err)
	}

	// Unsigned escalation resolution must fail
	if _, err := gov.ResolveEscalation("esc-consent-01", true, "did:key:z6MkOp", ""); err == nil {
		t.Fatal("expected error when resolving escalation with empty signature")
	}

	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	store := NewConsentChallengeStore()
	now := time.Now().UTC()
	nonce, _ := store.IssueChallenge(time.Minute, now)

	env, _ := MintPasskeyConsentEnvelope(
		priv,
		"did:key:z6MkOp",
		"cred-01",
		ConsentScopeBinding{
			RequestCanonicalHash: HashCanonicalRequest(`{"cluster":"prod-east","replicas":5}`),
			ActionType:           "k8s.deploy.prod",
			TargetResourceURI:    "consensus-main",
			ResourceVersion:      "v2.0",
			PolicyRevision:       "pol-1",
		},
		now,
		now.Add(time.Minute),
		1,
		nonce,
	)

	resolved, err := gov.ResolveEscalationWithConsent(store, "esc-consent-01", true, env, pub, "v2.0", "pol-1", now)
	if err != nil {
		t.Fatalf("expected ResolveEscalationWithConsent to succeed, got: %v", err)
	}
	if resolved.Status != models.EscalationApproved {
		t.Fatalf("expected approved status, got %s", resolved.Status)
	}
}
