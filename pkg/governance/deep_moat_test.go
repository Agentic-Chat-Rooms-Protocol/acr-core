package governance

import (
	"encoding/hex"
	"testing"
	"time"

	"acr-core/pkg/crypto"
)

func TestCapsBitmaskAndRoles(t *testing.T) {
	// Anonymous default: READ | POST | EDIT_OWN = 0x000B
	anon := DefaultCaps()
	if anon != 0x000B {
		t.Fatalf("Default caps should be 0x000B, got 0x%04X", anon)
	}

	if !HasCap(anon, CapRead) || !HasCap(anon, CapPost) || !HasCap(anon, CapEditOwn) {
		t.Fatalf("Default caps missing read/post/edit_own")
	}
	if HasCap(anon, CapSysop) || HasCap(anon, CapMcpEgress) {
		t.Fatalf("Default caps must not have sysop or mcp egress")
	}

	// Monotonic role hierarchy
	guestCaps := RoleGuest.Caps()
	agentCaps := RoleAgent.Caps()
	modCaps := RoleModerator.Caps()
	fedCaps := RoleFederator.Caps()
	sysopCaps := RoleSysop.Caps()

	if !HasCap(agentCaps, guestCaps) {
		t.Fatalf("Agent should contain Guest caps")
	}
	if !HasCap(modCaps, agentCaps) {
		t.Fatalf("Moderator should contain Agent caps")
	}
	if !HasCap(fedCaps, modCaps) {
		t.Fatalf("Federator should contain Moderator caps")
	}
	if !HasCap(sysopCaps, fedCaps) {
		t.Fatalf("Sysop should contain Federator caps")
	}
	if sysopCaps != AllCaps {
		t.Fatalf("Sysop should have AllCaps (0x03FF), got 0x%04X", sysopCaps)
	}

	// RequireCap
	if err := RequireCap(agentCaps, CapPost, "post"); err != nil {
		t.Fatalf("RequireCap failed unexpectedly: %v", err)
	}
	if err := RequireCap(anon, CapSysop, "admin"); err == nil {
		t.Fatalf("RequireCap should have failed for anon requesting sysop")
	}
}

func TestRoleClaimVerification(t *testing.T) {
	secret := []byte("top-secret-hmac-key")
	now := int64(1000)
	futureExp := int64(2000)
	pastExp := int64(500)

	// Valid claim for moderator
	sig := SignRoleClaim(secret, "moderator", futureExp)
	res := VerifyRoleClaim(secret, "moderator", futureExp, sig, now)
	if !res.Valid || res.FallbackApplied || res.GrantedRole != "moderator" {
		t.Fatalf("Valid claim should pass: %+v", res)
	}
	if res.CapsBitmask != uint32(RoleModerator.Caps()) {
		t.Fatalf("Granted caps bitmask mismatch: %d vs %d", res.CapsBitmask, RoleModerator.Caps())
	}

	// Expired claim -> fallback to agent
	sigExpired := SignRoleClaim(secret, "sysop", pastExp)
	resExpired := VerifyRoleClaim(secret, "sysop", pastExp, sigExpired, now)
	if resExpired.Valid || !resExpired.FallbackApplied || resExpired.GrantedRole != "agent" {
		t.Fatalf("Expired claim should fallback to agent: %+v", resExpired)
	}

	// Forged signature -> fallback to agent
	resForged := VerifyRoleClaim(secret, "sysop", futureExp, "0000000000000000000000000000000000000000000000000000000000000000", now)
	if resForged.Valid || !resForged.FallbackApplied || resForged.GrantedRole != "agent" {
		t.Fatalf("Forged claim should fallback to agent: %+v", resForged)
	}
}

func TestBudgetLedgerReserveAndCommit(t *testing.T) {
	ledger := NewBudgetLedger()

	ledger.Record("pod-1", 0.04)
	ledger.Record("pod-1", 0.03)
	ledger.Record("pod-1", -1.0) // ignored

	if (ledger.Spent("pod-1") - 0.07) > 1e-9 {
		t.Fatalf("Expected spent 0.07, got %f", ledger.Spent("pod-1"))
	}

	// Reserve pre-check: 0.07 + 0.02 <= 0.10 -> true
	if !ledger.Reserve("pod-1", 0.02, 0.10) {
		t.Fatalf("Reserve within cap should succeed")
	}
	// Reserve pre-check: 0.07 + 0.05 <= 0.10 -> false
	if ledger.Reserve("pod-1", 0.05, 0.10) {
		t.Fatalf("Reserve exceeding cap should fail")
	}

	// Bump cap by 0.05: effective cap becomes 0.15
	ledger.BumpCap("pod-1", 0.05)
	if !ledger.Reserve("pod-1", 0.05, 0.10) {
		t.Fatalf("Reserve with operator top-up should succeed")
	}

	status := ledger.Status("pod-1", 0.10)
	if status.OverBudget {
		t.Fatalf("Should not be over budget yet: %+v", status)
	}

	ledger.Record("pod-1", 0.10) // spent = 0.17 > 0.15
	statusOver := ledger.Status("pod-1", 0.10)
	if !statusOver.OverBudget || statusOver.Remaining != 0.0 {
		t.Fatalf("Should be over budget now: %+v", statusOver)
	}
}

func TestApprovalGateFailClosedVeto(t *testing.T) {
	pubOp1, privOp1, _ := crypto.GenerateKeypair()
	pubOp2, privOp2, _ := crypto.GenerateKeypair()
	pubRando, privRando, _ := crypto.GenerateKeypair()

	op1Hex := hex.EncodeToString(pubOp1)
	op2Hex := hex.EncodeToString(pubOp2)
	allowed := []string{op1Hex, op2Hex}

	now := time.Now().UTC()
	prop := NewActionProposal("deploy", "Deploy kernel update", "did:acr:agent:builder", "ops-room", now)

	gate := NewApprovalGate()

	// Initial state: not authorized
	if gate.IsAuthorized(prop.ActionID, allowed) {
		t.Fatalf("Unapproved proposal should not be authorized")
	}

	// Unauthorized party signs approve: should NOT authorize
	randoDecision, _ := SignDecision(privRando, prop.ActionID, VerdictApprove, "looks good", now)
	_ = gate.Record(*randoDecision)
	if gate.IsAuthorized(prop.ActionID, allowed) {
		t.Fatalf("Unallowed decider decision should not authorize")
	}

	// Op1 signs approve: now authorized
	op1Decision, _ := SignDecision(privOp1, prop.ActionID, VerdictApprove, "authorized", now)
	if err := gate.Record(*op1Decision); err != nil {
		t.Fatalf("Record op1 decision failed: %v", err)
	}
	if !gate.IsAuthorized(prop.ActionID, allowed) {
		t.Fatalf("Proposal with Op1 approval should be authorized")
	}

	// Op2 signs veto (reject): MUST immediately fail-closed and deny authorization!
	op2Veto, _ := SignDecision(privOp2, prop.ActionID, VerdictReject, "veto safety issue", now)
	if err := gate.Record(*op2Veto); err != nil {
		t.Fatalf("Record veto failed: %v", err)
	}
	if gate.IsAuthorized(prop.ActionID, allowed) {
		t.Fatalf("Vetoed proposal must NEVER be authorized (fail-closed violation)")
	}

	_ = pubOp1
	_ = pubOp2
	_ = pubRando
}
