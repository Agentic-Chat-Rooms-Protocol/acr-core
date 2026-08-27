package governance

import (
	"testing"

	"acr-core/pkg/models"
)

func TestEscalationLifecycle(t *testing.T) {
	gov := NewEngine(nil, nil)

	esc, err := gov.RequestEscalation(models.Escalation{
		ID:            "esc-test-1",
		RequestingDID: "did:key:z6Mkq5Xv",
		AgentName:     "Claude",
		RoomID:        "consensus-main",
		Action:        "file.transfer",
		RiskLevel:     "MEDIUM",
	})
	if err != nil {
		t.Fatalf("failed to request escalation: %v", err)
	}

	if esc.Status != models.EscalationPending {
		t.Errorf("expected pending status, got %s", esc.Status)
	}

	pending := gov.GetPendingEscalations()
	if len(pending) != 1 {
		t.Errorf("expected 1 pending escalation, got %d", len(pending))
	}

	resolved, err := gov.ResolveEscalation("esc-test-1", true, "did:key:z6Mka881", "sig-mock-ed25519")
	if err != nil {
		t.Fatalf("failed to resolve escalation: %v", err)
	}

	if resolved.Status != models.EscalationApproved {
		t.Errorf("expected approved status, got %s", resolved.Status)
	}

	trail := gov.GetAuditTrail()
	if len(trail) != 2 {
		t.Errorf("expected 2 audit entries, got %d", len(trail))
	}
	if trail[1].PrevHash != trail[0].StateHash {
		t.Errorf("cryptographic hash chain broken between audit index 0 and 1")
	}
}
