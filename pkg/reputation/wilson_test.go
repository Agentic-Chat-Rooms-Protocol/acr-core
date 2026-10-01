package reputation

import (
	"encoding/hex"
	"math"
	"testing"
	"time"

	"acr-core/pkg/crypto"
	"acr-core/pkg/identity"
)

func TestWilsonLowerBound_OrderingProof(t *testing.T) {
	// Agent A: 1/1 (100% raw)
	scoreA := WilsonLowerBound(1, 1, 1.96)
	// Agent B: 95/100 (95% raw)
	scoreB := WilsonLowerBound(95, 100, 1.96)
	// Agent C: 0/10 (0% raw)
	scoreC := WilsonLowerBound(0, 10, 1.96)

	// Invariant proof: Agent B must outrank Agent A despite lower raw percentage
	if !(scoreB > scoreA) {
		t.Fatalf("Wilson ranking failed: 95/100 (%f) must exceed 1/1 (%f)", scoreB, scoreA)
	}

	if scoreC != 0.0 {
		t.Fatalf("Zero successes should yield 0.0 score, got %f", scoreC)
	}

	// Verify exact values match Python verify-deep-moat.py test vector:
	// 95/100 -> ~0.8882, 1/1 -> ~0.2065
	if math.Abs(scoreB-0.8882) > 0.01 {
		t.Fatalf("Expected scoreB ~0.8882, got %f", scoreB)
	}
	if math.Abs(scoreA-0.2065) > 0.01 {
		t.Fatalf("Expected scoreA ~0.2065, got %f", scoreA)
	}
}

func TestWilsonLowerBound_BoundaryGuards(t *testing.T) {
	// k > n clamped to n
	overflow := WilsonLowerBound(15, 10, 1.96)
	expectedMax := WilsonLowerBound(10, 10, 1.96)
	if overflow != expectedMax {
		t.Fatalf("Overflow clamping failed: got %f, expected %f", overflow, expectedMax)
	}

	// k < 0 clamped to 0
	underflow := WilsonLowerBound(-5, 10, 1.96)
	if underflow != 0.0 {
		t.Fatalf("Underflow clamping failed: got %f, expected 0.0", underflow)
	}

	// n == 0
	zeroN := WilsonLowerBound(5, 0, 1.96)
	if zeroN != 0.0 {
		t.Fatalf("Zero sample size should yield 0.0, got %f", zeroN)
	}
}

func TestReputationLedger_ScoreAndScoreVia(t *testing.T) {
	ledger := NewLedger()
	now := time.Now().UTC()

	pubOld, privOld, _ := crypto.GenerateKeypair()
	pubNew, privNew, _ := crypto.GenerateKeypair()
	oldHex := hex.EncodeToString(pubOld)
	newHex := hex.EncodeToString(pubNew)

	// Record outcomes for old key
	for i := 0; i < 90; i++ {
		ledger.Record(OutcomeRecord{
			Agent:     oldHex,
			Success:   true,
			Weight:    1.0,
			Source:    "arena",
			Timestamp: now,
		})
	}
	for i := 0; i < 10; i++ {
		ledger.Record(OutcomeRecord{
			Agent:     oldHex,
			Success:   false,
			Weight:    1.0,
			Source:    "arena",
			Timestamp: now,
		})
	}

	// Record outcomes for new key
	for i := 0; i < 5; i++ {
		ledger.Record(OutcomeRecord{
			Agent:     newHex,
			Success:   true,
			Weight:    1.0,
			Source:    "pod",
			Timestamp: now,
		})
	}

	// Direct score for newHex alone: only 5/5 -> low Wilson bound
	directScoreNew := ledger.Score(newHex)
	if directScoreNew.Total != 5.0 || directScoreNew.Successes != 5.0 {
		t.Fatalf("Unexpected direct counts for newHex: %+v", directScoreNew)
	}

	// With rotation chain oldHex -> newHex
	chain := identity.NewRotationChain()
	link, _ := identity.SignRotationLink(privOld, privNew, now)
	chain.Add(*link)

	scoreVia := ledger.ScoreVia(newHex, chain)
	if scoreVia.Total != 105.0 || scoreVia.Successes != 95.0 {
		t.Fatalf("ScoreVia should aggregate old and new outcomes: expected 95/105, got %f/%f",
			scoreVia.Successes, scoreVia.Total)
	}

	// ScoreVia score should be high because of 95/105
	if scoreVia.Score <= directScoreNew.Score {
		t.Fatalf("Aggregated score (%f) should exceed unrotated new key score (%f)",
			scoreVia.Score, directScoreNew.Score)
	}

	_ = privOld
	_ = privNew
}
