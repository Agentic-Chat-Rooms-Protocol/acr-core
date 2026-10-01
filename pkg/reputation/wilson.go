package reputation

import (
	"math"
	"time"

	"acr-core/pkg/identity"
)

// OutcomeRecord represents a verified single trial outcome for an agent.
type OutcomeRecord struct {
	Agent     string    `json:"agent"`
	Success   bool      `json:"success"`
	Weight    float64   `json:"weight"`
	Source    string    `json:"source"`
	Timestamp time.Time `json:"timestamp"`
}

// ReputationScore represents the aggregated, confidence-adjusted reputation of an agent.
type ReputationScore struct {
	Agent     string  `json:"agent"`
	Successes float64 `json:"successes"`
	Total     float64 `json:"total"`
	Rate      float64 `json:"rate"`
	Score     float64 `json:"score"`
}

// WilsonLowerBound calculates the lower bound of the Wilson score interval at confidence z.
// If z is 0, standard 95% confidence (1.96) is used.
// Includes defensive input clamping and small-sample / zero-sample guards.
func WilsonLowerBound(k float64, n float64, z float64) float64 {
	if z <= 0.0 {
		z = 1.96
	}
	if n <= 0.0 || math.IsNaN(n) || math.IsInf(n, 0) {
		return 0.0
	}
	if math.IsNaN(k) || math.IsInf(k, 0) {
		return 0.0
	}

	// Defensive clamping for invalid or out-of-range inputs
	kClamped := math.Min(math.Max(0.0, k), n)
	p := kClamped / n

	denominator := 1.0 + (z * z) / n
	centre := p + (z * z) / (2.0 * n)
	radicand := math.Max(0.0, (p*(1.0-p)+(z*z)/(4.0*n))/n)
	spread := z * math.Sqrt(radicand)
	lower := (centre - spread) / denominator

	return math.Max(0.0, math.Min(1.0, lower))
}

// ReputationLedger aggregates outcome records and computes agent reputation scores.
type ReputationLedger struct {
	records []OutcomeRecord
}

// NewLedger constructs an empty ReputationLedger.
func NewLedger() *ReputationLedger {
	return &ReputationLedger{
		records: make([]OutcomeRecord, 0),
	}
}

// Record appends an outcome record. Records with non-positive or non-finite weights are ignored.
func (l *ReputationLedger) Record(outcome OutcomeRecord) {
	if outcome.Weight <= 0.0 || math.IsNaN(outcome.Weight) || math.IsInf(outcome.Weight, 0) {
		return
	}
	l.records = append(l.records, outcome)
}

// Score computes the Wilson 95% reputation score for an agent DID/pubkey.
func (l *ReputationLedger) Score(agent string) ReputationScore {
	var successes float64
	var total float64

	for _, r := range l.records {
		if r.Agent == agent {
			total += r.Weight
			if r.Success {
				successes += r.Weight
			}
		}
	}

	rate := 0.0
	if total > 0.0 {
		rate = successes / total
	}

	return ReputationScore{
		Agent:     agent,
		Successes: successes,
		Total:     total,
		Rate:      rate,
		Score:     WilsonLowerBound(successes, total, 1.96),
	}
}

// ScoreVia computes the reputation of an agent folding in key rotation history.
// Outcomes recorded under predecessor keys that resolve to the same canonical identity
// are aggregated together.
func (l *ReputationLedger) ScoreVia(agent string, chain *identity.RotationChain) ReputationScore {
	resolvedTarget := agent
	if chain != nil {
		resolvedTarget = chain.Resolve(agent)
	}

	var successes float64
	var total float64

	for _, r := range l.records {
		recResolved := r.Agent
		if chain != nil {
			recResolved = chain.Resolve(r.Agent)
		}

		if recResolved == resolvedTarget {
			total += r.Weight
			if r.Success {
				successes += r.Weight
			}
		}
	}

	rate := 0.0
	if total > 0.0 {
		rate = successes / total
	}

	return ReputationScore{
		Agent:     resolvedTarget,
		Successes: successes,
		Total:     total,
		Rate:      rate,
		Score:     WilsonLowerBound(successes, total, 1.96),
	}
}
