package governance

import (
	"math"
	"sync"
)

// BudgetStatus represents an entity's spend against a cap.
type BudgetStatus struct {
	Key         string  `json:"key"`
	Spent       float64 `json:"spent"`
	Cap         float64 `json:"cap"`
	Remaining   float64 `json:"remaining"`
	OverBudget  bool    `json:"over_budget"`
	Pct         float64 `json:"pct"`
}

// BudgetLedger tracks accumulated spend per key against a spend cap,
// supporting Reserve-and-Commit pre-checks and operator top-ups.
type BudgetLedger struct {
	mu    sync.RWMutex
	spent map[string]float64
	bumps map[string]float64
}

// NewBudgetLedger constructs an empty BudgetLedger.
func NewBudgetLedger() *BudgetLedger {
	return &BudgetLedger{
		spent: make(map[string]float64),
		bumps: make(map[string]float64),
	}
}

// Record adds amount (USD) to key's spend. Negative, NaN, or Inf amounts are ignored.
func (b *BudgetLedger) Record(key string, amount float64) {
	if amount <= 0.0 || math.IsNaN(amount) || math.IsInf(amount, 0) {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.spent[key] += amount
}

// Spent returns the total accumulated spend for key.
func (b *BudgetLedger) Spent(key string) float64 {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.spent[key]
}

// BumpCap adds operator top-up amount to key's effective cap.
func (b *BudgetLedger) BumpCap(key string, amount float64) {
	if amount <= 0.0 || math.IsNaN(amount) || math.IsInf(amount, 0) {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.bumps[key] += amount
}

// Bump returns the operator top-up for key.
func (b *BudgetLedger) Bump(key string) float64 {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.bumps[key]
}

// Reserve performs a Reserve-and-Commit pre-check: would spending amount more
// keep key within its effective cap? (spent + amount <= cap + bump).
func (b *BudgetLedger) Reserve(key string, amount float64, baseCap float64) bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	effectiveCap := baseCap + b.bumps[key]
	return b.spent[key]+amount <= effectiveCap
}

// Status returns the current budget metrics for key against baseCap.
func (b *BudgetLedger) Status(key string, baseCap float64) BudgetStatus {
	b.mu.RLock()
	defer b.mu.RUnlock()

	spent := b.spent[key]
	effectiveCap := baseCap + b.bumps[key]
	remaining := math.Max(0.0, effectiveCap-spent)
	overBudget := spent >= effectiveCap && effectiveCap > 0.0

	pct := 0.0
	if effectiveCap > 0.0 {
		pct = spent / effectiveCap
	}

	return BudgetStatus{
		Key:        key,
		Spent:      spent,
		Cap:        effectiveCap,
		Remaining:  remaining,
		OverBudget: overBudget,
		Pct:        pct,
	}
}
