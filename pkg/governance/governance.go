package governance

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"acr-core/pkg/identity"
	"acr-core/pkg/models"
)

// Engine manages human-in-the-loop escalations and append-only audit trail.
type Engine struct {
	mu           sync.RWMutex
	escalations  map[string]*models.Escalation
	auditTrail   []*models.AuditEntry
	latestHash   string
	onEscalation func(esc *models.Escalation)
	onAuditEntry func(entry *models.AuditEntry)
}

// NewEngine creates a new governance engine.
func NewEngine(onEscalation func(esc *models.Escalation), onAuditEntry func(entry *models.AuditEntry)) *Engine {
	return &Engine{
		escalations:  make(map[string]*models.Escalation),
		auditTrail:   make([]*models.AuditEntry, 0),
		latestHash:   "0000000000000000000000000000000000000000000000000000000000000000",
		onEscalation: onEscalation,
		onAuditEntry: onAuditEntry,
	}
}

// RequestEscalation records a new human escalation gate.
func (e *Engine) RequestEscalation(req models.Escalation) (*models.Escalation, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	req.Status = models.EscalationPending
	req.CreatedAt = time.Now().UTC()
	e.escalations[req.ID] = &req

	// Record to audit trail
	payloadBytes, _ := json.Marshal(req)
	entry := e.appendAuditLocked("ESCALATION_REQUEST", req.RequestingDID, req.RoomID, string(payloadBytes))

	if e.onEscalation != nil {
		go e.onEscalation(&req)
	}
	if e.onAuditEntry != nil {
		go e.onAuditEntry(entry)
	}

	return &req, nil
}

// ResolveEscalation signs off or rejects an escalation gate.
func (e *Engine) ResolveEscalation(id string, approve bool, operatorDID, signature string) (*models.Escalation, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	esc, exists := e.escalations[id]
	if !exists {
		return nil, fmt.Errorf("escalation with id %s not found", id)
	}

	now := time.Now().UTC()
	esc.ResolvedAt = &now
	esc.OperatorDID = operatorDID
	esc.Signature = signature

	if approve {
		esc.Status = models.EscalationApproved
	} else {
		esc.Status = models.EscalationRejected
	}

	// Record to audit trail
	payloadBytes, _ := json.Marshal(esc)
	eventType := "ESCALATION_REJECTED"
	if approve {
		eventType = "ESCALATION_APPROVED"
	}
	entry := e.appendAuditLocked(eventType, operatorDID, esc.RoomID, string(payloadBytes))

	if e.onAuditEntry != nil {
		go e.onAuditEntry(entry)
	}

	return esc, nil
}

// GetPendingEscalations returns all unapproved/unrejected gates.
func (e *Engine) GetPendingEscalations() []*models.Escalation {
	e.mu.RLock()
	defer e.mu.RUnlock()

	result := make([]*models.Escalation, 0)
	for _, esc := range e.escalations {
		if esc.Status == models.EscalationPending {
			result = append(result, esc)
		}
	}
	return result
}

// RecordAudit logs any state transition into the cryptographic hash chain.
func (e *Engine) RecordAudit(eventType, actorDID, roomID string, payload interface{}) *models.AuditEntry {
	e.mu.Lock()
	defer e.mu.Unlock()

	canonBytes, err := identity.CanonicalizeJSON(payload)
	if err != nil {
		canonBytes = []byte("{}")
	}
	entry := e.appendAuditLocked(eventType, actorDID, roomID, string(canonBytes))
	if e.onAuditEntry != nil {
		go e.onAuditEntry(entry)
	}
	return entry
}

func (e *Engine) appendAuditLocked(eventType, actorDID, roomID, payloadStr string) *models.AuditEntry {
	idx := uint64(len(e.auditTrail))
	ts := time.Now().UTC()
	newHash := identity.ComputeCanonicalEventHash(e.latestHash, idx, eventType, actorDID, payloadStr, ts)

	entry := &models.AuditEntry{
		Index:     idx,
		Timestamp: ts,
		EventType: eventType,
		ActorDID:  actorDID,
		RoomID:    roomID,
		Payload:   payloadStr,
		StateHash: newHash,
		PrevHash:  e.latestHash,
	}

	e.latestHash = newHash
	e.auditTrail = append(e.auditTrail, entry)
	return entry
}

// GetAuditTrail returns the full immutable history.
func (e *Engine) GetAuditTrail() []*models.AuditEntry {
	e.mu.RLock()
	defer e.mu.RUnlock()

	cp := make([]*models.AuditEntry, 0, len(e.auditTrail))
	for _, a := range e.auditTrail {
		cp = append(cp, a)
	}
	return cp
}
