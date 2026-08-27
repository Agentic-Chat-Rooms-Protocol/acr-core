package models

// BuddyStatus represents the state of a buddy relationship.
type BuddyStatus string

const (
	BuddyPending  BuddyStatus = "pending"
	BuddyAccepted BuddyStatus = "accepted"
	BuddyBlocked  BuddyStatus = "blocked"
)

// BuddyRelation represents a directional buddy relationship between two agents.
type BuddyRelation struct {
	FromDID   string      `json:"from_did"`
	ToDID     string      `json:"to_did"`
	Status    BuddyStatus `json:"status"`
	CreatedAt string      `json:"created_at"`
}

// HealthStatus represents the daemon's health check response.
type HealthStatus struct {
	Version         string `json:"version"`
	Status          string `json:"status"`
	Uptime          string `json:"uptime"`
	AgentCount      int    `json:"agent_count"`
	RoomCount       int    `json:"room_count"`
	AuditChainDepth int    `json:"audit_chain_depth"`
	MeshLatencyMs   float64 `json:"mesh_latency_ms"`
}

// AuthChallenge is the nonce sent to an agent for DID challenge-response auth.
type AuthChallenge struct {
	Nonce     string `json:"nonce"`
	ExpiresAt string `json:"expires_at"`
}

// AuthVerifyRequest is the agent's signed response to a challenge.
type AuthVerifyRequest struct {
	DID          string   `json:"did"`
	Name         string   `json:"name"`
	Avatar       string   `json:"avatar"`
	Role         string   `json:"role"`
	Org          string   `json:"org"`
	Capabilities []string `json:"capabilities"`
	Nonce        string   `json:"nonce"`
	Signature    string   `json:"signature"`
}

// RoomCreateRequest is the payload for creating a new room.
type RoomCreateRequest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Topic       string `json:"topic"`
	IsPrivate   bool   `json:"is_private"`
}

// RoomJoinRequest is the payload for joining/leaving a room.
type RoomJoinRequest struct {
	DID string `json:"did"`
}

// PersistentState contains serialized state for disk persistence (GAP-13).
type PersistentState struct {
	Agents    map[string]*Agent          `json:"agents"`
	Rooms     map[string]*Room           `json:"rooms"`
	History   map[string][]*Message      `json:"history"`
	Buddies   map[string][]BuddyRelation `json:"buddies"`
	Proposals map[string]*Proposal       `json:"proposals,omitempty"`
	Files     map[string]*FileAttachment `json:"files,omitempty"`
}
