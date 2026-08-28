package models

import "time"

// AgentStatus represents live presence states.
type AgentStatus string

const (
	StatusOnline       AgentStatus = "online"
	StatusAway         AgentStatus = "away"
	StatusDeliberating AgentStatus = "deliberating"
	StatusEscalated    AgentStatus = "escalated"
	StatusOffline      AgentStatus = "offline"
)

// Agent defines an autonomous or human actor registered with ACR.
type Agent struct {
	DID          string      `json:"did"`
	Name         string      `json:"name"`
	Avatar       string      `json:"avatar"`
	Role         string      `json:"role"` // "agent" | "human" | "sentinel"
	Status       AgentStatus `json:"status"`
	Org          string      `json:"org"`
	ProcessPath  string      `json:"process_path,omitempty"`
	Tags         []string    `json:"tags,omitempty"`
	Description  string      `json:"description,omitempty"`
	Capabilities []string    `json:"capabilities"`
	Verified     bool        `json:"verified"`
	LastSeen     time.Time   `json:"last_seen"`
	CurrentNonce string      `json:"current_nonce,omitempty"`
}

// Room represents an active consensus channel or topic.
type Room struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	Description  string    `json:"description"`
	Topic        string    `json:"topic"`
	IsPrivate    bool      `json:"is_private"`
	Participants []string  `json:"participants"` // Slice of DIDs
	CreatedAt    time.Time `json:"created_at"`
	MessageCount int       `json:"message_count"`
}

// McpToolCall captures an agent executing a typed MCP tool inside a room.
type McpToolCall struct {
	ID        string                 `json:"id"`
	ToolName  string                 `json:"tool_name"`
	Arguments map[string]interface{} `json:"arguments"`
	Output    string                 `json:"output,omitempty"`
	Status    string                 `json:"status"` // "pending" | "running" | "completed" | "failed"
	LatencyMs float64                `json:"latency_ms"`
}

// FileAttachment represents a file uploaded via signed URL or direct upload (GAP-17).
type FileAttachment struct {
	ID       string `json:"id"`
	Filename string `json:"filename"`
	Size     int64  `json:"size"`
	MimeType string `json:"mime_type"`
	URL      string `json:"url"`
}

// Message represents a broadcast or DM item in the ACR bus.
type Message struct {
	ID         string          `json:"id"`
	RoomID     string          `json:"room_id"`
	SenderDID  string          `json:"sender_did"`
	Sender     string          `json:"sender"`
	Avatar     string          `json:"avatar"`
	Role       string          `json:"role"` // "agent" | "human" | "system"
	Content    string          `json:"content"`
	ToolCall   *McpToolCall    `json:"tool_call,omitempty"`
	Attachment *FileAttachment `json:"attachment,omitempty"`
	Timestamp  time.Time       `json:"timestamp"`
	Signature  string          `json:"signature,omitempty"`
}

// EscalationStatus represents human governance states.
type EscalationStatus string

const (
	EscalationPending  EscalationStatus = "pending"
	EscalationApproved EscalationStatus = "approved"
	EscalationRejected EscalationStatus = "rejected"
)

// Escalation represents an ACP session/request_permission gate.
type Escalation struct {
	ID            string           `json:"id"`
	RequestingDID string           `json:"requesting_did"`
	AgentName     string           `json:"agent_name"`
	RoomID        string           `json:"room_id"`
	Action        string           `json:"action"`
	RiskLevel     string           `json:"risk_level"` // "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
	Payload       string           `json:"payload"`
	Status        EscalationStatus `json:"status"`
	CreatedAt     time.Time        `json:"created_at"`
	ResolvedAt    *time.Time       `json:"resolved_at,omitempty"`
	OperatorDID   string           `json:"operator_did,omitempty"`
	Signature     string           `json:"signature,omitempty"`
}

// AuditEntry provides append-only cryptographic event replay.
type AuditEntry struct {
	Index     uint64      `json:"index"`
	Timestamp time.Time   `json:"timestamp"`
	EventType string      `json:"event_type"` // "MESSAGE", "TOOL_EXEC", "ESCALATION", "DID_AUTH"
	ActorDID  string      `json:"actor_did"`
	RoomID    string      `json:"room_id"`
	Payload   interface{} `json:"payload"`
	StateHash string      `json:"state_hash"`
	PrevHash  string      `json:"prev_hash"`
}

// DissentRecord preserves dissenting rationale in consensus voting (GAP-08).
type DissentRecord struct {
	VoterDID  string    `json:"voter_did"`
	AgentName string    `json:"agent_name"`
	Rationale string    `json:"rationale"`
	Timestamp time.Time `json:"timestamp"`
}

// Proposal represents a consensus voting ballot in a deliberation room (GAP-08).
type Proposal struct {
	ID          string            `json:"id"`
	RoomID      string            `json:"room_id"`
	Title       string            `json:"title"`
	Description string            `json:"description"`
	ProposerDID string            `json:"proposer_did"`
	Options     []string          `json:"options"` // e.g. ["APPROVE", "REJECT", "DISSENT"]
	Votes       map[string]string `json:"votes"`   // key: voter_did, value: choice
	DissentLogs []DissentRecord   `json:"dissent_logs"`
	Status      string            `json:"status"` // "open" | "passed" | "rejected"
	CreatedAt   time.Time         `json:"created_at"`
	ClosedAt    *time.Time        `json:"closed_at,omitempty"`
}
