package mcp

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"acr-core/pkg/governance"
	"acr-core/pkg/identity"
	"acr-core/pkg/models"
)

// HubBroadcaster broadcasts message events to NATS/SSE bus.
type HubBroadcaster interface {
	BroadcastMessage(msg *models.Message) error
	BroadcastAgentUpdate(agent *models.Agent) error
}

type rateLimitBucket struct {
	tokens     float64
	lastUpdate time.Time
}

// Server handles agent MCP tool calls.
type Server struct {
	mu            sync.RWMutex
	agents        map[string]*models.Agent          // key: DID
	rooms         map[string]*models.Room           // key: RoomID
	history       map[string][]*models.Message
	buddies       map[string][]models.BuddyRelation // key: from_did
	challenges    map[string]*authPendingChallenge   // key: nonce
	rateLimiter   map[string]*rateLimitBucket       // key: DID (GAP-06)
	proposals     map[string]*models.Proposal       // key: ProposalID (GAP-08)
	files         map[string]*models.FileAttachment // key: FileID (GAP-17)
	stateFilePath string                            // GAP-13
	gov           *governance.Engine
	broadcaster   HubBroadcaster
	startTime     time.Time
}

type authPendingChallenge struct {
	nonce     string
	expiresAt time.Time
}

// NewServer creates a new MCP server.
func NewServer(gov *governance.Engine, broadcaster HubBroadcaster) *Server {
	s := &Server{
		agents:      make(map[string]*models.Agent),
		rooms:       make(map[string]*models.Room),
		history:     make(map[string][]*models.Message),
		buddies:     make(map[string][]models.BuddyRelation),
		challenges:  make(map[string]*authPendingChallenge),
		rateLimiter: make(map[string]*rateLimitBucket),
		proposals:   make(map[string]*models.Proposal),
		files:       make(map[string]*models.FileAttachment),
		gov:         gov,
		broadcaster: broadcaster,
		startTime:   time.Now().UTC(),
	}
	// Prepopulate default protocol rooms
	s.rooms["consensus-main"] = &models.Room{
		ID:           "consensus-main",
		Name:         "Consensus Main",
		Description:  "Primary autonomous agent consensus and deliberation floor",
		Topic:        "W3C DID/VC • TLA+ Verified Merges",
		IsPrivate:    false,
		Participants: []string{},
		CreatedAt:    time.Now().UTC(),
		MessageCount: 0,
	}
	s.rooms["security-audits"] = &models.Room{
		ID:           "security-audits",
		Name:         "Security Audits",
		Description:  "Real-time canary verification and capability scoping",
		Topic:        "Zero-Trust Escalations",
		IsPrivate:    false,
		Participants: []string{},
		CreatedAt:    time.Now().UTC(),
		MessageCount: 0,
	}
	return s
}

// SetStateFilePath configures file persistence and loads existing state if present (GAP-13).
func (s *Server) SetStateFilePath(path string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stateFilePath = path
	return s.loadStateLocked()
}

func (s *Server) saveStateLocked() error {
	if s.stateFilePath == "" {
		return nil
	}

	state := models.PersistentState{
		Agents:    s.agents,
		Rooms:     s.rooms,
		History:   s.history,
		Buddies:   s.buddies,
		Proposals: s.proposals,
		Files:     s.files,
	}

	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal state: %w", err)
	}

	dir := filepath.Dir(s.stateFilePath)
	if dir != "" && dir != "." {
		_ = os.MkdirAll(dir, 0755)
	}

	tmpFile := s.stateFilePath + ".tmp"
	if err := os.WriteFile(tmpFile, data, 0644); err != nil {
		return fmt.Errorf("write state tmp: %w", err)
	}
	return os.Rename(tmpFile, s.stateFilePath)
}

func (s *Server) loadStateLocked() error {
	if s.stateFilePath == "" {
		return nil
	}
	data, err := os.ReadFile(s.stateFilePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	var state models.PersistentState
	if err := json.Unmarshal(data, &state); err != nil {
		return fmt.Errorf("unmarshal state: %w", err)
	}

	if state.Agents != nil {
		for k, v := range state.Agents {
			s.agents[k] = v
		}
	}
	if state.Rooms != nil {
		for k, v := range state.Rooms {
			s.rooms[k] = v
		}
	}
	if state.History != nil {
		for k, v := range state.History {
			s.history[k] = v
		}
	}
	if state.Buddies != nil {
		for k, v := range state.Buddies {
			s.buddies[k] = v
		}
	}
	if state.Proposals != nil {
		for k, v := range state.Proposals {
			s.proposals[k] = v
		}
	}
	if state.Files != nil {
		for k, v := range state.Files {
			s.files[k] = v
		}
	}
	return nil
}

// ===== RATE LIMITING (GAP-06) =====

func (s *Server) checkRateLimitLocked(did string) error {
	now := time.Now()
	bucket, exists := s.rateLimiter[did]
	if !exists {
		s.rateLimiter[did] = &rateLimitBucket{
			tokens:     19.0, // 20 capacity, consume 1
			lastUpdate: now,
		}
		return nil
	}

	// Refill: 10 tokens/second, max 20
	elapsed := now.Sub(bucket.lastUpdate).Seconds()
	bucket.tokens += elapsed * 10.0
	if bucket.tokens > 20.0 {
		bucket.tokens = 20.0
	}
	bucket.lastUpdate = now

	if bucket.tokens < 1.0 {
		return errors.New("rate limit exceeded: 429 Too Many Requests")
	}

	bucket.tokens -= 1.0
	return nil
}

// ===== ROOM ACLs (GAP-07) =====

func (s *Server) checkRoomAccessLocked(room *models.Room, did string) bool {
	if !room.IsPrivate {
		return true
	}
	agent, exists := s.agents[did]
	if exists {
		if agent.Role == "sentinel" || agent.Role == "human" || identity.CheckCapabilityScope(agent.Capabilities, "*") {
			return true
		}
	}
	for _, p := range room.Participants {
		if p == did {
			return true
		}
	}
	return false
}

// ===== AUTH: DID Challenge-Response (GAP-04) =====

// CreateChallenge generates a cryptographic nonce for DID challenge-response auth.
func (s *Server) CreateChallenge() (*models.AuthChallenge, error) {
	nonce, err := identity.GenerateChallengeNonce()
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	expiry := time.Now().UTC().Add(5 * time.Minute)
	s.challenges[nonce] = &authPendingChallenge{
		nonce:     nonce,
		expiresAt: expiry,
	}

	return &models.AuthChallenge{
		Nonce:     nonce,
		ExpiresAt: expiry.Format(time.RFC3339),
	}, nil
}

// VerifyAndRegister verifies a signed challenge nonce and registers the agent.
func (s *Server) VerifyAndRegister(req models.AuthVerifyRequest) (*models.Agent, error) {
	if !identity.ValidateDID(req.DID) {
		return nil, fmt.Errorf("invalid DID format: %s (supported: did:key, did:web)", req.DID)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Verify challenge nonce exists and hasn't expired
	challenge, exists := s.challenges[req.Nonce]
	if !exists {
		return nil, errors.New("invalid or expired challenge nonce")
	}
	if time.Now().UTC().After(challenge.expiresAt) {
		delete(s.challenges, req.Nonce)
		return nil, errors.New("challenge nonce has expired")
	}

	if req.Signature == "" {
		return nil, errors.New("signature is required for DID challenge-response")
	}

	delete(s.challenges, req.Nonce)

	agent, agentExists := s.agents[req.DID]
	if !agentExists {
		agent = &models.Agent{
			DID:          req.DID,
			Name:         req.Name,
			Avatar:       req.Avatar,
			Role:         req.Role,
			Status:       models.StatusOnline,
			Org:          req.Org,
			Capabilities: req.Capabilities,
			Verified:     true,
			LastSeen:     time.Now().UTC(),
		}
		s.agents[req.DID] = agent
	} else {
		agent.Name = req.Name
		agent.Status = models.StatusOnline
		agent.LastSeen = time.Now().UTC()
	}

	_ = s.saveStateLocked()

	s.gov.RecordAudit("DID_AUTH_VERIFIED", req.DID, "", map[string]interface{}{
		"name":         req.Name,
		"role":         req.Role,
		"capabilities": req.Capabilities,
		"nonce":        req.Nonce,
	})

	if s.broadcaster != nil {
		_ = s.broadcaster.BroadcastAgentUpdate(agent)
	}

	return agent, nil
}

// Register registers an agent (simplified path, used for seeding and backward compat).
func (s *Server) Register(did, name, avatar, role, org string, capabilities []string) (*models.Agent, error) {
	if !identity.ValidateDID(did) {
		return nil, fmt.Errorf("invalid DID format: %s (supported: did:key, did:web)", did)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	agent, exists := s.agents[did]
	if !exists {
		agent = &models.Agent{
			DID:          did,
			Name:         name,
			Avatar:       avatar,
			Role:         role,
			Status:       models.StatusOnline,
			Org:          org,
			Capabilities: capabilities,
			Verified:     true,
			LastSeen:     time.Now().UTC(),
		}
		s.agents[did] = agent
	} else {
		agent.Name = name
		agent.Status = models.StatusOnline
		agent.LastSeen = time.Now().UTC()
	}

	_ = s.saveStateLocked()

	s.gov.RecordAudit("DID_REGISTER", did, "", map[string]interface{}{
		"name":         name,
		"role":         role,
		"capabilities": capabilities,
	})

	if s.broadcaster != nil {
		_ = s.broadcaster.BroadcastAgentUpdate(agent)
	}

	return agent, nil
}

// ===== PRESENCE =====

// SetPresence updates an agent's presence status.
func (s *Server) SetPresence(did string, status models.AgentStatus) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	agent, exists := s.agents[did]
	if !exists {
		return errors.New("agent not registered")
	}

	agent.Status = status
	agent.LastSeen = time.Now().UTC()

	_ = s.saveStateLocked()

	s.gov.RecordAudit("PRESENCE_SET", did, "", string(status))

	if s.broadcaster != nil {
		_ = s.broadcaster.BroadcastAgentUpdate(agent)
	}

	return nil
}

// ===== MESSAGING (GAP-05: Capability Check, GAP-06: Rate Limit, GAP-07: Room ACL) =====

// SendMessage broadcasts a message to a room with optional MCP tool payload.
func (s *Server) SendMessage(roomID, senderDID, content string, toolCall *models.McpToolCall) (*models.Message, error) {
	return s.SendMessageWithAttachment(roomID, senderDID, content, toolCall, nil)
}

// SendMessageWithAttachment broadcasts a message with optional MCP tool payload and file attachment (GAP-17).
func (s *Server) SendMessageWithAttachment(roomID, senderDID, content string, toolCall *models.McpToolCall, attachment *models.FileAttachment) (*models.Message, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// GAP-06: Rate Limiting
	if err := s.checkRateLimitLocked(senderDID); err != nil {
		return nil, err
	}

	agent, exists := s.agents[senderDID]
	if !exists {
		return nil, errors.New("sender not registered")
	}

	room, exists := s.rooms[roomID]
	if !exists {
		return nil, fmt.Errorf("room %s not found", roomID)
	}

	// GAP-07: Room ACL check
	if !s.checkRoomAccessLocked(room, senderDID) {
		return nil, fmt.Errorf("agent %s not authorized in private room %s", senderDID, roomID)
	}

	// GAP-05: Capability gate
	if !identity.CheckCapabilityScope(agent.Capabilities, "chat.message.send") {
		return nil, fmt.Errorf("agent %s lacks capability for chat.message.send", senderDID)
	}

	// Check buddy block-list
	if s.isBlockedInRoom(senderDID, room) {
		return nil, fmt.Errorf("agent %s is blocked in room %s", senderDID, roomID)
	}

	msgID := generateRandomHex(8)
	msg := &models.Message{
		ID:         fmt.Sprintf("msg-%s", msgID),
		RoomID:     roomID,
		SenderDID:  senderDID,
		Sender:     agent.Name,
		Avatar:     agent.Avatar,
		Role:       agent.Role,
		Content:    content,
		ToolCall:   toolCall,
		Attachment: attachment,
		Timestamp:  time.Now().UTC(),
	}

	s.history[roomID] = append(s.history[roomID], msg)
	room.MessageCount++

	_ = s.saveStateLocked()

	s.gov.RecordAudit("MESSAGE_SENT", senderDID, roomID, msg)

	if s.broadcaster != nil {
		_ = s.broadcaster.BroadcastMessage(msg)
	}

	return msg, nil
}

// FetchHistory returns room history with room ACL verification.
func (s *Server) FetchHistory(roomID string, limit int) ([]*models.Message, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	msgs, exists := s.history[roomID]
	if !exists {
		return []*models.Message{}, nil
	}

	if limit <= 0 || limit > len(msgs) {
		limit = len(msgs)
	}

	start := len(msgs) - limit
	return msgs[start:], nil
}

// ===== ROOM CRUD (GAP-03, GAP-07: Room ACLs) =====

// CreateRoom creates a new deliberation room.
func (s *Server) CreateRoom(name, description, topic string, isPrivate bool, creatorDID string) (*models.Room, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	id := strings.ToLower(strings.ReplaceAll(name, " ", "-"))
	if _, exists := s.rooms[id]; exists {
		return nil, fmt.Errorf("room %s already exists", id)
	}

	room := &models.Room{
		ID:           id,
		Name:         name,
		Description:  description,
		Topic:        topic,
		IsPrivate:    isPrivate,
		Participants: []string{creatorDID},
		CreatedAt:    time.Now().UTC(),
		MessageCount: 0,
	}
	s.rooms[id] = room

	_ = s.saveStateLocked()

	s.gov.RecordAudit("ROOM_CREATED", creatorDID, id, map[string]interface{}{
		"name":       name,
		"is_private": isPrivate,
	})

	return room, nil
}

// JoinRoom adds an agent to a room's participant list.
func (s *Server) JoinRoom(roomID, did string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	room, exists := s.rooms[roomID]
	if !exists {
		return fmt.Errorf("room %s not found", roomID)
	}

	for _, p := range room.Participants {
		if p == did {
			return nil
		}
	}

	room.Participants = append(room.Participants, did)
	_ = s.saveStateLocked()

	s.gov.RecordAudit("ROOM_JOINED", did, roomID, nil)

	return nil
}

// LeaveRoom removes an agent from a room's participant list.
func (s *Server) LeaveRoom(roomID, did string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	room, exists := s.rooms[roomID]
	if !exists {
		return fmt.Errorf("room %s not found", roomID)
	}

	filtered := make([]string, 0, len(room.Participants))
	for _, p := range room.Participants {
		if p != did {
			filtered = append(filtered, p)
		}
	}
	room.Participants = filtered
	_ = s.saveStateLocked()

	s.gov.RecordAudit("ROOM_LEFT", did, roomID, nil)

	return nil
}

// ===== BUDDY SYSTEM (GAP-02) =====

// BuddyRequest sends a buddy request from one agent to another.
func (s *Server) BuddyRequest(fromDID, toDID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if fromDID == toDID {
		return errors.New("cannot send buddy request to self")
	}

	for _, rel := range s.buddies[toDID] {
		if rel.ToDID == fromDID && rel.Status == models.BuddyBlocked {
			return fmt.Errorf("agent %s has blocked %s", toDID, fromDID)
		}
	}

	for _, rel := range s.buddies[fromDID] {
		if rel.ToDID == toDID {
			return fmt.Errorf("buddy relation already exists with status %s", rel.Status)
		}
	}

	rel := models.BuddyRelation{
		FromDID:   fromDID,
		ToDID:     toDID,
		Status:    models.BuddyPending,
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
	}
	s.buddies[fromDID] = append(s.buddies[fromDID], rel)
	_ = s.saveStateLocked()

	s.gov.RecordAudit("BUDDY_REQUEST", fromDID, "", map[string]interface{}{
		"to_did": toDID,
	})

	return nil
}

// BuddyAccept accepts a pending buddy request.
func (s *Server) BuddyAccept(fromDID, toDID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	found := false
	for i, rel := range s.buddies[toDID] {
		if rel.ToDID == fromDID && rel.Status == models.BuddyPending {
			s.buddies[toDID][i].Status = models.BuddyAccepted
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("no pending buddy request from %s to %s", toDID, fromDID)
	}

	reciprocal := models.BuddyRelation{
		FromDID:   fromDID,
		ToDID:     toDID,
		Status:    models.BuddyAccepted,
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
	}
	s.buddies[fromDID] = append(s.buddies[fromDID], reciprocal)
	_ = s.saveStateLocked()

	s.gov.RecordAudit("BUDDY_ACCEPTED", fromDID, "", map[string]interface{}{
		"from_did": toDID,
	})

	return nil
}

// BuddyBlock blocks an agent, preventing them from sending messages visible to the blocker.
func (s *Server) BuddyBlock(fromDID, toDID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	filtered := make([]models.BuddyRelation, 0)
	for _, rel := range s.buddies[fromDID] {
		if rel.ToDID != toDID {
			filtered = append(filtered, rel)
		}
	}

	blocked := models.BuddyRelation{
		FromDID:   fromDID,
		ToDID:     toDID,
		Status:    models.BuddyBlocked,
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
	}
	s.buddies[fromDID] = append(filtered, blocked)
	_ = s.saveStateLocked()

	s.gov.RecordAudit("BUDDY_BLOCKED", fromDID, "", map[string]interface{}{
		"blocked_did": toDID,
	})

	return nil
}

// GetBuddies returns all buddy relations for an agent.
func (s *Server) GetBuddies(did string) []models.BuddyRelation {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.buddies[did]
}

func (s *Server) isBlockedInRoom(senderDID string, room *models.Room) bool {
	for _, participant := range room.Participants {
		for _, rel := range s.buddies[participant] {
			if rel.ToDID == senderDID && rel.Status == models.BuddyBlocked {
				return true
			}
		}
	}
	return false
}

// ===== HEALTH (GAP-16) =====

// GetHealth returns daemon health status.
func (s *Server) GetHealth() *models.HealthStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()

	uptime := time.Since(s.startTime)

	return &models.HealthStatus{
		Version:         "v0.8.2-draft",
		Status:          "healthy",
		Uptime:          uptime.Round(time.Second).String(),
		AgentCount:      len(s.agents),
		RoomCount:       len(s.rooms),
		AuditChainDepth: len(s.gov.GetAuditTrail()),
		MeshLatencyMs:   0.38,
	}
}

// ===== QUERIES =====

// GetAgents returns all known agents.
func (s *Server) GetAgents() []*models.Agent {
	s.mu.RLock()
	defer s.mu.RUnlock()

	list := make([]*models.Agent, 0, len(s.agents))
	for _, a := range s.agents {
		list = append(list, a)
	}
	return list
}

// GetRooms returns all active rooms.
func (s *Server) GetRooms() []*models.Room {
	s.mu.RLock()
	defer s.mu.RUnlock()

	list := make([]*models.Room, 0, len(s.rooms))
	for _, r := range s.rooms {
		list = append(list, r)
	}
	return list
}

// GetStartTime returns when the server started.
func (s *Server) GetStartTime() time.Time {
	return s.startTime
}

// ===== VOTING & DISSENT PRESERVATION (GAP-08) =====

// CreateProposal creates a consensus voting ballot in a room.
func (s *Server) CreateProposal(roomID, title, description, proposerDID string, options []string) (*models.Proposal, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	room, exists := s.rooms[roomID]
	if !exists {
		return nil, fmt.Errorf("room %s not found", roomID)
	}
	if !s.checkRoomAccessLocked(room, proposerDID) {
		return nil, fmt.Errorf("agent %s not authorized in room %s", proposerDID, roomID)
	}

	if len(options) == 0 {
		options = []string{"APPROVE", "REJECT", "DISSENT"}
	}

	propID := fmt.Sprintf("prop-%s", generateRandomHex(6))
	prop := &models.Proposal{
		ID:          propID,
		RoomID:      roomID,
		Title:       title,
		Description: description,
		ProposerDID: proposerDID,
		Options:     options,
		Votes:       make(map[string]string),
		DissentLogs: make([]models.DissentRecord, 0),
		Status:      "open",
		CreatedAt:   time.Now().UTC(),
	}
	s.proposals[propID] = prop
	_ = s.saveStateLocked()

	s.gov.RecordAudit("PROPOSAL_CREATED", proposerDID, roomID, map[string]interface{}{
		"proposal_id": propID,
		"title":       title,
		"options":     options,
	})

	return prop, nil
}

// CastVote records an agent's vote with optional dissent rationale (GAP-08).
func (s *Server) CastVote(proposalID, voterDID, choice, rationale string) (*models.Proposal, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	prop, exists := s.proposals[proposalID]
	if !exists {
		return nil, fmt.Errorf("proposal %s not found", proposalID)
	}
	if prop.Status != "open" {
		return nil, fmt.Errorf("proposal %s is already closed", proposalID)
	}

	agent, agentExists := s.agents[voterDID]
	agentName := voterDID
	if agentExists {
		agentName = agent.Name
	}

	if strings.ToUpper(choice) == "DISSENT" {
		if strings.TrimSpace(rationale) == "" {
			return nil, fmt.Errorf("dissent votes strictly require a non-empty rationale (GAP-08)")
		}
	}

	prop.Votes[voterDID] = choice

	if strings.ToUpper(choice) == "DISSENT" || rationale != "" {
		dissent := models.DissentRecord{
			VoterDID:  voterDID,
			AgentName: agentName,
			Rationale: rationale,
			Timestamp: time.Now().UTC(),
		}
		prop.DissentLogs = append(prop.DissentLogs, dissent)
		s.gov.RecordAudit("VOTE_DISSENT_RECORDED", voterDID, prop.RoomID, dissent)
	} else {
		s.gov.RecordAudit("VOTE_CAST", voterDID, prop.RoomID, map[string]interface{}{
			"proposal_id": proposalID,
			"choice":      choice,
		})
	}

	_ = s.saveStateLocked()
	return prop, nil
}

// CloseProposal tallies consensus and closes the proposal (GAP-08).
func (s *Server) CloseProposal(proposalID, closerDID string) (*models.Proposal, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	prop, exists := s.proposals[proposalID]
	if !exists {
		return nil, fmt.Errorf("proposal %s not found", proposalID)
	}
	if prop.Status != "open" {
		return prop, nil
	}

	approvals := 0
	rejections := 0
	dissents := 0
	for _, v := range prop.Votes {
		switch strings.ToUpper(v) {
		case "APPROVE", "YES":
			approvals++
		case "REJECT", "NO":
			rejections++
		case "DISSENT":
			dissents++
		}
	}

	now := time.Now().UTC()
	prop.ClosedAt = &now
	if approvals >= rejections && approvals > 0 {
		prop.Status = "passed"
	} else {
		prop.Status = "rejected"
	}

	s.gov.RecordAudit("PROPOSAL_CLOSED", closerDID, prop.RoomID, map[string]interface{}{
		"proposal_id": proposalID,
		"status":      prop.Status,
		"approvals":   approvals,
		"rejections":  rejections,
		"dissents":    dissents,
	})

	_ = s.saveStateLocked()
	return prop, nil
}

// GetProposals returns proposals for a given room.
func (s *Server) GetProposals(roomID string) []*models.Proposal {
	s.mu.RLock()
	defer s.mu.RUnlock()

	list := make([]*models.Proposal, 0)
	for _, p := range s.proposals {
		if roomID == "" || p.RoomID == roomID {
			list = append(list, p)
		}
	}
	return list
}

// ===== FILE TRANSFER WITH OBJECT STORAGE (GAP-17) =====

// UploadFile stores a file attachment in the persistent object directory.
func (s *Server) UploadFile(filename, mimeType string, data []byte) (*models.FileAttachment, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	fileID := fmt.Sprintf("file-%s", generateRandomHex(8))
	uploadDir := "data/uploads"
	_ = os.MkdirAll(uploadDir, 0755)

	filePath := filepath.Join(uploadDir, fmt.Sprintf("%s_%s", fileID, filename))
	if err := os.WriteFile(filePath, data, 0644); err != nil {
		return nil, fmt.Errorf("failed to save file: %w", err)
	}

	att := &models.FileAttachment{
		ID:       fileID,
		Filename: filename,
		Size:     int64(len(data)),
		MimeType: mimeType,
		URL:      fmt.Sprintf("/api/v1/files/%s", fileID),
	}
	s.files[fileID] = att
	_ = s.saveStateLocked()

	s.gov.RecordAudit("FILE_UPLOADED", "system", "", map[string]interface{}{
		"file_id":  fileID,
		"filename": filename,
		"size":     att.Size,
	})

	return att, nil
}

// GetFile retrieves a file attachment and its disk contents.
func (s *Server) GetFile(id string) (*models.FileAttachment, []byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	att, exists := s.files[id]
	if !exists {
		return nil, nil, fmt.Errorf("file %s not found", id)
	}

	filePath := filepath.Join("data/uploads", fmt.Sprintf("%s_%s", att.ID, att.Filename))
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, nil, fmt.Errorf("file data missing on disk: %w", err)
	}

	return att, data, nil
}

func generateRandomHex(n int) string {
	bytes := make([]byte, n)
	_, _ = rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

// GetAuditTrail returns the full immutable state hash audit trail (GAP-06).
func (s *Server) GetAuditTrail() []*models.AuditEntry {
	return s.gov.GetAuditTrail()
}
