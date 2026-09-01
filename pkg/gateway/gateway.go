package gateway

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"acr-core/pkg/governance"
	"acr-core/pkg/mcp"
	"acr-core/pkg/models"
)

// Server provides SSE streaming and REST APIs for human frontends.
type Server struct {
	mcpServer *mcp.Server
	govEngine *governance.Engine
	mu        sync.RWMutex
	clients   map[chan []byte]bool
}

// NewServer creates a new gateway server.
func NewServer(mcpServer *mcp.Server, govEngine *governance.Engine) *Server {
	return &Server{
		mcpServer: mcpServer,
		govEngine: govEngine,
		clients:   make(map[chan []byte]bool),
	}
}

// BroadcastMessage sends a message to all connected SSE clients.
func (s *Server) BroadcastMessage(msg *models.Message) error {
	return s.broadcastEvent("message", msg)
}

// BroadcastAgentUpdate sends an agent status update to all connected SSE clients.
func (s *Server) BroadcastAgentUpdate(agent *models.Agent) error {
	return s.broadcastEvent("agent_update", agent)
}

// BroadcastEscalation sends a new escalation gate to SSE clients.
func (s *Server) BroadcastEscalation(esc *models.Escalation) error {
	return s.broadcastEvent("escalation", esc)
}

// BroadcastAuditEntry sends a new audit log to SSE clients.
func (s *Server) BroadcastAuditEntry(entry *models.AuditEntry) error {
	return s.broadcastEvent("audit", entry)
}

func (s *Server) broadcastEvent(eventType string, data interface{}) error {
	bytes, err := json.Marshal(map[string]interface{}{
		"type": eventType,
		"data": data,
	})
	if err != nil {
		return err
	}

	payload := fmt.Sprintf("event: %s\ndata: %s\n\n", eventType, string(bytes))
	msgBytes := []byte(payload)

	s.mu.RLock()
	defer s.mu.RUnlock()

	for ch := range s.clients {
		select {
		case ch <- msgBytes:
		default:
		}
	}
	return nil
}

// RegisterRoutes hooks up all HTTP handlers.
func (s *Server) RegisterRoutes(mux *http.ServeMux) {
	// Core streaming
	mux.HandleFunc("/api/v1/stream", s.handleSSE)

	// Health (GAP-16)
	mux.HandleFunc("/healthz", s.handleHealth)
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/api/v1/health", s.handleHealth)

	// Auth (GAP-04)
	mux.HandleFunc("/api/v1/auth/challenge", s.handleAuthChallenge)
	mux.HandleFunc("/api/v1/auth/verify", s.handleAuthVerify)

	// Rooms (GAP-03)
	mux.HandleFunc("/api/v1/rooms", s.handleRooms)
	mux.HandleFunc("/api/v1/rooms/", s.handleRoomSubroutes)

	// Agents
	mux.HandleFunc("/api/v1/agents", s.handleAgents)

	// Buddies (GAP-02)
	mux.HandleFunc("/api/v1/buddies", s.handleBuddies)
	mux.HandleFunc("/api/v1/buddies/", s.handleBuddyActions)

	// Escalations
	mux.HandleFunc("/api/v1/escalations", s.handleEscalations)
	mux.HandleFunc("/api/v1/escalations/", s.handleEscalationResolve)

	// Audit
	mux.HandleFunc("/api/v1/audit", s.handleAudit)
	mux.HandleFunc("/api/v1/audit/chain", s.handleAudit)
	mux.HandleFunc("/api/v1/audit/", s.handleAudit)

	// Proposals / Voting & Dissent (GAP-08)
	mux.HandleFunc("/api/v1/proposals", s.handleProposals)
	mux.HandleFunc("/api/v1/proposals/", s.handleProposalSubroutes)

	// Files / Object Storage (GAP-17)
	mux.HandleFunc("/api/v1/files/upload", s.handleFileUpload)
	mux.HandleFunc("/api/v1/files/", s.handleFileDownload)
}

func corsHeaders(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With, X-ACR-Session, X-ACR-Client")
	w.Header().Set("Access-Control-Allow-Private-Network", "true")
}

// CorsMiddleware wraps an http.Handler with Private Network Access (PNA) and CORS support.
func CorsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		corsHeaders(w)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func jsonResponse(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	corsHeaders(w)
	json.NewEncoder(w).Encode(data)
}

// ===== SSE =====

func (s *Server) handleSSE(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	clientChan := make(chan []byte, 64)
	s.mu.Lock()
	s.clients[clientChan] = true
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		delete(s.clients, clientChan)
		close(clientChan)
		s.mu.Unlock()
	}()

	// Send initial ping
	fmt.Fprintf(w, "event: connected\ndata: {\"status\":\"ready\"}\n\n")
	flusher.Flush()

	for {
		select {
		case <-r.Context().Done():
			return
		case msg := <-clientChan:
			w.Write(msg)
			flusher.Flush()
		}
	}
}

// ===== HEALTH (GAP-16) =====

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		corsHeaders(w)
		return
	}
	jsonResponse(w, s.mcpServer.GetHealth())
}

// ===== AUTH (GAP-04) =====

func (s *Server) handleAuthChallenge(w http.ResponseWriter, r *http.Request) {
	corsHeaders(w)
	if r.Method == http.MethodOptions {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	challenge, err := s.mcpServer.CreateChallenge()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonResponse(w, challenge)
}

func (s *Server) handleAuthVerify(w http.ResponseWriter, r *http.Request) {
	corsHeaders(w)
	if r.Method == http.MethodOptions {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req models.AuthVerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	agent, err := s.mcpServer.VerifyAndRegister(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	jsonResponse(w, agent)
}

// ===== ROOMS (GAP-03) =====

func (s *Server) handleRooms(w http.ResponseWriter, r *http.Request) {
	corsHeaders(w)
	if r.Method == http.MethodOptions {
		return
	}

	if r.Method == http.MethodGet {
		jsonResponse(w, s.mcpServer.GetRooms())
		return
	}

	if r.Method == http.MethodPost {
		var req models.RoomCreateRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		creatorDID := r.URL.Query().Get("creator_did")
		if creatorDID == "" {
			creatorDID = "did:key:z6Mka881...operator"
		}

		room, err := s.mcpServer.CreateRoom(req.Name, req.Description, req.Topic, req.IsPrivate, creatorDID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusCreated)
		jsonResponse(w, room)
		return
	}
}

func (s *Server) handleRoomSubroutes(w http.ResponseWriter, r *http.Request) {
	corsHeaders(w)
	if r.Method == http.MethodOptions {
		return
	}

	// Parse path: /api/v1/rooms/:id/:action
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 4 || parts[2] != "rooms" {
		http.NotFound(w, r)
		return
	}

	roomID := parts[3]

	// /api/v1/rooms/:id/messages
	if len(parts) >= 5 && parts[4] == "messages" {
		s.handleRoomMessages(w, r, roomID)
		return
	}

	// /api/v1/rooms/:id/join
	if len(parts) >= 5 && parts[4] == "join" && r.Method == http.MethodPost {
		var req models.RoomJoinRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := s.mcpServer.JoinRoom(roomID, req.DID); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		jsonResponse(w, map[string]string{"status": "joined", "room": roomID})
		return
	}

	// /api/v1/rooms/:id/leave
	if len(parts) >= 5 && parts[4] == "leave" && r.Method == http.MethodPost {
		var req models.RoomJoinRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := s.mcpServer.LeaveRoom(roomID, req.DID); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		jsonResponse(w, map[string]string{"status": "left", "room": roomID})
		return
	}

	http.NotFound(w, r)
}

func (s *Server) handleRoomMessages(w http.ResponseWriter, r *http.Request, roomID string) {
	if r.Method == http.MethodGet {
		limit := 50
		if lStr := r.URL.Query().Get("limit"); lStr != "" {
			if parsed, err := strconv.Atoi(lStr); err == nil {
				limit = parsed
			}
		}
		msgs, _ := s.mcpServer.FetchHistory(roomID, limit)
		jsonResponse(w, msgs)
		return
	}

	if r.Method == http.MethodPost {
		var req struct {
			SenderDID  string                 `json:"sender_did"`
			Content    string                 `json:"content"`
			ToolCall   *models.McpToolCall    `json:"tool_call,omitempty"`
			Attachment *models.FileAttachment `json:"attachment,omitempty"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		msg, err := s.mcpServer.SendMessageWithAttachment(roomID, req.SenderDID, req.Content, req.ToolCall, req.Attachment)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		jsonResponse(w, msg)
		return
	}
}

// ===== AGENTS =====

func (s *Server) handleAgents(w http.ResponseWriter, r *http.Request) {
	corsHeaders(w)
	if r.Method == http.MethodOptions {
		return
	}

	if r.Method == http.MethodPost {
		var req struct {
			DID          string   `json:"did"`
			Name         string   `json:"name"`
			Avatar       string   `json:"avatar"`
			Role         string   `json:"role"`
			Org          string   `json:"org"`
			ProcessPath  string   `json:"process_path"`
			Tags         []string `json:"tags"`
			Description  string   `json:"description"`
			Capabilities []string `json:"capabilities"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if req.DID == "" {
			req.DID = "did:key:z6Mka881...operator"
		}
		if req.Role == "" {
			req.Role = "human"
		}
		if req.Org == "" {
			req.Org = "ACR Root Administrator"
		}
		if len(req.Capabilities) == 0 {
			req.Capabilities = []string{"*"}
		}
		agent, err := s.mcpServer.Register(req.DID, req.Name, req.Avatar, req.Role, req.Org, req.Capabilities)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if req.ProcessPath != "" || req.Tags != nil || req.Description != "" {
			agent, _ = s.mcpServer.UpdateAgentProfile(req.DID, req.Name, req.Avatar, req.Org, req.ProcessPath, req.Description, req.Tags)
		}
		_ = s.BroadcastAgentUpdate(agent)
		jsonResponse(w, agent)
		return
	}

	jsonResponse(w, s.mcpServer.GetAgents())
}

// ===== BUDDIES (GAP-02) =====

func (s *Server) handleBuddies(w http.ResponseWriter, r *http.Request) {
	corsHeaders(w)
	if r.Method == http.MethodOptions {
		return
	}

	if r.Method == http.MethodGet {
		did := r.URL.Query().Get("did")
		if did == "" {
			did = "did:key:z6Mka881...operator"
		}
		jsonResponse(w, s.mcpServer.GetBuddies(did))
		return
	}
}

func (s *Server) handleBuddyActions(w http.ResponseWriter, r *http.Request) {
	corsHeaders(w)
	if r.Method == http.MethodOptions {
		return
	}

	// Path: /api/v1/buddies/request, /api/v1/buddies/accept, /api/v1/buddies/block
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 4 {
		http.NotFound(w, r)
		return
	}

	action := parts[3]

	var req struct {
		FromDID string `json:"from_did"`
		ToDID   string `json:"to_did"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var err error
	switch action {
	case "request":
		err = s.mcpServer.BuddyRequest(req.FromDID, req.ToDID)
	case "accept":
		err = s.mcpServer.BuddyAccept(req.FromDID, req.ToDID)
	case "block":
		err = s.mcpServer.BuddyBlock(req.FromDID, req.ToDID)
	default:
		http.NotFound(w, r)
		return
	}

	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	jsonResponse(w, map[string]string{"status": "ok", "action": action})
}

// ===== ESCALATIONS =====

func (s *Server) handleEscalations(w http.ResponseWriter, r *http.Request) {
	corsHeaders(w)
	if r.Method == http.MethodOptions {
		return
	}

	if r.Method == http.MethodGet {
		jsonResponse(w, s.govEngine.GetPendingEscalations())
		return
	}

	if r.Method == http.MethodPost {
		var req models.Escalation
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		esc, err := s.govEngine.RequestEscalation(req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		jsonResponse(w, esc)
		return
	}
}

func (s *Server) handleEscalationResolve(w http.ResponseWriter, r *http.Request) {
	corsHeaders(w)
	if r.Method == http.MethodOptions {
		return
	}

	// Path: /api/v1/escalations/:id/resolve
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 5 || parts[2] != "escalations" || parts[4] != "resolve" {
		http.NotFound(w, r)
		return
	}
	escID := parts[3]

	var req struct {
		Approve     bool   `json:"approve"`
		OperatorDID string `json:"operator_did"`
		Signature   string `json:"signature"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	resolved, err := s.govEngine.ResolveEscalation(escID, req.Approve, req.OperatorDID, req.Signature)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	jsonResponse(w, resolved)
}

// ===== AUDIT =====

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		corsHeaders(w)
		return
	}
	jsonResponse(w, s.govEngine.GetAuditTrail())
}

// ===== PROPOSALS / VOTING & DISSENT (GAP-08) =====

func (s *Server) handleProposals(w http.ResponseWriter, r *http.Request) {
	corsHeaders(w)
	if r.Method == http.MethodOptions {
		return
	}

	if r.Method == http.MethodGet {
		roomID := r.URL.Query().Get("room_id")
		jsonResponse(w, s.mcpServer.GetProposals(roomID))
		return
	}

	if r.Method == http.MethodPost {
		var req struct {
			RoomID      string   `json:"room_id"`
			Title       string   `json:"title"`
			Description string   `json:"description"`
			ProposerDID string   `json:"proposer_did"`
			Options     []string `json:"options"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		prop, err := s.mcpServer.CreateProposal(req.RoomID, req.Title, req.Description, req.ProposerDID, req.Options)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusCreated)
		jsonResponse(w, prop)
		return
	}
}

func (s *Server) handleProposalSubroutes(w http.ResponseWriter, r *http.Request) {
	corsHeaders(w)
	if r.Method == http.MethodOptions {
		return
	}

	// Path: /api/v1/proposals/:id/:action
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 5 || parts[2] != "proposals" {
		http.NotFound(w, r)
		return
	}

	propID := parts[3]
	action := parts[4]

	if action == "vote" && r.Method == http.MethodPost {
		var req struct {
			VoterDID  string `json:"voter_did"`
			Choice    string `json:"choice"`
			Rationale string `json:"rationale"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		prop, err := s.mcpServer.CastVote(propID, req.VoterDID, req.Choice, req.Rationale)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		jsonResponse(w, prop)
		return
	}

	if action == "close" && r.Method == http.MethodPost {
		var req struct {
			CloserDID string `json:"closer_did"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		prop, err := s.mcpServer.CloseProposal(propID, req.CloserDID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		jsonResponse(w, prop)
		return
	}

	http.NotFound(w, r)
}

// ===== FILE TRANSFER / OBJECT STORAGE (GAP-17) =====

func (s *Server) handleFileUpload(w http.ResponseWriter, r *http.Request) {
	corsHeaders(w)
	if r.Method == http.MethodOptions {
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Read multipart file or raw bytes
	err := r.ParseMultipartForm(50 << 20) // max 50MB
	if err == nil && r.MultipartForm != nil {
		file, header, err := r.FormFile("file")
		if err != nil {
			http.Error(w, "Missing file in multipart form", http.StatusBadRequest)
			return
		}
		defer file.Close()

		data, err := io.ReadAll(file)
		if err != nil {
			http.Error(w, "Failed to read file", http.StatusInternalServerError)
			return
		}

		mimeType := header.Header.Get("Content-Type")
		if mimeType == "" {
			mimeType = "application/octet-stream"
		}

		att, err := s.mcpServer.UploadFile(header.Filename, mimeType, data)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusCreated)
		jsonResponse(w, att)
		return
	}

	// Raw payload fallback
	filename := r.URL.Query().Get("filename")
	if filename == "" {
		filename = "attachment.bin"
	}
	mimeType := r.Header.Get("Content-Type")
	if mimeType == "" {
		mimeType = "application/octet-stream"
	}
	data, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read payload", http.StatusInternalServerError)
		return
	}

	att, err := s.mcpServer.UploadFile(filename, mimeType, data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusCreated)
	jsonResponse(w, att)
}

func (s *Server) handleFileDownload(w http.ResponseWriter, r *http.Request) {
	corsHeaders(w)
	if r.Method == http.MethodOptions {
		return
	}

	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 4 || parts[2] != "files" {
		http.NotFound(w, r)
		return
	}

	fileID := parts[3]
	att, data, err := s.mcpServer.GetFile(fileID)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", att.MimeType)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", att.Filename))
	w.Header().Set("Content-Length", strconv.FormatInt(att.Size, 10))
	w.Write(data)
}
