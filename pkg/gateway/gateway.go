package gateway

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"

	"acr-core/pkg/governance"
	"acr-core/pkg/mcp"
	"acr-core/pkg/models"
	"acr-core/pkg/version"
)

const maxUploadBytes int64 = 10 << 20 // 10 MiB

// SecurityConfig governs Cross-Origin Resource Sharing (CORS), PNA, Host/Origin allowlists, and optional Bearer API auth.
type SecurityConfig struct {
	EnableCORS     bool     `json:"enable_cors"`
	EnablePNA      bool     `json:"enable_pna"`
	RequireAuth    bool     `json:"require_auth"`
	APIToken       string   `json:"-"`
	AllowedOrigins []string `json:"allowed_origins,omitempty"`
	AllowedHosts   []string `json:"allowed_hosts,omitempty"`
}

// Server provides SSE streaming and REST APIs for human frontends.
type Server struct {
	mcpServer      *mcp.Server
	govEngine      *governance.Engine
	mu             sync.RWMutex
	clients        map[chan []byte]bool
	securityMu     sync.RWMutex
	securityConfig SecurityConfig
}

// NewServer creates a new gateway server.
func NewServer(mcpServer *mcp.Server, govEngine *governance.Engine) *Server {
	return &Server{
		mcpServer: mcpServer,
		govEngine: govEngine,
		clients:   make(map[chan []byte]bool),
		securityConfig: SecurityConfig{
			EnableCORS: false,
			EnablePNA:  false,
		},
	}
}

// GetSecurityConfig returns the active security configuration.
func (s *Server) GetSecurityConfig() SecurityConfig {
	s.securityMu.RLock()
	defer s.securityMu.RUnlock()
	return s.securityConfig
}

// SetSecurityConfig updates CORS and PNA settings dynamically at runtime.
func (s *Server) SetSecurityConfig(cfg SecurityConfig) {
	s.securityMu.Lock()
	defer s.securityMu.Unlock()
	s.securityConfig = cfg
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

	// Config & Security Policy (PNA / CORS)
	mux.HandleFunc("/api/v1/config/security", s.handleSecurityConfig)
	mux.HandleFunc("/api/v1/config", s.handleSecurityConfig)

	// Files / Object Storage (GAP-17)
	mux.HandleFunc("/api/v1/files/upload", s.handleFileUpload)
	mux.HandleFunc("/api/v1/files/", s.handleFileDownload)
}

var (
	globalSecurityMu     sync.RWMutex
	globalSecurityConfig = SecurityConfig{
		EnableCORS: false,
		EnablePNA:  false,
	}
)

// GetGlobalSecurityConfig returns the current global security configuration.
func GetGlobalSecurityConfig() SecurityConfig {
	globalSecurityMu.RLock()
	defer globalSecurityMu.RUnlock()
	return globalSecurityConfig
}

// SetGlobalSecurityConfig updates the global security configuration.
func SetGlobalSecurityConfig(cfg SecurityConfig) {
	globalSecurityMu.Lock()
	defer globalSecurityMu.Unlock()
	globalSecurityConfig = cfg
}

func extractHostname(hostHeader string) string {
	h := strings.TrimSpace(hostHeader)
	if h == "" {
		return ""
	}
	if parsedHost, _, err := net.SplitHostPort(h); err == nil {
		return strings.ToLower(strings.Trim(parsedHost, "[]"))
	}
	return strings.ToLower(strings.Trim(h, "[]"))
}

func isLoopbackRemoteAddr(remoteAddr string) bool {
	if strings.TrimSpace(remoteAddr) == "" {
		return false
	}
	host := remoteAddr
	if parsedHost, _, err := net.SplitHostPort(remoteAddr); err == nil {
		host = parsedHost
	}
	host = strings.Trim(host, "[]")
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func isHostAllowed(r *http.Request, cfg SecurityConfig) bool {
	if strings.TrimSpace(r.Host) == "" {
		return false
	}
	host := extractHostname(r.Host)
	if host == "" {
		return false
	}
	if host == "localhost" || host == "127.0.0.1" || host == "::1" {
		return true
	}
	for _, allowed := range cfg.AllowedHosts {
		ah := extractHostname(allowed)
		if ah == "" || ah == "*" {
			continue
		}
		if ah == host {
			return true
		}
	}
	return false
}

func isOriginAllowed(origin string, cfg SecurityConfig) bool {
	if origin == "" || origin == "null" {
		return false
	}
	for _, extra := range cfg.AllowedOrigins {
		trimmed := strings.TrimSpace(extra)
		if trimmed == "" || trimmed == "*" {
			continue
		}
		if strings.EqualFold(trimmed, origin) {
			return true
		}
	}
	u, err := url.Parse(origin)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return false
	}
	hostname := strings.ToLower(u.Hostname())
	if u.Scheme == "https" && (hostname == "agentchatrooms.dev" || hostname == "www.agentchatrooms.dev") {
		return true
	}
	if (u.Scheme == "http" || u.Scheme == "https") && (hostname == "localhost" || hostname == "127.0.0.1" || hostname == "::1") {
		return true
	}
	return false
}

func isPublicRoute(path string) bool {
	return path == "/health" || path == "/healthz" || path == "/api/v1/health" ||
		path == "/api/v1/auth/challenge" || path == "/api/v1/auth/verify"
}

func hasValidBearerToken(r *http.Request, expected string) bool {
	if expected == "" {
		return false
	}
	auth := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if !strings.HasPrefix(auth, prefix) {
		return false
	}
	provided := strings.TrimPrefix(auth, prefix)
	if provided == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(provided), []byte(expected)) == 1
}

func corsHeaders(w http.ResponseWriter) {
	// Handlers must not re-introduce wildcard '*' origins; CorsMiddleware writes validated Origin/PNA headers.
	w.Header().Set("Vary", "Origin")
}

// CorsMiddleware wraps an http.Handler with Host/Origin validation, Private Network Access (PNA), CORS, and optional Bearer auth.
func CorsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg := GetGlobalSecurityConfig()
		w.Header().Set("Vary", "Origin")

		if !isHostAllowed(r, cfg) {
			http.Error(w, "Forbidden host", http.StatusForbidden)
			return
		}

		enforceAuth := cfg.RequireAuth || cfg.APIToken != ""

		origin := r.Header.Get("Origin")
		if origin != "" {
			if !isOriginAllowed(origin, cfg) {
				http.Error(w, "Forbidden origin", http.StatusForbidden)
				return
			}
			if cfg.EnableCORS {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With, X-ACR-Session, X-ACR-Client, Access-Control-Request-Private-Network")
			}
			if cfg.EnablePNA && r.Method == http.MethodOptions {
				w.Header().Set("Access-Control-Allow-Private-Network", "true")
			}
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
		} else if r.Method == http.MethodOptions && !enforceAuth {
			http.Error(w, "Origin header required for preflight", http.StatusForbidden)
			return
		}

		if enforceAuth && !isPublicRoute(r.URL.Path) && !hasValidBearerToken(r, cfg.APIToken) {
			w.Header().Set("WWW-Authenticate", `Bearer realm="acr-local"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
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

func (s *Server) handleSecurityConfig(w http.ResponseWriter, r *http.Request) {
	corsHeaders(w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodPost && r.Method != http.MethodPut {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if r.Method == http.MethodPost || r.Method == http.MethodPut {
		if !isLoopbackRemoteAddr(r.RemoteAddr) {
			http.Error(w, "Forbidden: loopback peer required", http.StatusForbidden)
			return
		}
		if r.Header.Get("Origin") != "" {
			http.Error(w, "Forbidden: Origin header not permitted for security config mutation", http.StatusForbidden)
			return
		}
		cfg := GetGlobalSecurityConfig()
		if (cfg.RequireAuth || cfg.APIToken != "") && !hasValidBearerToken(r, cfg.APIToken) {
			w.Header().Set("WWW-Authenticate", `Bearer realm="acr-local"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || mediaType != "application/json" {
			http.Error(w, "Unsupported Media Type: application/json required", http.StatusUnsupportedMediaType)
			return
		}

		var req struct {
			EnableCORS *bool `json:"enable_cors"`
			EnablePNA  *bool `json:"enable_pna"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
			return
		}
		current := GetGlobalSecurityConfig()
		if req.EnableCORS != nil {
			current.EnableCORS = *req.EnableCORS
		}
		if req.EnablePNA != nil {
			current.EnablePNA = *req.EnablePNA
		}
		SetGlobalSecurityConfig(current)
		s.SetSecurityConfig(current)
	}

	cfg := GetGlobalSecurityConfig()
	pnaStatus := "disabled"
	if cfg.EnablePNA {
		pnaStatus = "active"
	}
	corsStatus := "disabled"
	if cfg.EnableCORS {
		corsStatus = "active"
	}

	jsonResponse(w, map[string]interface{}{
		"enable_cors":  cfg.EnableCORS,
		"enable_pna":   cfg.EnablePNA,
		"require_auth": cfg.RequireAuth || cfg.APIToken != "",
		"cors_status":  corsStatus,
		"pna_status":   pnaStatus,
		"version":      version.Get(),
	})
}

// ===== SSE =====

func (s *Server) handleSSE(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	corsHeaders(w)

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

	r.Body = http.MaxBytesReader(w, r.Body, maxUploadBytes)

	// Read multipart file or raw bytes
	err := r.ParseMultipartForm(maxUploadBytes)
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			http.Error(w, "Upload exceeds maximum size (10 MiB)", http.StatusRequestEntityTooLarge)
			return
		}
	}
	if err == nil && r.MultipartForm != nil {
		file, header, err := r.FormFile("file")
		if err != nil {
			http.Error(w, "Missing file in multipart form", http.StatusBadRequest)
			return
		}
		defer file.Close()

		data, err := io.ReadAll(io.LimitReader(file, maxUploadBytes+1))
		if err != nil {
			http.Error(w, "Failed to read file", http.StatusInternalServerError)
			return
		}
		if int64(len(data)) > maxUploadBytes {
			http.Error(w, "Upload exceeds maximum size (10 MiB)", http.StatusRequestEntityTooLarge)
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
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			http.Error(w, "Upload exceeds maximum size (10 MiB)", http.StatusRequestEntityTooLarge)
			return
		}
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
