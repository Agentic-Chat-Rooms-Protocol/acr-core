package review

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
)

// ReviewHandler exposes the REST API for the review subsystem.
// Routes:
//   GET  /api/v1/stacks?repo=<owner/name>          → StacksResponse
//   POST /api/v1/stacks                             → create stack (JSON body)
//   GET  /api/v1/review/diff?pr=<n>&repo=<r>       → PRDiffResponse
//   POST /api/v1/review/verdict                     → submit agent verdict
//   POST /webhooks/gitea                            → Gitea webhook receiver
type ReviewHandler struct {
	controller *StackController
	differ     *AstDiffer
}

// NewReviewHandler constructs a ReviewHandler.
func NewReviewHandler(controller *StackController, differ *AstDiffer) *ReviewHandler {
	return &ReviewHandler{controller: controller, differ: differ}
}

// RegisterRoutes registers the handler routes on the given mux.
func (h *ReviewHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/v1/stacks", h.handleStacks)
	mux.HandleFunc("/api/v1/review/diff", h.handleDiff)
	mux.HandleFunc("/api/v1/review/verdict", h.handleVerdict)
	mux.HandleFunc("/webhooks/gitea", h.handleGiteaWebhook)
}

// --- /api/v1/stacks ---

func (h *ReviewHandler) handleStacks(w http.ResponseWriter, r *http.Request) {
	setCORSHeaders(w)
	switch r.Method {
	case http.MethodOptions:
		w.WriteHeader(http.StatusNoContent)
	case http.MethodGet:
		h.listStacks(w, r)
	case http.MethodPost:
		h.createStack(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *ReviewHandler) listStacks(w http.ResponseWriter, r *http.Request) {
	repo := r.URL.Query().Get("repo")
	stacks := h.controller.ListStacks(repo)
	writeJSON(w, StacksResponse{Repo: repo, Stacks: stacks})
}

func (h *ReviewHandler) createStack(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Repo       string   `json:"repo"`
		BaseBranch string   `json:"base"`
		Branches   []string `json:"branches"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	stack, err := h.controller.OpenStack(r.Context(), req.Repo, req.BaseBranch, req.Branches)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusCreated)
	writeJSON(w, stack)
}

// --- /api/v1/review/diff ---

func (h *ReviewHandler) handleDiff(w http.ResponseWriter, r *http.Request) {
	setCORSHeaders(w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	prStr := r.URL.Query().Get("pr")
	prNum, _ := strconv.Atoi(prStr)

	// Read optional inline old/new source bodies for direct AST diff (used by tests and UI preview)
	oldSrc := r.URL.Query().Get("old")
	newSrc := r.URL.Query().Get("new")
	filePath := r.URL.Query().Get("file")
	if filePath == "" {
		filePath = "file.go"
	}

	if oldSrc == "" && newSrc == "" {
		// Return a synthetic demo diff so the UI renders without a real Gitea connection
		writeJSON(w, h.demoDiff(prNum))
		return
	}

	hunks, err := h.differ.DiffFile(filePath, oldSrc, newSrc)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	writeJSON(w, PRDiffResponse{
		PRNumber: prNum,
		Files: []FileDiff{{
			Path:  filePath,
			Hunks: hunks,
		}},
	})
}

// demoDiff returns a non-trivial representative diff for UI development / demos.
func (h *ReviewHandler) demoDiff(prNum int) PRDiffResponse {
	return PRDiffResponse{
		PRNumber: prNum,
		Files: []FileDiff{
			{
				Path:    "pkg/gateway/hub.go",
				Added:   4,
				Removed: 3,
				Hunks: []AstDiffHunk{
					{
						Kind:     HunkFunctionChanged,
						Name:     "Hub.FanoutMessage",
						OldStart: 142, OldEnd: 149,
						NewStart: 142, NewEnd: 150,
						OldLines: []DiffLine{
							{142, "context", "func (h *Hub) FanoutMessage(ctx context.Context, msg *Message) error {"},
							{143, "context", "\t// Verify agent DID challenge before bus ingress"},
							{144, "del", "\tif err := h.legacyAuthCheck(msg.AgentDID); err != nil {"},
							{145, "del", "\t\treturn ErrUnauthorized"},
							{146, "del", "\t}"},
						},
						NewLines: []DiffLine{
							{142, "context", "func (h *Hub) FanoutMessage(ctx context.Context, msg *Message) error {"},
							{143, "context", "\t// Verify agent DID challenge before bus ingress"},
							{144, "add", "\tif !h.vcVerifier.ValidateCapability(msg.AgentDID, msg.RequiredScope) {"},
							{145, "add", "\t\th.governance.RecordDissent(msg.AgentDID, \"CAPABILITY_DENIED\")"},
							{146, "add", "\t\treturn ErrVCCapabilityScopeExceeded"},
							{147, "add", "\t}"},
						},
					},
				},
			},
			{
				Path:    "pkg/store/kv_store.go",
				Added:   1,
				Removed: 1,
				Hunks: []AstDiffHunk{
					{
						Kind:     HunkStructChanged,
						Name:     "RedisRoster",
						OldStart: 58, OldEnd: 60,
						NewStart: 58, NewEnd: 60,
						OldLines: []DiffLine{
							{58, "context", "type RedisRoster struct {"},
							{59, "del", "\tmu sync.Mutex // legacy single-host locking"},
							{60, "context", "}"},
						},
						NewLines: []DiffLine{
							{58, "context", "type RedisRoster struct {"},
							{59, "add", "\tcluster *redis.ClusterClient // distributed pub/sub buddy roster"},
							{60, "context", "}"},
						},
					},
				},
			},
		},
	}
}

// --- /api/v1/review/verdict ---

func (h *ReviewHandler) handleVerdict(w http.ResponseWriter, r *http.Request) {
	setCORSHeaders(w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		StackID  string  `json:"stack_id"`
		Layer    int     `json:"layer"`
		Verdict  Verdict `json:"verdict"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := h.controller.SubmitVerdict(r.Context(), req.StackID, req.Layer, req.Verdict); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusAccepted)
	writeJSON(w, map[string]string{"status": "accepted"})
}

// --- /webhooks/gitea ---

// GiteaPREvent is a minimal subset of Gitea's pull_request webhook payload.
type GiteaPREvent struct {
	Action      string `json:"action"`
	PullRequest struct {
		Number int    `json:"number"`
		Title  string `json:"title"`
		Head   struct{ Label string `json:"label"` } `json:"head"`
		Base   struct{ Label string `json:"label"` } `json:"base"`
	} `json:"pull_request"`
	Repository struct {
		FullName string `json:"full_name"`
	} `json:"repository"`
}

func (h *ReviewHandler) handleGiteaWebhook(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}

	eventType := r.Header.Get("X-Gitea-Event")
	switch eventType {
	case "pull_request":
		var evt GiteaPREvent
		if err := json.Unmarshal(body, &evt); err == nil {
			h.onPREvent(evt)
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *ReviewHandler) onPREvent(evt GiteaPREvent) {
	// If PR title contains "[Stack" marker, locate and update the stack layer
	if strings.Contains(evt.PullRequest.Title, "[Stack") && evt.Action == "closed" {
		// Find the stack and mark the layer merged
		for _, s := range h.controller.ListStacks(evt.Repository.FullName) {
			for _, l := range s.Layers {
				if l.PRNumber == evt.PullRequest.Number {
					l.Status = "merged"
				}
			}
		}
	}
}

// --- helpers ---

func setCORSHeaders(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
	w.Header().Set("Content-Type", "application/json")
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		http.Error(w, fmt.Sprintf("json marshal: %v", err), http.StatusInternalServerError)
		return
	}
	_, _ = w.Write(b)
}
