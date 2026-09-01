package review

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"
)

// StackController manages the lifecycle of stacked PR chains against Gitea.
// It receives webhook events, maintains stack state in memory (backed by SQLite
// via the existing acr-core persistence layer), and enforces merge order.
type StackController struct {
	mu     sync.RWMutex
	stacks map[string]*Stack // keyed by stack ID

	gitea     *GiteaClient
	consensus *ConsensusEngine
	nats      NATSPublisher // interface so it can be nil in tests
}

// NATSPublisher abstracts NATS JetStream publishing.
type NATSPublisher interface {
	Publish(subject, data string) error
}

// NewStackController constructs a StackController.
// gitea may be nil in unit tests; nats may be nil to skip event publishing.
func NewStackController(gitea *GiteaClient, consensus *ConsensusEngine, nats NATSPublisher) *StackController {
	return &StackController{
		stacks:    make(map[string]*Stack),
		gitea:     gitea,
		consensus: consensus,
		nats:      nats,
	}
}

// GetStack retrieves a stack by ID.
func (sc *StackController) GetStack(id string) (*Stack, bool) {
	sc.mu.RLock()
	defer sc.mu.RUnlock()
	s, ok := sc.stacks[id]
	return s, ok
}

// ListStacks returns all stacks for a given repo slug (e.g. "ACR/acr-core").
func (sc *StackController) ListStacks(repo string) []*Stack {
	sc.mu.RLock()
	defer sc.mu.RUnlock()
	var out []*Stack
	for _, s := range sc.stacks {
		if s.Repo == repo || repo == "" {
			out = append(out, s)
		}
	}
	return out
}

// OpenStack creates a new stack from an ordered list of branch names.
// It will open one Gitea PR per layer if a GiteaClient is configured.
func (sc *StackController) OpenStack(ctx context.Context, repo, baseBranch string, branches []string) (*Stack, error) {
	stackID := newStackID()
	stack := &Stack{
		ID:         stackID,
		Repo:       repo,
		BaseBranch: baseBranch,
		Status:     StackStatusOpen,
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}

	// Build layers bottom-up
	prevPR := 0
	owner, repoName, _ := splitRepo(repo)
	for i, branch := range branches {
		layer := &StackLayer{
			Index:    i,
			Branch:   branch,
			ParentPR: prevPR,
			Status:   "open",
		}

		if sc.gitea != nil {
			parentBase := baseBranch
			if i > 0 {
				parentBase = branches[i-1]
			}
			title := fmt.Sprintf("[Stack %s / %d] %s", stackID[:8], i+1, branch)
			body := fmt.Sprintf("Stack: `%s` | Layer: %d | Parent PR: #%d\n\nAuto-opened by ACR Stack Controller.", stackID, i, prevPR)
			pr, err := sc.gitea.CreateStackPR(ctx, owner, repoName, branch, parentBase, title, body)
			if err != nil {
				log.Printf("stack_controller: create PR layer %d: %v", i, err)
			} else {
				layer.PRNumber = int(pr.Index)
				layer.Title = title
				prevPR = layer.PRNumber
				// Tag PR with stack metadata
				_ = sc.gitea.SetPRLabel(ctx, owner, repoName, layer.PRNumber, fmt.Sprintf("stack:%s", stackID))
				_ = sc.gitea.SetPRLabel(ctx, owner, repoName, layer.PRNumber, fmt.Sprintf("layer:%d", i))
			}
		}

		stack.Layers = append(stack.Layers, layer)
	}

	sc.mu.Lock()
	sc.stacks[stackID] = stack
	sc.mu.Unlock()

	sc.publishEvent("review.stack.updated", fmt.Sprintf(`{"event":"stack_opened","stack_id":%q,"repo":%q}`, stackID, repo))
	return stack, nil
}

// SubmitVerdict records an agent's signed verdict on a PR layer and checks quorum.
func (sc *StackController) SubmitVerdict(ctx context.Context, stackID string, layerIdx int, v Verdict) error {
	sc.mu.Lock()
	stack, ok := sc.stacks[stackID]
	if !ok {
		sc.mu.Unlock()
		return fmt.Errorf("stack %q not found", stackID)
	}
	if layerIdx >= len(stack.Layers) {
		sc.mu.Unlock()
		return fmt.Errorf("layer %d out of range", layerIdx)
	}
	layer := stack.Layers[layerIdx]
	layer.Verdicts = append(layer.Verdicts, v)
	sc.mu.Unlock()

	// Check if all layers have quorum
	if sc.allLayersApproved(stack) {
		return sc.finalizeStack(ctx, stack)
	}
	sc.publishEvent("review.pr.verdict", fmt.Sprintf(`{"event":"verdict_submitted","stack_id":%q,"layer":%d,"did":%q}`, stackID, layerIdx, v.AgentDID))
	return nil
}

// allLayersApproved returns true when every layer has ≥1 APPROVE verdict.
func (sc *StackController) allLayersApproved(stack *Stack) bool {
	sc.mu.RLock()
	defer sc.mu.RUnlock()
	for _, layer := range stack.Layers {
		approved := false
		for _, v := range layer.Verdicts {
			if v.Decision == "APPROVE" {
				approved = true
				break
			}
		}
		if !approved {
			return false
		}
	}
	return len(stack.Layers) > 0
}

// finalizeStack builds the MergeDecisionEnvelope, publishes to NATS, and
// posts it as a signed comment on each Gitea PR in the stack.
func (sc *StackController) finalizeStack(ctx context.Context, stack *Stack) error {
	var allVerdicts []Verdict
	var prIDs []int
	for _, l := range stack.Layers {
		allVerdicts = append(allVerdicts, l.Verdicts...)
		if l.PRNumber > 0 {
			prIDs = append(prIDs, l.PRNumber)
		}
	}

	env := &MergeDecisionEnvelope{
		StackID:   stack.ID,
		Repo:      stack.Repo,
		PRIDs:     prIDs,
		CommitSHA: "pending",
		Verdicts:  allVerdicts,
		Quorum:    fmt.Sprintf("%d/%d", len(stack.Layers), len(stack.Layers)),
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}

	if sc.consensus != nil {
		if err := sc.consensus.SignEnvelope(env); err != nil {
			log.Printf("stack_controller: sign envelope: %v", err)
		}
	}

	envJSON, _ := marshalEnvelope(env)
	commentBody := fmt.Sprintf("## ✅ ACR Consensus Proof\n\n```json\n%s\n```", envJSON)

	owner, repoName, _ := splitRepo(stack.Repo)
	if sc.gitea != nil {
		for _, prNum := range prIDs {
			if err := sc.gitea.PostConsensusComment(ctx, owner, repoName, prNum, commentBody); err != nil {
				log.Printf("stack_controller: post consensus comment PR#%d: %v", prNum, err)
			}
		}
	}

	sc.publishEvent("review.consensus.signed", envJSON)

	sc.mu.Lock()
	stack.Status = StackStatusMerging
	stack.UpdatedAt = time.Now()
	sc.mu.Unlock()

	return nil
}

func (sc *StackController) publishEvent(subject, data string) {
	if sc.nats != nil {
		if err := sc.nats.Publish(subject, data); err != nil {
			log.Printf("stack_controller: nats publish %s: %v", subject, err)
		}
	}
}

// --- helpers ---

func newStackID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func splitRepo(repo string) (owner, name, _ string) {
	parts := strings.SplitN(repo, "/", 2)
	if len(parts) == 2 {
		return parts[0], parts[1], ""
	}
	return repo, repo, ""
}

func marshalEnvelope(env *MergeDecisionEnvelope) (string, error) {
	// Simple manual JSON for deterministic canonical form (no map key reordering).
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf(`{"stack_id":%q,"repo":%q,"pr_ids":[`, env.StackID, env.Repo))
	for i, id := range env.PRIDs {
		if i > 0 {
			sb.WriteString(",")
		}
		sb.WriteString(fmt.Sprintf("%d", id))
	}
	sb.WriteString(fmt.Sprintf(`],"commit_sha":%q,"quorum":%q,"timestamp":%q,"verdicts":[`, env.CommitSHA, env.Quorum, env.Timestamp))
	for i, v := range env.Verdicts {
		if i > 0 {
			sb.WriteString(",")
		}
		sb.WriteString(fmt.Sprintf(`{"agent_did":%q,"decision":%q,"sig":%q,"timestamp":%q}`, v.AgentDID, v.Decision, v.Signature, v.Timestamp))
	}
	sb.WriteString("]}")
	return sb.String(), nil
}
