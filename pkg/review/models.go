package review

import "time"

// StackStatus represents the lifecycle state of a stacked PR chain.
type StackStatus string

const (
	StackStatusOpen    StackStatus = "open"
	StackStatusMerging StackStatus = "merging"
	StackStatusMerged  StackStatus = "merged"
	StackStatusClosed  StackStatus = "closed"
)

// Stack represents a Graphite-style ordered chain of pull requests.
type Stack struct {
	ID         string        `json:"id"`
	Repo       string        `json:"repo"`      // e.g. "ACR/acr-core"
	BaseBranch string        `json:"base"`      // target branch (e.g. "main")
	Layers     []*StackLayer `json:"layers"`    // ordered leaf-first
	Status     StackStatus   `json:"status"`
	CreatedAt  time.Time     `json:"created_at"`
	UpdatedAt  time.Time     `json:"updated_at"`
}

// StackLayer is one node in the stacked PR chain.
type StackLayer struct {
	Index      int       `json:"index"`        // 0 = closest to base
	PRNumber   int       `json:"pr_number"`
	Branch     string    `json:"branch"`
	ParentPR   int       `json:"parent_pr"`    // 0 if root layer
	Title      string    `json:"title"`
	Status     string    `json:"status"`       // "open" | "merged" | "closed"
	Verdicts   []Verdict `json:"verdicts"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// AstDiffHunkKind classifies the semantic nature of a code change.
type AstDiffHunkKind string

const (
	HunkFunctionChanged    AstDiffHunkKind = "FunctionChanged"
	HunkFunctionAdded      AstDiffHunkKind = "FunctionAdded"
	HunkFunctionRemoved    AstDiffHunkKind = "FunctionRemoved"
	HunkStructChanged      AstDiffHunkKind = "StructChanged"
	HunkImportAdded        AstDiffHunkKind = "ImportAdded"
	HunkImportRemoved      AstDiffHunkKind = "ImportRemoved"
	HunkTextOnly           AstDiffHunkKind = "TextOnly"
)

// AstDiffHunk is a semantically annotated diff region.
type AstDiffHunk struct {
	Kind        AstDiffHunkKind `json:"kind"`
	Name        string          `json:"name"`         // e.g. "FanoutMessage"
	OldStart    int             `json:"old_start"`
	OldEnd      int             `json:"old_end"`
	NewStart    int             `json:"new_start"`
	NewEnd      int             `json:"new_end"`
	OldLines    []DiffLine      `json:"old_lines"`
	NewLines    []DiffLine      `json:"new_lines"`
}

// DiffLine is a single annotated source line in a diff hunk.
type DiffLine struct {
	LineNum int    `json:"line_num"`
	Type    string `json:"type"`   // "context" | "add" | "del"
	Code    string `json:"code"`
}

// FileDiff is the full diff for a single changed file.
type FileDiff struct {
	Path     string        `json:"path"`
	OldPath  string        `json:"old_path"`
	Added    int           `json:"added"`
	Removed  int           `json:"removed"`
	Hunks    []AstDiffHunk `json:"hunks"`
}

// Verdict is a single agent's signed review decision.
type Verdict struct {
	AgentDID  string `json:"agent_did"`
	Decision  string `json:"decision"`    // "APPROVE" | "REQUEST_CHANGES" | "COMMENT"
	Signature string `json:"sig"`         // base64-encoded Ed25519 sig
	Timestamp string `json:"timestamp"`
}

// MergeDecisionEnvelope is the canonical cryptographic consensus proof
// that multiple agents have reviewed and approved a PR stack merge.
type MergeDecisionEnvelope struct {
	StackID   string    `json:"stack_id"`
	Repo      string    `json:"repo"`
	PRIDs     []int     `json:"pr_ids"`
	CommitSHA string    `json:"commit_sha"`
	Verdicts  []Verdict `json:"verdicts"`
	Quorum    string    `json:"quorum"`     // e.g. "3/3"
	Timestamp string    `json:"timestamp"`
}

// PRDiffResponse is returned by GET /api/v1/review/diff
type PRDiffResponse struct {
	PRNumber int        `json:"pr_number"`
	Files    []FileDiff `json:"files"`
}

// StacksResponse is returned by GET /api/v1/stacks
type StacksResponse struct {
	Repo   string   `json:"repo"`
	Stacks []*Stack `json:"stacks"`
}
