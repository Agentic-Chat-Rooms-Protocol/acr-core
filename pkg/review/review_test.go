package review_test

import (
	"context"
	"testing"

	"acr-core/pkg/review"
)

// --- Stack Controller ---

func TestStackController_OpenAndList(t *testing.T) {
	sc := review.NewStackController(nil, nil, nil)
	stack, err := sc.OpenStack(context.Background(), "ACR/acr-core", "main", []string{"feat/a", "feat/b"})
	if err != nil {
		t.Fatalf("OpenStack: %v", err)
	}
	if len(stack.Layers) != 2 {
		t.Fatalf("expected 2 layers, got %d", len(stack.Layers))
	}
	got := sc.ListStacks("ACR/acr-core")
	if len(got) != 1 {
		t.Fatalf("expected 1 stack, got %d", len(got))
	}
}

func TestStackController_SubmitVerdict(t *testing.T) {
	sc := review.NewStackController(nil, nil, nil)
	stack, _ := sc.OpenStack(context.Background(), "ACR/acr-core", "main", []string{"feat/x"})
	v := review.Verdict{
		AgentDID:  "did:key:z6MkTest",
		Decision:  "APPROVE",
		Signature: "fakesig==",
		Timestamp: "2026-09-01T00:00:00Z",
	}
	if err := sc.SubmitVerdict(context.Background(), stack.ID, 0, v); err != nil {
		t.Fatalf("SubmitVerdict: %v", err)
	}
}

func TestStackController_SubmitVerdict_NotFound(t *testing.T) {
	sc := review.NewStackController(nil, nil, nil)
	v := review.Verdict{Decision: "APPROVE"}
	if err := sc.SubmitVerdict(context.Background(), "nonexistent", 0, v); err == nil {
		t.Fatal("expected error for unknown stack")
	}
}

// --- AST Diff Engine ---

func TestAstDiffer_GoFunctionChanged(t *testing.T) {
	d := review.NewAstDiffer()

	oldSrc := `package foo

func Greet(name string) string {
	return "hello " + name
}
`
	newSrc := `package foo

func Greet(name string) string {
	return "hi " + name + "!"
}
`
	hunks, err := d.DiffFile("greet.go", oldSrc, newSrc)
	if err != nil {
		t.Fatalf("DiffFile: %v", err)
	}
	if len(hunks) == 0 {
		t.Fatal("expected at least one diff hunk")
	}
	found := false
	for _, h := range hunks {
		if h.Kind == review.HunkFunctionChanged && h.Name == "Greet" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected HunkFunctionChanged for Greet, got: %+v", hunks)
	}
}

func TestAstDiffer_GoFunctionAdded(t *testing.T) {
	d := review.NewAstDiffer()
	oldSrc := "package foo\n"
	newSrc := `package foo

func NewFunc() string { return "new" }
`
	hunks, err := d.DiffFile("file.go", oldSrc, newSrc)
	if err != nil {
		t.Fatalf("DiffFile: %v", err)
	}
	found := false
	for _, h := range hunks {
		if h.Kind == review.HunkFunctionAdded && h.Name == "NewFunc" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected HunkFunctionAdded for NewFunc, got: %+v", hunks)
	}
}

func TestAstDiffer_PlainTextFallback(t *testing.T) {
	d := review.NewAstDiffer()
	old := "line1\nline2\nline3\n"
	new := "line1\nchanged\nline3\n"
	hunks, err := d.DiffFile("readme.md", old, new)
	if err != nil {
		t.Fatalf("DiffFile: %v", err)
	}
	if len(hunks) == 0 {
		t.Fatal("expected text diff hunks")
	}
	if hunks[0].Kind != review.HunkTextOnly {
		t.Errorf("expected HunkTextOnly, got %q", hunks[0].Kind)
	}
}

func TestAstDiffer_NoDiff(t *testing.T) {
	d := review.NewAstDiffer()
	src := "package foo\nfunc A() {}\n"
	hunks, err := d.DiffFile("a.go", src, src)
	if err != nil {
		t.Fatalf("DiffFile: %v", err)
	}
	if len(hunks) != 0 {
		t.Errorf("expected no hunks for identical files, got %d", len(hunks))
	}
}

// --- Consensus Engine ---

func TestConsensusEngine_SignAndQuorum(t *testing.T) {
	eng, err := review.NewEphemeralConsensusEngine("did:key:z6MkTest")
	if err != nil {
		t.Fatalf("NewEphemeralConsensusEngine: %v", err)
	}
	env := &review.MergeDecisionEnvelope{
		StackID:   "stack-abc",
		Repo:      "ACR/acr-core",
		PRIDs:     []int{1, 2},
		CommitSHA: "abc123",
		Quorum:    "1/1",
		Timestamp: "2026-09-01T00:00:00Z",
	}
	if err := eng.SignEnvelope(env); err != nil {
		t.Fatalf("SignEnvelope: %v", err)
	}
	if len(env.Verdicts) != 1 {
		t.Fatalf("expected 1 verdict, got %d", len(env.Verdicts))
	}
	if env.Verdicts[0].Signature == "" {
		t.Error("expected non-empty signature")
	}
	if !review.QuorumReached(env, 1) {
		t.Error("expected quorum reached with threshold 1")
	}
	if review.QuorumReached(env, 2) {
		t.Error("expected quorum NOT reached with threshold 2")
	}
}
