package review

import (
	"bufio"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
)

// AstDiffer computes semantically annotated diffs for Go source files.
// For non-Go files it falls back to plain text diff hunks (HunkTextOnly).
type AstDiffer struct{}

// NewAstDiffer constructs an AstDiffer.
func NewAstDiffer() *AstDiffer { return &AstDiffer{} }

// DiffFile computes the diff between oldSrc and newSrc for the given file path.
// It returns semantically annotated hunks for .go files; plain hunks otherwise.
func (d *AstDiffer) DiffFile(path, oldSrc, newSrc string) ([]AstDiffHunk, error) {
	if strings.HasSuffix(path, ".go") {
		return d.diffGo(oldSrc, newSrc)
	}
	return d.diffText(oldSrc, newSrc), nil
}

// diffGo produces AST-annotated hunks for Go source files.
func (d *AstDiffer) diffGo(oldSrc, newSrc string) ([]AstDiffHunk, error) {
	oldFuncs, err := extractGoDecls(oldSrc)
	if err != nil {
		return nil, fmt.Errorf("ast_diff: parse old: %w", err)
	}
	newFuncs, err := extractGoDecls(newSrc)
	if err != nil {
		return nil, fmt.Errorf("ast_diff: parse new: %w", err)
	}

	var hunks []AstDiffHunk

	// Detect changed and added functions/methods
	for name, newDecl := range newFuncs {
		if oldDecl, exists := oldFuncs[name]; !exists {
			// Added
			hunks = append(hunks, AstDiffHunk{
				Kind:     HunkFunctionAdded,
				Name:     name,
				NewStart: newDecl.startLine,
				NewEnd:   newDecl.endLine,
				NewLines: linesToDiffLines(newDecl.lines, "add", newDecl.startLine),
			})
		} else if oldDecl.body != newDecl.body {
			// Changed
			hunks = append(hunks, AstDiffHunk{
				Kind:     HunkFunctionChanged,
				Name:     name,
				OldStart: oldDecl.startLine,
				OldEnd:   oldDecl.endLine,
				NewStart: newDecl.startLine,
				NewEnd:   newDecl.endLine,
				OldLines: linesToDiffLines(oldDecl.lines, "del", oldDecl.startLine),
				NewLines: linesToDiffLines(newDecl.lines, "add", newDecl.startLine),
			})
		}
	}

	// Detect removed functions
	for name, oldDecl := range oldFuncs {
		if _, exists := newFuncs[name]; !exists {
			hunks = append(hunks, AstDiffHunk{
				Kind:     HunkFunctionRemoved,
				Name:     name,
				OldStart: oldDecl.startLine,
				OldEnd:   oldDecl.endLine,
				OldLines: linesToDiffLines(oldDecl.lines, "del", oldDecl.startLine),
			})
		}
	}

	// If no semantic hunks found, fallback to plain text diff
	if len(hunks) == 0 {
		return d.diffText(oldSrc, newSrc), nil
	}
	return hunks, nil
}

// goDecl holds extracted info about a Go top-level declaration.
type goDecl struct {
	startLine int
	endLine   int
	body      string
	lines     []string
}

// extractGoDecls parses Go source and returns a map of decl name → goDecl.
func extractGoDecls(src string) (map[string]*goDecl, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "", src, parser.ParseComments)
	if err != nil {
		return nil, err
	}
	srcLines := strings.Split(src, "\n")
	decls := make(map[string]*goDecl)

	for _, decl := range f.Decls {
		switch d := decl.(type) {
		case *ast.FuncDecl:
			start := fset.Position(d.Pos()).Line
			end := fset.Position(d.End()).Line
			name := d.Name.Name
			if d.Recv != nil && len(d.Recv.List) > 0 {
				// Method: prefix with receiver type
				if t, ok := d.Recv.List[0].Type.(*ast.StarExpr); ok {
					if id, ok := t.X.(*ast.Ident); ok {
						name = id.Name + "." + name
					}
				} else if id, ok := d.Recv.List[0].Type.(*ast.Ident); ok {
					name = id.Name + "." + name
				}
			}
			// Store the raw source text of the function as the body fingerprint
			bodyText := ""
			if d.Body != nil {
				bStart := fset.Position(d.Body.Pos()).Offset
				bEnd := fset.Position(d.Body.End()).Offset
				if bEnd <= len(src) {
					bodyText = src[bStart:bEnd]
				}
			}
			startIdx := start - 1
			endIdx := end
			if startIdx < 0 {
				startIdx = 0
			}
			if endIdx > len(srcLines) {
				endIdx = len(srcLines)
			}
			decls[name] = &goDecl{
				startLine: start,
				endLine:   end,
				body:      bodyText,
				lines:     srcLines[startIdx:endIdx],
			}
		}
	}
	return decls, nil
}

func linesToDiffLines(lines []string, lineType string, startLine int) []DiffLine {
	var out []DiffLine
	for i, l := range lines {
		out = append(out, DiffLine{
			LineNum: startLine + i,
			Type:    lineType,
			Code:    l,
		})
	}
	return out
}

// diffText produces plain HunkTextOnly hunks for non-Go files using
// a simple LCS-based unified diff approach.
func (d *AstDiffer) diffText(oldSrc, newSrc string) []AstDiffHunk {
	oldLines := splitLines(oldSrc)
	newLines := splitLines(newSrc)

	// Simple patience-style: detect changed/added/removed line blocks
	hunks := computeTextHunks(oldLines, newLines)
	return hunks
}

func splitLines(src string) []string {
	var lines []string
	sc := bufio.NewScanner(strings.NewReader(src))
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	return lines
}

// computeTextHunks builds minimal TextOnly diff hunks from line slices.
func computeTextHunks(old, new []string) []AstDiffHunk {
	// Build LCS table
	m, n := len(old), len(new)
	lcs := make([][]int, m+1)
	for i := range lcs {
		lcs[i] = make([]int, n+1)
	}
	for i := m - 1; i >= 0; i-- {
		for j := n - 1; j >= 0; j-- {
			if old[i] == new[j] {
				lcs[i][j] = lcs[i+1][j+1] + 1
			} else if lcs[i+1][j] > lcs[i][j+1] {
				lcs[i][j] = lcs[i+1][j]
			} else {
				lcs[i][j] = lcs[i][j+1]
			}
		}
	}

	// Trace diff
	type edit struct{ typ, line string; lineNum int }
	var edits []edit
	i, j := 0, 0
	for i < m || j < n {
		if i < m && j < n && old[i] == new[j] {
			edits = append(edits, edit{"context", old[i], i + 1})
			i++; j++
		} else if j < n && (i >= m || lcs[i][j+1] >= lcs[i+1][j]) {
			edits = append(edits, edit{"add", new[j], j + 1})
			j++
		} else {
			edits = append(edits, edit{"del", old[i], i + 1})
			i++
		}
	}

	// Group contiguous non-context edits into hunks
	var hunks []AstDiffHunk
	inHunk := false
	var cur AstDiffHunk
	for _, e := range edits {
		if e.typ == "context" {
			if inHunk {
				hunks = append(hunks, cur)
				cur = AstDiffHunk{}
				inHunk = false
			}
			continue
		}
		if !inHunk {
			cur = AstDiffHunk{Kind: HunkTextOnly}
			inHunk = true
		}
		dl := DiffLine{LineNum: e.lineNum, Type: e.typ, Code: e.line}
		if e.typ == "del" {
			cur.OldLines = append(cur.OldLines, dl)
		} else {
			cur.NewLines = append(cur.NewLines, dl)
		}
	}
	if inHunk {
		hunks = append(hunks, cur)
	}
	return hunks
}
