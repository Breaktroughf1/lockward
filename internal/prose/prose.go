// Package prose computes sentence-level diffs for Markdown and plain text
// (SKILL.md, rules files, tool descriptions), so a reviewer sees what an
// update changed in plain language (PRD G4).
//
// Requirements: LW-FR-09.
package prose

import (
	"bytes"
	"strings"
	"unicode"
	"unicode/utf8"
)

// IsText reports whether b looks like text: valid UTF-8 with no NUL bytes.
func IsText(b []byte) bool {
	return utf8.Valid(b) && !bytes.ContainsRune(b, 0)
}

// Sentences splits text into sentences. Every non-blank line starts a new
// unit (Markdown headings, list items and code lines stay separate), and
// within a line a sentence ends at '.', '!' or '?' followed by whitespace.
func Sentences(text string) []string {
	var out []string
	for line := range strings.SplitSeq(strings.ReplaceAll(text, "\r\n", "\n"), "\n") {
		line = strings.TrimSpace(line)
		start := 0
		for i := 0; i < len(line); i++ {
			c := line[i]
			if (c == '.' || c == '!' || c == '?') && i+1 < len(line) && unicode.IsSpace(rune(line[i+1])) {
				if s := strings.TrimSpace(line[start : i+1]); s != "" {
					out = append(out, s)
				}
				start = i + 1
			}
		}
		if s := strings.TrimSpace(line[start:]); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// OpKind is a diff operation.
type OpKind int

// Diff operations.
const (
	Equal OpKind = iota
	Delete
	Insert
)

// Op is one diff operation on a sentence.
type Op struct {
	Kind OpKind
	Text string
}

// maxCells bounds the LCS table (time and memory) for hostile inputs.
const maxCells = 4_000_000

// Diff returns the operations turning a into b. Common prefixes and
// suffixes are trimmed first; if the remaining middle is too large for an
// exact LCS, it is reported as a block delete followed by a block insert.
func Diff(a, b []string) []Op {
	pre := 0
	for pre < len(a) && pre < len(b) && a[pre] == b[pre] {
		pre++
	}
	suf := 0
	for suf < len(a)-pre && suf < len(b)-pre && a[len(a)-1-suf] == b[len(b)-1-suf] {
		suf++
	}
	var ops []Op
	for _, s := range a[:pre] {
		ops = append(ops, Op{Equal, s})
	}
	ops = append(ops, middle(a[pre:len(a)-suf], b[pre:len(b)-suf])...)
	for _, s := range a[len(a)-suf:] {
		ops = append(ops, Op{Equal, s})
	}
	return ops
}

// tooLarge reports whether an (n+1)×(m+1) table exceeds maxCells. The
// division form cannot overflow, whatever the lengths.
func tooLarge(n, m int) bool {
	return n >= maxCells || m+1 > maxCells/(n+1)
}

func middle(a, b []string) []Op {
	n, m := len(a), len(b)
	if n == 0 || m == 0 || tooLarge(n, m) {
		var ops []Op
		for _, s := range a {
			ops = append(ops, Op{Delete, s})
		}
		for _, s := range b {
			ops = append(ops, Op{Insert, s})
		}
		return ops
	}
	// lcs[i][j] = LCS length of a[i:] and b[j:], stored row-major.
	w := m + 1
	lcs := make([]int32, (n+1)*w)
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			if a[i] == b[j] {
				lcs[i*w+j] = lcs[(i+1)*w+j+1] + 1
			} else {
				lcs[i*w+j] = max(lcs[(i+1)*w+j], lcs[i*w+j+1])
			}
		}
	}
	var ops []Op
	i, j := 0, 0
	for i < n && j < m {
		switch {
		case a[i] == b[j]:
			ops = append(ops, Op{Equal, a[i]})
			i++
			j++
		case lcs[(i+1)*w+j] >= lcs[i*w+j+1]:
			ops = append(ops, Op{Delete, a[i]})
			i++
		default:
			ops = append(ops, Op{Insert, b[j]})
			j++
		}
	}
	for ; i < n; i++ {
		ops = append(ops, Op{Delete, a[i]})
	}
	for ; j < m; j++ {
		ops = append(ops, Op{Insert, b[j]})
	}
	return ops
}

// Changed reports whether ops contain any insert or delete.
func Changed(ops []Op) bool {
	for _, o := range ops {
		if o.Kind != Equal {
			return true
		}
	}
	return false
}

// Format renders ops as "- removed" / "+ added" lines with up to context
// unchanged sentences around each change ("  kept"). Skipped runs of
// unchanged sentences are shown as "  …".
func Format(ops []Op, context int) string {
	keep := make([]bool, len(ops))
	for i, o := range ops {
		if o.Kind == Equal {
			continue
		}
		for k := max(0, i-context); k <= min(len(ops)-1, i+context); k++ {
			keep[k] = true
		}
	}
	var b strings.Builder
	skipped := false
	for i, o := range ops {
		if !keep[i] {
			skipped = true
			continue
		}
		if skipped {
			b.WriteString("  …\n")
		}
		skipped = false
		switch o.Kind {
		case Delete:
			b.WriteString("- ")
		case Insert:
			b.WriteString("+ ")
		default:
			b.WriteString("  ")
		}
		b.WriteString(o.Text)
		b.WriteByte('\n')
	}
	return b.String()
}
