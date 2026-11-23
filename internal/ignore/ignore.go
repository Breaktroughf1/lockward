// Package ignore implements .lockwardignore matching. Patterns follow a
// documented subset of gitignore syntax: "#" comments, "!" negation, a
// trailing "/" for directories only, a "/" anywhere else anchors the pattern
// to the root, and "*", "?", "[...]" and "**" wildcards. The last matching
// pattern wins, and a path inside an ignored directory is always ignored.
//
// Ignore patterns can hide files from the lockfile, so they are pinned and
// printed on every verify (THREAT_MODEL T13).
package ignore

import (
	"bufio"
	"bytes"
	"fmt"
	"regexp"
	"strings"
)

// FileName is the ignore file read from the project root.
const FileName = ".lockwardignore"

type rule struct {
	re      *regexp.Regexp
	negate  bool
	dirOnly bool
}

// Matcher matches slash-separated paths relative to the scope root.
type Matcher struct {
	Patterns []string // active pattern lines, in file order, for reporting
	rules    []rule
}

// Parse compiles the contents of an ignore file.
func Parse(content []byte) (*Matcher, error) {
	m := &Matcher{}
	sc := bufio.NewScanner(bytes.NewReader(content))
	sc.Buffer(make([]byte, 0, 4096), 1<<20)
	n := 0
	for sc.Scan() {
		n++
		line := strings.TrimRight(sc.Text(), " \t\r")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		r, err := compile(line)
		if err != nil {
			return nil, fmt.Errorf("%s line %d: %w", FileName, n, err)
		}
		m.Patterns = append(m.Patterns, line)
		m.rules = append(m.rules, r)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read %s: %w", FileName, err)
	}
	return m, nil
}

func compile(line string) (rule, error) {
	var r rule
	p := line
	if strings.HasPrefix(p, "!") {
		r.negate = true
		p = p[1:]
	} else if strings.HasPrefix(p, `\!`) || strings.HasPrefix(p, `\#`) {
		p = p[1:]
	}
	if strings.HasSuffix(p, "/") {
		r.dirOnly = true
		p = strings.TrimRight(p, "/")
	}
	if p == "" {
		return r, fmt.Errorf("empty pattern %q", line)
	}
	anchored := strings.Contains(p, "/")
	p = strings.TrimPrefix(p, "/")
	var b strings.Builder
	b.WriteString("^")
	if !anchored {
		b.WriteString("(?:.*/)?")
	}
	for i := 0; i < len(p); i++ {
		c := p[i]
		switch {
		case strings.HasPrefix(p[i:], "**/"):
			b.WriteString("(?:.*/)?")
			i += 2
		case strings.HasPrefix(p[i:], "/**") && i+3 == len(p):
			b.WriteString("/.*")
			i += 2
		case strings.HasPrefix(p[i:], "**"):
			b.WriteString(".*")
			i++
		case c == '*':
			b.WriteString("[^/]*")
		case c == '?':
			b.WriteString("[^/]")
		case c == '[':
			end := strings.IndexByte(p[i+1:], ']')
			if end < 0 {
				return r, fmt.Errorf("unterminated character class in %q", line)
			}
			class := p[i+1 : i+1+end]
			if strings.HasPrefix(class, "!") {
				class = "^" + class[1:]
			}
			b.WriteString("[" + strings.ReplaceAll(class, `\`, `\\`) + "]")
			i += end + 1
		case c == '\\' && i+1 < len(p):
			i++
			b.WriteString(regexp.QuoteMeta(string(p[i])))
		default:
			b.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	b.WriteString("$")
	re, err := regexp.Compile(b.String())
	if err != nil {
		return r, fmt.Errorf("invalid pattern %q: %w", line, err)
	}
	r.re = re
	return r, nil
}

// Match reports whether p (slash-separated, relative) is ignored. A path is
// ignored when it, or any of its parent directories, is ignored.
func (m *Matcher) Match(p string, isDir bool) bool {
	if m == nil || len(m.rules) == 0 {
		return false
	}
	parts := strings.Split(p, "/")
	for i := 1; i < len(parts); i++ {
		if m.matchOne(strings.Join(parts[:i], "/"), true) {
			return true
		}
	}
	return m.matchOne(p, isDir)
}

func (m *Matcher) matchOne(p string, isDir bool) bool {
	ignored := false
	for _, r := range m.rules {
		if r.dirOnly && !isDir {
			continue
		}
		if r.re.MatchString(p) {
			ignored = !r.negate
		}
	}
	return ignored
}

// Empty reports whether the matcher has no active patterns.
func (m *Matcher) Empty() bool { return m == nil || len(m.rules) == 0 }
