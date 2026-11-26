package adapter

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/Breaktroughf1/lockward/internal/asset"
	"github.com/Breaktroughf1/lockward/internal/hash"
	"github.com/Breaktroughf1/lockward/internal/ignore"
)

// Adapter discovers one agent's assets. Implementations are pure and
// read-only: they read bytes from Source.FS, never execute anything and never
// follow symlinks outside the filesystem root (ARCHITECTURE §4).
type Adapter interface {
	Name() string
	Discover(ctx context.Context, src *Source) (Result, error)
}

// Result is what an adapter found. Problems are non-fatal and always shown.
type Result struct {
	Assets   []asset.Asset
	Problems []asset.Problem
}

// Add appends assets and problems from another result.
func (r *Result) Add(o Result) {
	r.Assets = append(r.Assets, o.Assets...)
	r.Problems = append(r.Problems, o.Problems...)
}

// Problem appends a problem.
func (r *Result) Problem(agent, p, format string, args ...any) {
	r.Problems = append(r.Problems, asset.Problem{Agent: agent, Path: p, Message: fmt.Sprintf(format, args...)})
}

// Source is the filesystem an adapter scans.
type Source struct {
	FS      fs.FS       // rooted at the scope root; must refuse symlink escapes (os.Root.FS)
	Scope   asset.Scope // user or project
	RootDir string      // absolute OS path of the root, used to resolve absolute symlink targets; may be empty
	Ignore  *ignore.Matcher

	// MaxWalkEntries bounds the project walk; 0 means DefaultMaxWalkEntries.
	MaxWalkEntries int

	once    sync.Once
	entries []WalkEntry
	walkErr error

	mu      sync.Mutex
	escaped map[string]bool // directories skipped because they link outside the root
}

// EscapedDirs lists the symlinks pointing outside the root that hid a
// directory Children or Stat was asked about, sorted. Their
// contents were not scanned; discovery reports each one as a problem.
func (s *Source) EscapedDirs() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.escaped))
	for d := range s.escaped {
		out = append(out, d)
	}
	sort.Strings(out)
	return out
}

// Locate returns the symlink-free root-relative path of p's parent joined
// with p's own name, so that p itself is not followed (an Lstat of the
// result describes p) but any linked parent directory is. ok is false when
// a parent links outside the root.
func (s *Source) Locate(p string) (string, bool) {
	loc, escapedDir := s.locate(p)
	return loc, escapedDir == ""
}

// locate is Locate, returning the parent directory that escapes the root
// (empty when none does). A parent that is missing or not a directory
// leaves p unchanged: the Lstat that follows reports it missing.
func (s *Source) locate(p string) (loc, escapedDir string) {
	dir, name := path.Split(p)
	if dir == "" {
		return p, ""
	}
	dir = path.Clean(dir)
	resolved, k, escaped := s.Real(dir)
	switch {
	case escaped:
		return p, resolved // the link that escapes
	case k != Directory:
		return p, ""
	}
	return path.Join(resolved, name), ""
}

// WalkEntry is one path found by Source.Walk.
type WalkEntry struct {
	Path  string
	IsDir bool
}

// DefaultMaxWalkEntries bounds the project-scope walk (THREAT_MODEL T12).
const DefaultMaxWalkEntries = 2_000_000

// SkippedWalkDirs are directory names the nested-discovery walk does not
// enter. They never hold files an agent auto-loads from the project, and
// walking them would make lockfiles churn on every dependency install. Files
// inside them are still hashed when they are part of a pinned skill.
var SkippedWalkDirs = []string{".git", "node_modules"}

// ErrWalkLimit is returned when the project walk exceeds its entry limit.
var ErrWalkLimit = errors.New("project walk exceeds entry limit")

// Walk lists every path under a project root for nested discovery (nested
// AGENTS.md, CLAUDE.md, .claude/skills and so on). It is computed once and
// cached. User scope returns nothing: only fixed paths are read under ~.
func (s *Source) Walk() ([]WalkEntry, error) {
	if s.Scope != asset.ScopeProject {
		return nil, nil
	}
	s.once.Do(func() {
		limit := s.MaxWalkEntries
		if limit <= 0 {
			limit = DefaultMaxWalkEntries
		}
		s.walkErr = fs.WalkDir(s.FS, ".", func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				if p == "." {
					return err
				}
				return nil // unreadable subdirectory: skipped, the walk is best effort
			}
			if p == "." {
				return nil
			}
			if d.IsDir() && contains(SkippedWalkDirs, d.Name()) {
				return fs.SkipDir
			}
			if s.Ignored(p, d.IsDir()) {
				if d.IsDir() {
					return fs.SkipDir
				}
				return nil
			}
			if len(s.entries) >= limit {
				return fmt.Errorf("%w (%d); add patterns to %s", ErrWalkLimit, limit, ignore.FileName)
			}
			s.entries = append(s.entries, WalkEntry{Path: p, IsDir: d.IsDir()})
			return nil
		})
	})
	return s.entries, s.walkErr
}

// Ignored reports whether p is excluded by .lockwardignore.
func (s *Source) Ignored(p string, isDir bool) bool { return s.Ignore.Match(p, isDir) }

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// Nested returns walked file paths whose base name is one of names, at any
// depth including the root, sorted. User scope returns nothing.
func (s *Source) Nested(names ...string) ([]string, error) {
	entries, err := s.Walk()
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if !e.IsDir && contains(names, path.Base(e.Path)) {
			out = append(out, e.Path)
		}
	}
	sort.Strings(out)
	return out, nil
}

// NestedDirs returns walked directories whose path is rel or ends in "/"+rel
// (for example every ".claude/skills" at any depth), sorted.
func (s *Source) NestedDirs(rel string) ([]string, error) {
	entries, err := s.Walk()
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if e.IsDir && (e.Path == rel || strings.HasSuffix(e.Path, "/"+rel)) {
			out = append(out, e.Path)
		}
	}
	sort.Strings(out)
	return out, nil
}

// Kind classifies a path without following a final symlink.
type Kind int

// Path kinds.
const (
	Missing Kind = iota
	RegularFile
	Directory
	Symlink
	Other
)

// Stat classifies p using Lstat, so a symlink at p is reported as Symlink.
// Linked parent directories are followed within the root; a parent that
// links outside the root makes p Missing and is reported by EscapedDirs.
func (s *Source) Stat(p string) Kind {
	if s.Ignored(p, false) {
		return Missing
	}
	loc, escapedDir := s.locate(p)
	if escapedDir != "" {
		s.noteEscaped(escapedDir)
		return Missing
	}
	return lstatKind(s.FS, loc)
}

func (s *Source) noteEscaped(dir string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.escaped == nil {
		s.escaped = map[string]bool{}
	}
	s.escaped[dir] = true
}

// Resolve reports what p points to, following symlinks only within the root.
// escaped is true when p is a symlink whose target lies outside the root.
func (s *Source) Resolve(p string) (k Kind, escaped bool) {
	_, k, escaped = s.Real(p)
	return k, escaped
}

// maxLinkDepth bounds symlink chains (and loops).
const maxLinkDepth = 40

// Real resolves p to the root-relative path it finally refers to, following
// symlinks in every path component (not only the last), all within the
// root. Absolute targets are mapped through RootDir, because os.Root refuses
// every absolute link even when it points inside the root (common for
// dotfiles, including a linked parent directory). A component whose target
// lies outside the root, or a loop, makes the result escaped. The returned
// path contains no symlinks, so it can be opened through FS.
func (s *Source) Real(p string) (resolved string, k Kind, escaped bool) {
	if s.Ignored(p, false) {
		return p, Missing, false
	}
	rest := splitPath(p)
	done := ""
	hops := 0
	link := "" // the last symlink followed, reported when a relative target escapes
	for len(rest) > 0 {
		c := rest[0]
		rest = rest[1:]
		switch c {
		case "", ".":
			continue
		case "..":
			if done == "" {
				if link != "" {
					return link, Symlink, true
				}
				return p, Symlink, true
			}
			done = parentDir(done)
			continue
		}
		next := path.Join(done, c)
		switch kind := lstatKind(s.FS, next); kind {
		case Symlink:
			if hops++; hops > maxLinkDepth {
				return next, Symlink, true
			}
			target, err := hash.ReadLink(s.FS, next)
			if err != nil {
				return next, Symlink, true
			}
			link = next
			if filepath.IsAbs(target) || strings.HasPrefix(target, "/") {
				rel, ok := s.linkTarget(target)
				if !ok {
					return next, Symlink, true
				}
				done, rest = "", append(splitPath(rel), rest...)
				continue
			}
			rest = append(splitPath(filepath.ToSlash(target)), rest...)
		case Missing:
			return path.Join(append([]string{next}, rest...)...), Missing, false
		default:
			if len(rest) > 0 && kind != Directory {
				return path.Join(append([]string{next}, rest...)...), Missing, false
			}
			done = next
		}
	}
	if done == "" {
		// A link to the scan root itself would pin the whole root.
		return ".", Directory, hops > 0
	}
	if s.Ignored(done, false) {
		return done, Missing, false
	}
	return done, lstatKind(s.FS, done), false
}

func splitPath(p string) []string { return strings.Split(p, "/") }

func parentDir(p string) string {
	if d := path.Dir(p); d != "." {
		return d
	}
	return ""
}

// lstatKind classifies p without applying ignore patterns.
func lstatKind(fsys fs.FS, p string) Kind {
	info, err := fs.Lstat(fsys, p)
	if err != nil {
		return Missing
	}
	switch m := info.Mode(); {
	case m&fs.ModeSymlink != 0:
		return Symlink
	case m.IsDir():
		return Directory
	case m.IsRegular():
		return RegularFile
	default:
		return Other
	}
}

// linkTarget maps an absolute symlink target to a root-relative path,
// lexically. Relative targets are resolved component by component in Real.
func (s *Source) linkTarget(target string) (string, bool) {
	if s.RootDir == "" {
		return "", false
	}
	r, err := filepath.Rel(s.RootDir, filepath.FromSlash(target))
	if err != nil {
		return "", false
	}
	rel := path.Clean(filepath.ToSlash(r))
	if rel == ".." || strings.HasPrefix(rel, "../") || (rel != "." && !fs.ValidPath(rel)) {
		return "", false
	}
	return rel, true
}

// MaxConfigSize bounds config files read into memory for parsing. Larger
// files are pinned as raw bytes (streamed) with a problem reported.
const MaxConfigSize = 16 << 20

// ReadConfig reads a config file for parsing. ok is false when the file does
// not exist, or when a parent directory links outside the root (that link is
// recorded for EscapedDirs, as in Stat). A file that exists but cannot be read
// safely (the file itself is an escaping symlink, too large, not a regular
// file) yields ok=true, b=nil and a problem message.
func (s *Source) ReadConfig(p string) (b []byte, ok bool, problem string) {
	if _, escapedDir := s.locate(p); escapedDir != "" {
		s.noteEscaped(escapedDir)
		return nil, false, ""
	}
	resolved, k, escaped := s.Real(p)
	switch {
	case k == Missing:
		return nil, false, ""
	case escaped:
		return nil, true, "symlink points outside the scan root; not read"
	case k != RegularFile:
		return nil, true, "not a regular file; not read"
	}
	info, err := fs.Stat(s.FS, resolved)
	if err != nil {
		return nil, true, err.Error()
	}
	if info.Size() > MaxConfigSize {
		return nil, true, fmt.Sprintf("larger than %d bytes; pinned as raw bytes without parsing", MaxConfigSize)
	}
	f, err := s.FS.Open(resolved)
	if err != nil {
		return nil, true, err.Error()
	}
	defer f.Close()
	// Bounded read: the file may have grown since it was stat'ed.
	b, err = io.ReadAll(io.LimitReader(f, MaxConfigSize+1))
	if err != nil {
		return nil, true, err.Error()
	}
	if len(b) > MaxConfigSize {
		return nil, true, fmt.Sprintf("larger than %d bytes; pinned as raw bytes without parsing", MaxConfigSize)
	}
	return b, true, ""
}

// Children lists the entries of directory dir (not following a final
// symlink on dir itself unless it resolves inside the root), sorted.
func (s *Source) Children(dir string) []fs.DirEntry {
	resolved, k, escaped := s.Real(dir)
	if escaped {
		s.noteEscaped(resolved) // the link that escapes
	}
	if k != Directory || escaped {
		return nil
	}
	es, err := fs.ReadDir(s.FS, resolved)
	if err != nil {
		return nil
	}
	out := es[:0]
	for _, e := range es {
		if !s.Ignored(path.Join(dir, e.Name()), e.IsDir()) {
			out = append(out, e)
		}
	}
	return out
}

// Files lists regular files (and symlinks to them) under dir whose names end
// in one of suffixes, recursively if recursive is set. Paths are sorted.
func (s *Source) Files(dir string, recursive bool, suffixes ...string) []string {
	var out []string
	var walk func(d string)
	walk = func(d string) {
		for _, e := range s.Children(d) {
			p := path.Join(d, e.Name())
			k, _ := s.Resolve(p)
			if k == Directory && e.Type()&fs.ModeSymlink == 0 {
				if recursive {
					walk(p)
				}
				continue
			}
			if k == Directory {
				continue // directory symlinks are not descended
			}
			if len(suffixes) == 0 || hasAnySuffix(e.Name(), suffixes) {
				out = append(out, p)
			}
		}
	}
	walk(dir)
	sort.Strings(out)
	return out
}

func hasAnySuffix(name string, suffixes []string) bool {
	for _, suf := range suffixes {
		if strings.HasSuffix(name, suf) {
			return true
		}
	}
	return false
}
