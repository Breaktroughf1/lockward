// Package lock models the lockward.lock file (SPEC §3–4), encodes and decodes
// it canonically, and compares live state against it (SPEC §6).
package lock

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/Breaktroughf1/lockward/internal/asset"
	"github.com/Breaktroughf1/lockward/internal/hash"
)

// Version is the lockfile_version this build reads and writes (SPEC §7).
const Version = 1

// HashAlgorithm is the only supported digest algorithm.
const HashAlgorithm = "sha256"

// ProjectFileName is the project lockfile name (SPEC §1).
const ProjectFileName = "lockward.lock"

// MaxSize bounds how much of a lockfile is read (THREAT_MODEL T8).
const MaxSize = 256 << 20

// File is a decoded lockfile.
type File struct {
	LockfileVersion int           `json:"lockfile_version"`
	GeneratedBy     string        `json:"generated_by"`
	Scope           asset.Scope   `json:"scope"`
	HashAlgorithm   string        `json:"hash_algorithm"`
	Entries         []asset.Entry `json:"entries"`
}

// New returns a lockfile for scope with entries sorted by id.
func New(scope asset.Scope, generatedBy string, entries []asset.Entry) *File {
	f := &File{
		LockfileVersion: Version,
		GeneratedBy:     generatedBy,
		Scope:           scope,
		HashAlgorithm:   HashAlgorithm,
		Entries:         append([]asset.Entry{}, entries...),
	}
	SortEntries(f.Entries)
	return f
}

// SortEntries sorts entries bytewise by id (SPEC §2).
func SortEntries(e []asset.Entry) {
	sort.Slice(e, func(i, j int) bool { return e[i].ID < e[j].ID })
}

// ErrUnsupportedVersion is returned for lockfiles from a newer major version.
var ErrUnsupportedVersion = errors.New("unsupported lockfile version")

// Encode validates f and returns its canonical encoding (SPEC §2).
func Encode(f *File) ([]byte, error) {
	if f.Entries == nil {
		f.Entries = []asset.Entry{}
	}
	if err := f.Validate(); err != nil {
		return nil, err
	}
	return hash.CanonicalJSON(f)
}

// Decode parses and validates a lockfile. Unknown fields are ignored and an
// unknown lockfile_version is a hard failure (SPEC §7, THREAT_MODEL §6.6).
func Decode(b []byte) (*File, error) {
	var head struct {
		LockfileVersion *int `json:"lockfile_version"`
	}
	if err := json.Unmarshal(b, &head); err != nil {
		return nil, fmt.Errorf("parse lockfile: %w", err)
	}
	if head.LockfileVersion == nil {
		return nil, errors.New("parse lockfile: missing lockfile_version")
	}
	if *head.LockfileVersion != Version {
		return nil, fmt.Errorf("%w %d (this lockward reads version %d); upgrade lockward, or delete the file and run 'lockward lock' to regenerate it",
			ErrUnsupportedVersion, *head.LockfileVersion, Version)
	}
	var f File
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("parse lockfile: %w", err)
	}
	if err := f.Validate(); err != nil {
		return nil, err
	}
	return &f, nil
}

var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// Validate checks structural invariants of the lockfile.
func (f *File) Validate() error {
	if f.LockfileVersion != Version {
		return fmt.Errorf("%w %d", ErrUnsupportedVersion, f.LockfileVersion)
	}
	if f.HashAlgorithm != HashAlgorithm {
		return fmt.Errorf("lockfile: unsupported hash_algorithm %q (want %q)", f.HashAlgorithm, HashAlgorithm)
	}
	if f.Scope != asset.ScopeProject && f.Scope != asset.ScopeUser {
		return fmt.Errorf("lockfile: invalid scope %q", f.Scope)
	}
	seen := make(map[string]bool, len(f.Entries))
	for i := range f.Entries {
		e := &f.Entries[i]
		if err := validateEntry(e); err != nil {
			return fmt.Errorf("lockfile entry %q: %w", e.ID, err)
		}
		if seen[e.ID] {
			return fmt.Errorf("lockfile: duplicate entry id %q", e.ID)
		}
		seen[e.ID] = true
	}
	return nil
}

func validateEntry(e *asset.Entry) error {
	s, agent, _, err := asset.ParseID(e.ID)
	if err != nil {
		return err
	}
	if s != e.Surface {
		return fmt.Errorf("surface %q does not match id", e.Surface)
	}
	if agent != e.Agent {
		return fmt.Errorf("agent %q does not match id", e.Agent)
	}
	if !digestPattern.MatchString(e.Digest) {
		return fmt.Errorf("invalid digest %q", e.Digest)
	}
	if e.ToolsFingerprint != "" && !digestPattern.MatchString(e.ToolsFingerprint) {
		return fmt.Errorf("invalid tools_fingerprint %q", e.ToolsFingerprint)
	}
	file, _, _ := strings.Cut(e.Path, "#")
	if err := CheckRelPath(file); err != nil {
		return fmt.Errorf("path: %w", err)
	}
	for _, fl := range e.Files {
		if err := CheckRelPath(fl.Path); err != nil {
			return fmt.Errorf("file path: %w", err)
		}
		if fl.Digest != "" && !digestPattern.MatchString(fl.Digest) {
			return fmt.Errorf("file %q: invalid digest", fl.Path)
		}
	}
	for _, r := range e.ReferencedFiles {
		if err := CheckRelPath(r.Path); err != nil {
			return fmt.Errorf("referenced file: %w", err)
		}
		if !digestPattern.MatchString(r.Digest) {
			return fmt.Errorf("referenced file %q: invalid digest", r.Path)
		}
	}
	return nil
}

// CheckRelPath enforces SPEC §2 paths: relative, "/" separated, no ".."
// segments, no empty or "." segments, no control characters.
func CheckRelPath(p string) error {
	if p == "" {
		return errors.New("empty path")
	}
	if err := hash.CheckPath(p); err != nil {
		return err
	}
	if strings.HasPrefix(p, "/") || strings.Contains(p, "\\") || (len(p) > 1 && p[1] == ':') {
		return fmt.Errorf("%q is not a relative slash-separated path", p)
	}
	for seg := range strings.SplitSeq(p, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return fmt.Errorf("%q has an empty, '.' or '..' segment", p)
		}
	}
	return nil
}

// Read loads and decodes the lockfile at path. A missing file returns an
// error satisfying errors.Is(err, fs.ErrNotExist).
func Read(path string) (*File, error) {
	f, err := os.Open(path) //nolint:gosec // path is the lockfile chosen by the user
	if err != nil {
		return nil, fmt.Errorf("read lockfile: %w", err)
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, MaxSize+1))
	if err != nil {
		return nil, fmt.Errorf("read lockfile %s: %w", path, err)
	}
	if len(b) > MaxSize {
		return nil, fmt.Errorf("read lockfile %s: larger than %d bytes", path, MaxSize)
	}
	lf, err := Decode(b)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return lf, nil
}

// Write encodes f and atomically replaces path (write to a temporary file in
// the same directory, then rename).
func Write(path string, f *File) error {
	b, err := Encode(f)
	if err != nil {
		return err
	}
	return WriteAtomic(path, b, 0o644)
}

// WriteAtomic writes b to path via a temporary file and rename.
func WriteAtomic(path string, b []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }()
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := os.Rename(name, path); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}
