package hash

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"
)

// Kind identifies the type of a tree member.
type Kind string

// Tree member kinds. Their single-letter codes appear in tree-digest lines.
const (
	KindFile    Kind = "f"
	KindSymlink Kind = "l"
	KindSpecial Kind = "s"
)

// Member is one entry of a hashed tree.
type Member struct {
	Path    string // relative to the tree root, "/" separated
	Kind    Kind
	Mode    string // "0644" or "0755" for files, "0777" for symlinks, "0000" for special files
	Digest  string // file content digest; empty for symlinks and special files
	Size    int64
	Target  string // symlink target, recorded verbatim and never followed
	Special string // for special files: "fifo", "socket", "device", "char-device" or "irregular"
}

// Tree is the result of hashing a directory.
type Tree struct {
	Digest  string
	Members []Member // sorted bytewise by Path
	Ignored int      // members skipped by the ignore function
}

// TreeOptions configures TreeDigest.
type TreeOptions struct {
	// Ignore reports whether a path (relative to fsys root, not to dir) is
	// excluded by a user-configured .lockwardignore. Nil ignores nothing.
	Ignore func(p string, isDir bool) bool
	// MaxMembers bounds the number of members; 0 means DefaultMaxMembers.
	// Exceeding it is an error, never a silent truncation (THREAT_MODEL T12).
	MaxMembers int
}

// DefaultMaxMembers is the default member limit per tree.
const DefaultMaxMembers = 200_000

// ErrTooManyMembers is returned when a tree exceeds TreeOptions.MaxMembers.
var ErrTooManyMembers = errors.New("tree exceeds member limit")

// TreeDigest hashes every entry under dir in fsys per SPEC §5.2. Symlinks are
// recorded with their target and never followed. Special files are recorded
// and never opened. Directories contribute only through their contents.
func TreeDigest(fsys fs.FS, dir string, opts TreeOptions) (Tree, error) {
	limit := opts.MaxMembers
	if limit <= 0 {
		limit = DefaultMaxMembers
	}
	var t Tree
	err := fs.WalkDir(fsys, dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return fmt.Errorf("walk %s: %w", p, err)
		}
		if p == dir {
			if !d.IsDir() {
				return fmt.Errorf("tree %s: not a directory", dir)
			}
			return nil
		}
		rel := strings.TrimPrefix(p, dir+"/")
		if dir == "." {
			rel = p
		}
		if err := CheckPath(rel); err != nil {
			return fmt.Errorf("tree %s: %w", dir, err)
		}
		if opts.Ignore != nil && opts.Ignore(p, d.IsDir()) {
			t.Ignored++
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			return nil
		}
		if len(t.Members) >= limit {
			return fmt.Errorf("%w: %s has more than %d entries", ErrTooManyMembers, dir, limit)
		}
		m, err := member(fsys, p, rel, d)
		if err != nil {
			return err
		}
		t.Members = append(t.Members, m)
		return nil
	})
	if err != nil {
		return Tree{}, err
	}
	sort.Slice(t.Members, func(i, j int) bool { return t.Members[i].Path < t.Members[j].Path })
	t.Digest = MembersDigest(t.Members)
	return t, nil
}

func member(fsys fs.FS, p, rel string, d fs.DirEntry) (Member, error) {
	switch typ := d.Type(); {
	case typ&fs.ModeSymlink != 0:
		target, err := fs.ReadLink(fsys, p)
		if err != nil {
			return Member{}, fmt.Errorf("readlink %s: %w", p, err)
		}
		if err := CheckPath(target); err != nil {
			return Member{}, fmt.Errorf("symlink %s: %w", p, err)
		}
		return Member{Path: rel, Kind: KindSymlink, Mode: "0777", Target: target}, nil
	case typ.IsRegular():
		info, err := d.Info()
		if err != nil {
			return Member{}, fmt.Errorf("stat %s: %w", p, err)
		}
		digest, size, err := File(fsys, p)
		if err != nil {
			return Member{}, err
		}
		return Member{Path: rel, Kind: KindFile, Mode: NormalizeMode(info.Mode()), Digest: digest, Size: size}, nil
	default:
		return Member{Path: rel, Kind: KindSpecial, Mode: "0000", Special: specialName(typ)}, nil
	}
}

// NormalizeMode maps permission bits to "0755" if any execute bit is set and
// "0644" otherwise, so digests agree across platforms and umasks (SPEC §5.2).
func NormalizeMode(m fs.FileMode) string {
	if m.Perm()&0o111 != 0 {
		return "0755"
	}
	return "0644"
}

func specialName(t fs.FileMode) string {
	switch {
	case t&fs.ModeNamedPipe != 0:
		return "fifo"
	case t&fs.ModeSocket != 0:
		return "socket"
	case t&fs.ModeCharDevice != 0:
		return "char-device"
	case t&fs.ModeDevice != 0:
		return "device"
	default:
		return "irregular"
	}
}

// Line returns the SPEC §5.2 tree-digest line for m. The fourth field always
// has a fixed length ("sha256:" + 64 hex digits), so lines cannot be forged by
// crafted names or symlink targets: for symlinks it is the digest of the
// target string, for special files the digest of the special kind name.
func (m Member) Line() string {
	var last string
	switch m.Kind {
	case KindSymlink:
		last = SumString(m.Target)
	case KindSpecial:
		last = SumString(m.Special)
	default:
		last = m.Digest
	}
	return string(m.Kind) + " " + m.Mode + " " + m.Path + " " + last + "\n"
}

// MembersDigest computes the tree digest over members, which must already be
// sorted bytewise by Path.
func MembersDigest(members []Member) string {
	h := sha256.New()
	for _, m := range members {
		_, _ = h.Write([]byte(m.Line()))
	}
	return Prefix + hex.EncodeToString(h.Sum(nil))
}

// SingleFile hashes a lone file as a one-member tree, used for an item in a
// skills directory that is a file rather than a directory.
func SingleFile(fsys fs.FS, p string) (Tree, error) {
	info, err := fs.Lstat(fsys, p)
	if err != nil {
		return Tree{}, fmt.Errorf("stat %s: %w", p, err)
	}
	name := path.Base(p)
	if err := CheckPath(name); err != nil {
		return Tree{}, err
	}
	m, err := member(fsys, p, name, fs.FileInfoToDirEntry(info))
	if err != nil {
		return Tree{}, err
	}
	members := []Member{m}
	return Tree{Digest: MembersDigest(members), Members: members}, nil
}

// SymlinkedTreeDigest combines a directory symlink's target with the digest
// of the tree it resolves to, so retargeting a symlink is detected even when
// both trees are identical (SPEC §5.2.1). treeDigest is empty when the target
// lies outside the scan root and its contents are not pinned.
func SymlinkedTreeDigest(target, treeDigest string) string {
	s := "symlink " + SumString(target) + "\n"
	if treeDigest != "" {
		s += "tree " + treeDigest + "\n"
	}
	return SumString(s)
}
