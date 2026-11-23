package hash

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"strings"
	"unicode/utf8"
)

// Prefix is the algorithm prefix of every digest string (SPEC §5).
const Prefix = "sha256:"

// Sum returns the digest string of b.
func Sum(b []byte) string {
	s := sha256.Sum256(b)
	return Prefix + hex.EncodeToString(s[:])
}

// SumString returns the digest string of s.
func SumString(s string) string { return Sum([]byte(s)) }

// Reader streams r into SHA-256 and returns the digest and byte count. The
// whole input is consumed; nothing is truncated or sampled (SPEC §5.1).
func Reader(r io.Reader) (digest string, size int64, err error) {
	h := sha256.New()
	n, err := io.Copy(h, r)
	if err != nil {
		return "", n, fmt.Errorf("hash: read: %w", err)
	}
	return Prefix + hex.EncodeToString(h.Sum(nil)), n, nil
}

// File returns the SPEC §5.1 digest and size of a regular file in fsys.
// It refuses anything that is not a regular file once opened, so a FIFO or
// device swapped in is never read.
func File(fsys fs.FS, name string) (digest string, size int64, err error) {
	// Stat before opening: opening a FIFO blocks until a writer appears, so a
	// special file must be refused before Open is ever called.
	pre, err := fs.Stat(fsys, name)
	if err != nil {
		return "", 0, fmt.Errorf("hash %s: %w", name, err)
	}
	if !pre.Mode().IsRegular() {
		return "", 0, fmt.Errorf("hash %s: not a regular file (%s)", name, pre.Mode().Type())
	}
	f, err := fsys.Open(name)
	if err != nil {
		return "", 0, fmt.Errorf("hash %s: %w", name, err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return "", 0, fmt.Errorf("hash %s: %w", name, err)
	}
	if !info.Mode().IsRegular() {
		return "", 0, fmt.Errorf("hash %s: not a regular file (%s)", name, info.Mode().Type())
	}
	d, n, err := Reader(f)
	if err != nil {
		return "", 0, fmt.Errorf("hash %s: %w", name, err)
	}
	return d, n, nil
}

// Object returns the SPEC §5.3 digest: SHA-256 over the canonical JSON of v.
func Object(v any) (string, error) {
	b, err := CanonicalJSON(v)
	if err != nil {
		return "", err
	}
	return Sum(b), nil
}

// ErrUnsafePath reports a path that cannot be represented safely in a
// lockfile or tree-digest line.
var ErrUnsafePath = errors.New("unsafe path")

// CheckPath rejects paths that are not valid UTF-8 or contain control
// characters. Such names could forge tree-digest lines or be silently altered
// by JSON encoding, so they fail loudly instead (THREAT_MODEL T8).
func CheckPath(p string) error {
	if !utf8.ValidString(p) {
		return fmt.Errorf("%w: %q is not valid UTF-8", ErrUnsafePath, p)
	}
	if strings.ContainsFunc(p, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return fmt.Errorf("%w: %q contains a control character", ErrUnsafePath, p)
	}
	return nil
}
