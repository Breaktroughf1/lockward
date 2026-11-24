// Package snapshot keeps a local, content-addressed copy of small text files
// seen at lock or approve time, so diff can show sentence-level changes
// later. Snapshots never leave the machine and are verified against their
// digest on read, so a tampered cache cannot show a misleading diff.
package snapshot

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/Breaktroughf1/lockward/internal/hash"
	"github.com/Breaktroughf1/lockward/internal/lock"
	"github.com/Breaktroughf1/lockward/internal/prose"
)

// MaxSize is the largest file kept as a snapshot.
const MaxSize = 1 << 20

// EnvDir overrides the snapshot directory.
const EnvDir = "LOCKWARD_CACHE_DIR"

// Store is a snapshot directory.
type Store struct{ Dir string }

// Default returns the store under $LOCKWARD_CACHE_DIR or the user cache dir.
func Default() (*Store, error) {
	if d := os.Getenv(EnvDir); d != "" {
		return &Store{Dir: d}, nil
	}
	base, err := os.UserCacheDir()
	if err != nil {
		return nil, fmt.Errorf("snapshot cache: %w", err)
	}
	return &Store{Dir: filepath.Join(base, "lockward", "objects")}, nil
}

func (s *Store) path(digest string) (string, error) {
	hexd, ok := strings.CutPrefix(digest, hash.Prefix)
	if !ok || len(hexd) != 64 {
		return "", fmt.Errorf("snapshot: invalid digest %q", digest)
	}
	if _, err := hex.DecodeString(hexd); err != nil {
		return "", fmt.Errorf("snapshot: invalid digest %q", digest)
	}
	return filepath.Join(s.Dir, hexd[:2], hexd), nil
}

// Put stores b under its digest if it is text and at most MaxSize. It
// returns false (and no error) for content that is not kept.
func (s *Store) Put(b []byte) (bool, error) {
	if len(b) > MaxSize || !prose.IsText(b) {
		return false, nil
	}
	p, err := s.path(hash.Sum(b))
	if err != nil {
		return false, err
	}
	if _, err := os.Stat(p); err == nil {
		return true, nil
	}
	if err := lock.WriteAtomic(p, b, 0o600); err != nil {
		return false, fmt.Errorf("snapshot: %w", err)
	}
	return true, nil
}

// sensitiveNames match files that commonly hold credentials. Their content
// is never copied into the snapshot cache, even if it is text.
var sensitiveNames = regexp.MustCompile(`(?i)^(\.env(\..*)?|.*\.(pem|key|p12|pfx|jks|keystore|kdbx|asc|gpg)|id_(rsa|dsa|ecdsa|ed25519)(\.pub)?|\.netrc|\.npmrc|\.pypirc|\.git-credentials|credentials(\.json)?|.*secret.*|.*token.*)$`)

// Sensitive reports whether a file name looks like it holds credentials.
func Sensitive(name string) bool {
	return sensitiveNames.MatchString(filepath.Base(filepath.FromSlash(name)))
}

// Get returns the snapshot for digest, verified. ok is false if absent or if
// the stored bytes no longer match the digest.
func (s *Store) Get(digest string) ([]byte, bool) {
	p, err := s.path(digest)
	if err != nil {
		return nil, false
	}
	f, err := os.Open(p) //nolint:gosec // path is derived from a validated digest
	if err != nil {
		return nil, false
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, MaxSize+1))
	if err != nil || len(b) > MaxSize {
		return nil, false
	}
	sum := sha256.Sum256(b)
	if hash.Prefix+hex.EncodeToString(sum[:]) != digest {
		return nil, false
	}
	return b, true
}
