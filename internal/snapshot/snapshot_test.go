package snapshot

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Breaktroughf1/lockward/internal/hash"
)

func TestPutGet(t *testing.T) {
	s := &Store{Dir: t.TempDir()}
	b := []byte("Skill instructions.\n")
	ok, err := s.Put(b)
	if err != nil || !ok {
		t.Fatalf("Put = %v, %v", ok, err)
	}
	if ok, _ := s.Put(b); !ok {
		t.Error("second Put of existing content failed")
	}
	got, ok := s.Get(hash.Sum(b))
	if !ok || string(got) != string(b) {
		t.Errorf("Get = %q, %v", got, ok)
	}
	if _, ok := s.Get(hash.SumString("missing")); ok {
		t.Error("missing snapshot reported present")
	}
	if _, ok := s.Get("sha256:zz"); ok {
		t.Error("invalid digest accepted")
	}
}

func TestSkipsBinaryAndLarge(t *testing.T) {
	s := &Store{Dir: t.TempDir()}
	for _, b := range [][]byte{{0, 1, 2}, []byte(strings.Repeat("a", MaxSize+1)), {0xff, 0xfe}} {
		if ok, err := s.Put(b); ok || err != nil {
			t.Errorf("Put(%d bytes) = %v, %v; want skipped", len(b), ok, err)
		}
	}
}

func TestTamperedSnapshotRejected(t *testing.T) {
	s := &Store{Dir: t.TempDir()}
	b := []byte("original")
	if _, err := s.Put(b); err != nil {
		t.Fatal(err)
	}
	p, _ := s.path(hash.Sum(b))
	if err := os.WriteFile(p, []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Get(hash.Sum(b)); ok {
		t.Error("tampered snapshot accepted")
	}
}

func TestDefault(t *testing.T) {
	t.Setenv(EnvDir, filepath.Join(t.TempDir(), "c"))
	s, err := Default()
	if err != nil || !strings.HasSuffix(s.Dir, "c") {
		t.Errorf("Default = %+v, %v", s, err)
	}
	t.Setenv(EnvDir, "")
	if s, err := Default(); err == nil && !strings.Contains(s.Dir, "lockward") {
		t.Errorf("Default dir = %s", s.Dir)
	}
}
