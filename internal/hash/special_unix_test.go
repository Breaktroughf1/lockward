//go:build unix

package hash

import (
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// TestSpecialFilesRecordedNeverOpened: opening a FIFO would block forever, so
// special files must be recorded by kind and never read (THREAT_MODEL T8).
func TestSpecialFilesRecordedNeverOpened(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{"s/SKILL.md": "x"})
	if err := syscall.Mkfifo(filepath.Join(dir, "s", "pipe"), 0o644); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	fsys := rootFS(t, dir)
	tree, err := TreeDigest(fsys, "s", TreeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	var pipe Member
	for _, m := range tree.Members {
		if m.Path == "pipe" {
			pipe = m
		}
	}
	if pipe.Kind != KindSpecial || pipe.Special != "fifo" || pipe.Mode != "0000" {
		t.Errorf("pipe member = %+v", pipe)
	}
	if _, _, err := File(fsys, "s/pipe"); err == nil {
		t.Error("File on a FIFO must fail")
	}
	single, err := SingleFile(fsys, "s/pipe")
	if err != nil || single.Members[0].Kind != KindSpecial {
		t.Errorf("SingleFile(fifo) = %+v, %v", single, err)
	}
	_ = os.Remove(filepath.Join(dir, "s", "pipe"))
}

func TestSpecialName(t *testing.T) {
	for m, want := range map[fs.FileMode]string{
		fs.ModeNamedPipe: "fifo", fs.ModeSocket: "socket",
		fs.ModeDevice | fs.ModeCharDevice: "char-device", fs.ModeDevice: "device", fs.ModeIrregular: "irregular",
	} {
		if got := specialName(m); got != want {
			t.Errorf("specialName(%v) = %s, want %s", m, got, want)
		}
	}
}
