package identity

import (
	"os"
	"path/filepath"
	"testing"
)

func write(t *testing.T, p, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestApprover(t *testing.T) {
	t.Setenv(EnvApprover, "")
	t.Setenv("XDG_CONFIG_HOME", "")
	home := t.TempDir()
	repo := t.TempDir()
	if got := Approver(repo, home); got != "" {
		t.Errorf("no config = %q", got)
	}
	write(t, filepath.Join(home, ".gitconfig"), "[core]\n\teditor = vim\n[user]\n\tname = Dev\n\temail = global@example.com\n")
	if got := Approver(repo, home); got != "global@example.com" {
		t.Errorf("global = %q", got)
	}
	write(t, filepath.Join(repo, ".git", "config"), "# comment\n[User]\n  email = \"repo@example.com\"\n")
	if got := Approver(repo, home); got != "repo@example.com" {
		t.Errorf("repo = %q", got)
	}
	t.Setenv(EnvApprover, "ci-bot")
	if got := Approver(repo, home); got != "ci-bot" {
		t.Errorf("env = %q", got)
	}
}

func TestWorktreeAndXDG(t *testing.T) {
	t.Setenv(EnvApprover, "")
	base := t.TempDir()
	main := filepath.Join(base, "main")
	wt := filepath.Join(base, "wt")
	write(t, filepath.Join(main, ".git", "config"), "[user]\nemail = main@example.com\n")
	write(t, filepath.Join(main, ".git", "worktrees", "wt", "commondir"), "../..\n")
	write(t, filepath.Join(wt, ".git"), "gitdir: ../main/.git/worktrees/wt\n")
	t.Setenv("XDG_CONFIG_HOME", "")
	if got := Approver(wt, ""); got != "main@example.com" {
		t.Errorf("worktree = %q", got)
	}
	xdg := t.TempDir()
	write(t, filepath.Join(xdg, "git", "config"), "[user]\nemail = xdg@example.com\n")
	t.Setenv("XDG_CONFIG_HOME", xdg)
	if got := Approver(t.TempDir(), ""); got != "xdg@example.com" {
		t.Errorf("xdg = %q", got)
	}
	write(t, filepath.Join(base, "bad", ".git"), "not a gitdir line")
	if got := Approver(filepath.Join(base, "bad"), ""); got != "xdg@example.com" {
		t.Errorf("bad .git file = %q", got)
	}
}
