// Package identity finds the approver name written to approved.by (SPEC §4)
// by reading git configuration files. It never runs git.
package identity

import (
	"bufio"
	"bytes"
	"os"
	"path/filepath"
	"strings"
)

// EnvApprover overrides the approver identity.
const EnvApprover = "LOCKWARD_APPROVER"

// Approver returns, in order: $LOCKWARD_APPROVER, user.email from the
// repository's git config, from the global git configs, or "" if none.
func Approver(repoRoot, home string) string {
	if v := strings.TrimSpace(os.Getenv(EnvApprover)); v != "" {
		return v
	}
	var files []string
	if repoRoot != "" {
		files = append(files, repoConfigs(repoRoot)...)
	}
	if home != "" {
		files = append(files, filepath.Join(home, ".gitconfig"))
	}
	if x := os.Getenv("XDG_CONFIG_HOME"); x != "" {
		files = append(files, filepath.Join(x, "git", "config"))
	} else if home != "" {
		files = append(files, filepath.Join(home, ".config", "git", "config"))
	}
	for _, f := range files {
		if e := userEmail(f); e != "" {
			return e
		}
	}
	return ""
}

// repoConfigs returns the config file(s) of the repository at root,
// following a ".git" file (worktrees and submodules) to its gitdir.
func repoConfigs(root string) []string {
	gitPath := filepath.Join(root, ".git")
	info, err := os.Stat(gitPath)
	if err != nil {
		return nil
	}
	if info.IsDir() {
		return []string{filepath.Join(gitPath, "config")}
	}
	b, err := os.ReadFile(gitPath) //nolint:gosec // .git file of the chosen repository
	if err != nil {
		return nil
	}
	dir, ok := strings.CutPrefix(strings.TrimSpace(string(b)), "gitdir:")
	if !ok {
		return nil
	}
	dir = strings.TrimSpace(dir)
	if !filepath.IsAbs(dir) {
		dir = filepath.Join(root, dir)
	}
	out := []string{filepath.Join(dir, "config.worktree")}
	if c, err := os.ReadFile(filepath.Join(dir, "commondir")); err == nil { //nolint:gosec // inside the gitdir
		common := strings.TrimSpace(string(c))
		if !filepath.IsAbs(common) {
			common = filepath.Join(dir, common)
		}
		out = append(out, filepath.Join(common, "config"))
	}
	return append(out, filepath.Join(dir, "config"))
}

// userEmail extracts user.email from a git config file (INI subset).
func userEmail(path string) string {
	b, err := os.ReadFile(path) //nolint:gosec // git config file
	if err != nil || len(b) > 1<<20 {
		return ""
	}
	inUser := false
	email := ""
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		if strings.HasPrefix(line, "[") {
			section := strings.ToLower(strings.TrimSpace(strings.Trim(line, "[]")))
			inUser = section == "user"
			continue
		}
		if !inUser {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if ok && strings.EqualFold(strings.TrimSpace(k), "email") {
			email = strings.Trim(strings.TrimSpace(v), `"`)
		}
	}
	return email
}
