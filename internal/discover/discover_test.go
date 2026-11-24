package discover

import (
	"context"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Breaktroughf1/lockward/internal/asset"
	"github.com/Breaktroughf1/lockward/internal/hash"
	"github.com/Breaktroughf1/lockward/internal/lock"
)

var update = flag.Bool("update", false, "update golden files")

// plantedSecrets appear in fixtures and must never reach any output.
var plantedSecrets = []string{
	"ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8",
	"s3cr3t-value", "literal-key-value", "abc123secret", "plain-value",
}

var fixtures = []struct {
	dir   string
	scope asset.Scope
}{
	{"claude-code/project", asset.ScopeProject}, {"claude-code/user", asset.ScopeUser},
	{"cursor/project", asset.ScopeProject}, {"cursor/user", asset.ScopeUser},
	{"codex/project", asset.ScopeProject}, {"codex/user", asset.ScopeUser},
	{"gemini-cli/project", asset.ScopeProject}, {"gemini-cli/user", asset.ScopeUser},
	{"windsurf/project", asset.ScopeProject}, {"windsurf/user", asset.ScopeUser},
	{"copilot/project", asset.ScopeProject}, {"copilot/user", asset.ScopeUser},
	{"generic/project", asset.ScopeProject}, {"generic/user", asset.ScopeUser},
	{"malformed/project", asset.ScopeProject},
}

func fixtureRoot(dir string) string {
	return filepath.Join("..", "..", "testdata", "adapters", filepath.FromSlash(dir))
}

// render is the golden form: the lockfile followed by the problems.
func render(t *testing.T, res *Result) string {
	t.Helper()
	b, err := lock.Encode(lock.New(res.Scope, "lockward test", res.Entries))
	if err != nil {
		t.Fatal(err)
	}
	var sb strings.Builder
	sb.Write(b)
	sb.WriteString("--- problems ---\n")
	for _, p := range res.Problems {
		sb.WriteString(p.String() + "\n")
	}
	return sb.String()
}

func TestAdaptersGolden(t *testing.T) {
	for _, fx := range fixtures {
		t.Run(fx.dir, func(t *testing.T) {
			res, err := Run(context.Background(), Options{Root: fixtureRoot(fx.dir), Scope: fx.scope})
			if err != nil {
				t.Fatal(err)
			}
			defer res.Close()
			got := render(t, res)
			golden := filepath.Join("testdata", "golden", strings.ReplaceAll(fx.dir, "/", "-")+".txt")
			if *update {
				if err := os.MkdirAll(filepath.Dir(golden), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(golden, []byte(got), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(golden)
			if err != nil {
				t.Fatalf("%v (run go test ./internal/discover -update)", err)
			}
			if got != string(want) {
				t.Errorf("output differs from %s (run with -update and review the diff):\n%s", golden, got)
			}
		})
	}
}

// TestInvariant_NoSecretValuesInOutput is THREAT_MODEL §6 invariant 5.
func TestInvariant_NoSecretValuesInOutput(t *testing.T) {
	for _, fx := range fixtures {
		res, err := Run(context.Background(), Options{Root: fixtureRoot(fx.dir), Scope: fx.scope})
		if err != nil {
			t.Fatal(err)
		}
		out := render(t, res)
		_ = res.Close()
		for _, s := range plantedSecrets {
			if strings.Contains(out, s) {
				t.Errorf("%s: secret %q appears in output", fx.dir, s)
			}
		}
	}
}

// TestLockTwiceByteIdentical covers US-1.
func TestLockTwiceByteIdentical(t *testing.T) {
	for _, fx := range fixtures {
		a, err := Run(context.Background(), Options{Root: fixtureRoot(fx.dir), Scope: fx.scope})
		if err != nil {
			t.Fatal(err)
		}
		b, err := Run(context.Background(), Options{Root: fixtureRoot(fx.dir), Scope: fx.scope})
		if err != nil {
			t.Fatal(err)
		}
		if render(t, a) != render(t, b) {
			t.Errorf("%s: two runs differ", fx.dir)
		}
		_, _ = a.Close(), b.Close()
	}
}

func run(t *testing.T, root string, scope asset.Scope) *Result {
	t.Helper()
	res, err := Run(context.Background(), Options{Root: root, Scope: scope})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = res.Close() })
	return res
}

func byID(res *Result) map[string]asset.Entry {
	m := map[string]asset.Entry{}
	for _, e := range res.Entries {
		m[e.ID] = e
	}
	return m
}

func TestKeyBehaviours(t *testing.T) {
	cc := byID(run(t, fixtureRoot("claude-code/project"), asset.ScopeProject))
	for _, id := range []string{
		"skill:claude-code:pdf-tools", "skill:claude-code:nested-skill", "mcp:claude-code:github",
		"rules:claude-code:sub/CLAUDE.md", "settings:claude-code:.claude/settings.json",
		"hook:claude-code:.claude/settings.json#PreToolUse/0/0",
	} {
		if _, ok := cc[id]; !ok {
			t.Errorf("missing %s", id)
		}
	}
	if _, ok := cc["rules:claude-code:node_modules/dep/CLAUDE.md"]; ok {
		t.Error("node_modules must not be walked for nested rules")
	}
	hook := cc["hook:claude-code:.claude/settings.json#PreToolUse/0/0"]
	if len(hook.ReferencedFiles) != 1 || hook.ReferencedFiles[0].Path != ".claude/hooks/guard.sh" {
		t.Errorf("hook referenced files = %+v", hook.ReferencedFiles)
	}
	gh := cc["mcp:claude-code:github"]
	if gh.Server.Package == nil || gh.Server.Package.Version != "2.1.0" || gh.Source.String() != "npm:@modelcontextprotocol/server-github" {
		t.Errorf("github server = %+v source %+v", gh.Server, gh.Source)
	}
	skill := cc["skill:claude-code:pdf-tools"]
	var hasHidden, hasBin bool
	for _, f := range skill.Files {
		hasHidden = hasHidden || f.Path == ".hidden-config"
		hasBin = hasBin || f.Path == "assets/logo.bin"
	}
	if !hasHidden || !hasBin {
		t.Errorf("skill files must include dotfiles and binaries: %+v", skill.Files)
	}
	user := byID(run(t, fixtureRoot("claude-code/user"), asset.ScopeUser))
	if _, ok := user["skill:claude-code:.trash"]; ok {
		t.Error(".trash must not be pinned")
	}
	if _, ok := user["mcp:claude-code:proj@local/db"]; !ok {
		t.Errorf("local-scope MCP server missing: %v", keys(user))
	}

	mal := run(t, fixtureRoot("malformed/project"), asset.ScopeProject)
	m := byID(mal)
	if _, ok := m["mcp:cursor:.cursor/mcp.json"]; !ok {
		t.Error("unparseable config must be pinned as raw bytes")
	}
	if _, ok := m[IgnoreID]; !ok || mal.Ignore == nil || mal.Ignored != 2 {
		t.Errorf("ignore handling: entry=%v ignored=%d", ok, mal.Ignored)
	}
	if len(mal.Problems) == 0 {
		t.Error("malformed configs must be reported as problems")
	}
}

func keys(m map[string]asset.Entry) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

func write(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for name, content := range files {
		p := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func symlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
}

// TestSymlinkedSkills covers skills that are symlinks, inside and outside
// the scan root (THREAT_MODEL §6 invariant 4).
func TestSymlinkedSkills(t *testing.T) {
	outer := t.TempDir()
	write(t, outer, map[string]string{"elsewhere/s/SKILL.md": "outside", "root/real/s2/SKILL.md": "inside"})
	root := filepath.Join(outer, "root")
	if err := os.MkdirAll(filepath.Join(root, ".claude", "skills"), 0o755); err != nil {
		t.Fatal(err)
	}
	symlink(t, "../../../elsewhere/s", filepath.Join(root, ".claude", "skills", "outside"))
	symlink(t, "../../real/s2", filepath.Join(root, ".claude", "skills", "inside"))
	symlink(t, filepath.Join(root, "real", "s2"), filepath.Join(root, ".claude", "skills", "absolute"))

	res := run(t, root, asset.ScopeProject)
	m := byID(res)
	out := m["skill:claude-code:outside"]
	if out.Symlink == "" || len(out.Files) != 0 || out.Digest == "" {
		t.Errorf("outside symlink entry = %+v", out)
	}
	if !strings.Contains(render(t, res), "outside the scan root") {
		t.Error("escaping symlink must be reported as a problem")
	}
	in := m["skill:claude-code:inside"]
	if len(in.Files) != 1 || in.Files[0].Path != "SKILL.md" {
		t.Errorf("inside symlink must pin target contents: %+v", in)
	}
	abs := m["skill:claude-code:absolute"]
	if len(abs.Files) != 1 {
		t.Errorf("absolute in-root symlink must pin target contents: %+v", abs)
	}
	if in.Digest == abs.Digest {
		t.Error("different symlink targets must give different digests")
	}
	for _, e := range res.Entries {
		for _, f := range e.Files {
			if strings.Contains(f.Path, "outside") || f.Digest == hash.SumString("outside") {
				t.Errorf("content outside the root was read: %+v", f)
			}
		}
	}
}

func TestSymlinkedRulesFile(t *testing.T) {
	outer := t.TempDir()
	write(t, outer, map[string]string{"secret.md": "outside", "root/docs/real.md": "inside"})
	root := filepath.Join(outer, "root")
	symlink(t, "docs/real.md", filepath.Join(root, "CLAUDE.md"))
	symlink(t, "../secret.md", filepath.Join(root, "AGENTS.md"))
	m := byID(run(t, root, asset.ScopeProject))
	if e := m["rules:claude-code:CLAUDE.md"]; e.Symlink != "docs/real.md" || e.Digest != hash.SumString("inside") {
		t.Errorf("in-root symlinked rules = %+v", e)
	}
	if e := m["rules:generic:AGENTS.md"]; e.Symlink != "../secret.md" || e.Digest == hash.SumString("outside") {
		t.Errorf("escaping symlinked rules = %+v", e)
	}
}

func TestErrors(t *testing.T) {
	if _, err := Run(context.Background(), Options{Root: filepath.Join(t.TempDir(), "missing"), Scope: asset.ScopeProject}); !errors.Is(err, ErrConfig) {
		t.Errorf("missing root err = %v", err)
	}
	dir := t.TempDir()
	write(t, dir, map[string]string{".lockwardignore": "[unterminated\n"})
	if _, err := Run(context.Background(), Options{Root: dir, Scope: asset.ScopeProject}); !errors.Is(err, ErrConfig) {
		t.Errorf("bad ignore err = %v", err)
	}
	dir2 := t.TempDir()
	write(t, dir2, map[string]string{".claude/skills/s/a": "1", ".claude/skills/s/b": "2"})
	if _, err := Run(context.Background(), Options{Root: dir2, Scope: asset.ScopeProject, MaxMembers: 1}); !errors.Is(err, hash.ErrTooManyMembers) {
		t.Errorf("member limit err = %v", err)
	}
	if _, err := Run(context.Background(), Options{Root: dir2, Scope: asset.ScopeProject, MaxWalkEntries: 1}); err == nil {
		t.Error("walk limit not enforced")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Run(ctx, Options{Root: dir2, Scope: asset.ScopeProject}); !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled ctx err = %v", err)
	}
	if runtime.GOOS != "windows" {
		dir3 := t.TempDir()
		write(t, dir3, map[string]string{".claude/skills/s/ok": "1"})
		if err := os.WriteFile(filepath.Join(dir3, ".claude", "skills", "s", "bad\nname"), nil, 0o644); err == nil {
			if _, err := Run(context.Background(), Options{Root: dir3, Scope: asset.ScopeProject}); !errors.Is(err, hash.ErrUnsafePath) {
				t.Errorf("unsafe name err = %v", err)
			}
		}
	}
}

func TestMergeAndNames(t *testing.T) {
	in := []asset.Asset{
		{Surface: asset.SurfaceRules, Agent: "a", Name: "X", Path: "p1", LoadedBy: []string{"a"}},
		{Surface: asset.SurfaceRules, Agent: "b", Name: "Y", Path: "p1", LoadedBy: []string{"b"}},
		{Surface: asset.SurfaceSkill, Agent: "a", Name: "dup", Path: "one/dup"},
		{Surface: asset.SurfaceSkill, Agent: "a", Name: "dup", Path: "two/dup"},
	}
	out := merge(in)
	if len(out) != 3 || strings.Join(out[0].LoadedBy, ",") != "a,b" {
		t.Errorf("merge = %+v", out)
	}
	assignNames(out)
	if out[1].Name != "one/dup" || out[2].Name != "two/dup" {
		t.Errorf("collision names = %q, %q", out[1].Name, out[2].Name)
	}
}

// A rules file reached through a linked parent directory is pinned by
// content; a dangling rules link is a problem, not a fatal error.
func TestRulesThroughLinkedParentAndDangling(t *testing.T) {
	root := t.TempDir()
	write(t, root, map[string]string{"kit/claude.md": "kit rules", ".claude/rules/.keep": ""})
	symlink(t, filepath.Join(root, "kit"), filepath.Join(root, ".claude", "kitlink"))
	symlink(t, filepath.Join(root, ".claude", "kitlink", "claude.md"), filepath.Join(root, ".claude", "rules", "kit.md"))
	symlink(t, "nowhere.md", filepath.Join(root, ".claude", "rules", "gone.md"))
	res := run(t, root, asset.ScopeProject)
	m := map[string]asset.Entry{}
	for _, e := range res.Entries {
		m[e.Path] = e
	}
	if e := m[".claude/rules/kit.md"]; e.Digest != hash.SumString("kit rules") {
		t.Errorf("linked-parent rules = %+v", e)
	}
	if e, ok := m[".claude/rules/gone.md"]; !ok || e.Symlink != "nowhere.md" {
		t.Errorf("dangling rules = %+v", e)
	}
	found := false
	for _, p := range res.Problems {
		found = found || (p.Path == ".claude/rules/gone.md" && strings.Contains(p.Message, "dangling"))
	}
	if !found {
		t.Errorf("dangling rules link not reported: %+v", res.Problems)
	}
}

// A dotfiles-style home where ~/.claude is an absolute symlink into the home
// (GNU Stow, chezmoi symlink mode) must be discovered in full. v0.2.1 found
// nothing and said nothing. A linked directory outside the root is reported.
func TestLinkedAgentDirectory(t *testing.T) {
	outer := t.TempDir()
	home := filepath.Join(outer, "home")
	write(t, outer, map[string]string{
		"home/dotfiles/claude/skills/s/SKILL.md": "# s\n",
		"home/dotfiles/claude/CLAUDE.md":         "rules\n",
		"home/dotfiles/claude/settings.json":     `{"permissions":{"allow":["Bash(*)"]}}`,
		"elsewhere/skills/x/SKILL.md":            "# x\n",
	})
	symlink(t, filepath.Join(home, "dotfiles", "claude"), filepath.Join(home, ".claude"))
	symlink(t, filepath.Join(outer, "elsewhere", "skills"), filepath.Join(home, ".agents"))
	res := run(t, home, asset.ScopeUser)
	m := byID(res)
	if e := m["skill:claude-code:s"]; e.Path != ".claude/skills/s" || len(e.Files) != 1 {
		t.Errorf("skill under linked ~/.claude = %+v", e)
	}
	if e := m["rules:claude-code:.claude/CLAUDE.md"]; e.Digest != hash.SumString("rules\n") {
		t.Errorf("rules under linked ~/.claude = %+v (entries %v)", e, keys(m))
	}
	if _, ok := m["settings:claude-code:.claude/settings.json"]; !ok {
		t.Errorf("settings under linked ~/.claude missing (entries %v)", keys(m))
	}
	found := false
	for _, p := range res.Problems {
		found = found || (p.Path == ".agents" && strings.Contains(p.Message, "outside the scan root"))
	}
	n := 0
	for _, p := range res.Problems {
		if strings.HasPrefix(p.Path, ".agents") {
			n++
		}
	}
	if !found || n != 1 {
		t.Errorf("escaping linked directory must be reported once: %+v", res.Problems)
	}
}
