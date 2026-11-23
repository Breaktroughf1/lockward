package adapter

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Breaktroughf1/lockward/internal/asset"
)

func TestParseJSONC(t *testing.T) {
	in := "\xef\xbb\xbf{\n  // line comment\n  \"a\": \"keep // this\", /* block */\n  \"b\": [1, 2,],\n  \"c\": \"esc \\\" quote, }\",\n}\n"
	m, err := ParseJSONC([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	if m["a"] != "keep // this" || m["c"] != `esc " quote, }` || len(m["b"].([]any)) != 2 {
		t.Errorf("parsed = %#v", m)
	}
	for _, bad := range []string{"{", "[]", "null", "{} {}", "{/* open"} {
		if _, err := ParseJSONC([]byte(bad)); err == nil {
			t.Errorf("ParseJSONC(%q) accepted", bad)
		}
	}
}

func TestParseTOML(t *testing.T) {
	m, err := ParseTOML([]byte("[mcp_servers.x]\ncommand = \"npx\"\nargs = [\"a\"]\n"))
	if err != nil {
		t.Fatal(err)
	}
	if Str(Obj(Obj(m, "mcp_servers"), "x"), "command") != "npx" {
		t.Errorf("parsed = %#v", m)
	}
	if _, err := ParseTOML([]byte("= broken")); err == nil {
		t.Error("broken TOML accepted")
	}
	if m, err := ParseTOML(nil); err != nil || m == nil {
		t.Errorf("empty TOML = %v, %v", m, err)
	}
}

func TestPointerAndLookup(t *testing.T) {
	if got := Pointer("projects", "/home/a~b", "mcpServers"); got != "/projects/~1home~1a~0b/mcpServers" {
		t.Errorf("Pointer = %s", got)
	}
	m := map[string]any{"a": map[string]any{"b": 1}, "x.y": 2}
	if v, ok := Lookup(m, "a.b"); !ok || v != 1 {
		t.Error("dotted lookup")
	}
	if v, ok := Lookup(m, "x.y"); !ok || v != 2 {
		t.Error("literal dotted key lookup")
	}
	if _, ok := Lookup(m, "a.b.c"); ok {
		t.Error("lookup through non-object")
	}
	if got := Strings(map[string]any{"k": "one"}, "k"); !slices.Equal(got, []string{"one"}) {
		t.Errorf("Strings(string) = %v", got)
	}
}

func TestDetectPackage(t *testing.T) {
	tests := []struct {
		cmd     string
		args    []string
		eco     string
		name    string
		version string
		digest  string
	}{
		{"npx", []string{"-y", "@scope/pkg@1.2.3"}, "npm", "@scope/pkg", "1.2.3", ""},
		{"npx", []string{"-y", "@scope/pkg"}, "npm", "@scope/pkg", "", ""},
		{"npx", []string{"pkg@^1.2.0"}, "npm", "pkg", "", ""},
		{"npx", []string{"pkg@latest"}, "npm", "pkg", "", ""},
		{"npx", []string{"--package", "real@2.0.0", "bin"}, "npm", "real", "2.0.0", ""},
		{"npx", []string{"--package=real@2.0.0", "bin"}, "npm", "real", "2.0.0", ""},
		{"npx", []string{"github:o/r#0123456789abcdef0123456789abcdef01234567"}, "npm", "github:o/r#0123456789abcdef0123456789abcdef01234567", "0123456789abcdef0123456789abcdef01234567", ""},
		{"/usr/local/bin/npx.cmd", []string{"x@1.0.0-beta.1"}, "npm", "x", "1.0.0-beta.1", ""},
		{"pnpm", []string{"dlx", "x@1.0.0"}, "npm", "x", "1.0.0", ""},
		{"npm", []string{"exec", "--", "x@1.0.0"}, "npm", "x", "1.0.0", ""},
		{"bunx", []string{"x"}, "npm", "x", "", ""},
		{"uvx", []string{"mcp-server-git==0.6.2"}, "pypi", "mcp-server-git", "0.6.2", ""},
		{"uvx", []string{"pkg@1.0"}, "pypi", "pkg", "1.0", ""},
		{"uvx", []string{"pkg[extra]==2.0.1"}, "pypi", "pkg", "2.0.1", ""},
		{"uvx", []string{"pkg>=1"}, "pypi", "pkg", "", ""},
		{"uvx", []string{"--from", "real==1.0", "cmd"}, "pypi", "real", "1.0", ""},
		{"uvx", []string{"--python", "3.12", "pkg"}, "pypi", "pkg", "", ""},
		{"uv", []string{"tool", "run", "pkg==3"}, "pypi", "pkg", "3", ""},
		{"pipx", []string{"run", "--spec", "x==1.0", "x"}, "pypi", "x", "1.0", ""},
		{"docker", []string{"run", "-i", "--rm", "-e", "TOKEN", "ghcr.io/o/img:1.0"}, "oci", "ghcr.io/o/img", "1.0", ""},
		{"docker", []string{"run", "localhost:5000/img"}, "oci", "localhost:5000/img", "", ""},
		{"podman", []string{"run", "img@sha256:" + strings.Repeat("a", 64)}, "oci", "img", "", "sha256:" + strings.Repeat("a", 64)},
	}
	for _, tt := range tests {
		p := DetectPackage(tt.cmd, tt.args)
		if p == nil || p.Ecosystem != tt.eco || p.Name != tt.name || p.Version != tt.version || p.Digest != tt.digest {
			t.Errorf("DetectPackage(%s %q) = %+v", tt.cmd, tt.args, p)
		}
	}
	for _, c := range [][]string{{"node", "server.js"}, {"python", "-m", "x"}, {"docker", "ps"}, {"npm", "test"}} {
		if p := DetectPackage(c[0], c[1:]); p != nil {
			t.Errorf("DetectPackage(%q) = %+v, want nil", c, p)
		}
	}
	if p := DetectPackage("npx", nil); p == nil || p.Pinned() {
		t.Error("bare npx must be an unpinned package")
	}
}

func TestParseServer(t *testing.T) {
	srv, secrets, auto := ParseServer(map[string]any{
		"command": "npx", "args": []any{"-y", "x@1.0.0", "--token", "abc"},
		"env":     map[string]any{"API_KEY": "literal", "REF": "${REF}", "MODE": "fast"},
		"headers": map[string]any{"Authorization": "Bearer abcdefghijklmnop"},
		"trust":   true, "disabled": true,
	}, DialectGemini)
	if srv.Transport != "stdio" || !srv.Trust || !srv.Disabled || srv.Args[3] != "[REDACTED]" {
		t.Errorf("server = %+v", srv)
	}
	if !slices.Equal(srv.EnvKeys, []string{"API_KEY", "MODE", "REF"}) {
		t.Errorf("env keys = %v", srv.EnvKeys)
	}
	slices.Sort(secrets)
	if !slices.Equal(secrets, []string{"args[3]", "env.API_KEY", "headers.Authorization"}) {
		t.Errorf("secrets = %v", secrets)
	}
	if len(auto) != 1 {
		t.Errorf("auto-approve = %v", auto)
	}

	for _, tc := range []struct {
		m    map[string]any
		d    Dialect
		want string
	}{
		{map[string]any{"url": "https://x"}, DialectGemini, "sse"},
		{map[string]any{"httpUrl": "https://x"}, DialectGemini, "http"},
		{map[string]any{"url": "https://x"}, DialectDefault, "http"},
		{map[string]any{"serverUrl": "https://x"}, DialectDefault, "http"},
		{map[string]any{"type": "streamable-http", "url": "https://x"}, DialectDefault, "http"},
		{map[string]any{"transport": "sse", "url": "https://x"}, DialectDefault, "sse"},
		{map[string]any{"type": "local", "command": "x"}, DialectDefault, "stdio"},
		{map[string]any{"type": "ws", "url": "wss://x"}, DialectDefault, "ws"},
		{map[string]any{"type": "custom"}, DialectDefault, "custom"},
		{map[string]any{}, DialectDefault, "stdio"},
	} {
		if s, _, _ := ParseServer(tc.m, tc.d); s.Transport != tc.want {
			t.Errorf("transport(%v) = %s, want %s", tc.m, s.Transport, tc.want)
		}
	}

	codex, secrets, auto := ParseServer(map[string]any{
		"url": "https://x", "bearer_token_env_var": "TOK", "env_vars": []any{"A", map[string]any{"name": "B"}},
		"http_headers": map[string]any{"X": "v"}, "env_http_headers": map[string]any{"Y": "ENV"},
		"bearer_token": "literal", "default_tools_approval_mode": "approve",
		"tools": map[string]any{"rm": map[string]any{"approval_mode": "approve"}}, "enabled": false,
	}, DialectCodex)
	if !slices.Equal(codex.EnvKeys, []string{"A", "B", "TOK"}) || !slices.Equal(codex.HeaderKeys, []string{"X", "Y"}) || !codex.Disabled {
		t.Errorf("codex server = %+v", codex)
	}
	if !slices.Contains(secrets, "bearer_token") || len(auto) != 2 {
		t.Errorf("codex secrets=%v auto=%v", secrets, auto)
	}
	if src := SourceOf(&asset.MCPServer{URL: "https://mcp.example.com/x"}); src.String() != "url:mcp.example.com" {
		t.Errorf("SourceOf(url) = %v", src)
	}
	if src := SourceOf(&asset.MCPServer{Command: "./bin/srv"}); src.String() != "local:./bin/srv" {
		t.Errorf("SourceOf(local) = %v", src)
	}
	if SourceOf(&asset.MCPServer{}) != nil {
		t.Error("SourceOf(empty) must be nil")
	}
}

func TestHooksShapes(t *testing.T) {
	events := map[string]any{
		"PreToolUse": []any{map[string]any{"matcher": "Bash", "hooks": []any{
			map[string]any{"type": "command", "command": "a.sh"},
			map[string]any{"type": "http", "url": "https://h?token=abc", "headers": map[string]any{"Authorization": "Bearer abcdefghijklmnop"}},
			"junk",
		}}},
		"afterFileEdit": []any{map[string]any{"command": "fmt", "args": []any{"--key", "zzz"}}, 7},
		"bad":           "x",
	}
	r := Hooks(events, HookOptions{Agent: "a", File: "f.json", Pointer: []string{"hooks"}})
	if len(r.Assets) != 3 || len(r.Problems) != 1 {
		t.Fatalf("assets=%d problems=%d", len(r.Assets), len(r.Problems))
	}
	byName := map[string]asset.Asset{}
	for _, a := range r.Assets {
		byName[a.Name] = a
	}
	pre := byName["f.json#PreToolUse/0/0"]
	if pre.Hook.Matcher != "Bash" || pre.Path != "f.json#/hooks/PreToolUse/0/hooks/0" {
		t.Errorf("nested hook = %+v", pre)
	}
	httpHook := byName["f.json#PreToolUse/0/1"]
	if strings.Contains(httpHook.Hook.URL, "abc") || len(httpHook.InlineSecrets) != 2 {
		t.Errorf("http hook = %+v secrets=%v", httpHook.Hook, httpHook.InlineSecrets)
	}
	flat := byName["f.json#afterFileEdit/0"]
	if flat.Path != "f.json#/hooks/afterFileEdit/0" || flat.Hook.Args[1] != "[REDACTED]" {
		t.Errorf("flat hook = %+v", flat.Hook)
	}
}

func newSource(t *testing.T, dir string, scope asset.Scope) *Source {
	t.Helper()
	r, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	return &Source{FS: r.FS(), Scope: scope, RootDir: dir}
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

func TestReferencedFiles(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, map[string]string{"scripts/a.sh": "", "b.py": "", ".cursor/hooks/c.sh": "", "dir/x": ""})
	src := newSource(t, dir, asset.ScopeProject)
	h := &asset.Hook{Command: `"$CLAUDE_PROJECT_DIR"/scripts/a.sh && python3 b.py; ../escape.sh; /etc/passwd; $OTHER/x.sh; https://x/y.sh ` + filepath.ToSlash(filepath.Join(dir, "dir", "x"))}
	got := ReferencedFiles(src, h, "")
	if !slices.Equal(got, []string{"b.py", "dir/x", "scripts/a.sh"}) {
		t.Errorf("ReferencedFiles = %v", got)
	}
	if got := ReferencedFiles(src, &asset.Hook{Command: "./hooks/c.sh"}, ".cursor"); !slices.Equal(got, []string{".cursor/hooks/c.sh"}) {
		t.Errorf("base dir resolution = %v", got)
	}
	usrc := newSource(t, dir, asset.ScopeUser)
	if got := ReferencedFiles(usrc, &asset.Hook{Bash: "~/scripts/a.sh", PowerShell: "$HOME/b.py"}, ""); !slices.Equal(got, []string{"b.py", "scripts/a.sh"}) {
		t.Errorf("home resolution = %v", got)
	}
}

func symlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
}

func TestRealAndReadConfig(t *testing.T) {
	outer := t.TempDir()
	dir := filepath.Join(outer, "root")
	write(t, outer, map[string]string{"outside.json": "{}", "root/dotfiles/settings.json": `{"a":1}`, "root/big.json": strings.Repeat(" ", MaxConfigSize+1)})
	symlink(t, filepath.Join(dir, "dotfiles", "settings.json"), filepath.Join(dir, "abs.json"))
	symlink(t, "abs.json", filepath.Join(dir, "chain.json"))
	symlink(t, "../outside.json", filepath.Join(dir, "esc.json"))
	symlink(t, "loop2", filepath.Join(dir, "loop1"))
	symlink(t, "loop1", filepath.Join(dir, "loop2"))
	symlink(t, "missing.json", filepath.Join(dir, "dangling.json"))
	src := newSource(t, dir, asset.ScopeUser)

	for _, p := range []string{"abs.json", "chain.json"} {
		b, ok, problem := src.ReadConfig(p)
		if !ok || problem != "" || string(b) != `{"a":1}` {
			t.Errorf("ReadConfig(%s) = %q %v %q", p, b, ok, problem)
		}
	}
	for _, p := range []string{"esc.json", "loop1"} {
		if _, ok, problem := src.ReadConfig(p); !ok || problem == "" {
			t.Errorf("ReadConfig(%s) must report a problem", p)
		}
	}
	if _, ok, _ := src.ReadConfig("dangling.json"); ok {
		t.Error("dangling link must read as missing")
	}
	if _, ok, problem := src.ReadConfig("big.json"); !ok || !strings.Contains(problem, "larger") {
		t.Errorf("oversized config problem = %q", problem)
	}
	if _, ok, problem := src.ReadConfig("dotfiles"); !ok || problem == "" {
		t.Error("directory must not be read as config")
	}
	if _, ok, _ := src.ReadConfig("nope.json"); ok {
		t.Error("missing file reported as present")
	}
}

func TestWalkAndFiles(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, map[string]string{
		"AGENTS.md": "", "a/AGENTS.md": "", "node_modules/x/AGENTS.md": "", ".git/AGENTS.md": "",
		"a/.claude/skills/s/SKILL.md": "", "rules/x.mdc": "", "rules/sub/y.mdc": "", "rules/z.md": "",
	})
	src := newSource(t, dir, asset.ScopeProject)
	got, err := src.Nested("AGENTS.md")
	if err != nil || !slices.Equal(got, []string{"AGENTS.md", "a/AGENTS.md"}) {
		t.Errorf("Nested = %v %v", got, err)
	}
	dirs, _ := src.NestedDirs(".claude/skills")
	if !slices.Equal(dirs, []string{"a/.claude/skills"}) {
		t.Errorf("NestedDirs = %v", dirs)
	}
	if got := src.Files("rules", true, ".mdc"); !slices.Equal(got, []string{"rules/sub/y.mdc", "rules/x.mdc"}) {
		t.Errorf("Files recursive = %v", got)
	}
	if got := src.Files("rules", false, ".mdc"); !slices.Equal(got, []string{"rules/x.mdc"}) {
		t.Errorf("Files flat = %v", got)
	}
	user := newSource(t, dir, asset.ScopeUser)
	if e, _ := user.Walk(); e != nil {
		t.Error("user scope must not walk")
	}
	limited := &Source{FS: src.FS, Scope: asset.ScopeProject, MaxWalkEntries: 2}
	if _, err := limited.Walk(); err == nil {
		t.Error("walk limit not enforced")
	}
}

func TestSettingsScrubAndAllow(t *testing.T) {
	m := map[string]any{
		"permissions":  map[string]any{"allow": []any{"Read", "ghp_abcdefghijklmnopqrstuvwxyz0123"}},
		"env":          map[string]any{"B": "x", "A": "y"},
		"apiKey":       "literal",
		"chat.tools.x": true, "chat.other": 1, "nested": map[string]any{"token": "zzz"},
	}
	r := Settings(m, SettingsOptions{Agent: "a", File: "s.json", Keys: []string{"permissions", "env", "apiKey", "chat.tools.*", "nested", "missing"}})
	s := r.Assets[0].Settings
	if s["apiKey"] != "[REDACTED]" || s["chat.tools.x"] != true || s["chat.other"] != nil {
		t.Errorf("settings = %#v", s)
	}
	if keys := s["env"].(map[string]any)["keys"].([]any); keys[0] != "A" {
		t.Errorf("env keys = %v", keys)
	}
	if s["nested"].(map[string]any)["token"] != "[REDACTED]" {
		t.Error("nested sensitive value not masked")
	}
	if allow := s["permissions"].(map[string]any)["allow"].([]any); allow[1] != "[REDACTED]" {
		t.Errorf("token in list not masked: %v", allow)
	}
	if len(Settings(m, SettingsOptions{Keys: []string{"none"}}).Assets) != 0 {
		t.Error("no keys present must yield no asset")
	}
	got := BroadAllowEntries([]string{"Read", "Bash(*)", "mcp__*", "mcp__github", "mcp__github__*", "mcp__github__list_issues", "Bash(git diff *)", "*"})
	if !slices.Equal(got, []string{"Bash(*)", "mcp__*", "mcp__github", "mcp__github__*", "*"}) {
		t.Errorf("BroadAllowEntries = %v", got)
	}
	if !slices.Equal(With("b", "a", "b"), []string{"a", "b"}) {
		t.Error("With")
	}
}

// FuzzConfigParsers feeds arbitrary bytes through the JSONC and TOML parsers
// and every structure walker that consumes their output. Untrusted
// repositories control these files (scan-repo), so none may panic.
func FuzzConfigParsers(f *testing.F) {
	f.Add([]byte(`{"mcpServers":{"a":{"command":"npx","args":["-y","x@1.0.0"],"env":{"K":"v"}}},"hooks":{"E":[{"matcher":"m","hooks":[{"type":"command","command":"x.sh"}]}]}}`))
	f.Add([]byte("[mcp_servers.x]\ncommand = \"uvx\"\nargs = [\"a==1\"]\n[[hooks.E]]\nmatcher = \"m\"\n"))
	f.Add([]byte(`{"servers":{"x":{"url":"https://u:p@h/?token=t"}},"permissions":{"allow":["*"]}}`))
	f.Fuzz(func(_ *testing.T, b []byte) {
		for _, parse := range []func([]byte) (map[string]any, error){ParseJSONC, ParseTOML} {
			m, err := parse(b)
			if err != nil {
				continue
			}
			for _, key := range []string{"mcpServers", "servers", "mcp_servers"} {
				Servers(Obj(m, key), ServerOptions{Agent: "a", File: "f"})
			}
			Hooks(Obj(m, "hooks"), HookOptions{Agent: "a", File: "f"})
			Hooks(m, HookOptions{Agent: "a", File: "f"})
			Settings(m, SettingsOptions{Agent: "a", File: "f", Keys: []string{"permissions", "env", "chat.*", "a.b"},
				AutoApprove: func(m map[string]any) []string { return BroadAllowEntries(Strings(Obj(m, "permissions"), "allow")) }})
		}
	})
}
