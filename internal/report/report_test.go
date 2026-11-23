package report

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/Breaktroughf1/lockward/internal/asset"
	"github.com/Breaktroughf1/lockward/internal/lock"
	"github.com/Breaktroughf1/lockward/internal/policy"
)

var update = flag.Bool("update", false, "update golden files")

func d(c byte) string { return "sha256:" + strings.Repeat(string(c), 64) }

func entries() (locked, live []asset.Entry) {
	skill := asset.Entry{ID: "skill:claude-code:pdf tools", Surface: asset.SurfaceSkill, Agent: "claude-code", Path: ".claude/skills/pdf tools", Digest: d('a'),
		Files: []asset.File{{Path: "SKILL.md", Digest: d('b')}}, Approved: &asset.Approval{By: "dev@example.com"}}
	mcp := asset.Entry{ID: "mcp:cursor:gh", Surface: asset.SurfaceMCP, Agent: "cursor", Path: ".cursor/mcp.json#/mcpServers/gh", Digest: d('c'),
		Server: &asset.MCPServer{Transport: "stdio", Command: "npx", Args: []string{"-y", "@scope/gh-mcp@1.2.3"},
			Package: &asset.Package{Ecosystem: "npm", Name: "@scope/gh-mcp", Version: "1.2.3"}}, ToolsFingerprint: d('f')}
	py := asset.Entry{ID: "mcp:codex:git", Surface: asset.SurfaceMCP, Agent: "codex", Path: ".codex/config.toml#/mcp_servers/git", Digest: d('9'),
		Server: &asset.MCPServer{Transport: "stdio", Command: "uvx", Package: &asset.Package{Ecosystem: "pypi", Name: "MCP_Server_Git", Version: "0.6.2"}}}
	remote := asset.Entry{ID: "mcp:claude-code:stripe", Surface: asset.SurfaceMCP, Agent: "claude-code", Path: ".mcp.json#/mcpServers/stripe", Digest: d('8'),
		Server: &asset.MCPServer{Transport: "http", URL: "https://mcp.stripe.com"}}
	rules := asset.Entry{ID: "rules:generic:AGENTS.md", Surface: asset.SurfaceRules, Agent: "generic", Path: "AGENTS.md", Digest: d('d'), LoadedBy: []string{"codex", "cursor"}}
	hook := asset.Entry{ID: "hook:claude-code:.claude/settings.json#PreToolUse/0/0", Surface: asset.SurfaceHook, Agent: "claude-code",
		Path: ".claude/settings.json#/hooks/PreToolUse/0/hooks/0", Digest: d('e'), Hook: &asset.Hook{Event: "PreToolUse", Command: "x.sh"}}
	settings := asset.Entry{ID: "settings:claude-code:.claude/settings.json", Surface: asset.SurfaceSettings, Agent: "claude-code",
		Path: ".claude/settings.json", Digest: d('7'), Settings: map[string]any{"permissions": map[string]any{}}}
	locked = []asset.Entry{skill, mcp, rules, py, remote, hook, settings}
	modSkill := skill
	modSkill.Digest = d('1')
	added := asset.Entry{ID: "mcp:cursor:new", Surface: asset.SurfaceMCP, Agent: "cursor", Path: ".cursor/mcp.json#/mcpServers/new", Digest: d('2'),
		Server: &asset.MCPServer{Transport: "stdio", Command: "npx", Package: &asset.Package{Ecosystem: "npm", Name: "x", Spec: "x"}}}
	live = []asset.Entry{modSkill, mcp, added, py, remote, hook, settings}
	return locked, live
}

func sample(frozen bool) *Report {
	locked, live := entries()
	return &Report{
		Version: "0.1.0", Frozen: frozen, ExitCode: 2,
		Scopes: []Scope{{
			Scope: asset.ScopeProject, Lockfile: "lockward.lock",
			Results: lock.Compare(locked, live),
			Findings: []policy.Finding{
				{Rule: "LW001", Name: "unpinned-mcp-package", Severity: policy.SeverityError, EntryID: "mcp:cursor:new",
					Path: ".cursor/mcp.json", Message: `MCP server "new" runs npm package "x" without an exact version`, Remediation: "Pin it."},
				{Rule: "LW004", Name: "external-url-reference", Severity: policy.SeverityWarning, EntryID: "skill:claude-code:pdf tools",
					Path: ".claude/skills/pdf tools/SKILL.md", Line: 3, Message: "instructs fetching or executing from evil.example.com", Remediation: "Review."},
			},
			Suppressed: 1,
			Problems:   []asset.Problem{{Agent: "cursor", Path: ".cursor/hooks.json", Message: "parse JSON: unexpected EOF; pinned as raw bytes"}},
			PolicyFile: "lockward.policy.yaml", PolicyDigest: d('3'),
			IgnorePatterns: []string{"*.log"}, Ignored: 2,
			Notices: []string{"tools fingerprint for mcp:cursor:gh not re-checked (pass --tools)"},
		}},
	}
}

func golden(t *testing.T, name string, got []byte) {
	t.Helper()
	p := filepath.Join("testdata", "golden", name)
	if *update {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("%v (run go test ./internal/report -update)", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("%s differs (run with -update and review):\n%s", name, got)
	}
}

func TestTextGolden(t *testing.T) {
	var b bytes.Buffer
	if err := Text(&b, sample(false), TextOptions{}); err != nil {
		t.Fatal(err)
	}
	golden(t, "verify.txt", b.Bytes())
	out := b.String()
	for _, want := range []string{"lockward diff 'skill:claude-code:pdf tools'", "lockward approve mcp:cursor:new", "fix: Pin it.", "at .claude/skills/pdf tools/SKILL.md:3", "1 suppressed", "built-in defaults"[:0]} {
		if !strings.Contains(out, want) {
			t.Errorf("text output missing %q", want)
		}
	}
	if strings.Contains(out, "\x1b[") {
		t.Error("colour codes without Color option")
	}
	b.Reset()
	r := sample(true)
	r.ExitCode = 1
	r.Scopes[0].PolicyFile = ""
	r.Scopes = append(r.Scopes, Scope{Scope: asset.ScopeUser, Lockfile: "~/.config/lockward/user.lock", Results: lock.Compare(nil, nil)})
	_ = Text(&b, r, TextOptions{Color: true, Verbose: true})
	if !strings.Contains(b.String(), "\x1b[31m") || !strings.Contains(b.String(), "built-in defaults") || !strings.Contains(b.String(), "user scope") {
		t.Errorf("colour/verbose output:\n%s", b.String())
	}
	b.Reset()
	r.ExitCode = 0
	r.Scopes = r.Scopes[1:]
	_ = Text(&b, r, TextOptions{})
	if !strings.Contains(b.String(), "clean: 0 entries") {
		t.Errorf("clean output: %s", b.String())
	}
}

func TestJSONGolden(t *testing.T) {
	var b bytes.Buffer
	if err := JSON(&b, sample(false)); err != nil {
		t.Fatal(err)
	}
	golden(t, "verify.json", b.Bytes())
	var v map[string]any
	if err := json.Unmarshal(b.Bytes(), &v); err != nil {
		t.Fatal(err)
	}
	if v["exit_code"].(float64) != 2 || v["summary"].(map[string]any)["modified"].(float64) != 1 {
		t.Errorf("summary = %v", v["summary"])
	}
}

// schemaLoader serves the vendored schemas and refuses everything else, so
// validation never touches the network (LW-NFR-01).
type schemaLoader map[string]string

func (l schemaLoader) Load(url string) (any, error) {
	file, ok := l[strings.TrimSuffix(url, "#")]
	if !ok {
		return nil, fmt.Errorf("offline test: refusing to fetch %s", url)
	}
	f, err := os.Open(filepath.Join("..", "..", "testdata", "schemas", file))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return jsonschema.UnmarshalJSON(f)
}

func validate(t *testing.T, schemaURL string, doc []byte) {
	t.Helper()
	c := jsonschema.NewCompiler()
	c.UseLoader(schemaLoader{
		"http://cyclonedx.org/schema/bom-1.6.schema.json":                                            "bom-1.6.schema.json",
		"http://cyclonedx.org/schema/spdx.schema.json":                                               "spdx.schema.json",
		"http://cyclonedx.org/schema/jsf-0.82.schema.json":                                           "jsf-0.82.schema.json",
		"https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json": "sarif-schema-2.1.0.json",
	})
	sch, err := c.Compile(schemaURL)
	if err != nil {
		t.Fatalf("compile schema: %v", err)
	}
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(doc))
	if err != nil {
		t.Fatal(err)
	}
	if err := sch.Validate(inst); err != nil {
		t.Errorf("document does not validate against %s:\n%v", schemaURL, err)
	}
}

func TestSARIFValidAndGolden(t *testing.T) {
	var b bytes.Buffer
	if err := SARIF(&b, sample(false)); err != nil {
		t.Fatal(err)
	}
	golden(t, "verify.sarif", b.Bytes())
	validate(t, "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json", b.Bytes())
	var log sarifLog
	if err := json.Unmarshal(b.Bytes(), &log); err != nil {
		t.Fatal(err)
	}
	res := log.Runs[0].Results
	// US-2: one result per drifted item plus one per finding.
	if len(res) != 3+2 {
		t.Fatalf("results = %d, want 5", len(res))
	}
	rules := log.Runs[0].Tool.Driver.Rules
	for _, r := range res {
		if rules[r.RuleIndex].ID != r.RuleID {
			t.Errorf("ruleIndex mismatch for %s", r.RuleID)
		}
		if r.PartialFingerprints["lockward/v1"] == "" {
			t.Error("missing fingerprint")
		}
	}
	levels := map[string]string{}
	for _, r := range res {
		levels[r.Properties["status"]] = r.Level
	}
	if levels["added"] != "warning" || levels["modified"] != "error" || levels["removed"] != "error" {
		t.Errorf("levels without --frozen = %v", levels)
	}
	if !strings.Contains(b.String(), "pdf%20tools") {
		t.Error("artifact URIs must be percent-encoded")
	}
	b.Reset()
	_ = SARIF(&b, sample(true))
	var frozen sarifLog
	if err := json.Unmarshal(b.Bytes(), &frozen); err != nil {
		t.Fatal(err)
	}
	for _, r := range frozen.Runs[0].Results {
		if r.Properties["status"] == "added" && r.Level != "error" {
			t.Error("additions must be errors with --frozen")
		}
	}
	validate(t, "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json", b.Bytes())
}

func TestCycloneDXValidAndDeterministic(t *testing.T) {
	locked, _ := entries()
	var a, b bytes.Buffer
	if err := CycloneDX(&a, locked, BOMOptions{Version: "0.1.0", Scope: asset.ScopeProject, Name: "demo"}); err != nil {
		t.Fatal(err)
	}
	rev := append([]asset.Entry{}, locked...)
	for i, j := 0, len(rev)-1; i < j; i, j = i+1, j-1 {
		rev[i], rev[j] = rev[j], rev[i]
	}
	if err := CycloneDX(&b, rev, BOMOptions{Version: "0.1.0", Scope: asset.ScopeProject, Name: "demo"}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a.Bytes(), b.Bytes()) {
		t.Error("BOM depends on input order")
	}
	golden(t, "bom.cdx.json", a.Bytes())
	validate(t, "http://cyclonedx.org/schema/bom-1.6.schema.json", a.Bytes())
	out := a.String()
	for _, want := range []string{"pkg:npm/%40scope/gh-mcp@1.2.3", "pkg:pypi/mcp-server-git@0.6.2", `"type": "file"`, `"type": "data"`, "urn:uuid:"} {
		if !strings.Contains(out, want) {
			t.Errorf("BOM missing %q", want)
		}
	}
	var empty bytes.Buffer
	if err := CycloneDX(&empty, nil, BOMOptions{Version: "0.1.0", Scope: asset.ScopeUser}); err != nil {
		t.Fatal(err)
	}
	validate(t, "http://cyclonedx.org/schema/bom-1.6.schema.json", empty.Bytes())
	if serial(locked[:1]) == serial(locked[:2]) {
		t.Error("serial number does not depend on entries")
	}
}

func TestPURL(t *testing.T) {
	for _, tc := range []struct {
		p    asset.Package
		want string
	}{
		{asset.Package{Ecosystem: "npm", Name: "left-pad", Version: "1.3.0"}, "pkg:npm/left-pad@1.3.0"},
		{asset.Package{Ecosystem: "npm", Name: "x"}, ""},
		{asset.Package{Ecosystem: "npm", Name: "github:o/r", Version: "abc"}, ""},
		{asset.Package{Ecosystem: "oci", Name: "img", Digest: "sha256:aa"}, ""},
	} {
		if got := purl(&tc.p); got != tc.want {
			t.Errorf("purl(%+v) = %q, want %q", tc.p, got, tc.want)
		}
	}
}

func TestShellQuote(t *testing.T) {
	for in, want := range map[string]string{
		"mcp:cursor:gh": "mcp:cursor:gh", "hook:claude-code:.claude/settings.json#PreToolUse/0/0": "hook:claude-code:.claude/settings.json#PreToolUse/0/0",
		"skill:x:a b": "'skill:x:a b'", "skill:x:it's": `'skill:x:it'\''s'`, "": "''", "#x": "'#x'", "a$b": "'a$b'",
	} {
		if got := ShellQuote(in); got != want {
			t.Errorf("ShellQuote(%q) = %s, want %s", in, got, want)
		}
	}
}
