package scanner

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Breaktroughf1/lockward/internal/asset"
)

const sample = `{"version":"2.1.0","runs":[
 {"tool":{"driver":{"name":"SkillSpector"}},"results":[
  {"ruleId":"SS-EXFIL","level":"error","message":{"text":"Exfiltrates data"},
   "locations":[{"physicalLocation":{"artifactLocation":{"uri":".claude/skills/pdf%20tools/scripts/run.py"},"region":{"startLine":12}}}]},
  {"ruleId":"SS-INJ","message":{"text":"Prompt injection"},
   "locations":[{"physicalLocation":{"artifactLocation":{"uri":"file:///repo/CLAUDE.md"}}}]},
  {"ruleId":"SS-OTHER","level":"note","message":{"text":"Elsewhere"},
   "locations":[{"physicalLocation":{"artifactLocation":{"uri":"src/main.go"}}}]},
  {"ruleId":"SS-NOLOC","level":"warning","message":{"text":"No location"}}]},
 {"tool":{"driver":{}},"results":[
  {"ruleId":"X","level":"warning","message":{"text":"Nested skill"},
   "locations":[{"physicalLocation":{"artifactLocation":{"uri":"./.claude/skills/pdf tools/sub/inner/a.md"}}}]}]}]}`

func TestParseAndAttach(t *testing.T) {
	fs, err := Parse([]byte(sample), "/repo")
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 5 || fs[1].Level != "warning" || fs[1].URI != "CLAUDE.md" || fs[0].URI != ".claude/skills/pdf tools/scripts/run.py" || fs[4].Tool != "unknown scanner" {
		t.Fatalf("parsed = %+v", fs)
	}
	entries := []asset.Entry{
		{ID: "skill:claude-code:pdf tools", Surface: asset.SurfaceSkill, Path: ".claude/skills/pdf tools"},
		{ID: "skill:claude-code:inner", Surface: asset.SurfaceSkill, Path: ".claude/skills/pdf tools/sub/inner"},
		{ID: "rules:claude-code:CLAUDE.md", Surface: asset.SurfaceRules, Path: "CLAUDE.md"},
		{ID: "mcp:claude-code:x", Surface: asset.SurfaceMCP, Path: ".mcp.json#/mcpServers/x"},
	}
	got := map[string]string{}
	for _, f := range Attach(fs, entries) {
		got[f.RuleID] = f.EntryID
	}
	want := map[string]string{
		"SS-EXFIL": "skill:claude-code:pdf tools", "SS-INJ": "rules:claude-code:CLAUDE.md",
		"SS-OTHER": "", "SS-NOLOC": "", "X": "skill:claude-code:inner",
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s attached to %q, want %q", k, got[k], v)
		}
	}
}

func TestParseErrors(t *testing.T) {
	for _, in := range []string{`{`, `{"version":"2.0.0","runs":[]}`} {
		if _, err := Parse([]byte(in), ""); err == nil {
			t.Errorf("Parse(%s) accepted", in)
		}
	}
}

func TestLoad(t *testing.T) {
	p := filepath.Join(t.TempDir(), "s.sarif")
	if err := os.WriteFile(p, []byte(sample), 0o600); err != nil {
		t.Fatal(err)
	}
	if fs, err := Load(p, ""); err != nil || len(fs) != 5 {
		t.Errorf("Load = %d, %v", len(fs), err)
	}
	if _, err := Load(p+".missing", ""); err == nil {
		t.Error("missing file accepted")
	}
}

func FuzzParse(f *testing.F) {
	f.Add([]byte(sample), "/repo")
	f.Fuzz(func(_ *testing.T, b []byte, root string) {
		fs, err := Parse(b, root)
		if err != nil {
			return
		}
		_ = Attach(fs, []asset.Entry{{ID: "skill:a:b", Surface: asset.SurfaceSkill, Path: "a"}})
	})
}
