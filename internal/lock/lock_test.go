package lock

import (
	"errors"
	"flag"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Breaktroughf1/lockward/internal/asset"
)

var update = flag.Bool("update", false, "update golden files")

func d(c byte) string { return "sha256:" + strings.Repeat(string(c), 64) }

func size(n int64) *int64 { return &n }

func sampleEntries() []asset.Entry {
	return []asset.Entry{
		{ID: "skill:claude-code:pdf-tools", Surface: asset.SurfaceSkill, Agent: "claude-code",
			LoadedBy: []string{"claude-code", "copilot", "cursor"},
			Path:     ".claude/skills/pdf-tools", Digest: d('a'),
			Files: []asset.File{
				{Path: "SKILL.md", Digest: d('b'), Size: size(2140), Mode: "0644"},
				{Path: "scripts/run.py", Digest: d('c'), Size: size(812), Mode: "0755"},
				{Path: "latest", Symlink: "scripts/run.py"},
			}},
		{ID: "mcp:cursor:github", Surface: asset.SurfaceMCP, Agent: "cursor", Path: ".cursor/mcp.json#/mcpServers/github",
			Digest: d('d'), Source: &asset.Source{Type: "npm", Ref: "@modelcontextprotocol/server-github"},
			Server: &asset.MCPServer{Transport: "stdio", Command: "npx", Args: []string{"-y", "@modelcontextprotocol/server-github@2.1.0"},
				Package: &asset.Package{Ecosystem: "npm", Name: "@modelcontextprotocol/server-github", Version: "2.1.0"},
				EnvKeys: []string{"GITHUB_TOKEN"}}},
		{ID: "hook:claude-code:.claude/settings.json#PreToolUse/0/0", Surface: asset.SurfaceHook, Agent: "claude-code",
			Path: ".claude/settings.json#/hooks/PreToolUse/0/hooks/0", Digest: d('e'),
			Hook:            &asset.Hook{Event: "PreToolUse", Matcher: "Bash", Type: "command", Command: "./scripts/guard.sh"},
			ReferencedFiles: []asset.FileRef{{Path: "scripts/guard.sh", Digest: d('f')}},
			Approved:        &asset.Approval{By: "dev@example.com"}},
		{ID: "rules:generic:AGENTS.md", Surface: asset.SurfaceRules, Agent: "generic", Path: "AGENTS.md", Digest: d('1'),
			LoadedBy: []string{"codex", "copilot", "cursor"}},
	}
}

func TestEncodeGolden(t *testing.T) {
	f := New(asset.ScopeProject, "lockward 0.1.0", sampleEntries())
	got, err := Encode(f)
	if err != nil {
		t.Fatal(err)
	}
	golden := filepath.Join("testdata", "golden", "project.lock")
	if *update {
		if err := os.MkdirAll(filepath.Dir(golden), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(golden, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("%v (run go test ./internal/lock -update)", err)
	}
	if string(got) != string(want) {
		t.Errorf("encoding differs from %s:\n%s", golden, got)
	}
}

// TestRoundTripByteIdentical covers US-1: re-encoding a decoded lockfile is
// byte-identical.
func TestRoundTripByteIdentical(t *testing.T) {
	b1, err := Encode(New(asset.ScopeProject, "lockward 0.1.0", sampleEntries()))
	if err != nil {
		t.Fatal(err)
	}
	f, err := Decode(b1)
	if err != nil {
		t.Fatal(err)
	}
	b2, err := Encode(f)
	if err != nil {
		t.Fatal(err)
	}
	if string(b1) != string(b2) {
		t.Errorf("round trip changed bytes:\n%s\n---\n%s", b1, b2)
	}
	if f.Entries[0].ID != "hook:claude-code:.claude/settings.json#PreToolUse/0/0" {
		t.Errorf("entries not sorted by id: first = %s", f.Entries[0].ID)
	}
	if !strings.HasSuffix(string(b1), "}\n") || strings.Contains(string(b1), "\r") {
		t.Error("lockfile must end with a newline and use \\n line endings")
	}
}

func TestEncodeEmpty(t *testing.T) {
	b, err := Encode(&File{LockfileVersion: 1, Scope: asset.ScopeUser, HashAlgorithm: "sha256"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"entries": []`) {
		t.Errorf("empty entries must encode as []: %s", b)
	}
}

// TestInvariant_UnknownLockfileVersionFails is THREAT_MODEL §6 invariant 6.
func TestInvariant_UnknownLockfileVersionFails(t *testing.T) {
	for _, v := range []string{"0", "2", "99"} {
		_, err := Decode([]byte(`{"lockfile_version": ` + v + `, "scope": "project", "hash_algorithm": "sha256", "entries": []}`))
		if !errors.Is(err, ErrUnsupportedVersion) {
			t.Errorf("version %s: err = %v, want ErrUnsupportedVersion", v, err)
		}
	}
}

func TestDecodeIgnoresUnknownFields(t *testing.T) {
	in := `{"lockfile_version":1,"scope":"project","hash_algorithm":"sha256","future":{"x":1},
	"entries":[{"id":"rules:generic:AGENTS.md","surface":"rules","agent":"generic","path":"AGENTS.md","digest":"` + d('a') + `","new_field":true}]}`
	f, err := Decode([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Entries) != 1 {
		t.Errorf("entries = %d", len(f.Entries))
	}
}

func TestDecodeRejectsInvalid(t *testing.T) {
	entry := func(fields string) string {
		return `{"lockfile_version":1,"scope":"project","hash_algorithm":"sha256","entries":[` + fields + `]}`
	}
	ok := `{"id":"rules:generic:AGENTS.md","surface":"rules","agent":"generic","path":"AGENTS.md","digest":"` + d('a') + `"}`
	tests := map[string]string{
		"not json":          `{`,
		"no version":        `{"scope":"project"}`,
		"bad hash alg":      `{"lockfile_version":1,"scope":"project","hash_algorithm":"md5","entries":[]}`,
		"bad scope":         `{"lockfile_version":1,"scope":"global","hash_algorithm":"sha256","entries":[]}`,
		"duplicate id":      entry(ok + "," + ok),
		"bad id":            entry(strings.Replace(ok, `"id":"rules:generic:AGENTS.md"`, `"id":"nope"`, 1)),
		"surface mismatch":  entry(strings.Replace(ok, `"surface":"rules"`, `"surface":"skill"`, 1)),
		"agent mismatch":    entry(strings.Replace(ok, `"agent":"generic"`, `"agent":"cursor"`, 1)),
		"bad digest":        entry(strings.Replace(ok, d('a'), "sha256:XYZ", 1)),
		"absolute path":     entry(strings.Replace(ok, `"path":"AGENTS.md"`, `"path":"/etc/passwd"`, 1)),
		"dotdot path":       entry(strings.Replace(ok, `"path":"AGENTS.md"`, `"path":"../x"`, 1)),
		"backslash path":    entry(strings.Replace(ok, `"path":"AGENTS.md"`, `"path":"a\\\\b"`, 1)),
		"bad file path":     entry(strings.Replace(ok, `}`, `,"files":[{"path":"../../x","digest":"`+d('a')+`"}]}`, 1)),
		"bad file digest":   entry(strings.Replace(ok, `}`, `,"files":[{"path":"x","digest":"bad"}]}`, 1)),
		"bad ref path":      entry(strings.Replace(ok, `}`, `,"referenced_files":[{"path":"/x","digest":"`+d('a')+`"}]}`, 1)),
		"bad ref digest":    entry(strings.Replace(ok, `}`, `,"referenced_files":[{"path":"x","digest":"bad"}]}`, 1)),
		"bad fingerprint":   entry(strings.Replace(ok, `}`, `,"tools_fingerprint":"bad"}`, 1)),
		"drive letter path": entry(strings.Replace(ok, `"path":"AGENTS.md"`, `"path":"C:/x"`, 1)),
	}
	for name, in := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := Decode([]byte(in)); err == nil {
				t.Errorf("Decode accepted %s", in)
			}
		})
	}
}

func TestReadWrite(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "sub", ProjectFileName)
	f := New(asset.ScopeProject, "lockward test", sampleEntries())
	if err := Write(p, f); err != nil {
		t.Fatal(err)
	}
	got, err := Read(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Entries) != len(f.Entries) {
		t.Errorf("entries = %d, want %d", len(got.Entries), len(f.Entries))
	}
	if _, err := Read(filepath.Join(dir, "missing")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("missing lockfile err = %v, want ErrNotExist", err)
	}
	if err := os.WriteFile(p, []byte(`{"lockfile_version":2}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(p); !errors.Is(err, ErrUnsupportedVersion) {
		t.Errorf("err = %v", err)
	}
	entries, _ := os.ReadDir(filepath.Join(dir, "sub"))
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp-") {
			t.Errorf("temporary file left behind: %s", e.Name())
		}
	}
	bad := New(asset.ScopeProject, "x", []asset.Entry{{ID: "bad"}})
	if err := Write(p, bad); err == nil {
		t.Error("Write accepted an invalid entry")
	}
}

func mk(id, digest string) asset.Entry {
	s, agent, _, _ := asset.ParseID(id)
	return asset.Entry{ID: id, Surface: s, Agent: agent, Path: "x", Digest: digest}
}

func TestCompare(t *testing.T) {
	locked := []asset.Entry{mk("rules:generic:a", d('1')), mk("rules:generic:b", d('2')), mk("rules:generic:c", d('3'))}
	live := []asset.Entry{mk("rules:generic:a", d('1')), mk("rules:generic:b", d('9')), mk("rules:generic:d", d('4'))}
	res := Compare(locked, live)
	got := map[string]Status{}
	for _, r := range res {
		got[r.ID] = r.Status
	}
	want := map[string]Status{"rules:generic:a": StatusOK, "rules:generic:b": StatusModified, "rules:generic:c": StatusRemoved, "rules:generic:d": StatusAdded}
	for id, s := range want {
		if got[id] != s {
			t.Errorf("%s = %s, want %s", id, got[id], s)
		}
	}
	if res[2].Entry() != res[2].Locked || res[3].Entry() != res[3].Live {
		t.Error("Result.Entry picks the wrong side")
	}
	c := Counts(res)
	if c[StatusOK] != 1 || c[StatusAdded] != 1 {
		t.Errorf("counts = %v", c)
	}
	fp := mk("rules:generic:a", d('1'))
	fp.ToolsFingerprint = d('7')
	if Compare(locked[:1], []asset.Entry{fp})[0].Status != StatusModified {
		t.Error("tools_fingerprint change not detected")
	}
}

func TestDrift(t *testing.T) {
	added := []Result{{Status: StatusAdded}, {Status: StatusOK}}
	if Drift(added, false) || !Drift(added, true) {
		t.Error("additions must only fail in frozen mode")
	}
	for _, s := range []Status{StatusModified, StatusRemoved} {
		if !Drift([]Result{{Status: s}}, false) {
			t.Errorf("%s must fail without --frozen", s)
		}
	}
	if Drift([]Result{{Status: StatusOK}}, true) {
		t.Error("ok results must not drift")
	}
}

func TestRelockCarriesApprovals(t *testing.T) {
	old := []asset.Entry{mk("rules:generic:a", d('1')), mk("rules:generic:b", d('2'))}
	old[0].Approved = &asset.Approval{By: "a@x"}
	old[1].Approved = &asset.Approval{By: "b@x"}
	live := []asset.Entry{mk("rules:generic:b", d('3')), mk("rules:generic:a", d('1'))}
	out := Relock(old, live)
	if out[0].ID != "rules:generic:a" || out[0].Approved == nil || out[1].Approved != nil {
		t.Errorf("Relock = %+v", out)
	}
}

func TestApprove(t *testing.T) {
	locked := []asset.Entry{mk("rules:generic:a", d('1')), mk("rules:generic:b", d('2')), mk("rules:generic:c", d('3'))}
	live := []asset.Entry{mk("rules:generic:a", d('9')), mk("rules:generic:b", d('8')), mk("rules:generic:d", d('4'))}

	out, approved, err := Approve(locked, live, []string{"rules:generic:a"}, false, "me@x")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(approved, []string{"rules:generic:a"}) {
		t.Errorf("approved = %v", approved)
	}
	byID := index(out)
	if byID["rules:generic:a"].Digest != d('9') || byID["rules:generic:a"].Approved.By != "me@x" {
		t.Error("selected entry not updated")
	}
	if byID["rules:generic:b"].Digest != d('2') {
		t.Error("unselected entry changed")
	}
	if _, ok := byID["rules:generic:d"]; ok {
		t.Error("unselected addition approved")
	}

	out, approved, err = Approve(locked, live, nil, true, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(approved) != 4 || len(out) != 3 {
		t.Errorf("approve --all: approved=%v out=%d", approved, len(out))
	}
	if _, ok := index(out)["rules:generic:c"]; ok {
		t.Error("removed entry kept after approve --all")
	}

	if _, _, err := Approve(locked, live, []string{"rules:generic:typo"}, false, ""); err == nil {
		t.Error("unknown id accepted")
	}

	// Approving an unchanged entry without --by keeps its approval.
	locked[0].Approved = &asset.Approval{By: "old@x"}
	out, _, _ = Approve(locked, locked, []string{"rules:generic:a"}, false, "")
	if index(out)["rules:generic:a"].Approved.By != "old@x" {
		t.Error("existing approval dropped")
	}
}

func FuzzDecode(f *testing.F) {
	b, _ := Encode(New(asset.ScopeProject, "x", sampleEntries()))
	f.Add(b)
	f.Add([]byte(`{"lockfile_version":1}`))
	f.Fuzz(func(t *testing.T, in []byte) {
		lf, err := Decode(in)
		if err != nil {
			return
		}
		out, err := Encode(lf)
		if err != nil {
			t.Fatalf("decoded lockfile does not re-encode: %v", err)
		}
		if _, err := Decode(out); err != nil {
			t.Fatalf("re-encoded lockfile does not decode: %v", err)
		}
	})
}
