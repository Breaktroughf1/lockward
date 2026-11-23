package asset

import (
	"slices"
	"testing"
)

func TestIDRoundTrip(t *testing.T) {
	id := MakeID(SurfaceHook, AgentClaudeCode, ".claude/settings.json#PreToolUse/0/0")
	s, a, n, err := ParseID(id)
	if err != nil || s != SurfaceHook || a != AgentClaudeCode || n != ".claude/settings.json#PreToolUse/0/0" {
		t.Errorf("ParseID(%q) = %v %v %v %v", id, s, a, n, err)
	}
	for _, bad := range []string{"", "skill", "skill:x", "skill:x:", "widget:x:y"} {
		if _, _, _, err := ParseID(bad); err == nil {
			t.Errorf("ParseID(%q) accepted", bad)
		}
	}
}

func TestPackagePinned(t *testing.T) {
	for _, tc := range []struct {
		p    *Package
		want bool
	}{
		{nil, false},
		{&Package{Ecosystem: "npm", Name: "x"}, false},
		{&Package{Ecosystem: "npm", Name: "x", Version: "1.0.0"}, true},
		{&Package{Ecosystem: "oci", Name: "img", Version: "1.0"}, false},
		{&Package{Ecosystem: "oci", Name: "img", Digest: "sha256:ab"}, true},
	} {
		if got := tc.p.Pinned(); got != tc.want {
			t.Errorf("%+v.Pinned() = %v, want %v", tc.p, got, tc.want)
		}
	}
}

func TestHookCommandsAndSource(t *testing.T) {
	h := &Hook{Command: "a", Bash: "b", Args: []string{"x", "y"}}
	if got := h.Commands(); !slices.Equal(got, []string{"a", "b", "x y"}) {
		t.Errorf("Commands = %q", got)
	}
	if (*Hook)(nil).Commands() != nil {
		t.Error("nil hook has commands")
	}
	if (&Source{Type: "npm", Ref: "pkg"}).String() != "npm:pkg" || (*Source)(nil).String() != "" {
		t.Error("Source.String")
	}
	if !SurfaceRules.Valid() || Surface("x").Valid() {
		t.Error("Surface.Valid")
	}
	if (Problem{Agent: "a", Path: "p", Message: "m"}).String() != "a: p: m" {
		t.Error("Problem.String")
	}
}
