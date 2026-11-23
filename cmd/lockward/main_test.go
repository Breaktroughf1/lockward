package main

import (
	"bytes"
	"slices"
	"strings"
	"testing"

	"github.com/Breaktroughf1/lockward/internal/exitcode"
)

type result struct {
	code           int
	stdout, stderr string
}

func runCLI(args ...string) result {
	var out, errb bytes.Buffer
	code := run(args, &out, &errb)
	return result{code: code, stdout: out.String(), stderr: errb.String()}
}

func TestRun(t *testing.T) {
	const (
		clean    = int(exitcode.Clean)
		usage    = int(exitcode.Usage)
		internal = int(exitcode.Internal)
	)
	tests := []struct {
		name       string
		args       []string
		wantCode   int
		wantStdout string // substring; "" means stdout must be empty
		wantStderr string // substring; "" means stderr must be empty
	}{
		// Top level.
		{"no args", nil, usage, "", "Usage:"},
		{"--help", []string{"--help"}, clean, "Commands:", ""},
		{"-h", []string{"-h"}, clean, "Commands:", ""},
		{"help", []string{"help"}, clean, "Commands:", ""},
		{"help command", []string{"help", "verify"}, clean, "--frozen", ""},
		{"help unknown command", []string{"help", "nope"}, usage, "", "unknown command"},
		{"help too many", []string{"help", "a", "b"}, usage, "", "at most one"},
		{"unknown command", []string{"frobnicate"}, usage, "", `unknown command "frobnicate"`},
		{"command -h", []string{"scan-repo", "-h"}, clean, "Usage: lockward scan-repo", ""},
		{"unknown flag", []string{"verify", "--nope"}, usage, "", "flag provided but not defined"},

		// version.
		{"version", []string{"version"}, clean, "lockward ", ""},
		{"version extra arg", []string{"version", "x"}, usage, "", "unexpected argument"},

		// init.
		{"init", []string{"init"}, internal, "", "not implemented yet"},
		{"init extra arg", []string{"init", "x"}, usage, "", "unexpected argument"},

		// lock.
		{"lock", []string{"lock"}, internal, "", "roadmap week 3"},
		{"lock scope user", []string{"lock", "--scope", "user"}, internal, "", "not implemented"},
		{"lock scope project", []string{"lock", "--scope=project"}, internal, "", "not implemented"},
		{"lock scope all", []string{"lock", "-scope", "all"}, internal, "", "not implemented"},
		{"lock bad scope", []string{"lock", "--scope", "global"}, usage, "", "must be one of user, project, all"},

		// verify.
		{"verify", []string{"verify"}, internal, "", "roadmap week 4"},
		{"verify frozen sarif", []string{"verify", "--frozen", "--format", "sarif"}, internal, "", "not implemented"},
		{"verify bad format", []string{"verify", "--format", "cyclonedx"}, usage, "", "must be one of text, json, sarif"},
		{"verify extra arg", []string{"verify", "x"}, usage, "", "unexpected argument"},

		// diff.
		{"diff", []string{"diff"}, internal, "", "not implemented"},
		{"diff id", []string{"diff", "skill:claude-code:pdf"}, internal, "", "not implemented"},
		{"diff two ids", []string{"diff", "a", "b"}, usage, "", "at most one entry id"},
		{"diff empty id", []string{"diff", ""}, usage, "", "empty argument"},

		// approve.
		{"approve ids", []string{"approve", "a", "b"}, internal, "", "not implemented"},
		{"approve all", []string{"approve", "--all"}, internal, "", "not implemented"},
		{"approve nothing", []string{"approve"}, usage, "", "at least one entry id"},
		{"approve ids and all", []string{"approve", "a", "--all"}, usage, "", "not both"},

		// status.
		{"status", []string{"status"}, internal, "", "not implemented"},
		{"status extra arg", []string{"status", "x"}, usage, "", "unexpected argument"},

		// scan-repo, including flags after positionals (PRD §8).
		{"scan-repo", []string{"scan-repo", "./repo"}, internal, "", "roadmap week 6"},
		{"scan-repo flag after path", []string{"scan-repo", "./repo", "--format", "json"}, internal, "", "not implemented"},
		{"scan-repo flag before path", []string{"scan-repo", "--format", "sarif", "./repo"}, internal, "", "not implemented"},
		{"scan-repo dash path after --", []string{"scan-repo", "--", "--format"}, internal, "", "not implemented"},
		{"scan-repo no path", []string{"scan-repo"}, usage, "", "exactly one repository path, got 0"},
		{"scan-repo two paths", []string{"scan-repo", "a", "b"}, usage, "", "exactly one repository path, got 2"},
		{"scan-repo two paths around flag", []string{"scan-repo", "a", "--format", "json", "b"}, usage, "", "got 2"},
		{"scan-repo bad format after path", []string{"scan-repo", "./repo", "--format", "xml"}, usage, "", "must be one of"},

		// bom.
		{"bom", []string{"bom"}, internal, "", "not implemented"},
		{"bom cyclonedx", []string{"bom", "--format", "cyclonedx"}, internal, "", "not implemented"},
		{"bom bad format", []string{"bom", "--format", "spdx"}, usage, "", "must be one of cyclonedx"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := runCLI(tt.args...)
			if got.code != tt.wantCode {
				t.Errorf("exit code = %d, want %d\nstdout: %s\nstderr: %s", got.code, tt.wantCode, got.stdout, got.stderr)
			}
			checkStream(t, "stdout", got.stdout, tt.wantStdout)
			checkStream(t, "stderr", got.stderr, tt.wantStderr)
		})
	}
}

func checkStream(t *testing.T, name, got, want string) {
	t.Helper()
	if want == "" {
		if got != "" {
			t.Errorf("%s = %q, want empty", name, got)
		}
		return
	}
	if !strings.Contains(got, want) {
		t.Errorf("%s = %q, want substring %q", name, got, want)
	}
}

// TestCommandSurface pins the command set to PRD §8.
func TestCommandSurface(t *testing.T) {
	want := []string{"init", "lock", "verify", "diff", "approve", "status", "scan-repo", "bom", "version"}
	var got []string
	for _, c := range commands {
		got = append(got, c.name)
	}
	if !slices.Equal(got, want) {
		t.Errorf("commands = %v, want %v (PRD §8)", got, want)
	}
}

// TestInvariant_StubNeverReportsClean guards against a stubbed command exiting
// 0, which CI would read as "no drift". Every command except version must exit
// non-zero until it is implemented.
func TestInvariant_StubNeverReportsClean(t *testing.T) {
	validArgs := map[string][]string{
		"init":      nil,
		"lock":      nil,
		"verify":    {"--frozen"},
		"diff":      nil,
		"approve":   {"--all"},
		"status":    nil,
		"scan-repo": {"."},
		"bom":       nil,
	}
	for _, c := range commands {
		if c.name == "version" {
			continue
		}
		args, ok := validArgs[c.name]
		if !ok {
			t.Errorf("no valid-args case for command %q; add one", c.name)
			continue
		}
		if got := runCLI(append([]string{c.name}, args...)...); got.code == int(exitcode.Clean) {
			t.Errorf("%s exited %d (clean) while stubbed", c.name, got.code)
		}
	}
}

func TestEveryCommandHasHelp(t *testing.T) {
	for _, c := range commands {
		got := runCLI("help", c.name)
		if got.code != int(exitcode.Clean) || !strings.HasPrefix(got.stdout, "Usage: lockward "+c.name) {
			t.Errorf("help %s: code %d, stdout %q", c.name, got.code, got.stdout)
		}
	}
}

func TestResolveVersion(t *testing.T) {
	old := version
	t.Cleanup(func() { version = old })
	version = "v9.9.9"
	if got := resolveVersion(); got != "v9.9.9" {
		t.Errorf("resolveVersion() = %q, want injected v9.9.9", got)
	}
	version = ""
	if got := resolveVersion(); got == "" {
		t.Error("resolveVersion() returned empty string")
	}
}
