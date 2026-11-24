package repo

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/Breaktroughf1/lockward/internal/asset"
	"github.com/Breaktroughf1/lockward/internal/policy"
	"github.com/Breaktroughf1/lockward/internal/report"
)

// Text renders the scan for a terminal.
func Text(w io.Writer, r *Result, color bool) error {
	red, yellow, bold, reset := "", "", "", ""
	if color {
		red, yellow, bold, reset = "\x1b[31m", "\x1b[33m", "\x1b[1m", "\x1b[0m"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%sscan-repo%s %s (read-only; nothing was executed)\n", bold, reset, report.Safe(r.Root))
	if r.PolicyFile != "" {
		fmt.Fprintf(&b, "  policy: %s\n", report.Safe(r.PolicyFile))
	} else {
		b.WriteString("  policy: built-in defaults\n")
	}
	if r.IgnoreFileSkipped {
		b.WriteString("  note: the repository has a .lockwardignore; it was not honoured, so nothing is hidden\n")
	}
	if r.RepoPolicyIgnored {
		b.WriteString("  note: the repository has a lockward.policy.yaml; it was not used (pass --policy to choose one)\n")
	}
	if len(r.Items) == 0 {
		b.WriteString("\n  No files that the supported agents auto-load were found.\n")
	}
	runs, connects := 0, 0
	for _, it := range r.Items {
		if it.CanRun {
			runs++
		}
		if it.Connects {
			connects++
		}
		marker := "  "
		if it.CanRun || len(it.Approvals) > 0 {
			marker = red + "! " + reset
		} else if it.Connects {
			marker = yellow + "~ " + reset
		}
		fmt.Fprintf(&b, "\n%s%-8s %s\n", marker, it.Surface, report.Safe(it.Path))
		fmt.Fprintf(&b, "           loaded by: %s\n", report.Safe(strings.Join(it.LoadedBy, ", ")))
		if it.Executes != "" {
			fmt.Fprintf(&b, "           %s\n", report.Safe(it.Executes))
		} else if it.Surface == asset.SurfaceRules || it.Surface == asset.SurfaceSkill {
			b.WriteString("           instructions the agent reads automatically\n")
		}
		if len(it.URLs) > 0 {
			fmt.Fprintf(&b, "           references: %s\n", report.Safe(strings.Join(it.URLs, ", ")))
		}
	}
	if len(r.Findings) > 0 {
		b.WriteString("\nfindings:\n")
		for _, f := range r.Findings {
			c := yellow
			if f.Severity == policy.SeverityError {
				c = red
			}
			loc := f.Path
			if f.Line > 0 {
				loc = fmt.Sprintf("%s:%d", f.Path, f.Line)
			}
			fmt.Fprintf(&b, "  %s%-7s%s %s %s  %s\n          %s\n          at %s\n", c, f.Severity, reset, f.Rule, f.Name, report.Safe(f.EntryID), report.Safe(f.Message), report.Safe(loc))
		}
	}
	if len(r.Problems) > 0 {
		b.WriteString("\nproblems:\n")
		for _, p := range r.Problems {
			fmt.Fprintf(&b, "  %s\n", report.Safe(p.String()))
		}
	}
	errs, warns := 0, 0
	for _, f := range r.Findings {
		if f.Severity == policy.SeverityError {
			errs++
		} else {
			warns++
		}
	}
	fmt.Fprintf(&b, "\n%d auto-loaded item(s): %d can run commands, %d connect to servers; %d error(s), %d warning(s)\n",
		len(r.Items), runs, connects, errs, warns)
	if runs > 0 || errs > 0 {
		b.WriteString("Review the items marked ! before opening this repository in an agent or IDE.\n")
	}
	_, err := io.WriteString(w, b.String())
	return err
}

type jsonItem struct {
	ID        string   `json:"id"`
	Surface   string   `json:"surface"`
	Path      string   `json:"path"`
	LoadedBy  []string `json:"loaded_by"`
	Executes  string   `json:"executes,omitempty"`
	CanRun    bool     `json:"can_run_commands"`
	Connects  bool     `json:"connects_to_server"`
	URLs      []string `json:"referenced_hosts"`
	Approvals []string `json:"auto_approvals"`
}

// JSON renders the scan as JSON.
func JSON(w io.Writer, r *Result, version string) error {
	type finding struct {
		Rule     string `json:"rule"`
		Name     string `json:"name"`
		Severity string `json:"severity"`
		ID       string `json:"id"`
		Path     string `json:"path,omitempty"`
		Line     int    `json:"line,omitempty"`
		Message  string `json:"message"`
	}
	out := struct {
		SchemaVersion     int        `json:"schema_version"`
		Tool              string     `json:"tool"`
		Version           string     `json:"version"`
		Root              string     `json:"root"`
		ExitCode          int        `json:"exit_code"`
		IgnoreFileSkipped bool       `json:"ignore_file_not_honoured"`
		RepoPolicyIgnored bool       `json:"repo_policy_not_used"`
		Items             []jsonItem `json:"items"`
		Findings          []finding  `json:"findings"`
		Problems          []string   `json:"problems"`
	}{SchemaVersion: 1, Tool: "lockward", Version: version, Root: r.Root, ExitCode: int(r.ExitCode),
		IgnoreFileSkipped: r.IgnoreFileSkipped, RepoPolicyIgnored: r.RepoPolicyIgnored,
		Items: []jsonItem{}, Findings: []finding{}, Problems: []string{}}
	for _, it := range r.Items {
		out.Items = append(out.Items, jsonItem{ID: it.ID, Surface: string(it.Surface), Path: it.Path, LoadedBy: it.LoadedBy,
			Executes: it.Executes, CanRun: it.CanRun, Connects: it.Connects, URLs: nonNil(it.URLs), Approvals: nonNil(it.Approvals)})
	}
	for _, f := range r.Findings {
		out.Findings = append(out.Findings, finding{f.Rule, f.Name, string(f.Severity), f.EntryID, f.Path, f.Line, f.Message})
	}
	for _, p := range r.Problems {
		out.Problems = append(out.Problems, p.String())
	}
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// SARIF renders the scan's findings as SARIF 2.1.0, plus a note-level result
// for every item that can run commands or connect to a server.
func SARIF(w io.Writer, r *Result, version string) error {
	s := report.Scope{Scope: asset.ScopeProject, Findings: r.Findings, Suppressed: r.Suppressed}
	for _, it := range r.Items {
		if it.CanRun || it.Connects {
			file, _, _ := strings.Cut(it.Path, "#")
			s.Notes = append(s.Notes, report.Note{ID: it.ID, Path: file,
				Message: fmt.Sprintf("%s %s is auto-loaded by %s and %s", it.Surface, it.Path, strings.Join(it.LoadedBy, ", "), it.Executes)})
		}
	}
	return report.SARIF(w, &report.Report{Version: version, Scopes: []report.Scope{s}, ExitCode: int(r.ExitCode)})
}
