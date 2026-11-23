package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/Breaktroughf1/lockward/internal/lock"
	"github.com/Breaktroughf1/lockward/internal/policy"
)

// TextOptions configures the text renderer.
type TextOptions struct {
	Color   bool // ANSI colour (only when writing to a terminal and NO_COLOR is unset)
	Verbose bool // also list ok entries
}

type palette struct{ red, yellow, green, dim, bold, reset string }

func colors(on bool) palette {
	if !on {
		return palette{}
	}
	return palette{"\x1b[31m", "\x1b[33m", "\x1b[32m", "\x1b[2m", "\x1b[1m", "\x1b[0m"}
}

// Text renders a human-readable report. Every failing line names the item,
// the reason and the exact command to review, approve or fix it (LW-NFR-09).
func Text(w io.Writer, r *Report, o TextOptions) error {
	p := colors(o.Color)
	var b strings.Builder
	for i, s := range r.Scopes {
		if i > 0 {
			b.WriteString("\n")
		}
		fmt.Fprintf(&b, "%s%s scope%s (%s)\n", p.bold, s.Scope, p.reset, s.Lockfile)
		if s.PolicyFile != "" {
			fmt.Fprintf(&b, "  policy: %s (%s)\n", s.PolicyFile, short(s.PolicyDigest))
		} else {
			b.WriteString("  policy: built-in defaults (run 'lockward init' to create lockward.policy.yaml)\n")
		}
		if len(s.IgnorePatterns) > 0 {
			fmt.Fprintf(&b, "  ignore: .lockwardignore has %d pattern(s): %s; %d file(s) inside pinned skills ignored\n",
				len(s.IgnorePatterns), strings.Join(s.IgnorePatterns, ", "), s.Ignored)
		}
		for _, n := range s.Notices {
			fmt.Fprintf(&b, "  note: %s\n", n)
		}
		writeResults(&b, s, r.Frozen, o, p)
		writeFindings(&b, s, p)
		if len(s.Problems) > 0 {
			b.WriteString("\n  problems (pinned or skipped as noted; review them):\n")
			for _, pr := range s.Problems {
				fmt.Fprintf(&b, "    %s%s%s\n", p.yellow, pr.String(), p.reset)
			}
		}
	}
	c := r.Counts()
	status := p.green + "clean" + p.reset
	switch r.ExitCode {
	case 1:
		status = p.red + "drift" + p.reset
	case 2:
		status = p.red + "policy violation" + p.reset
	}
	fmt.Fprintf(&b, "\n%s: %d entries (%d ok, %d modified, %d added, %d removed); %d error(s), %d warning(s)",
		status, c.Entries, c.OK, c.Modified, c.Added, c.Removed, c.Errors, c.Warnings)
	if c.Suppressed > 0 {
		fmt.Fprintf(&b, ", %d suppressed by exceptions", c.Suppressed)
	}
	if c.Added > 0 && !r.Frozen {
		b.WriteString("\nAdditions are reported but do not fail without --frozen.")
	}
	b.WriteString("\n")
	_, err := io.WriteString(w, b.String())
	return err
}

func short(d string) string {
	if len(d) > 19 {
		return d[:19] + "…"
	}
	return d
}

func writeResults(b *strings.Builder, s Scope, frozen bool, o TextOptions, p palette) {
	scopeFlag := ""
	if s.Scope == "user" {
		scopeFlag = " --scope user"
	}
	wrote := false
	for _, res := range s.Results {
		if res.Status == lock.StatusOK && !o.Verbose {
			continue
		}
		if !wrote {
			b.WriteString("\n")
			wrote = true
		}
		color := p.dim
		switch {
		case FailsDrift(res.Status, frozen):
			color = p.red
		case res.Status == lock.StatusAdded:
			color = p.yellow
		}
		e := res.Entry()
		q := ShellQuote(res.ID)
		fmt.Fprintf(b, "  %s%-8s%s  %s  %s%s%s\n", color, res.Status, p.reset, res.ID, p.dim, e.Path, p.reset)
		switch res.Status {
		case lock.StatusModified:
			fmt.Fprintf(b, "            review: lockward diff%s %s\n", scopeFlag, q)
			fmt.Fprintf(b, "            accept: lockward approve%s %s\n", scopeFlag, q)
		case lock.StatusAdded:
			fmt.Fprintf(b, "            review it, then accept: lockward approve%s %s\n", scopeFlag, q)
		case lock.StatusRemoved:
			fmt.Fprintf(b, "            accept the removal: lockward approve%s %s\n", scopeFlag, q)
		}
	}
}

func writeFindings(b *strings.Builder, s Scope, p palette) {
	if len(s.Findings) == 0 {
		return
	}
	b.WriteString("\n")
	for _, f := range s.Findings {
		color := p.yellow
		if f.Severity == policy.SeverityError {
			color = p.red
		}
		loc := f.Path
		if f.Line > 0 {
			loc = fmt.Sprintf("%s:%d", f.Path, f.Line)
		}
		fmt.Fprintf(b, "  %s%-7s%s %s %s  %s\n", color, f.Severity, p.reset, f.Rule, f.Name, f.EntryID)
		fmt.Fprintf(b, "          %s\n", f.Message)
		if loc != "" {
			fmt.Fprintf(b, "          at %s\n", loc)
		}
		fmt.Fprintf(b, "          fix: %s\n", f.Remediation)
	}
}
