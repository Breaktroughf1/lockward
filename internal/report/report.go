// Package report renders verification results as text, JSON, SARIF 2.1.0 and
// CycloneDX 1.6. Renderers only see data that is already redacted, so they
// can never emit environment or header values (THREAT_MODEL §6.5).
//
// Requirements: LW-FR-13, LW-NFR-06, LW-NFR-09.
package report

import (
	"strings"

	"github.com/Breaktroughf1/lockward/internal/asset"
	"github.com/Breaktroughf1/lockward/internal/lock"
	"github.com/Breaktroughf1/lockward/internal/policy"
)

// InformationURI is the project home used in SARIF and CycloneDX output.
const InformationURI = "https://github.com/Breaktroughf1/lockward"

// Report is the outcome of verify (or status) across one or more scopes.
type Report struct {
	Version  string // lockward version
	Frozen   bool
	Scopes   []Scope
	ExitCode int
}

// Scope is the outcome for one scope.
type Scope struct {
	Scope          asset.Scope
	Lockfile       string // display path of the lockfile
	Results        []lock.Result
	Findings       []policy.Finding
	Suppressed     int
	Problems       []asset.Problem
	PolicyFile     string // display path; empty when built-in defaults are used
	PolicyDigest   string
	IgnorePatterns []string
	Ignored        int
	Notices        []string
	Notes          []Note // informational items (scan-repo); SARIF level "note"
}

// Note is an informational SARIF result.
type Note struct {
	ID      string
	Path    string
	Message string
}

// Counts summarises a report.
type Counts struct {
	Entries, OK, Added, Removed, Modified, Errors, Warnings, Suppressed, Problems int
}

// Counts totals results and findings across scopes.
func (r *Report) Counts() Counts {
	var c Counts
	for _, s := range r.Scopes {
		for _, res := range s.Results {
			c.Entries++
			switch res.Status {
			case lock.StatusOK:
				c.OK++
			case lock.StatusAdded:
				c.Added++
			case lock.StatusRemoved:
				c.Removed++
			case lock.StatusModified:
				c.Modified++
			}
		}
		for _, f := range s.Findings {
			if f.Severity == policy.SeverityError {
				c.Errors++
			} else {
				c.Warnings++
			}
		}
		c.Suppressed += s.Suppressed
		c.Problems += len(s.Problems)
	}
	return c
}

// FailsDrift reports whether a drift result fails under the frozen setting.
func FailsDrift(s lock.Status, frozen bool) bool {
	return s == lock.StatusModified || s == lock.StatusRemoved || (frozen && s == lock.StatusAdded)
}

// ShellQuote quotes s for POSIX shells when it contains characters outside a
// conservative safe set, so printed fix commands can be pasted as-is.
func ShellQuote(s string) string {
	if s != "" && strings.Trim(s, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_@%+=:,./-#") == "" && s[0] != '#' {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
