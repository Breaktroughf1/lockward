// Package scanner imports SARIF 2.1.0 results from external content scanners
// (SkillSpector, Cisco skill-scanner, Snyk agent-scan and others) and
// attaches each result to the lockfile entry its location points into
// (LW-FR-16). Imported findings are informational: they are shown for review
// but never change Lockward's exit code, so no external tool can override a
// deterministic drift or policy result (ADR-0003).
package scanner

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Breaktroughf1/lockward/internal/asset"
)

// MaxSize bounds an imported SARIF file.
const MaxSize = 64 << 20

// Finding is one imported scanner result.
type Finding struct {
	Tool    string
	RuleID  string
	Level   string // error | warning | note | none
	URI     string // location as given by the scanner (normalised)
	Line    int
	Message string
	EntryID string // attached lockfile entry, empty if none matched
}

type sarifLog struct {
	Version string `json:"version"`
	Runs    []struct {
		Tool struct {
			Driver struct {
				Name string `json:"name"`
			} `json:"driver"`
		} `json:"tool"`
		Results []struct {
			RuleID  string `json:"ruleId"`
			Level   string `json:"level"`
			Message struct {
				Text string `json:"text"`
			} `json:"message"`
			Locations []struct {
				PhysicalLocation struct {
					ArtifactLocation struct {
						URI string `json:"uri"`
					} `json:"artifactLocation"`
					Region struct {
						StartLine int `json:"startLine"`
					} `json:"region"`
				} `json:"physicalLocation"`
			} `json:"locations"`
		} `json:"results"`
	} `json:"runs"`
}

// Load reads a SARIF file. root is the scope root, used to turn absolute
// file URIs into scope-relative paths.
func Load(file, root string) ([]Finding, error) {
	f, err := os.Open(file) //nolint:gosec // file chosen by the user via --scanner-sarif
	if err != nil {
		return nil, fmt.Errorf("scanner SARIF: %w", err)
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, MaxSize+1))
	if err != nil {
		return nil, fmt.Errorf("scanner SARIF %s: %w", file, err)
	}
	if len(b) > MaxSize {
		return nil, fmt.Errorf("scanner SARIF %s: larger than %d bytes", file, MaxSize)
	}
	return Parse(b, root)
}

// Parse decodes SARIF 2.1.0 results.
func Parse(b []byte, root string) ([]Finding, error) {
	var log sarifLog
	if err := json.Unmarshal(b, &log); err != nil {
		return nil, fmt.Errorf("scanner SARIF: %w", err)
	}
	if log.Version != "2.1.0" {
		return nil, fmt.Errorf("scanner SARIF: unsupported version %q (want 2.1.0)", log.Version)
	}
	var out []Finding
	for _, run := range log.Runs {
		tool := run.Tool.Driver.Name
		if tool == "" {
			tool = "unknown scanner"
		}
		for _, r := range run.Results {
			level := r.Level
			if level == "" {
				level = "warning" // SARIF default
			}
			fd := Finding{Tool: tool, RuleID: r.RuleID, Level: level, Message: r.Message.Text}
			if len(r.Locations) > 0 {
				loc := r.Locations[0].PhysicalLocation
				fd.URI = normalise(loc.ArtifactLocation.URI, root)
				fd.Line = loc.Region.StartLine
			}
			out = append(out, fd)
		}
	}
	return out, nil
}

// normalise turns a SARIF artifact URI into a slash-separated path relative
// to root where possible.
func normalise(uri, root string) string {
	p := uri
	if u, err := url.Parse(uri); err == nil && (u.Scheme == "file" || u.Scheme == "") {
		p = u.Path
		if u.Scheme == "" {
			if unescaped, err := url.PathUnescape(uri); err == nil {
				p = unescaped
			}
		}
	}
	p = filepath.ToSlash(p)
	if root != "" && (filepath.IsAbs(filepath.FromSlash(p)) || strings.HasPrefix(p, "/")) {
		if rel, err := filepath.Rel(root, filepath.FromSlash(p)); err == nil && !strings.HasPrefix(rel, "..") {
			p = filepath.ToSlash(rel)
		}
	}
	return strings.TrimPrefix(path.Clean("/"+strings.TrimPrefix(p, "./")), "/")
}

// Attach links each finding to the entry whose file it names, or the skill
// whose directory contains it. It returns the findings sorted for output.
func Attach(findings []Finding, entries []asset.Entry) []Finding {
	byFile := map[string]string{}
	type dir struct{ path, id string }
	var dirs []dir
	for _, e := range entries {
		file, _, _ := strings.Cut(e.Path, "#")
		if e.Surface == asset.SurfaceSkill {
			dirs = append(dirs, dir{file, e.ID})
		}
		if _, ok := byFile[file]; !ok {
			byFile[file] = e.ID
		}
	}
	// Longest directory first so nested skills win over their parents.
	sort.Slice(dirs, func(i, j int) bool { return len(dirs[i].path) > len(dirs[j].path) })
	out := make([]Finding, len(findings))
	for i, f := range findings {
		out[i] = f
		if id, ok := byFile[f.URI]; ok && f.URI != "" {
			out[i].EntryID = id
			continue
		}
		for _, d := range dirs {
			if strings.HasPrefix(f.URI, d.path+"/") {
				out[i].EntryID = d.id
				break
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.EntryID != b.EntryID {
			return a.EntryID < b.EntryID
		}
		if a.Tool != b.Tool {
			return a.Tool < b.Tool
		}
		if a.URI != b.URI {
			return a.URI < b.URI
		}
		return a.Line < b.Line
	})
	return out
}
