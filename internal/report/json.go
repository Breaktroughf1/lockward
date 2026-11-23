package report

import (
	"encoding/json"
	"io"
)

// JSONSchemaVersion versions the JSON report format.
const JSONSchemaVersion = 1

type jsonReport struct {
	SchemaVersion int         `json:"schema_version"`
	Tool          string      `json:"tool"`
	Version       string      `json:"version"`
	Frozen        bool        `json:"frozen"`
	ExitCode      int         `json:"exit_code"`
	Summary       jsonSummary `json:"summary"`
	Scopes        []jsonScope `json:"scopes"`
}

type jsonSummary struct {
	Entries    int `json:"entries"`
	OK         int `json:"ok"`
	Added      int `json:"added"`
	Removed    int `json:"removed"`
	Modified   int `json:"modified"`
	Errors     int `json:"errors"`
	Warnings   int `json:"warnings"`
	Suppressed int `json:"suppressed"`
	Problems   int `json:"problems"`
}

type jsonScope struct {
	Scope          string        `json:"scope"`
	Lockfile       string        `json:"lockfile"`
	Policy         *jsonPolicy   `json:"policy"`
	IgnorePatterns []string      `json:"ignore_patterns"`
	Ignored        int           `json:"ignored_files"`
	Results        []jsonResult  `json:"results"`
	Findings       []jsonFinding `json:"findings"`
	Suppressed     int           `json:"suppressed"`
	Problems       []jsonProblem `json:"problems"`
	Notices        []string      `json:"notices"`
}

type jsonPolicy struct {
	File   string `json:"file"`
	Digest string `json:"digest"`
}

type jsonResult struct {
	ID           string `json:"id"`
	Status       string `json:"status"`
	Surface      string `json:"surface"`
	Agent        string `json:"agent"`
	Path         string `json:"path"`
	LockedDigest string `json:"locked_digest,omitempty"`
	LiveDigest   string `json:"live_digest,omitempty"`
}

type jsonFinding struct {
	Rule        string `json:"rule"`
	Name        string `json:"name"`
	Severity    string `json:"severity"`
	ID          string `json:"id"`
	Path        string `json:"path,omitempty"`
	Line        int    `json:"line,omitempty"`
	Message     string `json:"message"`
	Remediation string `json:"remediation"`
}

type jsonProblem struct {
	Agent   string `json:"agent"`
	Path    string `json:"path"`
	Message string `json:"message"`
}

// JSON renders the report as indented JSON with stable field order.
func JSON(w io.Writer, r *Report) error {
	c := r.Counts()
	out := jsonReport{
		SchemaVersion: JSONSchemaVersion, Tool: "lockward", Version: r.Version, Frozen: r.Frozen, ExitCode: r.ExitCode,
		Summary: jsonSummary(c),
		Scopes:  []jsonScope{},
	}
	for _, s := range r.Scopes {
		js := jsonScope{
			Scope: string(s.Scope), Lockfile: s.Lockfile, IgnorePatterns: nonNil(s.IgnorePatterns), Ignored: s.Ignored,
			Results: []jsonResult{}, Findings: []jsonFinding{}, Problems: []jsonProblem{}, Suppressed: s.Suppressed,
			Notices: nonNil(s.Notices),
		}
		if s.PolicyFile != "" {
			js.Policy = &jsonPolicy{File: s.PolicyFile, Digest: s.PolicyDigest}
		}
		for _, res := range s.Results {
			e := res.Entry()
			jr := jsonResult{ID: res.ID, Status: string(res.Status), Surface: string(e.Surface), Agent: e.Agent, Path: e.Path}
			if res.Locked != nil {
				jr.LockedDigest = res.Locked.Digest
			}
			if res.Live != nil {
				jr.LiveDigest = res.Live.Digest
			}
			js.Results = append(js.Results, jr)
		}
		for _, f := range s.Findings {
			js.Findings = append(js.Findings, jsonFinding{
				Rule: f.Rule, Name: f.Name, Severity: string(f.Severity), ID: f.EntryID, Path: f.Path, Line: f.Line,
				Message: f.Message, Remediation: f.Remediation,
			})
		}
		for _, p := range s.Problems {
			js.Problems = append(js.Problems, jsonProblem(p))
		}
		out.Scopes = append(out.Scopes, js)
	}
	return encode(w, out)
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func encode(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
