package report

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/url"
	"strings"

	"github.com/Breaktroughf1/lockward/internal/asset"
	"github.com/Breaktroughf1/lockward/internal/lock"
	"github.com/Breaktroughf1/lockward/internal/policy"
)

// SARIF 2.1.0 types (only the fields Lockward emits).
type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool               sarifTool                  `json:"tool"`
	OriginalURIBaseIDs map[string]sarifArtifactID `json:"originalUriBaseIds"`
	Results            []sarifResult              `json:"results"`
}

type sarifArtifactID struct {
	Description sarifText `json:"description"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID                   string         `json:"id"`
	Name                 string         `json:"name"`
	ShortDescription     sarifText      `json:"shortDescription"`
	FullDescription      sarifText      `json:"fullDescription"`
	Help                 sarifText      `json:"help"`
	HelpURI              string         `json:"helpUri"`
	DefaultConfiguration sarifRuleLevel `json:"defaultConfiguration"`
	Properties           sarifRuleProps `json:"properties"`
}

type sarifRuleLevel struct {
	Level string `json:"level"`
}

type sarifRuleProps struct {
	Tags []string `json:"tags"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	RuleIndex           int               `json:"ruleIndex"`
	Level               string            `json:"level"`
	Message             sarifText         `json:"message"`
	Locations           []sarifLocation   `json:"locations"`
	PartialFingerprints map[string]string `json:"partialFingerprints"`
	Properties          map[string]string `json:"properties"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
	Region           *sarifRegion  `json:"region,omitempty"`
}

type sarifArtifact struct {
	URI       string `json:"uri"`
	URIBaseID string `json:"uriBaseId"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

// Drift rule ids used in SARIF output.
const (
	RuleDriftModified = "drift-modified"
	RuleDriftAdded    = "drift-added"
	RuleDriftRemoved  = "drift-removed"
)

func sarifRules() []sarifRule {
	help := InformationURI + "/blob/main/docs/POLICY.md"
	drift := func(id, name, short, full, fix string) sarifRule {
		return sarifRule{
			ID: id, Name: name, ShortDescription: sarifText{short}, FullDescription: sarifText{full},
			Help: sarifText{fix}, HelpURI: InformationURI + "/blob/main/docs/USAGE.md#verify",
			DefaultConfiguration: sarifRuleLevel{"error"}, Properties: sarifRuleProps{Tags: []string{"security", "supply-chain", "drift"}},
		}
	}
	rules := []sarifRule{
		drift(RuleDriftModified, "asset-modified", "Agent asset changed since it was approved",
			"The content of a skill, MCP server definition, hook, rules file or setting differs from lockward.lock.",
			"Review with 'lockward diff <id>' and accept with 'lockward approve <id>'."),
		drift(RuleDriftAdded, "asset-added", "Agent asset not in the lockfile",
			"An agent would load an asset that has never been approved.",
			"Review the asset and accept it with 'lockward approve <id>'."),
		drift(RuleDriftRemoved, "asset-removed", "Approved agent asset is missing",
			"An asset recorded in lockward.lock is no longer present.",
			"Accept the removal with 'lockward approve <id>'."),
	}
	for _, r := range policy.Rules {
		rules = append(rules, sarifRule{
			ID: r.ID, Name: r.Name, ShortDescription: sarifText{r.Summary}, FullDescription: sarifText{r.Summary},
			Help: sarifText{r.Help}, HelpURI: help + "#" + strings.ToLower(r.ID),
			DefaultConfiguration: sarifRuleLevel{level(r.Default)}, Properties: sarifRuleProps{Tags: []string{"security", "supply-chain", "policy"}},
		})
	}
	return rules
}

func level(s policy.Severity) string {
	if s == policy.SeverityError {
		return "error"
	}
	return "warning"
}

// SARIF renders a SARIF 2.1.0 log with one result per drifted entry and per
// policy finding (US-2).
func SARIF(w io.Writer, r *Report) error {
	rules := sarifRules()
	idx := map[string]int{}
	for i, rule := range rules {
		idx[rule.ID] = i
	}
	run := sarifRun{
		Tool: sarifTool{Driver: sarifDriver{Name: "lockward", Version: r.Version, InformationURI: InformationURI, Rules: rules}},
		OriginalURIBaseIDs: map[string]sarifArtifactID{
			"PROJECTROOT": {Description: sarifText{"The project root (directory containing lockward.lock)."}},
			"USERHOME":    {Description: sarifText{"The user's home directory (user scope)."}},
		},
		Results: []sarifResult{},
	}
	for _, s := range r.Scopes {
		base := "PROJECTROOT"
		if s.Scope == asset.ScopeUser {
			base = "USERHOME"
		}
		for _, res := range s.Results {
			if res.Status == lock.StatusOK {
				continue
			}
			ruleID := map[lock.Status]string{lock.StatusModified: RuleDriftModified, lock.StatusAdded: RuleDriftAdded, lock.StatusRemoved: RuleDriftRemoved}[res.Status]
			lvl := "error"
			if !FailsDrift(res.Status, r.Frozen) {
				lvl = "warning"
			}
			e := res.Entry()
			file, ptr, _ := strings.Cut(e.Path, "#")
			uri := file
			msg := fmt.Sprintf("%s %s %s (%s)", e.Surface, res.ID, res.Status, e.Path)
			if res.Status == lock.StatusRemoved && s.Scope == asset.ScopeProject {
				uri = lock.ProjectFileName
			}
			if ptr != "" {
				msg += " at JSON pointer " + ptr
			}
			q := ShellQuote(res.ID)
			msg += ". " + map[lock.Status]string{
				lock.StatusModified: "Review: lockward diff " + q + "; accept: lockward approve " + q,
				lock.StatusAdded:    "Review it, then accept: lockward approve " + q,
				lock.StatusRemoved:  "Accept the removal: lockward approve " + q,
			}[res.Status]
			run.Results = append(run.Results, sarifResult{
				RuleID: ruleID, RuleIndex: idx[ruleID], Level: lvl, Message: sarifText{msg},
				Locations:           []sarifLocation{location(uri, base, 0)},
				PartialFingerprints: fingerprint(ruleID, res.ID, ""),
				Properties:          map[string]string{"entryId": res.ID, "scope": string(s.Scope), "status": string(res.Status)},
			})
		}
		for _, f := range s.Findings {
			file, _, _ := strings.Cut(f.Path, "#")
			run.Results = append(run.Results, sarifResult{
				RuleID: f.Rule, RuleIndex: idx[f.Rule], Level: level(f.Severity),
				Message:             sarifText{fmt.Sprintf("%s: %s. Fix: %s", f.EntryID, f.Message, f.Remediation)},
				Locations:           []sarifLocation{location(file, base, f.Line)},
				PartialFingerprints: fingerprint(f.Rule, f.EntryID, f.Message),
				Properties:          map[string]string{"entryId": f.EntryID, "scope": string(s.Scope)},
			})
		}
	}
	return encode(w, sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs:    []sarifRun{run},
	})
}

func location(file, base string, line int) sarifLocation {
	loc := sarifLocation{PhysicalLocation: sarifPhysical{ArtifactLocation: sarifArtifact{URI: escapePath(file), URIBaseID: base}}}
	if line > 0 {
		loc.PhysicalLocation.Region = &sarifRegion{StartLine: line}
	}
	return loc
}

func escapePath(p string) string {
	if p == "" {
		return "."
	}
	parts := strings.Split(p, "/")
	for i, s := range parts {
		parts[i] = url.PathEscape(s)
	}
	return strings.Join(parts, "/")
}

// fingerprint gives GitHub code scanning a stable identity per result.
func fingerprint(rule, id, msg string) map[string]string {
	h := sha256.Sum256([]byte(rule + "\x00" + id + "\x00" + msg))
	return map[string]string{"lockward/v1": hex.EncodeToString(h[:16])}
}
