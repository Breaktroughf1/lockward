// Package repo implements scan-repo: a static, read-only report of the files
// in an untrusted repository that agents would auto-load or auto-execute.
// Nothing in the scanned repository is ever executed, and the repository's
// own .lockwardignore and lockward.policy.yaml are not honoured, so it
// cannot hide files from the scan or weaken the rules applied to it.
//
// Requirements: LW-FR-12, US-5.
package repo

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/Breaktroughf1/lockward/internal/asset"
	"github.com/Breaktroughf1/lockward/internal/discover"
	"github.com/Breaktroughf1/lockward/internal/exitcode"
	"github.com/Breaktroughf1/lockward/internal/policy"
	"github.com/Breaktroughf1/lockward/internal/scanner"
	"github.com/Breaktroughf1/lockward/internal/textscan"
)

// Item is one auto-loaded asset.
type Item struct {
	ID        string
	Surface   asset.Surface
	Path      string
	LoadedBy  []string
	Executes  string // what it can run or connect to; empty for instructions only
	CanRun    bool   // runs commands (hooks, stdio MCP servers, skills with scripts)
	Connects  bool   // connects to a remote server
	URLs      []string
	Approvals []string // auto-approval settings (LW008)
}

// Result is a scan-repo report.
type Result struct {
	Root              string
	Items             []Item
	Findings          []policy.Finding
	Suppressed        int
	Problems          []asset.Problem
	IgnoreFileSkipped bool
	RepoPolicyIgnored bool
	PolicyFile        string // user-supplied policy, if any
	PolicyDigest      string
	ExitCode          exitcode.Code
	Scanner           []scanner.Finding // imported, informational (LW-FR-16)
}

// maxURLs bounds the hosts listed per item.
const maxURLs = 20

// Scan inspects root. policyPath may be empty for the built-in policy; it
// must never be the scanned repository's own policy file.
func Scan(ctx context.Context, root, policyPath string, scannerSARIF ...string) (*Result, error) {
	res, err := discover.Run(ctx, discover.Options{Root: root, Scope: asset.ScopeProject, NoIgnore: true})
	if err != nil {
		if errors.Is(err, discover.ErrConfig) {
			return nil, &exitcode.Error{Code: exitcode.Usage, Err: err}
		}
		return nil, err
	}
	defer res.Close()
	out := &Result{Root: root, Problems: res.Problems, IgnoreFileSkipped: res.IgnoreFileSkipped}
	if _, err := fs.Stat(res.FS, policy.FileName); err == nil {
		out.RepoPolicyIgnored = true
	}
	pol := policy.Default()
	if policyPath != "" {
		p, digest, found, err := policy.Load(policyPath)
		if err != nil {
			return nil, &exitcode.Error{Code: exitcode.Usage, Err: err}
		}
		if !found {
			return nil, exitcode.New(exitcode.Usage, "policy file %s does not exist", policyPath)
		}
		pol, out.PolicyFile, out.PolicyDigest = p, policyPath, digest
	}
	pr, err := policy.Evaluate(pol, policy.Input{FS: res.FS, Entries: res.Entries, Assets: res.Assets})
	if err != nil {
		return nil, err
	}
	out.Findings, out.Suppressed = pr.Findings, pr.Suppressed
	for _, e := range res.Entries {
		if e.ID == discover.IgnoreID {
			continue
		}
		it, err := describe(res.FS, e, res.Assets[e.ID])
		if err != nil {
			return nil, err
		}
		out.Items = append(out.Items, it)
	}
	var imported []scanner.Finding
	for _, f := range scannerSARIF {
		fs, err := scanner.Load(f, res.Root)
		if err != nil {
			return nil, exitcode.New(exitcode.Usage, "--scanner-sarif: %v", err)
		}
		imported = append(imported, fs...)
	}
	if len(imported) > 0 {
		out.Scanner = scanner.Attach(imported, res.Entries)
	}
	if pr.Errors() > 0 {
		out.ExitCode = exitcode.Policy
	}
	return out, nil
}

var urlPattern = regexp.MustCompile(`https?://([A-Za-z0-9.-]+)`)

func describe(fsys fs.FS, e asset.Entry, a *asset.Asset) (Item, error) {
	it := Item{ID: e.ID, Surface: e.Surface, Path: e.Path, LoadedBy: e.LoadedBy}
	if len(it.LoadedBy) == 0 {
		it.LoadedBy = []string{e.Agent}
	}
	hosts := map[string]bool{}
	addText := func(s string) {
		for _, m := range urlPattern.FindAllStringSubmatch(s, -1) {
			hosts[strings.ToLower(strings.TrimSuffix(m[1], "."))] = true
		}
	}
	scan := func(p string) error {
		return scanURLs(fsys, p, hosts)
	}
	if a != nil {
		it.Approvals = a.AutoApprove
	}
	switch {
	case e.Hook == nil && e.Server == nil && e.Settings == nil && (e.Surface == asset.SurfaceHook || e.Surface == asset.SurfaceMCP || e.Surface == asset.SurfaceSettings):
		// Pinned as raw bytes because it could not be parsed.
		it.Executes = "config file could not be parsed; review it by hand (the agent may still load it)"
		if a != nil && a.ContentPath != "" {
			if err := scan(a.ContentPath); err != nil {
				return it, err
			}
		}
	case e.Surface == asset.SurfaceHook:
		h := e.Hook
		it.CanRun = len(h.Commands()) > 0
		it.Connects = h.URL != ""
		trigger := "on " + h.Event
		if h.Matcher != "" {
			trigger += fmt.Sprintf(" (matcher %q)", h.Matcher)
		}
		switch {
		case it.CanRun:
			it.Executes = fmt.Sprintf("runs %q automatically %s", h.Commands()[0], trigger)
		case h.URL != "":
			it.Executes = fmt.Sprintf("sends events to %s %s", h.URL, trigger)
		case h.Prompt != "":
			it.Executes = "adds a model prompt " + trigger
		case h.Tool != "":
			it.Executes = fmt.Sprintf("calls MCP tool %s/%s %s", h.Server, h.Tool, trigger)
		}
		for _, c := range h.Commands() {
			addText(c)
		}
		addText(h.URL)
		for _, r := range e.ReferencedFiles {
			if err := scan(r.Path); err != nil {
				return it, err
			}
		}
	case e.Surface == asset.SurfaceMCP:
		s := e.Server
		if s.URL != "" {
			it.Connects = true
			it.Executes = "connects to " + s.URL
			if u, err := url.Parse(s.URL); err == nil && u.Hostname() != "" {
				hosts[strings.ToLower(u.Hostname())] = true
			}
		} else if s.Command != "" {
			it.CanRun = true
			it.Executes = "launches " + strings.TrimSpace(s.Command+" "+strings.Join(s.Args, " "))
			addText(strings.Join(s.Args, " "))
		}
		if s.Trust {
			it.Executes += " (trusted: tool calls skip confirmation)"
		}
	case e.Surface == asset.SurfaceSkill:
		scripts := 0
		if a != nil && a.ContentPath != "" {
			for _, f := range e.Files {
				if f.Digest == "" {
					continue
				}
				if f.Mode == "0755" || isScript(f.Path) {
					scripts++
				}
				if err := scan(path.Join(a.ContentPath, f.Path)); err != nil {
					return it, err
				}
			}
		}
		if scripts > 0 {
			it.CanRun = true
			it.Executes = fmt.Sprintf("contains %d script(s) or executable(s) the agent may run", scripts)
		}
	case e.Surface == asset.SurfaceRules:
		if a != nil && a.ContentPath != "" {
			if err := scan(a.ContentPath); err != nil {
				return it, err
			}
		}
	case e.Surface == asset.SurfaceSettings:
		if len(it.Approvals) > 0 {
			it.Executes = "auto-approves: " + strings.Join(it.Approvals, "; ")
		}
	}
	for h := range hosts {
		it.URLs = append(it.URLs, h)
	}
	sort.Strings(it.URLs)
	if len(it.URLs) > maxURLs {
		it.URLs = append(it.URLs[:maxURLs], fmt.Sprintf("… %d more", len(it.URLs)-maxURLs))
	}
	return it, nil
}

var scriptExts = []string{".sh", ".bash", ".zsh", ".py", ".js", ".mjs", ".cjs", ".ts", ".rb", ".pl", ".ps1", ".bat", ".cmd", ".php", ".lua"}

func isScript(p string) bool {
	lower := strings.ToLower(p)
	for _, e := range scriptExts {
		if strings.HasSuffix(lower, e) {
			return true
		}
	}
	return false
}

// scanURLs streams a file (no size cap) and records referenced hosts.
func scanURLs(fsys fs.FS, p string, hosts map[string]bool) error {
	f, err := fsys.Open(p)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}
	defer f.Close()
	if info, err := f.Stat(); err != nil || !info.Mode().IsRegular() {
		return err
	}
	return textscan.Scan(f, func(block []byte) bool { return bytes.Contains(block, []byte("://")) },
		func(_ int, b []byte) {
			for _, m := range urlPattern.FindAllSubmatch(b, -1) {
				hosts[strings.ToLower(strings.TrimSuffix(string(m[1]), "."))] = true
			}
		})
}
