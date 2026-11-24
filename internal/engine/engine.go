// Package engine orchestrates lock, verify, approve and diff for one scope:
// discovery, tool fingerprints, lockfile I/O, comparison and policy. The CLI
// in cmd/lockward only parses flags and prints what the engine returns.
package engine

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"

	"github.com/Breaktroughf1/lockward/internal/asset"
	"github.com/Breaktroughf1/lockward/internal/discover"
	"github.com/Breaktroughf1/lockward/internal/exitcode"
	"github.com/Breaktroughf1/lockward/internal/lock"
	"github.com/Breaktroughf1/lockward/internal/policy"
	"github.com/Breaktroughf1/lockward/internal/report"
	"github.com/Breaktroughf1/lockward/internal/scanner"
	"github.com/Breaktroughf1/lockward/internal/snapshot"
	"github.com/Breaktroughf1/lockward/internal/tools"
)

// Config describes one scope.
type Config struct {
	Scope           asset.Scope
	Root            string            // scope root directory
	Lockfile        string            // lockfile path
	DisplayLockfile string            // lockfile path as shown to the user
	PolicyPath      string            // policy file path (missing file means built-in defaults)
	DisplayPolicy   string            // policy path as shown to the user
	Tools           map[string]string // entry id -> tools/list JSON file (LW-FR-06)
	Version         string            // lockward version for generated_by
	MaxMembers      int
	MaxWalkEntries  int
	Snapshots       *snapshot.Store // nil disables snapshots
	ScannerSARIF    []string        // external scanner SARIF files to import (LW-FR-16)
}

func (c Config) generatedBy() string { return "lockward " + c.Version }

func (c Config) display() string {
	if c.DisplayLockfile != "" {
		return c.DisplayLockfile
	}
	return c.Lockfile
}

// usage wraps err as a user-fixable error (exit code 3).
func usage(format string, args ...any) error {
	return exitcode.New(exitcode.Usage, format, args...)
}

// classify maps lower-level errors to exit codes.
func classify(err error) error {
	var ec *exitcode.Error
	switch {
	case err == nil, errors.As(err, &ec):
		return err
	case errors.Is(err, discover.ErrConfig), errors.Is(err, lock.ErrUnsupportedVersion), errors.Is(err, fs.ErrPermission):
		return &exitcode.Error{Code: exitcode.Usage, Err: err}
	case errors.Is(err, context.Canceled):
		return &exitcode.Error{Code: exitcode.Internal, Err: err}
	}
	return err
}

// readLockfile loads the lockfile for c. A missing file returns (nil, nil)
// when allowMissing is set, else a usage error with the fix.
func readLockfile(c Config, allowMissing bool) (*lock.File, error) {
	lf, err := lock.Read(c.Lockfile)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		if allowMissing {
			return nil, nil
		}
		flag := ""
		if c.Scope == asset.ScopeUser {
			flag = " --scope user"
		}
		return nil, usage("no lockfile at %s; create one with 'lockward lock%s'", c.display(), flag)
	case err != nil:
		return nil, usage("%s", strings.ReplaceAll(err.Error(), c.Lockfile, c.display()))
	}
	if lf.Scope != c.Scope {
		return nil, usage("%s is a %s-scope lockfile, not %s scope", c.display(), lf.Scope, c.Scope)
	}
	return lf, nil
}

// Live is discovered state with tool fingerprints applied.
type Live struct {
	*discover.Result
	Notices []string
}

// discoverLive discovers the scope and applies tool fingerprints: those
// supplied with --tools are computed; others are carried over from the
// lockfile (they cannot be re-checked without a tools/list file).
func discoverLive(ctx context.Context, c Config, locked []asset.Entry) (*Live, error) {
	res, err := discover.Run(ctx, discover.Options{Root: c.Root, Scope: c.Scope, MaxMembers: c.MaxMembers, MaxWalkEntries: c.MaxWalkEntries})
	if err != nil {
		return nil, classify(err)
	}
	l := &Live{Result: res}
	idx := map[string]int{}
	for i, e := range res.Entries {
		idx[e.ID] = i
	}
	for _, id := range sortedKeys(c.Tools) {
		i, ok := idx[id]
		if !ok || res.Entries[i].Surface != asset.SurfaceMCP {
			_ = res.Close()
			return nil, usage("--tools %s: no MCP server with that id in %s scope (see 'lockward verify' for ids)", id, c.Scope)
		}
		fp, err := tools.FingerprintFile(c.Tools[id])
		if err != nil {
			_ = res.Close()
			return nil, usage("--tools %s: %v", id, err)
		}
		res.Entries[i].ToolsFingerprint = fp
	}
	for _, le := range locked {
		i, ok := idx[le.ID]
		if !ok || le.ToolsFingerprint == "" {
			continue
		}
		if _, supplied := c.Tools[le.ID]; supplied {
			continue
		}
		res.Entries[i].ToolsFingerprint = le.ToolsFingerprint
		l.Notices = append(l.Notices, fmt.Sprintf("tools fingerprint for %s was not re-checked (pass --tools %s=<tools/list.json>)", le.ID, le.ID))
	}
	return l, nil
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// LockResult summarises a lock run.
type LockResult struct {
	Entries  []asset.Entry
	Changes  []lock.Result // previous lockfile vs new, non-ok only
	Problems []asset.Problem
	Notices  []string
	Ignore   []string
	Ignored  int
	Created  bool
}

// Lock discovers the scope and writes its lockfile, carrying over approvals
// for unchanged entries. A lockfile that exists but cannot be read is never
// overwritten.
func Lock(ctx context.Context, c Config) (*LockResult, error) {
	old, err := readLockfile(c, true)
	if err != nil {
		return nil, fmt.Errorf("%w (lock never overwrites a lockfile it cannot read)", err)
	}
	var oldEntries []asset.Entry
	if old != nil {
		oldEntries = old.Entries
	}
	live, err := discoverLive(ctx, c, oldEntries)
	if err != nil {
		return nil, err
	}
	defer live.Close()
	entries := lock.Relock(oldEntries, live.Entries)
	if err := lock.Write(c.Lockfile, lock.New(c.Scope, c.generatedBy(), entries)); err != nil {
		return nil, classify(err)
	}
	out := &LockResult{Entries: entries, Problems: live.Problems, Notices: live.Notices, Created: old == nil, Ignored: live.Ignored}
	if live.Ignore != nil {
		out.Ignore = live.Ignore.Patterns
	}
	for _, r := range lock.Compare(oldEntries, entries) {
		if r.Status != lock.StatusOK {
			out.Changes = append(out.Changes, r)
		}
	}
	out.Notices = append(out.Notices, storeSnapshots(c, live, entries)...)
	return out, nil
}

// Verify compares live state with the lockfile and evaluates policy.
func Verify(ctx context.Context, c Config, frozen bool) (report.Scope, exitcode.Code, error) {
	lf, err := readLockfile(c, false)
	if err != nil {
		return report.Scope{}, exitcode.Usage, err
	}
	live, err := discoverLive(ctx, c, lf.Entries)
	if err != nil {
		return report.Scope{}, exitcode.From(err), err
	}
	defer live.Close()
	pol, digest, found, err := policy.Load(c.PolicyPath)
	if err != nil {
		return report.Scope{}, exitcode.Usage, usage("%v", err)
	}
	pr, err := policy.Evaluate(pol, policy.Input{FS: live.FS, Entries: live.Entries, Assets: live.Assets})
	if err != nil {
		return report.Scope{}, exitcode.Internal, err
	}
	s := report.Scope{
		Scope: c.Scope, Lockfile: c.display(), Results: lock.Compare(lf.Entries, live.Entries),
		Findings: pr.Findings, Suppressed: pr.Suppressed, Problems: live.Problems, Ignored: live.Ignored, Notices: live.Notices,
	}
	if found {
		s.PolicyFile, s.PolicyDigest = c.DisplayPolicy, digest
		if s.PolicyFile == "" {
			s.PolicyFile = c.PolicyPath
		}
	}
	if live.Ignore != nil {
		s.IgnorePatterns = live.Ignore.Patterns
	}
	if s.Scanner, err = ImportScanner(c.ScannerSARIF, c.Root, live.Entries); err != nil {
		return report.Scope{}, exitcode.Usage, err
	}
	code := exitcode.Clean
	switch {
	case lock.Drift(s.Results, frozen):
		code = exitcode.Drift
	case pr.Errors() > 0:
		code = exitcode.Policy
	}
	return s, code, nil
}

// Approve updates the selected entries in the lockfile from live state.
func Approve(ctx context.Context, c Config, ids []string, all bool, by string) ([]string, error) {
	lf, err := readLockfile(c, false)
	if err != nil {
		return nil, err
	}
	live, err := discoverLive(ctx, c, lf.Entries)
	if err != nil {
		return nil, err
	}
	defer live.Close()
	entries, approved, err := lock.Approve(lf.Entries, live.Entries, ids, all, by)
	if err != nil {
		return nil, usage("%v", err)
	}
	if len(approved) == 0 {
		return nil, nil
	}
	lf.Entries = entries
	lf.GeneratedBy = c.generatedBy()
	if err := lock.Write(c.Lockfile, lf); err != nil {
		return nil, classify(err)
	}
	var selected []asset.Entry
	set := map[string]bool{}
	for _, id := range approved {
		set[id] = true
	}
	for _, e := range entries {
		if set[e.ID] {
			selected = append(selected, e)
		}
	}
	storeSnapshots(c, live, selected)
	return approved, nil
}

// storeSnapshots keeps local copies of text content so diff can show prose
// changes later. Failures are reported as notices, never fatal.
func storeSnapshots(c Config, live *Live, entries []asset.Entry) []string {
	if c.Snapshots == nil {
		return nil
	}
	var failed int
	put := func(p string) {
		if snapshot.Sensitive(p) {
			return // never copy credential-like files into the cache
		}
		info, err := fs.Stat(live.FS, p)
		if err != nil || !info.Mode().IsRegular() || info.Size() > snapshot.MaxSize {
			return
		}
		b, err := fs.ReadFile(live.FS, p)
		if err != nil {
			return
		}
		if _, err := c.Snapshots.Put(b); err != nil {
			failed++
		}
	}
	for _, e := range entries {
		a := live.Assets[e.ID]
		if a == nil || a.ContentPath == "" {
			continue
		}
		switch e.Surface {
		case asset.SurfaceRules:
			put(a.ContentPath)
		case asset.SurfaceSkill:
			for _, f := range e.Files {
				if f.Digest != "" && f.Size != nil && *f.Size <= snapshot.MaxSize {
					put(path.Join(a.ContentPath, f.Path))
				}
			}
		}
	}
	if failed > 0 {
		return []string{fmt.Sprintf("could not save %d snapshot(s) to %s; 'lockward diff' will show file-level changes only", failed, c.Snapshots.Dir)}
	}
	return nil
}

// ImportScanner loads external scanner SARIF files and attaches their
// findings to entries (LW-FR-16). The findings never affect exit codes.
func ImportScanner(files []string, root string, entries []asset.Entry) ([]scanner.Finding, error) {
	var all []scanner.Finding
	for _, f := range files {
		fs, err := scanner.Load(f, root)
		if err != nil {
			return nil, usage("--scanner-sarif: %v", err)
		}
		all = append(all, fs...)
	}
	if len(all) == 0 {
		return nil, nil
	}
	return scanner.Attach(all, entries), nil
}
