package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Breaktroughf1/lockward/internal/asset"
	"github.com/Breaktroughf1/lockward/internal/engine"
	"github.com/Breaktroughf1/lockward/internal/exitcode"
	"github.com/Breaktroughf1/lockward/internal/identity"
	"github.com/Breaktroughf1/lockward/internal/ignore"
	"github.com/Breaktroughf1/lockward/internal/lock"
	"github.com/Breaktroughf1/lockward/internal/policy"
	"github.com/Breaktroughf1/lockward/internal/repo"
	"github.com/Breaktroughf1/lockward/internal/report"
)

// env is what a command action may touch.
type env struct {
	ctx    context.Context
	stdout io.Writer
	stderr io.Writer
}

// action runs a command after flags are parsed. It returns nil for a clean
// result or an error carrying an exitcode.Code.
type action func(e *env, args []string) error

// command describes one PRD §8 subcommand.
type command struct {
	name    string
	usage   string // synopsis after "lockward "
	summary string
	// define registers the command's flags on fs and returns its action.
	define func(fs *flag.FlagSet) action
}

// commands lists the v0.1 CLI surface from PRD §8, in documented order.
var commands = []*command{
	{
		name:    "init",
		usage:   "init [--root DIR]",
		summary: "Write a default lockward.policy.yaml, .lockwardignore and .gitattributes (existing files are left alone).",
		define: func(fs *flag.FlagSet) action {
			o := locFlags(fs, false)
			return func(e *env, args []string) error {
				if err := noArgs(args); err != nil {
					return err
				}
				return runInit(e, o)
			}
		},
	},
	{
		name:    "lock",
		usage:   "lock [--scope user|project|all] [--tools ID=FILE]",
		summary: "Discover agent assets and write the lockfile (lockward.lock for the project, user.lock for ~).",
		define: func(fs *flag.FlagSet) action {
			scope := newEnum(fs, "scope", "all", "which assets to lock", "user", "project", "all")
			o := locFlags(fs, true)
			return func(e *env, args []string) error {
				if err := noArgs(args); err != nil {
					return err
				}
				return runLock(e, o, scope.String())
			}
		},
	},
	{
		name:    "verify",
		usage:   "verify [--frozen] [--format text|json|sarif] [--scope auto|user|project|all]",
		summary: "Compare live agent assets with the lockfile and evaluate policy.",
		define: func(fs *flag.FlagSet) action {
			frozen := fs.Bool("frozen", false, "fail on any difference, including additions (use in CI)")
			format := newEnum(fs, "format", "text", "output format", "text", "json", "sarif")
			scope := newEnum(fs, "scope", "auto", "scopes to verify; auto means every scope that has a lockfile", "auto", "user", "project", "all")
			verbose := fs.Bool("verbose", false, "also list unchanged entries")
			scan := stringsFlag{}
			fs.Var(&scan, "scanner-sarif", "SARIF from an external scanner to attach to entries (repeatable; informational, LW-FR-16)")
			o := locFlags(fs, true)
			return func(e *env, args []string) error {
				if err := noArgs(args); err != nil {
					return err
				}
				o.scanner = scan
				return runVerify(e, o, scope.String(), format.String(), *frozen, *verbose)
			}
		},
	},
	{
		name:    "diff",
		usage:   "diff [<id>] [--scope auto|user|project|all]",
		summary: "Show file-level and sentence-level changes since the lockfile (exit 1 if anything changed).",
		define: func(fs *flag.FlagSet) action {
			scope := newEnum(fs, "scope", "auto", "scopes to compare", "auto", "user", "project", "all")
			o := locFlags(fs, true)
			return func(e *env, args []string) error {
				if len(args) > 1 {
					return exitcode.New(exitcode.Usage, "accepts at most one entry id, got %d", len(args))
				}
				if err := nonEmpty(args); err != nil {
					return err
				}
				id := ""
				if len(args) == 1 {
					id = args[0]
				}
				return runDiff(e, o, scope.String(), id)
			}
		},
	},
	{
		name:    "approve",
		usage:   "approve <id>... | --all [--scope project|user] [--by NAME]",
		summary: "Accept the current state of the given lockfile entries (only those entries change).",
		define: func(fs *flag.FlagSet) action {
			all := fs.Bool("all", false, "approve every changed entry")
			scope := newEnum(fs, "scope", "project", "lockfile to update", "project", "user")
			by := fs.String("by", "", "approver recorded in approved.by (default: $LOCKWARD_APPROVER or git user.email)")
			o := locFlags(fs, true)
			return func(e *env, args []string) error {
				switch {
				case *all && len(args) > 0:
					return exitcode.New(exitcode.Usage, "pass entry ids or --all, not both")
				case !*all && len(args) == 0:
					return exitcode.New(exitcode.Usage, "pass at least one entry id, or --all")
				}
				if err := nonEmpty(args); err != nil {
					return err
				}
				return runApprove(e, o, scope.String(), args, *all, *by)
			}
		},
	},
	{
		name:    "status",
		usage:   "status [--scope auto|user|project|all]",
		summary: "Print a one-line summary for prompts and scripts (exit code as verify --frozen).",
		define: func(fs *flag.FlagSet) action {
			scope := newEnum(fs, "scope", "auto", "scopes to check", "auto", "user", "project", "all")
			o := locFlags(fs, true)
			return func(e *env, args []string) error {
				if err := noArgs(args); err != nil {
					return err
				}
				return runStatus(e, o, scope.String())
			}
		},
	},
	{
		name:    "scan-repo",
		usage:   "scan-repo <path> [--format text|json|sarif] [--policy FILE]",
		summary: "Report files an agent would auto-load from a repository, without executing anything.",
		define: func(fs *flag.FlagSet) action {
			format := newEnum(fs, "format", "text", "output format", "text", "json", "sarif")
			pol := fs.String("policy", "", "policy file to apply (the repository's own policy is never used)")
			scan := stringsFlag{}
			fs.Var(&scan, "scanner-sarif", "SARIF from an external scanner to attach to items (repeatable; informational, LW-FR-16)")
			return func(e *env, args []string) error {
				if len(args) != 1 {
					return exitcode.New(exitcode.Usage, "requires exactly one repository path, got %d", len(args))
				}
				if err := nonEmpty(args); err != nil {
					return err
				}
				return runScanRepo(e, args[0], format.String(), *pol, scan)
			}
		},
	},
	{
		name:    "bom",
		usage:   "bom [--format cyclonedx] [--scope project|user]",
		summary: "Export a CycloneDX 1.6 AI-BOM of the locked agent assets.",
		define: func(fs *flag.FlagSet) action {
			newEnum(fs, "format", "cyclonedx", "output format", "cyclonedx")
			scope := newEnum(fs, "scope", "project", "lockfile to export", "project", "user")
			o := locFlags(fs, true)
			return func(e *env, args []string) error {
				if err := noArgs(args); err != nil {
					return err
				}
				return runBOM(e, o, scope.String())
			}
		},
	},
	{
		name:    "version",
		usage:   "version",
		summary: "Print the lockward version.",
		define: func(*flag.FlagSet) action {
			return func(e *env, args []string) error {
				if err := noArgs(args); err != nil {
					return err
				}
				if _, err := fmt.Fprintf(e.stdout, "lockward %s\n", resolveVersion()); err != nil {
					return fmt.Errorf("write version: %w", err)
				}
				return nil
			}
		},
	},
}

func lookup(name string) (*command, bool) {
	for _, c := range commands {
		if c.name == name {
			return c, true
		}
	}
	return nil, false
}

func noArgs(args []string) error {
	if len(args) > 0 {
		return exitcode.New(exitcode.Usage, "unexpected argument %q", args[0])
	}
	return nil
}

func nonEmpty(args []string) error {
	for _, a := range args {
		if a == "" {
			return exitcode.New(exitcode.Usage, "empty argument")
		}
	}
	return nil
}

// --- shared location flags ------------------------------------------------

type locations struct {
	root, home, userLock, policy *string
	maxFiles                     *int
	tools                        toolsFlag
	scanner                      stringsFlag
}

// stringsFlag collects a repeatable string flag.
type stringsFlag []string

func (s *stringsFlag) String() string { return strings.Join(*s, ",") }

func (s *stringsFlag) Set(v string) error {
	if v == "" {
		return errors.New("empty value")
	}
	*s = append(*s, v)
	return nil
}

func locFlags(fs *flag.FlagSet, full bool) *locations {
	o := &locations{tools: toolsFlag{}}
	o.root = fs.String("root", "", "project root (default: nearest parent directory with .git or lockward.lock)")
	if !full {
		return o
	}
	o.home = fs.String("home", "", "user scope root (default: your home directory)")
	o.userLock = fs.String("user-lockfile", "", "user lockfile (default: <user config dir>/lockward/user.lock)")
	o.policy = fs.String("policy", "", "policy file (default: lockward.policy.yaml in the project root; <user config dir>/lockward/policy.yaml for user scope)")
	o.maxFiles = fs.Int("max-files", 0, "maximum files per skill before failing (default 200000)")
	fs.Var(o.tools, "tools", "MCP tools/list JSON for an entry, as ID=FILE (repeatable; LW-FR-06)")
	return o
}

// toolsFlag collects repeated --tools ID=FILE values.
type toolsFlag map[string]string

func (t toolsFlag) String() string {
	keys := make([]string, 0, len(t))
	for k, v := range t {
		keys = append(keys, k+"="+v)
	}
	sort.Strings(keys)
	return strings.Join(keys, ",")
}

func (t toolsFlag) Set(v string) error {
	id, file, ok := strings.Cut(v, "=")
	if !ok || id == "" || file == "" {
		return errors.New("want ID=FILE, e.g. mcp:cursor:github=github-tools.json")
	}
	if _, _, _, err := asset.ParseID(id); err != nil {
		return err
	}
	t[id] = file
	return nil
}

// projectRoot resolves --root or searches upward for .git or lockward.lock.
func projectRoot(flagRoot string) (string, error) {
	if flagRoot != "" {
		abs, err := filepath.Abs(flagRoot)
		if err != nil {
			return "", exitcode.New(exitcode.Usage, "--root: %v", err)
		}
		if info, err := os.Stat(abs); err != nil || !info.IsDir() {
			return "", exitcode.New(exitcode.Usage, "--root %s is not a directory", flagRoot)
		}
		return abs, nil
	}
	cwd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("current directory: %w", err)
	}
	for dir := cwd; ; dir = filepath.Dir(dir) {
		for _, marker := range []string{".git", lock.ProjectFileName} {
			if _, err := os.Lstat(filepath.Join(dir, marker)); err == nil {
				return dir, nil
			}
		}
		if filepath.Dir(dir) == dir {
			return cwd, nil
		}
	}
}

func homeDir(flagHome string) (string, error) {
	if flagHome != "" {
		abs, err := filepath.Abs(flagHome)
		if err != nil {
			return "", exitcode.New(exitcode.Usage, "--home: %v", err)
		}
		return abs, nil
	}
	h, err := os.UserHomeDir()
	if err != nil {
		return "", exitcode.New(exitcode.Usage, "cannot find your home directory (pass --home): %v", err)
	}
	return h, nil
}

func userConfigDir() (string, error) {
	d, err := os.UserConfigDir()
	if err != nil {
		return "", exitcode.New(exitcode.Usage, "cannot find the user config directory (pass --user-lockfile): %v", err)
	}
	return filepath.Join(d, "lockward"), nil
}

// display shortens p for output: relative to the working directory when
// inside it, "~/..." when inside home.
func display(p, home string) string {
	if cwd, err := os.Getwd(); err == nil {
		if r, err := filepath.Rel(cwd, p); err == nil && !strings.HasPrefix(r, "..") && !filepath.IsAbs(r) {
			return filepath.ToSlash(r)
		}
	}
	if home != "" {
		if r, err := filepath.Rel(home, p); err == nil && !strings.HasPrefix(r, "..") && !filepath.IsAbs(r) {
			return "~/" + filepath.ToSlash(r)
		}
	}
	return p
}

// scopeConfig builds the engine configuration for one scope.
func scopeConfig(o *locations, scope asset.Scope) (engine.Config, error) {
	home, _ := homeDir(deref(o.home))
	c := engine.Config{Scope: scope, Version: resolveVersion(), Tools: map[string]string(o.tools)}
	if o.maxFiles != nil {
		c.MaxMembers = *o.maxFiles
	}
	if scope == asset.ScopeProject {
		root, err := projectRoot(deref(o.root))
		if err != nil {
			return c, err
		}
		c.Root = root
		c.Lockfile = filepath.Join(root, lock.ProjectFileName)
		c.PolicyPath = filepath.Join(root, policy.FileName)
	} else {
		h, err := homeDir(deref(o.home))
		if err != nil {
			return c, err
		}
		c.Root = h
		c.Lockfile = deref(o.userLock)
		if c.Lockfile == "" || deref(o.policy) == "" {
			cfg, err := userConfigDir()
			if err != nil {
				return c, err
			}
			if c.Lockfile == "" {
				c.Lockfile = filepath.Join(cfg, "user.lock")
			}
			c.PolicyPath = filepath.Join(cfg, "policy.yaml")
		}
	}
	if p := deref(o.policy); p != "" {
		abs, err := filepath.Abs(p)
		if err != nil {
			return c, exitcode.New(exitcode.Usage, "--policy: %v", err)
		}
		if _, err := os.Stat(abs); err != nil {
			return c, exitcode.New(exitcode.Usage, "--policy %s: %v", p, err)
		}
		c.PolicyPath = abs
	}
	for _, f := range o.scanner {
		abs, err := filepath.Abs(f)
		if err != nil {
			return c, exitcode.New(exitcode.Usage, "--scanner-sarif: %v", err)
		}
		c.ScannerSARIF = append(c.ScannerSARIF, abs)
	}
	c.DisplayLockfile = display(c.Lockfile, home)
	c.DisplayPolicy = display(c.PolicyPath, home)
	if s, err := snapshotStore(); err == nil {
		c.Snapshots = s
	}
	return c, nil
}

func deref[T any](p *T) T {
	var zero T
	if p == nil {
		return zero
	}
	return *p
}

// scopesFor expands a --scope value. "auto" selects every scope whose
// lockfile exists, and fails if there is none.
func scopesFor(o *locations, sel string) ([]engine.Config, error) {
	var want []asset.Scope
	switch sel {
	case "project":
		want = []asset.Scope{asset.ScopeProject}
	case "user":
		want = []asset.Scope{asset.ScopeUser}
	default:
		want = []asset.Scope{asset.ScopeProject, asset.ScopeUser}
	}
	var out []engine.Config
	for _, s := range want {
		c, err := scopeConfig(o, s)
		if err != nil {
			if sel == "auto" && s == asset.ScopeUser {
				continue
			}
			return nil, err
		}
		if sel == "auto" {
			if _, err := os.Stat(c.Lockfile); err != nil {
				continue
			}
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		return nil, exitcode.New(exitcode.Usage, "no lockfile found (looked for %s and the user lockfile); create one with 'lockward lock'", lock.ProjectFileName)
	}
	return out, nil
}

// --- commands --------------------------------------------------------------

func runInit(e *env, o *locations) error {
	root, err := projectRoot(deref(o.root))
	if err != nil {
		return err
	}
	for _, f := range []struct{ name, content string }{
		{policy.FileName, policy.DefaultFile},
		{ignore.FileName, defaultIgnoreFile},
	} {
		p := filepath.Join(root, f.name)
		if _, err := os.Lstat(p); err == nil {
			fmt.Fprintf(e.stdout, "exists, left unchanged: %s\n", display(p, ""))
			continue
		}
		if err := lock.WriteAtomic(p, []byte(f.content), 0o644); err != nil {
			return exitcode.New(exitcode.Usage, "write %s: %v", p, err)
		}
		fmt.Fprintf(e.stdout, "created %s\n", display(p, ""))
	}
	if err := initGitattributes(e, root); err != nil {
		return err
	}
	fmt.Fprintln(e.stdout, "Next: review the policy, run 'lockward lock', and commit lockward.lock with these files.")
	return nil
}

// gitattributesMarker identifies the block written by init.
const gitattributesMarker = "# lockward: keep agent files LF"

// gitattributesBlock keeps agent files LF on every OS. Lockward pins raw
// bytes, and Git's core.autocrlf would otherwise check them out as CRLF on
// Windows and show drift. "text=auto" lets Git leave binary files (images,
// bytecode inside skills) untouched; plain "text" would corrupt them.
const gitattributesBlock = gitattributesMarker + ` on every OS (Lockward pins raw bytes; see docs/USAGE.md)
CLAUDE.md text=auto eol=lf
CLAUDE.local.md text=auto eol=lf
AGENTS.md text=auto eol=lf
GEMINI.md text=auto eol=lf
.cursorrules text=auto eol=lf
.windsurfrules text=auto eol=lf
.mcp.json text=auto eol=lf
.claude/** text=auto eol=lf
.cursor/** text=auto eol=lf
.codex/** text=auto eol=lf
.gemini/** text=auto eol=lf
.agents/** text=auto eol=lf
.devin/** text=auto eol=lf
.windsurf/** text=auto eol=lf
.amazonq/** text=auto eol=lf
.vscode/mcp.json text=auto eol=lf
.github/copilot-instructions.md text=auto eol=lf
.github/instructions/** text=auto eol=lf
.github/prompts/** text=auto eol=lf
.github/agents/** text=auto eol=lf
.github/skills/** text=auto eol=lf
.github/hooks/** text=auto eol=lf
lockward.lock text=auto eol=lf
lockward.policy.yaml text=auto eol=lf
.lockwardignore text=auto eol=lf
`

// initGitattributes creates .gitattributes with the LF block when it is
// missing. An existing file is never modified: init prints the block to add.
func initGitattributes(e *env, root string) error {
	p := filepath.Join(root, ".gitattributes")
	b, err := os.ReadFile(p) //nolint:gosec // .gitattributes in the chosen project root
	switch {
	case errors.Is(err, os.ErrNotExist):
		if err := lock.WriteAtomic(p, []byte(gitattributesBlock), 0o644); err != nil {
			return exitcode.New(exitcode.Usage, "write %s: %v", p, err)
		}
		fmt.Fprintf(e.stdout, "created %s (keeps agent files LF so Windows checkouts do not drift)\n", display(p, ""))
	case err != nil:
		return exitcode.New(exitcode.Usage, "read %s: %v", p, err)
	case strings.Contains(string(b), gitattributesMarker):
		fmt.Fprintf(e.stdout, "exists, left unchanged: %s (already keeps agent files LF)\n", display(p, ""))
	default:
		fmt.Fprintf(e.stdout, "exists, left unchanged: %s\n", display(p, ""))
		fmt.Fprintf(e.stdout, "  To stop Windows checkouts (core.autocrlf) from showing drift, append these lines,\n  then run 'git add --renormalize .' and commit:\n\n%s\n", indent(gitattributesBlock, "    "))
	}
	return nil
}

func indent(s, prefix string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for i, l := range lines {
		lines[i] = prefix + l
	}
	return strings.Join(lines, "\n")
}

const defaultIgnoreFile = `# .lockwardignore: paths Lockward does not pin (gitignore-style patterns).
# Ignoring files hides them from drift detection, so every pattern here is
# pinned in lockward.lock and printed by 'lockward verify'. Prefer none.
#
# Example: version-control metadata inside a cloned skill
# **/.git/
`

func runLock(e *env, o *locations, sel string) error {
	cfgs, err := scopesFor(o, sel)
	if err != nil {
		return err
	}
	for i, c := range cfgs {
		res, err := engine.Lock(e.ctx, c)
		if err != nil {
			return err
		}
		if i > 0 {
			fmt.Fprintln(e.stdout)
		}
		verb := "updated"
		if res.Created {
			verb = "created"
		}
		fmt.Fprintf(e.stdout, "%s scope: %s %s with %d entries (%s)\n", c.Scope, verb, report.Safe(c.DisplayLockfile), len(res.Entries), surfaceCounts(res.Entries))
		if len(res.Changes) > 0 {
			counts := lock.Counts(res.Changes)
			fmt.Fprintf(e.stdout, "  changes since the previous lockfile: %d added, %d modified, %d removed (approvals kept only for unchanged entries)\n",
				counts[lock.StatusAdded], counts[lock.StatusModified], counts[lock.StatusRemoved])
		}
		if len(res.Ignore) > 0 {
			fmt.Fprintf(e.stdout, "  ignore: %d pattern(s) from .lockwardignore; %d file(s) inside skills not pinned\n", len(res.Ignore), res.Ignored)
		}
		for _, n := range res.Notices {
			fmt.Fprintf(e.stdout, "  note: %s\n", report.Safe(n))
		}
		for _, p := range res.Problems {
			fmt.Fprintf(e.stdout, "  problem: %s\n", report.Safe(p.String()))
		}
		if c.Scope == asset.ScopeProject {
			for _, f := range personalFiles(res.Entries) {
				fmt.Fprintf(e.stdout, "  note: pinned %s, a personal file that is usually not committed; CI will report it as removed. If it should not be shared, add it to .lockwardignore and lock again.\n", report.Safe(f))
			}
		}
	}
	if cfgs[0].Scope == asset.ScopeProject {
		fmt.Fprintf(e.stdout, "Next: commit %s, then run 'lockward verify' (use --frozen in CI).\n", lock.ProjectFileName)
	}
	return nil
}

// personalFiles returns pinned project files that agents treat as personal
// and that are normally gitignored (CLAUDE.local.md, settings.local.json...).
func personalFiles(entries []asset.Entry) []string {
	seen := map[string]bool{}
	var out []string
	for _, e := range entries {
		file, _, _ := strings.Cut(e.Path, "#")
		base := filepath.Base(file)
		if strings.Contains(base, ".local.") && !seen[file] {
			seen[file] = true
			out = append(out, file)
		}
	}
	sort.Strings(out)
	return out
}

func surfaceCounts(entries []asset.Entry) string {
	n := map[asset.Surface]int{}
	for _, e := range entries {
		n[e.Surface]++
	}
	var parts []string
	for _, s := range asset.Surfaces {
		if n[s] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n[s], s))
		}
	}
	if len(parts) == 0 {
		return "no agent assets found"
	}
	return strings.Join(parts, ", ")
}

func verifyAll(e *env, o *locations, sel string, frozen bool) (*report.Report, error) {
	cfgs, err := scopesFor(o, sel)
	if err != nil {
		return nil, err
	}
	r := &report.Report{Version: resolveVersion(), Frozen: frozen}
	worst := exitcode.Clean
	for _, c := range cfgs {
		s, code, err := engine.Verify(e.ctx, c, frozen)
		if err != nil {
			return nil, err
		}
		r.Scopes = append(r.Scopes, s)
		if code == exitcode.Drift || (code == exitcode.Policy && worst == exitcode.Clean) {
			worst = code
		}
	}
	r.ExitCode = int(worst)
	return r, nil
}

func runVerify(e *env, o *locations, sel, format string, frozen, verbose bool) error {
	r, err := verifyAll(e, o, sel, frozen)
	if err != nil {
		return err
	}
	switch format {
	case "json":
		err = report.JSON(e.stdout, r)
	case "sarif":
		err = report.SARIF(e.stdout, r)
	default:
		err = report.Text(e.stdout, r, report.TextOptions{Color: useColor(e.stdout), Verbose: verbose})
	}
	if err != nil {
		return fmt.Errorf("write report: %w", err)
	}
	return silent(exitcode.Code(r.ExitCode))
}

// silent carries an exit code without printing another message: the
// report already explains the result.
func silent(code exitcode.Code) error {
	if code == exitcode.Clean {
		return nil
	}
	return &exitcode.Error{Code: code}
}

func runStatus(e *env, o *locations, sel string) error {
	r, err := verifyAll(e, o, sel, true)
	if err != nil {
		var ec *exitcode.Error
		if errors.As(err, &ec) && ec.Code == exitcode.Usage && strings.Contains(err.Error(), "no lockfile") {
			fmt.Fprintln(e.stdout, "lockward: no lockfile (run 'lockward lock')")
			return silent(exitcode.Usage)
		}
		return err
	}
	c := r.Counts()
	switch {
	case r.ExitCode == int(exitcode.Drift):
		fmt.Fprintf(e.stdout, "lockward: drift (%d modified, %d added, %d removed); run 'lockward verify'\n", c.Modified, c.Added, c.Removed)
	case r.ExitCode == int(exitcode.Policy):
		fmt.Fprintf(e.stdout, "lockward: policy (%d error(s)); run 'lockward verify'\n", c.Errors)
	default:
		fmt.Fprintf(e.stdout, "lockward: clean (%d entries)\n", c.Entries)
	}
	return silent(exitcode.Code(r.ExitCode))
}

func runDiff(e *env, o *locations, sel, id string) error {
	cfgs, err := scopesFor(o, sel)
	if err != nil {
		return err
	}
	changed, known := false, false
	for _, c := range cfgs {
		items, notices, err := engine.Diff(e.ctx, c, id)
		if errors.Is(err, engine.ErrUnknownID) {
			continue
		}
		if err != nil {
			return err
		}
		known = true
		for _, n := range notices {
			fmt.Fprintf(e.stdout, "note: %s\n", report.Safe(n))
		}
		for _, it := range items {
			changed = true
			ent := it.Result.Entry()
			fmt.Fprintf(e.stdout, "%s  %s  %s\n%s", it.Result.Status, report.Safe(it.Result.ID), report.Safe(ent.Path), it.Body)
		}
	}
	if id != "" && !known {
		return exitcode.New(exitcode.Usage, "unknown entry id %q (see 'lockward verify' for ids)", id)
	}
	if !changed {
		fmt.Fprintln(e.stdout, "no changes since the lockfile")
		return nil
	}
	return silent(exitcode.Drift)
}

func runApprove(e *env, o *locations, sel string, ids []string, all bool, by string) error {
	c, err := scopeConfig(o, asset.Scope(sel))
	if err != nil {
		return err
	}
	if by == "" {
		home, _ := homeDir(deref(o.home))
		repoRoot := ""
		if c.Scope == asset.ScopeProject {
			repoRoot = c.Root
		}
		by = identity.Approver(repoRoot, home)
	}
	approved, err := engine.Approve(e.ctx, c, ids, all, by)
	if err != nil {
		return err
	}
	if len(approved) == 0 {
		fmt.Fprintln(e.stdout, "nothing to approve: the lockfile already matches")
		return nil
	}
	who := ""
	if by != "" {
		who = " as " + by
	}
	fmt.Fprintf(e.stdout, "approved %d entr%s in %s%s:\n", len(approved), plural(len(approved), "y", "ies"), report.Safe(c.DisplayLockfile), report.Safe(who))
	for _, id := range approved {
		fmt.Fprintf(e.stdout, "  %s\n", report.Safe(id))
	}
	if by == "" {
		fmt.Fprintln(e.stdout, "note: no approver identity found (set git user.email, LOCKWARD_APPROVER or --by); approved.by was not recorded")
	}
	return nil
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

func runScanRepo(e *env, target, format, pol string, scan []string) error {
	info, err := os.Stat(target)
	if err != nil || !info.IsDir() {
		return exitcode.New(exitcode.Usage, "%s is not a directory", target)
	}
	if pol != "" {
		if pol, err = filepath.Abs(pol); err != nil {
			return exitcode.New(exitcode.Usage, "--policy: %v", err)
		}
	}
	for i, f := range scan {
		if scan[i], err = filepath.Abs(f); err != nil {
			return exitcode.New(exitcode.Usage, "--scanner-sarif: %v", err)
		}
	}
	r, err := repo.Scan(e.ctx, target, pol, scan...)
	if err != nil {
		return err
	}
	switch format {
	case "json":
		err = repo.JSON(e.stdout, r, resolveVersion())
	case "sarif":
		err = repo.SARIF(e.stdout, r, resolveVersion())
	default:
		err = repo.Text(e.stdout, r, useColor(e.stdout))
	}
	if err != nil {
		return fmt.Errorf("write report: %w", err)
	}
	return silent(r.ExitCode)
}

func runBOM(e *env, o *locations, sel string) error {
	c, err := scopeConfig(o, asset.Scope(sel))
	if err != nil {
		return err
	}
	lf, err := lock.Read(c.Lockfile)
	if errors.Is(err, os.ErrNotExist) {
		return exitcode.New(exitcode.Usage, "no lockfile at %s; create one with 'lockward lock'", c.DisplayLockfile)
	}
	if err != nil {
		return exitcode.New(exitcode.Usage, "%v", err)
	}
	name := filepath.Base(c.Root)
	if c.Scope == asset.ScopeUser {
		name = "user agent configuration"
	}
	return report.CycloneDX(e.stdout, lf.Entries, report.BOMOptions{Version: resolveVersion(), Scope: c.Scope, Name: name})
}

// useColor reports whether w is a terminal and colour is not disabled.
func useColor(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok || os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb" {
		return false
	}
	info, err := f.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}
