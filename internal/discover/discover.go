// Package discover runs the registered agent adapters over a scope root and
// turns what they find into hashed lockfile entries. It applies
// .lockwardignore and pins the ignore patterns themselves (THREAT_MODEL T13).
//
// Requirements: LW-FR-01, LW-FR-02, LW-FR-04, LW-FR-05, LW-FR-07.
package discover

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/Breaktroughf1/lockward/internal/adapter"
	"github.com/Breaktroughf1/lockward/internal/adapter/claudecode"
	"github.com/Breaktroughf1/lockward/internal/adapter/codex"
	"github.com/Breaktroughf1/lockward/internal/adapter/copilot"
	"github.com/Breaktroughf1/lockward/internal/adapter/cursor"
	"github.com/Breaktroughf1/lockward/internal/adapter/geminicli"
	"github.com/Breaktroughf1/lockward/internal/adapter/generic"
	"github.com/Breaktroughf1/lockward/internal/adapter/windsurf"
	"github.com/Breaktroughf1/lockward/internal/asset"
	"github.com/Breaktroughf1/lockward/internal/hash"
	"github.com/Breaktroughf1/lockward/internal/ignore"
)

// Adapters returns every built-in adapter in a fixed order.
func Adapters() []adapter.Adapter {
	return []adapter.Adapter{
		claudecode.Adapter{}, cursor.Adapter{}, codex.Adapter{}, geminicli.Adapter{},
		windsurf.Adapter{}, copilot.Adapter{}, generic.Adapter{},
	}
}

// Options configures a discovery run.
type Options struct {
	Root           string // scope root directory (OS path)
	Scope          asset.Scope
	Adapters       []adapter.Adapter // nil means Adapters()
	MaxMembers     int               // per skill tree; 0 means hash.DefaultMaxMembers
	MaxWalkEntries int               // project walk; 0 means adapter.DefaultMaxWalkEntries
	// NoIgnore disables .lockwardignore. scan-repo sets it: an untrusted
	// repository must not be able to hide its own files.
	NoIgnore bool
}

// Result is the outcome of a discovery run. Close releases the root.
type Result struct {
	Scope    asset.Scope
	Root     string
	FS       fs.FS
	Entries  []asset.Entry           // sorted by id
	Assets   map[string]*asset.Asset // by entry id, for policy evaluation
	Problems []asset.Problem         // sorted
	Ignore   *ignore.Matcher         // nil when there is no .lockwardignore
	Ignored  int                     // files inside pinned skills skipped by .lockwardignore
	// IgnoreFileSkipped is set when NoIgnore was requested and the root
	// contains a .lockwardignore that was therefore not honoured.
	IgnoreFileSkipped bool

	root *os.Root
}

// Close releases the opened root directory.
func (res *Result) Close() error {
	if res == nil || res.root == nil {
		return nil
	}
	return res.root.Close()
}

// IgnoreID is the id of the entry that pins .lockwardignore patterns.
var IgnoreID = asset.MakeID(asset.SurfaceSettings, asset.AgentGeneric, ignore.FileName)

// ErrConfig marks errors the user must fix (bad ignore file, unreadable or
// unsafe files); the CLI maps it to exit code 3.
var ErrConfig = errors.New("configuration error")

// Run discovers and hashes every asset under opts.Root.
func Run(ctx context.Context, opts Options) (*Result, error) {
	abs, err := filepath.Abs(opts.Root)
	if err != nil {
		return nil, fmt.Errorf("%w: resolve %s: %w", ErrConfig, opts.Root, err)
	}
	root, err := os.OpenRoot(abs)
	if err != nil {
		return nil, fmt.Errorf("%w: open %s: %w", ErrConfig, abs, err)
	}
	res := &Result{Scope: opts.Scope, Root: abs, FS: root.FS(), root: root, Assets: map[string]*asset.Asset{}}
	if err := res.run(ctx, opts); err != nil {
		_ = root.Close()
		return nil, err
	}
	return res, nil
}

func (res *Result) run(ctx context.Context, opts Options) error {
	src := &adapter.Source{FS: res.FS, Scope: opts.Scope, RootDir: res.Root, MaxWalkEntries: opts.MaxWalkEntries}
	var ignoreEntry *asset.Entry
	if b, ok, problem := src.ReadConfig(ignore.FileName); ok && opts.NoIgnore {
		_ = b
		_ = problem
		res.IgnoreFileSkipped = true
	} else if ok {
		if problem != "" {
			return fmt.Errorf("%w: %s: %s", ErrConfig, ignore.FileName, problem)
		}
		m, err := ignore.Parse(b)
		if err != nil {
			return fmt.Errorf("%w: %w", ErrConfig, err)
		}
		res.Ignore, src.Ignore = m, m
		patterns := append([]string{}, m.Patterns...)
		e := asset.Entry{
			ID: IgnoreID, Surface: asset.SurfaceSettings, Agent: asset.AgentGeneric, Path: ignore.FileName,
			Settings: map[string]any{"patterns": patterns},
		}
		d, err := hash.Object(e.Settings)
		if err != nil {
			return err
		}
		e.Digest = d
		ignoreEntry = &e
	}

	adapters := opts.Adapters
	if adapters == nil {
		adapters = Adapters()
	}
	var assets []asset.Asset
	for _, a := range adapters {
		if err := ctx.Err(); err != nil {
			return err
		}
		found, err := a.Discover(ctx, src)
		if err != nil {
			return fmt.Errorf("%w: %s adapter: %w", ErrConfig, a.Name(), err)
		}
		assets = append(assets, found.Assets...)
		res.Problems = append(res.Problems, found.Problems...)
	}
	for _, d := range src.EscapedDirs() {
		res.Problems = append(res.Problems, asset.Problem{Agent: "lockward", Path: d,
			Message: "directory is a symlink to a location outside the scan root; its contents were not scanned. Widen the scan root (--root or --home) to include the target"})
	}
	assets = merge(assets)
	assignNames(assets)

	b := builder{src: src, maxMembers: opts.MaxMembers}
	for i := range assets {
		if err := ctx.Err(); err != nil {
			return err
		}
		a := &assets[i]
		e, problems, err := b.entry(a)
		if err != nil {
			return fmt.Errorf("%w: %s: %w", ErrConfig, a.Path, err)
		}
		res.Problems = append(res.Problems, problems...)
		res.Entries = append(res.Entries, e)
		res.Assets[e.ID] = a
	}
	res.Ignored = b.ignored
	if ignoreEntry != nil {
		res.Entries = append(res.Entries, *ignoreEntry)
	}
	sort.Slice(res.Entries, func(i, j int) bool { return res.Entries[i].ID < res.Entries[j].ID })
	sort.Slice(res.Problems, func(i, j int) bool {
		if res.Problems[i].Path != res.Problems[j].Path {
			return res.Problems[i].Path < res.Problems[j].Path
		}
		return res.Problems[i].Message < res.Problems[j].Message
	})
	return nil
}

// merge combines assets reported for the same surface and path by more than
// one adapter, keeping the first and unioning LoadedBy.
func merge(in []asset.Asset) []asset.Asset {
	idx := map[string]int{}
	var out []asset.Asset
	for _, a := range in {
		key := string(a.Surface) + "\x00" + a.Path
		if i, ok := idx[key]; ok {
			out[i].LoadedBy = append(out[i].LoadedBy, a.LoadedBy...)
			out[i].LoadedBy = append(out[i].LoadedBy, a.Agent)
			continue
		}
		idx[key] = len(out)
		out = append(out, a)
	}
	for i := range out {
		lb := append([]string{out[i].Agent}, out[i].LoadedBy...)
		slices.Sort(lb)
		out[i].LoadedBy = slices.Compact(lb)
	}
	return out
}

// assignNames keeps each asset's short name unless two assets would share an
// id, in which case every colliding asset uses its full path instead.
func assignNames(assets []asset.Asset) {
	count := map[string]int{}
	for _, a := range assets {
		count[asset.MakeID(a.Surface, a.Agent, a.Name)]++
	}
	for i := range assets {
		if count[asset.MakeID(assets[i].Surface, assets[i].Agent, assets[i].Name)] > 1 {
			assets[i].Name = assets[i].Path
		}
	}
}

type builder struct {
	src        *adapter.Source
	maxMembers int
	ignored    int
}

func (b *builder) entry(a *asset.Asset) (asset.Entry, []asset.Problem, error) {
	e := asset.Entry{
		ID:      asset.MakeID(a.Surface, a.Agent, a.Name),
		Surface: a.Surface,
		Agent:   a.Agent,
		Path:    a.Path,
	}
	if len(a.LoadedBy) > 1 || (len(a.LoadedBy) == 1 && a.LoadedBy[0] != a.Agent) {
		e.LoadedBy = a.LoadedBy
	}
	file, _, _ := strings.Cut(a.Path, "#")
	if err := hash.CheckPath(file); err != nil {
		return e, nil, err
	}
	var problems []asset.Problem
	var err error
	switch {
	case a.SkillDir:
		problems, err = b.skill(a, &e)
	case a.Server != nil:
		e.Server = a.Server
		e.Source = a.Source
		e.Digest, err = hash.Object(a.Server)
	case a.Hook != nil:
		e.Hook = a.Hook
		for _, p := range adapter.ReferencedFiles(b.src, a.Hook, a.HookBaseDir) {
			d, _, ferr := hash.File(b.src.FS, p)
			if ferr != nil {
				return e, nil, ferr
			}
			e.ReferencedFiles = append(e.ReferencedFiles, asset.FileRef{Path: p, Digest: d})
		}
		e.Digest, err = hash.Object(struct {
			Hook            *asset.Hook     `json:"hook"`
			ReferencedFiles []asset.FileRef `json:"referenced_files,omitempty"`
		}{a.Hook, e.ReferencedFiles})
	case a.Settings != nil:
		e.Settings = a.Settings
		e.Digest, err = hash.Object(a.Settings)
	case a.Raw:
		problems, err = b.rawFile(a, &e)
	default:
		err = errors.New("adapter produced an asset with no content")
	}
	return e, problems, err
}

func (b *builder) rawFile(a *asset.Asset, e *asset.Entry) ([]asset.Problem, error) {
	file, ok := b.src.Locate(a.File)
	if !ok {
		return nil, errors.New("file's parent directory resolves outside the scan root")
	}
	if b.src.Stat(file) == adapter.Symlink {
		target, err := hash.ReadLink(b.src.FS, file)
		if err != nil {
			return nil, fmt.Errorf("readlink: %w", err)
		}
		if err := hash.CheckPath(target); err != nil {
			return nil, err
		}
		e.Symlink = target
	}
	resolved, k, escaped := b.src.Real(file)
	switch {
	case escaped:
		e.Digest = hash.SymlinkedTreeDigest(e.Symlink, "")
		return []asset.Problem{{Agent: a.Agent, Path: a.File,
			Message: "symlink points outside the scan root; only the link target is pinned, not the content"}}, nil
	case k == adapter.Missing:
		e.Digest = hash.SymlinkedTreeDigest(e.Symlink, "")
		return []asset.Problem{{Agent: a.Agent, Path: a.File,
			Message: "dangling symlink; only the link target is pinned. Fix or remove the link, then run 'lockward lock'"}}, nil
	}
	d, _, err := hash.File(b.src.FS, resolved)
	if err != nil {
		return nil, err
	}
	e.Digest = d
	a.ContentPath = resolved
	return nil, nil
}

func (b *builder) skill(a *asset.Asset, e *asset.Entry) ([]asset.Problem, error) {
	opts := hash.TreeOptions{MaxMembers: b.maxMembers, Ignore: b.src.Ignored}
	dir, ok := b.src.Locate(a.File)
	if !ok {
		return nil, errors.New("skill's parent directory resolves outside the scan root")
	}
	var target string
	switch b.src.Stat(dir) {
	case adapter.Symlink:
		t, err := hash.ReadLink(b.src.FS, dir)
		if err != nil {
			return nil, fmt.Errorf("readlink: %w", err)
		}
		if err := hash.CheckPath(t); err != nil {
			return nil, err
		}
		target = t
		e.Symlink = t
		resolved, k, escaped := b.src.Real(dir)
		if escaped || k == adapter.Missing {
			e.Digest = hash.SymlinkedTreeDigest(t, "")
			return []asset.Problem{{Agent: a.Agent, Path: a.File,
				Message: "skill is a symlink to a location outside the scan root (or a dangling link); its contents are not pinned"}}, nil
		}
		if k != adapter.Directory {
			tree, err := hash.SingleFile(b.src.FS, resolved)
			if err != nil {
				return nil, err
			}
			e.Files = files(tree)
			e.Digest = hash.SymlinkedTreeDigest(t, tree.Digest)
			a.ContentPath = path.Dir(resolved)
			return nil, nil
		}
		dir = resolved
	case adapter.RegularFile, adapter.Other:
		tree, err := hash.SingleFile(b.src.FS, dir)
		if err != nil {
			return nil, err
		}
		e.Files = files(tree)
		e.Digest = tree.Digest
		a.ContentPath = path.Dir(dir)
		return nil, nil
	case adapter.Missing:
		return nil, errors.New("skill disappeared during discovery")
	}
	tree, err := hash.TreeDigest(b.src.FS, dir, opts)
	if err != nil {
		return nil, err
	}
	b.ignored += tree.Ignored
	a.ContentPath = dir
	e.Files = files(tree)
	e.Digest = tree.Digest
	if target != "" {
		e.Digest = hash.SymlinkedTreeDigest(target, tree.Digest)
	}
	return nil, nil
}

func files(t hash.Tree) []asset.File {
	out := make([]asset.File, 0, len(t.Members))
	for _, m := range t.Members {
		f := asset.File{Path: m.Path}
		switch m.Kind {
		case hash.KindSymlink:
			f.Symlink = m.Target
		case hash.KindSpecial:
			f.Special = m.Special
		default:
			size := m.Size
			f.Digest, f.Size, f.Mode = m.Digest, &size, m.Mode
		}
		out = append(out, f)
	}
	return out
}
