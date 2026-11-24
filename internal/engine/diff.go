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
	"github.com/Breaktroughf1/lockward/internal/hash"
	"github.com/Breaktroughf1/lockward/internal/lock"
	"github.com/Breaktroughf1/lockward/internal/prose"
	"github.com/Breaktroughf1/lockward/internal/report"
	"github.com/Breaktroughf1/lockward/internal/snapshot"
)

// DiffItem is the explanation of one changed entry.
type DiffItem struct {
	Result lock.Result
	Body   string // indented, human-readable detail
}

// maxPreview bounds the sentences shown for added prose.
const maxPreview = 40

// ErrUnknownID is returned by Diff when id is in neither the lockfile nor
// live state of the scope.
var ErrUnknownID = errors.New("unknown entry id")

// Diff explains what changed for every non-ok entry, or for id only.
func Diff(ctx context.Context, c Config, id string) ([]DiffItem, []string, error) {
	lf, err := readLockfile(c, false)
	if err != nil {
		return nil, nil, err
	}
	live, err := discoverLive(ctx, c, lf.Entries)
	if err != nil {
		return nil, nil, err
	}
	defer live.Close()
	results := lock.Compare(lf.Entries, live.Entries)
	found := false
	var items []DiffItem
	for _, r := range results {
		if id != "" && r.ID != id {
			continue
		}
		found = true
		if r.Status == lock.StatusOK {
			continue
		}
		d := differ{c: c, live: live}
		items = append(items, DiffItem{Result: r, Body: d.explain(r)})
	}
	if id != "" && !found {
		return nil, nil, fmt.Errorf("%w %q in %s scope", ErrUnknownID, id, c.Scope)
	}
	return items, live.Notices, nil
}

type differ struct {
	c    Config
	live *Live
	b    strings.Builder
}

func (d *differ) line(indent int, format string, args ...any) {
	d.b.WriteString(strings.Repeat("  ", indent))
	// File contents and recorded commands are untrusted: neutralise control
	// and bidirectional characters before they reach a terminal.
	d.b.WriteString(report.Safe(fmt.Sprintf(format, args...)))
	d.b.WriteByte('\n')
}

func (d *differ) explain(r lock.Result) string {
	switch r.Status {
	case lock.StatusRemoved:
		d.line(2, "no longer present (approving removes it from the lockfile)")
	case lock.StatusAdded:
		d.added(r.Live)
	case lock.StatusModified:
		d.modified(r.Locked, r.Live)
	}
	return d.b.String()
}

func (d *differ) contentPath(id string) string {
	if a := d.live.Assets[id]; a != nil {
		return a.ContentPath
	}
	return ""
}

func (d *differ) added(e *asset.Entry) {
	switch e.Surface {
	case asset.SurfaceSkill:
		d.line(2, "new skill with %d file(s):", len(e.Files))
		for _, f := range e.Files {
			d.line(3, "+ %s", describeFile(f))
		}
		if p := d.contentPath(e.ID); p != "" {
			for _, f := range e.Files {
				if strings.EqualFold(path.Base(f.Path), "SKILL.md") {
					d.preview(path.Join(p, f.Path), f.Path)
				}
			}
		}
	case asset.SurfaceRules:
		if p := d.contentPath(e.ID); p != "" {
			d.preview(p, e.Path)
		}
	default:
		d.object(nil, e)
	}
}

func (d *differ) preview(p, name string) {
	b, ok := d.readLive(p)
	if !ok {
		return
	}
	sentences := prose.Sentences(string(b))
	d.line(3, "%s:", name)
	for i, s := range sentences {
		if i == maxPreview {
			d.line(4, "… %d more sentence(s)", len(sentences)-maxPreview)
			break
		}
		d.line(4, "+ %s", s)
	}
}

func (d *differ) readLive(p string) ([]byte, bool) {
	info, err := fs.Stat(d.live.FS, p)
	if err != nil || !info.Mode().IsRegular() || info.Size() > snapshot.MaxSize {
		return nil, false
	}
	b, err := fs.ReadFile(d.live.FS, p)
	if err != nil || !prose.IsText(b) {
		return nil, false
	}
	return b, true
}

func (d *differ) modified(old, cur *asset.Entry) {
	if old.ToolsFingerprint != cur.ToolsFingerprint {
		d.line(2, "MCP tool descriptions changed (tools fingerprint %s → %s)", short(old.ToolsFingerprint), short(cur.ToolsFingerprint))
	}
	if old.Symlink != cur.Symlink {
		d.line(2, "symlink target: %q → %q", old.Symlink, cur.Symlink)
	}
	switch cur.Surface {
	case asset.SurfaceSkill:
		d.skill(old, cur)
	case asset.SurfaceRules:
		d.prose(old.Digest, d.contentPath(cur.ID), cur.Path, 2)
	default:
		if old.Digest != cur.Digest {
			d.object(old, cur)
		}
	}
}

func (d *differ) skill(old, cur *asset.Entry) {
	before := map[string]asset.File{}
	after := map[string]asset.File{}
	for _, f := range old.Files {
		before[f.Path] = f
	}
	for _, f := range cur.Files {
		after[f.Path] = f
	}
	var names []string
	for p := range before {
		names = append(names, p)
	}
	for p := range after {
		if _, ok := before[p]; !ok {
			names = append(names, p)
		}
	}
	sort.Strings(names)
	root := d.contentPath(cur.ID)
	for _, n := range names {
		b, inOld := before[n]
		a, inNew := after[n]
		switch {
		case !inOld:
			d.line(2, "A %s", describeFile(a))
		case !inNew:
			d.line(2, "D %s", n)
		case !sameFile(b, a):
			d.line(2, "M %s", n)
			if b.Mode != a.Mode && b.Mode != "" && a.Mode != "" {
				d.line(3, "mode %s → %s", b.Mode, a.Mode)
			}
			if b.Symlink != a.Symlink {
				d.line(3, "symlink %q → %q", b.Symlink, a.Symlink)
			}
			if b.Digest != a.Digest && a.Digest != "" && b.Digest != "" && root != "" {
				d.prose(b.Digest, path.Join(root, n), "", 3)
			}
		}
	}
}

func sameFile(a, b asset.File) bool {
	return a.Digest == b.Digest && a.Mode == b.Mode && a.Symlink == b.Symlink && a.Special == b.Special
}

// prose prints a sentence-level diff between the snapshot of oldDigest and
// the live file at p, or explains why it cannot.
func (d *differ) prose(oldDigest, p, name string, indent int) {
	if name != "" {
		d.line(indent, "%s:", name)
		indent++
	}
	newB, ok := d.readLive(p)
	if !ok {
		d.line(indent, "binary or large file changed (content not shown)")
		return
	}
	var oldB []byte
	if d.c.Snapshots != nil {
		oldB, ok = d.c.Snapshots.Get(oldDigest)
	} else {
		ok = false
	}
	if !ok {
		d.line(indent, "no local snapshot of the approved version (%s), so only the new text can be shown:", short(oldDigest))
		for i, s := range prose.Sentences(string(newB)) {
			if i == maxPreview {
				d.line(indent+1, "…")
				break
			}
			d.line(indent+1, "  %s", s)
		}
		return
	}
	ops := prose.Diff(prose.Sentences(string(oldB)), prose.Sentences(string(newB)))
	if !prose.Changed(ops) {
		d.line(indent, "only whitespace or line breaks changed")
		return
	}
	for _, l := range strings.Split(strings.TrimRight(prose.Format(ops, 1), "\n"), "\n") {
		d.line(indent, "%s", l)
	}
}

// object prints a line diff of the canonical JSON of an entry's recorded
// object (MCP server, hook or settings).
func (d *differ) object(old, cur *asset.Entry) {
	render := func(e *asset.Entry) []string {
		if e == nil {
			return nil
		}
		v := map[string]any{}
		switch {
		case e.Server != nil:
			v["server"] = e.Server
		case e.Hook != nil:
			v["hook"] = e.Hook
			if len(e.ReferencedFiles) > 0 {
				v["referenced_files"] = e.ReferencedFiles
			}
		case e.Settings != nil:
			v["settings"] = e.Settings
		default:
			v["digest"] = e.Digest
		}
		b, err := hash.CanonicalJSON(v)
		if err != nil {
			return []string{e.Digest}
		}
		return strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	}
	ops := prose.Diff(render(old), render(cur))
	for _, l := range strings.Split(strings.TrimRight(prose.Format(ops, 2), "\n"), "\n") {
		d.line(2, "%s", l)
	}
}

func describeFile(f asset.File) string {
	switch {
	case f.Symlink != "":
		return fmt.Sprintf("%s -> %s (symlink)", f.Path, f.Symlink)
	case f.Special != "":
		return fmt.Sprintf("%s (%s)", f.Path, f.Special)
	case f.Size != nil:
		return fmt.Sprintf("%s (%d bytes, %s)", f.Path, *f.Size, f.Mode)
	}
	return f.Path
}

func short(d string) string {
	if d == "" {
		return "none"
	}
	if len(d) > 19 {
		return d[:19] + "…"
	}
	return d
}
