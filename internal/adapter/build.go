package adapter

import (
	"io/fs"
	"path"
	"regexp"
	"slices"
	"strings"

	"github.com/Breaktroughf1/lockward/internal/asset"
	"github.com/Breaktroughf1/lockward/internal/redact"
)

// Skills returns one skill asset per entry of each skills directory. A child
// directory (or a symlink to one) is a skill whose whole tree is pinned, so
// nested category folders are covered too. Loose files are pinned as
// single-file skills, since an agent may still read them.
func Skills(src *Source, agent string, loadedBy []string, dirs ...string) Result {
	var r Result
	for _, dir := range dirs {
		for _, e := range src.Children(dir) {
			p := path.Join(dir, e.Name())
			r.Assets = append(r.Assets, asset.Asset{
				Surface:  asset.SurfaceSkill,
				Agent:    agent,
				LoadedBy: loadedBy,
				Name:     e.Name(),
				Path:     p,
				File:     p,
				SkillDir: true,
				Source:   &asset.Source{Type: "local", Ref: p},
			})
		}
	}
	return r
}

// Rules returns a rules asset for each path that exists as a file (or a
// symlink, which discovery records and follows only within the root).
func Rules(src *Source, agent string, loadedBy []string, paths ...string) Result {
	var r Result
	for _, p := range paths {
		switch src.Stat(p) {
		case RegularFile, Symlink:
			r.Assets = append(r.Assets, asset.Asset{
				Surface: asset.SurfaceRules, Agent: agent, LoadedBy: loadedBy,
				Name: p, Path: p, File: p, Raw: true,
			})
		case Other:
			r.Problem(agent, p, "not a regular file; not pinned")
		}
	}
	return r
}

// RulesIn returns rules assets for files under dir with the given suffixes.
func RulesIn(src *Source, agent string, loadedBy []string, dir string, recursive bool, suffixes ...string) Result {
	return Rules(src, agent, loadedBy, src.Files(dir, recursive, suffixes...)...)
}

// RawConfig pins a config file that could not be parsed as raw bytes so its
// changes are still detected, and reports why.
func RawConfig(surface asset.Surface, agent string, loadedBy []string, file, why string) Result {
	var r Result
	r.Assets = append(r.Assets, asset.Asset{
		Surface: surface, Agent: agent, LoadedBy: loadedBy,
		Name: file, Path: file, File: file, Raw: true,
	})
	r.Problem(agent, file, "%s; pinned as raw bytes", why)
	return r
}

// LoadJSON reads and parses a JSON/JSONC config. ok is false if the file is
// missing. On failure the file is pinned raw under surface and a problem is
// returned in res.
func LoadJSON(src *Source, surface asset.Surface, agent string, loadedBy []string, file string) (m map[string]any, ok bool, res Result) {
	return load(src, surface, agent, loadedBy, file, ParseJSONC)
}

// LoadTOML is LoadJSON for TOML files.
func LoadTOML(src *Source, surface asset.Surface, agent string, loadedBy []string, file string) (m map[string]any, ok bool, res Result) {
	return load(src, surface, agent, loadedBy, file, ParseTOML)
}

func load(src *Source, surface asset.Surface, agent string, loadedBy []string, file string, parse func([]byte) (map[string]any, error)) (map[string]any, bool, Result) {
	b, ok, problem := src.ReadConfig(file)
	if !ok {
		return nil, false, Result{}
	}
	if problem != "" {
		if src.Stat(file) == Symlink {
			// Escaping symlink: record the link itself as a rules-like raw
			// entry is impossible (content unreadable), so report only.
			var r Result
			r.Problem(agent, file, "%s", problem)
			return nil, true, r
		}
		return nil, true, RawConfig(surface, agent, loadedBy, file, problem)
	}
	m, err := parse(b)
	if err != nil {
		return nil, true, RawConfig(surface, agent, loadedBy, file, err.Error())
	}
	return m, true, Result{}
}

// SettingsOptions describes a settings subset to pin.
type SettingsOptions struct {
	Agent    string
	LoadedBy []string
	File     string
	// Keys are top-level or dotted keys to keep. A key ending in "*" keeps
	// every top-level key with that prefix (VS Code style flat keys).
	Keys []string
	// All pins every top-level key except Exclude (used for project-scope
	// config files, which are committed and reviewed, so any change matters).
	All     bool
	Exclude []string
	// AutoApprove computes human-readable auto-approval findings (LW008).
	AutoApprove func(m map[string]any) []string
}

// Settings pins the security-relevant subset of a config file. It returns no
// asset when none of the keys are present. Values are redacted, and any
// object under an "env" key is reduced to its sorted key names.
func Settings(m map[string]any, o SettingsOptions) Result {
	sub := map[string]any{}
	if o.All {
		for _, k := range SortedKeys(m) {
			if !contains(o.Exclude, k) {
				sub[k] = scrub(k, m[k], 0)
			}
		}
	}
	for _, k := range o.Keys {
		if prefix, ok := strings.CutSuffix(k, "*"); ok {
			for _, key := range SortedKeys(m) {
				if strings.HasPrefix(key, prefix) {
					sub[key] = scrub(key, m[key], 0)
				}
			}
			continue
		}
		if v, ok := Lookup(m, k); ok {
			sub[k] = scrub(k, v, 0)
		}
	}
	if len(sub) == 0 {
		return Result{}
	}
	a := asset.Asset{
		Surface: asset.SurfaceSettings, Agent: o.Agent, LoadedBy: o.LoadedBy,
		Name: o.File, Path: o.File, File: o.File, Settings: sub,
	}
	if o.AutoApprove != nil {
		a.AutoApprove = o.AutoApprove(m)
	}
	return Result{Assets: []asset.Asset{a}}
}

// nameOnly reports keys whose object values are reduced to their key names:
// environment variables and HTTP headers (values never stored, SPEC §4.2).
func nameOnly(key string) bool {
	base := strings.ToLower(path.Base(strings.ReplaceAll(key, ".", "/")))
	switch base {
	case "env", "headers", "http_headers", "env_http_headers", "environment":
		return true
	}
	return false
}

func scrub(key string, v any, depth int) any {
	if depth > 64 {
		return nil
	}
	switch t := v.(type) {
	case string:
		if redact.InlineSecret(key, t) {
			return redact.Mask
		}
		return redact.String(t)
	case []any:
		out := make([]any, len(t))
		for i, e := range t {
			out[i] = scrub(key, e, depth+1)
		}
		return out
	case map[string]any:
		if nameOnly(key) {
			keys := make([]any, 0, len(t))
			for _, k := range SortedKeys(t) {
				keys = append(keys, k)
			}
			return map[string]any{"keys": keys}
		}
		out := make(map[string]any, len(t))
		for k, e := range t {
			out[k] = scrub(k, e, depth+1)
		}
		return out
	default:
		return v
	}
}

// broadAllow matches permission allow-list entries that approve a whole tool
// class or MCP server: "*", "Bash", "Bash(*)", "mcp__*", "mcp__server",
// "mcp__server__*".
var broadAllow = regexp.MustCompile(`^(\*|Bash|Bash\(\*\)|Bash\(:\*\)|mcp__\*|mcp__[^_*]+(__\*)?|exec\(\*\))$`)

// BroadAllowEntries returns allow-list entries that auto-approve broadly.
func BroadAllowEntries(list []string) []string {
	var out []string
	for _, e := range list {
		if broadAllow.MatchString(strings.TrimSpace(e)) {
			out = append(out, e)
		}
	}
	return out
}

// With returns loadedBy plus agent, deduplicated and sorted.
func With(agent string, others ...string) []string {
	out := append([]string{agent}, others...)
	slices.Sort(out)
	return slices.Compact(out)
}

// ValidPath reports whether p is a valid slash-separated relative path.
func ValidPath(p string) bool { return fs.ValidPath(p) }
