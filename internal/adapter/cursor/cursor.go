// Package cursor discovers Cursor assets.
//
// Config paths read by this adapter, with upstream sources and the date they
// were verified, are documented in README.md in this directory.
package cursor

import (
	"context"

	"github.com/Breaktroughf1/lockward/internal/adapter"
	"github.com/Breaktroughf1/lockward/internal/asset"
)

const name = asset.AgentCursor

// Adapter implements adapter.Adapter for Cursor.
type Adapter struct{}

// Name returns "cursor".
func (Adapter) Name() string { return name }

var self = []string{name}

// Discover implements adapter.Adapter.
func (Adapter) Discover(_ context.Context, src *adapter.Source) (adapter.Result, error) {
	var r adapter.Result
	skillDirs := []string{".cursor/skills", ".codex/skills"}
	hookBase := ".cursor" // user hooks run from ~/.cursor
	if src.Scope == asset.ScopeProject {
		nested, err := src.NestedDirs(".cursor/skills")
		if err != nil {
			return r, err
		}
		skillDirs = append(append([]string{}, nested...), ".codex/skills")
		hookBase = "" // project hooks run from the project root
		r.Add(adapter.RulesIn(src, name, self, ".cursor/rules", true, ".mdc"))
		r.Add(adapter.Rules(src, name, self, ".cursorrules"))
	}
	r.Add(adapter.Skills(src, name, self, dedupe(skillDirs)...))

	if m, ok, res := adapter.LoadJSON(src, asset.SurfaceMCP, name, self, ".cursor/mcp.json"); ok {
		r.Add(res)
		if m != nil {
			r.Add(adapter.Servers(adapter.Obj(m, "mcpServers"), adapter.ServerOptions{
				Agent: name, LoadedBy: self, File: ".cursor/mcp.json", Pointer: []string{"mcpServers"},
			}))
		}
	}
	if m, ok, res := adapter.LoadJSON(src, asset.SurfaceHook, name, self, ".cursor/hooks.json"); ok {
		r.Add(res)
		if m != nil {
			r.Add(adapter.Hooks(adapter.Obj(m, "hooks"), adapter.HookOptions{
				Agent: name, LoadedBy: self, File: ".cursor/hooks.json", Pointer: []string{"hooks"}, BaseDir: hookBase,
			}))
		}
	}
	return r, nil
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
