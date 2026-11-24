// Package windsurf discovers Windsurf assets. Windsurf's Cascade agent is now
// "Devin Local", which reads .devin/ and ~/.config/devin/ and keeps the
// .windsurf/ paths as legacy fallbacks; this adapter covers both.
//
// Config paths read by this adapter, with upstream sources and the date they
// were verified, are documented in README.md in this directory.
package windsurf

import (
	"context"
	"fmt"

	"github.com/Breaktroughf1/lockward/internal/adapter"
	"github.com/Breaktroughf1/lockward/internal/asset"
)

const name = asset.AgentWindsurf

// Adapter implements adapter.Adapter for Windsurf / Devin Local.
type Adapter struct{}

// Name returns "windsurf".
func (Adapter) Name() string { return name }

var self = []string{name}

// Discover implements adapter.Adapter.
func (Adapter) Discover(_ context.Context, src *adapter.Source) (adapter.Result, error) {
	var r adapter.Result
	if src.Scope == asset.ScopeProject {
		for _, f := range []string{".devin/mcp_config.json", ".devin/mcp_config.local.json"} {
			r.Add(mcpFile(src, f))
		}
		for _, f := range []string{".devin/config.json", ".devin/config.local.json"} {
			r.Add(configFile(src, f))
		}
		r.Add(hooksFile(src, ".devin/hooks.v1.json", false))
		r.Add(hooksFile(src, ".windsurf/hooks.json", true))
		r.Add(adapter.Skills(src, name, self, ".devin/skills", ".windsurf/skills"))
		r.Add(adapter.Rules(src, name, self, ".windsurfrules", ".devin/global_rules.md", ".windsurf/global_rules.md", "AGENTS.local.md", "AGENT.md"))
		for _, d := range []string{".devin/rules", ".windsurf/rules", ".devin/workflows", ".windsurf/workflows"} {
			r.Add(adapter.RulesIn(src, name, self, d, true, ".md"))
		}
		return r, nil
	}
	for _, f := range []string{".config/devin/mcp_config.json", "AppData/Roaming/devin/mcp_config.json", ".codeium/windsurf/mcp_config.json"} {
		r.Add(mcpFile(src, f))
	}
	for _, f := range []string{".config/devin/config.json", "AppData/Roaming/devin/config.json"} {
		r.Add(configFile(src, f))
	}
	r.Add(adapter.Skills(src, name, self, ".config/devin/skills", "AppData/Roaming/devin/skills"))
	r.Add(adapter.Rules(src, name, self, ".config/devin/AGENTS.md", "AppData/Roaming/devin/AGENTS.md",
		".devin/global_rules.md", ".codeium/windsurf/memories/global_rules.md"))
	for _, d := range []string{".devin/rules", ".codeium/windsurf/global_workflows"} {
		r.Add(adapter.RulesIn(src, name, self, d, true, ".md"))
	}
	return r, nil
}

func mcpFile(src *adapter.Source, file string) adapter.Result {
	m, ok, r := adapter.LoadJSON(src, asset.SurfaceMCP, name, self, file)
	if !ok || m == nil {
		return r
	}
	r.Add(adapter.Servers(adapter.Obj(m, "mcpServers"), adapter.ServerOptions{
		Agent: name, LoadedBy: self, File: file, Pointer: []string{"mcpServers"},
	}))
	return r
}

// configFile reads .devin/config.json-style files: legacy mcpServers, a
// hooks key and permissions.
func configFile(src *adapter.Source, file string) adapter.Result {
	m, ok, r := adapter.LoadJSON(src, asset.SurfaceSettings, name, self, file)
	if !ok || m == nil {
		return r
	}
	r.Add(adapter.Servers(adapter.Obj(m, "mcpServers"), adapter.ServerOptions{
		Agent: name, LoadedBy: self, File: file, Pointer: []string{"mcpServers"},
	}))
	r.Add(adapter.Hooks(adapter.Obj(m, "hooks"), adapter.HookOptions{
		Agent: name, LoadedBy: self, File: file, Pointer: []string{"hooks"},
	}))
	r.Add(adapter.Settings(m, adapter.SettingsOptions{
		Agent: name, LoadedBy: self, File: file, Keys: []string{"permissions"}, AutoApprove: autoApprove,
		All: src.Scope == asset.ScopeProject, Exclude: []string{"mcpServers", "hooks"},
	}))
	return r
}

// hooksFile reads a hooks file. .devin/hooks.v1.json is the events map
// itself; legacy .windsurf/hooks.json wraps it in a "hooks" key.
func hooksFile(src *adapter.Source, file string, wrapped bool) adapter.Result {
	m, ok, r := adapter.LoadJSON(src, asset.SurfaceHook, name, self, file)
	if !ok || m == nil {
		return r
	}
	events, ptr := m, []string(nil)
	if wrapped {
		events, ptr = adapter.Obj(m, "hooks"), []string{"hooks"}
	}
	r.Add(adapter.Hooks(events, adapter.HookOptions{Agent: name, LoadedBy: self, File: file, Pointer: ptr}))
	return r
}

func autoApprove(m map[string]any) []string {
	var out []string
	for _, e := range adapter.BroadAllowEntries(adapter.Strings(adapter.Obj(m, "permissions"), "allow")) {
		out = append(out, fmt.Sprintf("permissions.allow contains %q", e))
	}
	return out
}
