// Package codex discovers OpenAI Codex assets.
//
// Config paths read by this adapter, with upstream sources and the date they
// were verified, are documented in README.md in this directory. AGENTS.md and
// .agents/skills are shared with other agents and owned by the generic adapter.
package codex

import (
	"context"
	"fmt"
	"path"
	"strings"

	"github.com/Breaktroughf1/lockward/internal/adapter"
	"github.com/Breaktroughf1/lockward/internal/asset"
)

const name = asset.AgentCodex

// Adapter implements adapter.Adapter for Codex.
type Adapter struct{}

// Name returns "codex".
func (Adapter) Name() string { return name }

var self = []string{name}

var settingsKeys = []string{
	"approval_policy", "approvals_reviewer", "sandbox_mode", "sandbox_workspace_write",
	"project_doc_fallback_filenames", "project_doc_max_bytes", "features", "notify",
	"profile", "profiles", "shell_environment_policy",
}

// Discover implements adapter.Adapter.
func (Adapter) Discover(_ context.Context, src *adapter.Source) (adapter.Result, error) {
	var r adapter.Result
	cfg := config(src, &r, ".codex/config.toml")
	if m, ok, res := adapter.LoadJSON(src, asset.SurfaceHook, name, self, ".codex/hooks.json"); ok {
		r.Add(res)
		if m != nil {
			events := adapter.Obj(m, "hooks")
			if events == nil {
				events = m
			}
			r.Add(adapter.Hooks(events, adapter.HookOptions{Agent: name, LoadedBy: self, File: ".codex/hooks.json", Pointer: hookPtr(m)}))
		}
	}
	if src.Scope == asset.ScopeUser {
		r.Add(adapter.Rules(src, name, self, ".codex/AGENTS.md", ".codex/AGENTS.override.md"))
		return r, nil
	}
	names := []string{"AGENTS.override.md"}
	for _, f := range adapter.Strings(cfg, "project_doc_fallback_filenames") {
		if f != "" && !strings.ContainsAny(f, `/\`) && f != "AGENTS.md" {
			names = append(names, path.Clean(f))
		}
	}
	nested, err := src.Nested(names...)
	if err != nil {
		return r, err
	}
	r.Add(adapter.Rules(src, name, self, nested...))
	return r, nil
}

func hookPtr(m map[string]any) []string {
	if adapter.Obj(m, "hooks") != nil {
		return []string{"hooks"}
	}
	return nil
}

// config parses config.toml, pins its MCP servers, hooks and security
// settings, and returns the parsed map (nil if absent or unparseable).
func config(src *adapter.Source, r *adapter.Result, file string) map[string]any {
	m, ok, res := adapter.LoadTOML(src, asset.SurfaceSettings, name, self, file)
	r.Add(res)
	if !ok || m == nil {
		return nil
	}
	r.Add(adapter.Servers(adapter.Obj(m, "mcp_servers"), adapter.ServerOptions{
		Agent: name, LoadedBy: self, File: file, Pointer: []string{"mcp_servers"}, Dialect: adapter.DialectCodex,
	}))
	r.Add(adapter.Hooks(adapter.Obj(m, "hooks"), adapter.HookOptions{
		Agent: name, LoadedBy: self, File: file, Pointer: []string{"hooks"},
	}))
	r.Add(adapter.Settings(m, adapter.SettingsOptions{
		Agent: name, LoadedBy: self, File: file, Keys: settingsKeys, AutoApprove: autoApprove,
	}))
	return m
}

func autoApprove(m map[string]any) []string {
	var out []string
	if p := adapter.Str(m, "approval_policy"); p == "never" {
		out = append(out, `approval_policy = "never"`)
	}
	profiles := adapter.Obj(m, "profiles")
	for _, p := range adapter.SortedKeys(profiles) {
		pm, _ := profiles[p].(map[string]any)
		if adapter.Str(pm, "approval_policy") == "never" {
			out = append(out, fmt.Sprintf(`profiles.%s.approval_policy = "never"`, p))
		}
	}
	return out
}
