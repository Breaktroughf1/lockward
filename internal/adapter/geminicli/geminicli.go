// Package geminicli discovers Gemini CLI assets.
//
// Config paths read by this adapter, with upstream sources and the date they
// were verified, are documented in README.md in this directory.
package geminicli

import (
	"context"
	"fmt"
	"path"
	"strings"

	"github.com/Breaktroughf1/lockward/internal/adapter"
	"github.com/Breaktroughf1/lockward/internal/asset"
)

const name = asset.AgentGeminiCLI

// Adapter implements adapter.Adapter for Gemini CLI.
type Adapter struct{}

// Name returns "gemini-cli".
func (Adapter) Name() string { return name }

var self = []string{name}

var settingsKeys = []string{
	"tools", "mcp", "security", "context", "hooksConfig", "skills", "policyPaths",
	"adminPolicyPaths", "general.defaultApprovalMode", "advanced",
}

// Discover implements adapter.Adapter.
func (Adapter) Discover(_ context.Context, src *adapter.Source) (adapter.Result, error) {
	var r adapter.Result
	settings := settingsFile(src, &r, ".gemini/settings.json")
	contextNames := []string{"GEMINI.md"}
	if c, ok := adapter.Lookup(settings, "context.fileName"); ok {
		for _, n := range toNames(c) {
			if n != "" && !strings.ContainsAny(n, `/\`) && n != "GEMINI.md" && n != "AGENTS.md" {
				contextNames = append(contextNames, path.Clean(n))
			}
		}
	}
	r.Add(adapter.Skills(src, name, self, ".gemini/skills"))
	r.Add(adapter.RulesIn(src, name, self, ".gemini/commands", true, ".toml"))
	if src.Scope == asset.ScopeProject {
		nested, err := src.Nested(contextNames...)
		if err != nil {
			return r, err
		}
		r.Add(adapter.Rules(src, name, self, nested...))
		return r, nil
	}
	for _, n := range contextNames {
		r.Add(adapter.Rules(src, name, self, path.Join(".gemini", n)))
	}
	r.Add(extensions(src))
	return r, nil
}

func toNames(v any) []string {
	switch t := v.(type) {
	case string:
		return []string{t}
	case []any:
		var out []string
		for _, e := range t {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func settingsFile(src *adapter.Source, r *adapter.Result, file string) map[string]any {
	m, ok, res := adapter.LoadJSON(src, asset.SurfaceSettings, name, self, file)
	r.Add(res)
	if !ok || m == nil {
		return nil
	}
	r.Add(adapter.Servers(adapter.Obj(m, "mcpServers"), adapter.ServerOptions{
		Agent: name, LoadedBy: self, File: file, Pointer: []string{"mcpServers"}, Dialect: adapter.DialectGemini,
	}))
	r.Add(adapter.Hooks(adapter.Obj(m, "hooks"), adapter.HookOptions{
		Agent: name, LoadedBy: self, File: file, Pointer: []string{"hooks"},
	}))
	r.Add(adapter.Settings(m, adapter.SettingsOptions{
		Agent: name, LoadedBy: self, File: file, Keys: settingsKeys, AutoApprove: autoApprove,
		All: src.Scope == asset.ScopeProject, Exclude: []string{"mcpServers", "hooks"},
	}))
	return m
}

// extensions pins each installed extension directory as a tree, and parses
// its manifest MCP servers and hooks so policy rules apply to them.
func extensions(src *adapter.Source) adapter.Result {
	var r adapter.Result
	const dir = ".gemini/extensions"
	ext := adapter.Skills(src, name, self, dir)
	for i := range ext.Assets {
		ext.Assets[i].Name = "extensions/" + ext.Assets[i].Name
	}
	r.Add(ext)
	for _, e := range src.Children(dir) {
		base := path.Join(dir, e.Name())
		manifest := path.Join(base, "gemini-extension.json")
		if m, ok, res := adapter.LoadJSON(src, asset.SurfaceMCP, name, self, manifest); ok {
			r.Add(res)
			if m != nil {
				r.Add(adapter.Servers(adapter.Obj(m, "mcpServers"), adapter.ServerOptions{
					Agent: name, LoadedBy: self, File: manifest, Pointer: []string{"mcpServers"},
					Dialect: adapter.DialectGemini, NamePrefix: e.Name() + "/",
				}))
			}
		}
		hooks := path.Join(base, "hooks/hooks.json")
		if m, ok, res := adapter.LoadJSON(src, asset.SurfaceHook, name, self, hooks); ok {
			r.Add(res)
			if m != nil {
				r.Add(adapter.Hooks(adapter.Obj(m, "hooks"), adapter.HookOptions{
					Agent: name, LoadedBy: self, File: hooks, Pointer: []string{"hooks"}, BaseDir: base,
				}))
			}
		}
	}
	return r
}

func autoApprove(m map[string]any) []string {
	var out []string
	allowed, _ := adapter.Lookup(m, "tools.allowed")
	for _, t := range toNames(allowed) {
		if t == "*" || t == "run_shell_command" {
			out = append(out, fmt.Sprintf("tools.allowed contains %q", t))
		}
	}
	return out
}
