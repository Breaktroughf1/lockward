// Package copilot discovers GitHub Copilot assets (VS Code, Copilot CLI and
// the Copilot coding agent).
//
// Config paths read by this adapter, with upstream sources and the date they
// were verified, are documented in README.md in this directory.
package copilot

import (
	"context"
	"fmt"
	"strings"

	"github.com/Breaktroughf1/lockward/internal/adapter"
	"github.com/Breaktroughf1/lockward/internal/asset"
)

const name = asset.AgentCopilot

// Adapter implements adapter.Adapter for GitHub Copilot.
type Adapter struct{}

// Name returns "copilot".
func (Adapter) Name() string { return name }

var self = []string{name}

// vscodeKeys are the VS Code settings that control what Copilot loads and
// what it may run without asking.
var vscodeKeys = []string{
	"chat.tools.*", "chat.mcp.*", "chat.use*", "chat.permissions.*", "chat.defaultConfiguration",
	"chat.hookFilesLocations", "chat.instructionsFilesLocations", "chat.promptFilesLocations",
	"chat.agentSkillsLocations", "chat.agentFilesLocations",
}

// Discover implements adapter.Adapter.
func (Adapter) Discover(_ context.Context, src *adapter.Source) (adapter.Result, error) {
	var r adapter.Result
	if src.Scope == asset.ScopeProject {
		r.Add(mcpFile(src, ".vscode/mcp.json", "servers"))
		r.Add(mcpFile(src, ".github/mcp.json", "mcpServers"))
		r.Add(adapter.Skills(src, name, self, ".github/skills"))
		r.Add(adapter.Rules(src, name, self, ".github/copilot-instructions.md"))
		r.Add(adapter.RulesIn(src, name, self, ".github/instructions", true, ".instructions.md"))
		r.Add(adapter.RulesIn(src, name, self, ".github/prompts", true, ".prompt.md"))
		r.Add(adapter.RulesIn(src, name, self, ".github/agents", true, ".md"))
		r.Add(adapter.RulesIn(src, name, self, ".github/chatmodes", true, ".chatmode.md"))
		for _, f := range src.Files(".github/hooks", false, ".json") {
			r.Add(hooksFile(src, f, ""))
		}
		for _, f := range []string{".github/copilot/settings.json", ".github/copilot/settings.local.json"} {
			r.Add(hooksFile(src, f, ""))
		}
		r.Add(vscodeSettings(src, ".vscode/settings.json"))
		return r, nil
	}
	r.Add(mcpFile(src, ".copilot/mcp-config.json", "mcpServers"))
	r.Add(adapter.Skills(src, name, self, ".copilot/skills"))
	r.Add(adapter.Rules(src, name, self, ".copilot/copilot-instructions.md"))
	r.Add(adapter.RulesIn(src, name, self, ".copilot/instructions", true, ".instructions.md"))
	r.Add(adapter.RulesIn(src, name, self, ".copilot/agents", true, ".md"))
	for _, f := range src.Files(".copilot/hooks", false, ".json") {
		r.Add(hooksFile(src, f, ".copilot"))
	}
	r.Add(hooksFile(src, ".copilot/settings.json", ".copilot"))
	for _, f := range []string{
		".config/Code/User/settings.json",
		"Library/Application Support/Code/User/settings.json",
		"AppData/Roaming/Code/User/settings.json",
	} {
		r.Add(vscodeSettings(src, f))
	}
	return r, nil
}

func mcpFile(src *adapter.Source, file, key string) adapter.Result {
	m, ok, r := adapter.LoadJSON(src, asset.SurfaceMCP, name, self, file)
	if !ok || m == nil {
		return r
	}
	r.Add(adapter.Servers(adapter.Obj(m, key), adapter.ServerOptions{
		Agent: name, LoadedBy: self, File: file, Pointer: []string{key},
	}))
	return r
}

func hooksFile(src *adapter.Source, file, base string) adapter.Result {
	m, ok, r := adapter.LoadJSON(src, asset.SurfaceHook, name, self, file)
	if !ok || m == nil {
		return r
	}
	r.Add(adapter.Hooks(adapter.Obj(m, "hooks"), adapter.HookOptions{
		Agent: name, LoadedBy: self, File: file, Pointer: []string{"hooks"}, BaseDir: base,
	}))
	return r
}

func vscodeSettings(src *adapter.Source, file string) adapter.Result {
	m, ok, r := adapter.LoadJSON(src, asset.SurfaceSettings, name, self, file)
	if !ok || m == nil {
		return r
	}
	r.Add(adapter.Settings(m, adapter.SettingsOptions{
		Agent: name, LoadedBy: self, File: file, Keys: vscodeKeys, AutoApprove: autoApprove,
	}))
	return r
}

func autoApprove(m map[string]any) []string {
	var out []string
	for _, k := range []string{"chat.tools.global.autoApprove", "chat.tools.autoApprove"} {
		if v, ok := m[k].(bool); ok && v {
			out = append(out, k+" = true")
		}
	}
	term, _ := m["chat.tools.terminal.autoApprove"].(map[string]any)
	for _, k := range adapter.SortedKeys(term) {
		if v, ok := term[k].(bool); ok && v && isCatchAll(k) {
			out = append(out, fmt.Sprintf("chat.tools.terminal.autoApprove approves every command (%q)", k))
		}
	}
	return out
}

func isCatchAll(pattern string) bool {
	p := strings.TrimSpace(pattern)
	return p == "*" || p == "/.*/" || p == "/.+/" || p == "/^.*$/" || p == ".*"
}
