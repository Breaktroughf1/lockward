// Package claudecode discovers Claude Code assets.
//
// Config paths read by this adapter, with upstream sources and the date they
// were verified, are documented in README.md in this directory.
package claudecode

import (
	"context"
	"fmt"
	"path"
	"strings"

	"github.com/Breaktroughf1/lockward/internal/adapter"
	"github.com/Breaktroughf1/lockward/internal/asset"
)

const name = asset.AgentClaudeCode

// Adapter implements adapter.Adapter for Claude Code.
type Adapter struct{}

// Name returns "claude-code".
func (Adapter) Name() string { return name }

var (
	// Cursor and Copilot read .claude/skills for compatibility.
	skillLoaders = adapter.With(name, asset.AgentCursor, asset.AgentCopilot)
	// Copilot reads a root .mcp.json; Copilot and Devin read .claude/settings hooks.
	mcpLoaders  = adapter.With(name, asset.AgentCopilot)
	hookLoaders = adapter.With(name, asset.AgentCopilot, asset.AgentWindsurf)
	// Copilot and Devin read a root CLAUDE.md.
	rootRulesLoaders = adapter.With(name, asset.AgentCopilot, asset.AgentWindsurf)
	self             = []string{name}
	agentLoaders     = adapter.With(name, asset.AgentCopilot)
)

// settingsKeys are the security-relevant settings pinned as a settings entry.
var settingsKeys = []string{
	"permissions", "enableAllProjectMcpServers", "enabledMcpjsonServers", "disabledMcpjsonServers",
	"allowedMcpServers", "deniedMcpServers", "disableAllHooks", "allowManagedHooksOnly", "sandbox", "env",
	"apiKeyHelper", "statusLine", "enabledPlugins", "extraKnownMarketplaces", "awsAuthRefresh",
	"awsCredentialExport", "otelHeadersHelper", "claudeMdExcludes", "skipDangerousModePermissionPrompt",
}

// Discover implements adapter.Adapter.
func (Adapter) Discover(_ context.Context, src *adapter.Source) (adapter.Result, error) {
	var r adapter.Result
	if src.Scope == asset.ScopeProject {
		dirs, err := src.NestedDirs(".claude/skills")
		if err != nil {
			return r, err
		}
		r.Add(adapter.Skills(src, name, skillLoaders, dirs...))
		r.Add(mcpFile(src, ".mcp.json", mcpLoaders))
		r.Add(adapter.Rules(src, name, rootRulesLoaders, "CLAUDE.md"))
		r.Add(adapter.Rules(src, name, self, ".claude/CLAUDE.md", "CLAUDE.local.md"))
		nested, err := src.Nested("CLAUDE.md", "CLAUDE.local.md")
		if err != nil {
			return r, err
		}
		for _, p := range nested {
			if strings.Contains(p, "/") && !strings.HasPrefix(p, ".claude/") {
				r.Add(adapter.Rules(src, name, self, p))
			}
		}
	} else {
		r.Add(userSkills(src))
		r.Add(claudeJSON(src))
		r.Add(adapter.Rules(src, name, self, ".claude/CLAUDE.md"))
	}
	for _, f := range []string{".claude/settings.json", ".claude/settings.local.json"} {
		r.Add(settingsFile(src, f))
	}
	r.Add(adapter.RulesIn(src, name, self, ".claude/rules", true, ".md"))
	r.Add(adapter.RulesIn(src, name, self, ".claude/commands", true, ".md"))
	r.Add(adapter.RulesIn(src, name, agentLoaders, ".claude/agents", true, ".md"))
	return r, nil
}

func userSkills(src *adapter.Source) adapter.Result {
	all := adapter.Skills(src, name, skillLoaders, ".claude/skills")
	var r adapter.Result
	r.Problems = all.Problems
	for _, a := range all.Assets {
		if a.Name == ".trash" { // deleted skills, never loaded
			continue
		}
		r.Assets = append(r.Assets, a)
	}
	return r
}

func mcpFile(src *adapter.Source, file string, loaders []string) adapter.Result {
	m, ok, r := adapter.LoadJSON(src, asset.SurfaceMCP, name, loaders, file)
	if !ok || m == nil {
		return r
	}
	r.Add(adapter.Servers(adapter.Obj(m, "mcpServers"), adapter.ServerOptions{
		Agent: name, LoadedBy: loaders, File: file, Pointer: []string{"mcpServers"},
	}))
	return r
}

// claudeJSON reads ~/.claude.json. The file is rewritten constantly by Claude
// Code, so only individual server objects are pinned, never the whole file.
func claudeJSON(src *adapter.Source) adapter.Result {
	const file = ".claude.json"
	b, ok, problem := src.ReadConfig(file)
	var r adapter.Result
	if !ok {
		return r
	}
	if problem != "" {
		r.Problem(name, file, "%s", problem)
		return r
	}
	m, err := adapter.ParseJSONC(b)
	if err != nil {
		// Not pinned raw: the file churns on every Claude Code run.
		r.Problem(name, file, "cannot parse (%v); its MCP servers are not pinned", err)
		return r
	}
	r.Add(adapter.Servers(adapter.Obj(m, "mcpServers"), adapter.ServerOptions{
		Agent: name, LoadedBy: self, File: file, Pointer: []string{"mcpServers"},
	}))
	projects := adapter.Obj(m, "projects")
	for _, proj := range adapter.SortedKeys(projects) {
		pm, _ := projects[proj].(map[string]any)
		servers := adapter.Obj(pm, "mcpServers")
		if len(servers) == 0 {
			continue
		}
		r.Add(adapter.Servers(servers, adapter.ServerOptions{
			Agent: name, LoadedBy: self, File: file, Pointer: []string{"projects", proj, "mcpServers"},
			NamePrefix: path.Base(strings.ReplaceAll(proj, `\`, "/")) + "@local/",
		}))
	}
	return r
}

func settingsFile(src *adapter.Source, file string) adapter.Result {
	m, ok, r := adapter.LoadJSON(src, asset.SurfaceSettings, name, hookLoaders, file)
	if !ok || m == nil {
		return r
	}
	base := ""
	if src.Scope == asset.ScopeUser {
		base = ".claude"
	}
	r.Add(adapter.Hooks(adapter.Obj(m, "hooks"), adapter.HookOptions{
		Agent: name, LoadedBy: hookLoaders, File: file, Pointer: []string{"hooks"}, BaseDir: base,
	}))
	r.Add(adapter.Settings(m, adapter.SettingsOptions{
		Agent: name, LoadedBy: self, File: file, Keys: settingsKeys, AutoApprove: autoApprove,
	}))
	return r
}

func autoApprove(m map[string]any) []string {
	var out []string
	perms := adapter.Obj(m, "permissions")
	switch mode := adapter.Str(perms, "defaultMode"); mode {
	case "bypassPermissions", "dontAsk":
		out = append(out, fmt.Sprintf("permissions.defaultMode = %q", mode))
	}
	for _, e := range adapter.BroadAllowEntries(adapter.Strings(perms, "allow")) {
		out = append(out, fmt.Sprintf("permissions.allow contains %q", e))
	}
	if adapter.Bool(m, "enableAllProjectMcpServers") {
		out = append(out, "enableAllProjectMcpServers = true")
	}
	for _, s := range adapter.Strings(m, "enabledMcpjsonServers") {
		out = append(out, fmt.Sprintf("enabledMcpjsonServers approves %q without a prompt", s))
	}
	return out
}
