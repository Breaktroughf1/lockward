// Package generic discovers assets shared by several agents (AGENTS.md and
// .agents/skills, both open standards) plus auto-loaded files of agents
// outside the supported six that are worth pinning and flagging in
// scan-repo (Amazon Q, PRD §2).
//
// Config paths read by this adapter, with upstream sources and the date they
// were verified, are documented in README.md in this directory.
package generic

import (
	"context"

	"github.com/Breaktroughf1/lockward/internal/adapter"
	"github.com/Breaktroughf1/lockward/internal/asset"
)

const name = asset.AgentGeneric

// Adapter implements adapter.Adapter for cross-agent assets.
type Adapter struct{}

// Name returns "generic".
func (Adapter) Name() string { return name }

var (
	agentsMDLoaders = []string{asset.AgentCodex, asset.AgentCopilot, asset.AgentCursor, asset.AgentWindsurf}
	skillsLoaders   = []string{asset.AgentCodex, asset.AgentCopilot, asset.AgentCursor, asset.AgentGeminiCLI, asset.AgentWindsurf}
	amazonQ         = []string{"amazon-q"}
)

// Discover implements adapter.Adapter.
func (Adapter) Discover(_ context.Context, src *adapter.Source) (adapter.Result, error) {
	var r adapter.Result
	if src.Scope == asset.ScopeUser {
		r.Add(adapter.Skills(src, name, skillsLoaders, ".agents/skills"))
		return r, nil
	}
	dirs, err := src.NestedDirs(".agents/skills")
	if err != nil {
		return r, err
	}
	r.Add(adapter.Skills(src, name, skillsLoaders, dirs...))
	agentsMD, err := src.Nested("AGENTS.md")
	if err != nil {
		return r, err
	}
	r.Add(adapter.Rules(src, name, agentsMDLoaders, agentsMD...))

	if m, ok, res := adapter.LoadJSON(src, asset.SurfaceMCP, name, amazonQ, ".amazonq/mcp.json"); ok {
		r.Add(res)
		if m != nil {
			r.Add(adapter.Servers(adapter.Obj(m, "mcpServers"), adapter.ServerOptions{
				Agent: name, LoadedBy: amazonQ, File: ".amazonq/mcp.json", Pointer: []string{"mcpServers"}, NamePrefix: "amazon-q/",
			}))
		}
	}
	r.Add(adapter.RulesIn(src, name, amazonQ, ".amazonq/rules", true, ".md"))
	return r, nil
}
