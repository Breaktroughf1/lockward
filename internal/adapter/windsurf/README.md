# Windsurf / Devin Local adapter

Agent id: `windsurf`. Base docs: https://docs.devin.ai/ (redirected from docs.windsurf.com)

Verified against upstream docs on **2026-11-23**. When the upstream docs change, update this file, the adapter and its fixtures under `testdata/adapters/` together.

| Surface | What is read | Upstream page |
|---|---|---|
| MCP | `.devin/mcp_config.json`, `.devin/mcp_config.local.json`, legacy `mcpServers` in `.devin/config.json` (project); `~/.config/devin/mcp_config.json`, `%APPDATA%/devin/mcp_config.json`, legacy `~/.codeium/windsurf/mcp_config.json` (user). | cli/extensibility/mcp/configuration |
| Hooks | `.devin/hooks.v1.json` (the file is the events map), `hooks` in `.devin/config.json` / `.devin/config.local.json` / `~/.config/devin/config.json`, legacy `.windsurf/hooks.json`. | cli/extensibility/hooks/overview |
| Skills | `.devin/skills/*/`, legacy `.windsurf/skills/*/` (project); `~/.config/devin/skills/*/` (user). | desktop/cascade/skills |
| Rules / workflows | `.windsurfrules`, `.devin/rules/**/*.md`, `.windsurf/rules/**/*.md`, `.devin/global_rules.md`, `.windsurf/global_rules.md`, `AGENTS.local.md`, `AGENT.md`, `.devin/workflows/`, `.windsurf/workflows/` (project); `~/.config/devin/AGENTS.md`, `~/.devin/rules/`, `~/.devin/global_rules.md`, `~/.codeium/windsurf/memories/global_rules.md`, `~/.codeium/windsurf/global_workflows/` (user). | cli/extensibility/rules, desktop/cascade/workflows |
| LW008 | Broad `permissions.allow` entries such as `mcp__*` or `*`. | cli/extensibility/mcp/configuration |

## Known limits

- `~/.codeium/windsurf/mcp_config.json` and `~/.codeium/windsurf/memories/global_rules.md` are no longer in the docs; they are kept as legacy paths because existing installs still use them.

Fixtures: `testdata/adapters/` (see `internal/discover/discover_test.go`).
