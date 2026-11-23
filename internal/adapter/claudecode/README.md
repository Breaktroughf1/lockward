# Claude Code adapter

Agent id: `claude-code`. Base docs: https://code.claude.com/docs/en/

Verified against upstream docs on **2026-11-23**. When the upstream docs change, update this file, the adapter and its fixtures under `testdata/adapters/` together.

| Surface | What is read | Upstream page |
|---|---|---|
| Skills | `.claude/skills/*/` at the root and in any subdirectory (project); `~/.claude/skills/*/` (user, excluding `.trash`). Each child is pinned as a whole tree. | skills |
| MCP | `.mcp.json` → `mcpServers` (project). `~/.claude.json` → `mcpServers` and `projects[<path>].mcpServers` (user; ids are `<project>@local/<server>`). Only server objects are pinned: Claude Code rewrites `~/.claude.json` on every run. | mcp |
| Hooks | `hooks` in `.claude/settings.json` and `.claude/settings.local.json` (both scopes). User hooks resolve relative paths against `~/.claude`. | hooks |
| Settings | `permissions`, `enableAllProjectMcpServers`, `enabledMcpjsonServers`, `disabledMcpjsonServers`, `allowedMcpServers`, `deniedMcpServers`, `disableAllHooks`, `allowManagedHooksOnly`, `sandbox`, `env` (names only), `apiKeyHelper`, `statusLine`, `enabledPlugins`, `extraKnownMarketplaces`, `awsAuthRefresh`, `awsCredentialExport`, `otelHeadersHelper`, `claudeMdExcludes`, `skipDangerousModePermissionPrompt`. | settings-reference |
| Rules | `CLAUDE.md`, `.claude/CLAUDE.md`, `CLAUDE.local.md`, nested `CLAUDE.md`/`CLAUDE.local.md`, `.claude/rules/**/*.md`, `.claude/commands/**/*.md`, `.claude/agents/**/*.md`; `~/.claude/CLAUDE.md` and the same `~/.claude/` directories. | memory, skills, sub-agents |
| LW008 | `permissions.defaultMode` of `bypassPermissions` or `dontAsk`; broad `permissions.allow` entries (`*`, `Bash`, `Bash(*)`, `mcp__*`, whole servers); `enableAllProjectMcpServers`; `enabledMcpjsonServers`. | settings-reference, mcp |

## Known limits

- Plugin contents (`~/.claude/plugins/`) are not discovered: the on-disk layout is not documented upstream. Enabled plugins are still pinned through the `enabledPlugins` setting.
- Managed settings outside the home directory (`/etc/claude-code/`, `/Library/Application Support/ClaudeCode/`) are not read.

Fixtures: `testdata/adapters/` (see `internal/discover/discover_test.go`).
