# Verified agent config paths

Verified against upstream docs on **2026-11-23**. These supersede the "initial config paths" table in [ARCHITECTURE.md §4](ARCHITECTURE.md#4-adapter-contract). When an adapter is written, copy its section into `internal/adapter/<name>/README.md`.

`~` = user scope root; other paths are relative to the project root. "(legacy)" means upstream still reads the path but no longer recommends it.

## Upstream changes to the original plan

- **Windsurf:** docs.windsurf.com now redirects to docs.devin.ai. Cascade is the legacy agent, replaced by "Devin Local", which uses `.devin/` and `~/.config/devin/`. The `.windsurf/` paths are legacy fallbacks. `~/.codeium/windsurf/mcp_config.json` and `~/.codeium/windsurf/memories/global_rules.md` no longer appear in the docs.
- **Codex:** skills live in `.agents/skills/` and `~/.agents/skills/`, not `.codex/skills/`. Codex now supports hooks, and reads project `.codex/config.toml` only for trusted projects.
- **Gemini CLI:** the docs say it was replaced by Antigravity CLI on 18 June 2026 for unpaid and Google One users. It now has skills and hooks.
- **Copilot:** besides `.vscode/mcp.json`, there are now `.mcp.json`, `.github/mcp.json` and `~/.copilot/mcp-config.json`. Skills, hooks and custom agents are also supported. VS Code's "Local harness" is deprecated (removal Feb 2027).
- **Shared paths:** several agents read the same files: `.agents/skills/`, `AGENTS.md`, `.claude/skills/` and `.claude/settings.json` hooks. Discovery must deduplicate by path and record every agent that loads each file. Otherwise one file gets pinned under several ids.

## Claude Code — https://code.claude.com/docs/en/

| Surface | Paths | Source page |
|---|---|---|
| Skills | `.claude/skills/<name>/SKILL.md`, `~/.claude/skills/<name>/`, nested `<subdir>/.claude/skills/`, plugin `<plugin>/skills/<name>/`. Symlinked skill folders are followed. `~/.claude/skills/synced/` is reserved | skills |
| MCP | `.mcp.json` (`mcpServers`); `~/.claude.json` top-level, plus `projects["<abs path>"].mcpServers` for local scope. Server keys: `type` (stdio/http/sse/ws), `command`, `args`, `env`, `url`, `headers`, `headersHelper`, `oauth` | mcp |
| Hooks | `~/.claude/settings.json`, `.claude/settings.json`, `.claude/settings.local.json`, plugin `hooks/hooks.json`, skill and subagent frontmatter. Shape: `hooks.<Event>[].{matcher, hooks[].{type, command, …}}` | hooks |
| Rules | `CLAUDE.md`, `.claude/CLAUDE.md`, `CLAUDE.local.md`, `~/.claude/CLAUDE.md`, `.claude/rules/**/*.md`, `~/.claude/rules/*.md`, nested `CLAUDE.md`. AGENTS.md is read only when no CLAUDE.md exists | memory |
| Commands / agents | `.claude/commands/**/*.md`, `.claude/agents/` and `~/.claude/agents/` (recursive) | skills, sub-agents |
| Auto-approve (LW008) | `permissions.allow`, `permissions.defaultMode` (`bypassPermissions`, `dontAsk`, `auto`), `enableAllProjectMcpServers`, `enabledMcpjsonServers` | settings-reference, mcp |

Note: `~/.claude.json` is rewritten constantly by Claude Code, so pin individual server objects, never the whole file.

## Cursor — https://cursor.com/docs/

| Surface | Paths | Source page |
|---|---|---|
| Skills | `.cursor/skills/`, `.agents/skills/`, `~/.cursor/skills/`, `~/.agents/skills/`; compatibility: `.claude/skills/`, `.codex/skills/` and their `~` forms | context/skills |
| MCP | `.cursor/mcp.json`, `~/.cursor/mcp.json` (`mcpServers`: `type`, `command`, `args`, `env`, `envFile`, `url`, `headers`, `auth`) | context/mcp |
| Hooks | `.cursor/hooks.json`, `~/.cursor/hooks.json`; enterprise `/etc/cursor/hooks.json` and equivalents. Shape: `{"version":1,"hooks":{"<event>":[{"command":…}]}}` | agent/hooks |
| Rules | `.cursor/rules/**/*.mdc` (plain `.md` there is ignored), `AGENTS.md` (nested). `.cursorrules` is not documented any more (legacy). User rules aren't stored on disk | context/rules |
| Auto-approve | No file key documented (Run Modes page returned 404) | context/mcp |

## Codex — https://learn.chatgpt.com/docs/ (redirected from developers.openai.com)

| Surface | Paths | Source page |
|---|---|---|
| Config | `~/.codex/config.toml` (`$CODEX_HOME`), `.codex/config.toml` (trusted projects only) | config-file/config-reference |
| MCP | `[mcp_servers.<name>]`: `command`, `args`, `env`, `env_vars`, `cwd`, `url`, `bearer_token_env_var`, `http_headers`, `env_http_headers`, `enabled`, `default_tools_approval_mode`, `tools.<t>.approval_mode` | extend/mcp |
| Skills | `.agents/skills/` (cwd, parents up to repo root), `~/.agents/skills/`, `/etc/codex/skills` | build-skills |
| Rules | `~/.codex/AGENTS.override.md` or `AGENTS.md`; per directory from root to cwd: `AGENTS.override.md`, `AGENTS.md`, then `project_doc_fallback_filenames` | agent-configuration/agents-md |
| Hooks | `[hooks]` in config.toml or `hooks.json`; Claude-like event arrays; gated by `features.hooks` | config-reference (page summary, not verbatim) |
| Auto-approve | `approval_policy = "never"`, `sandbox_mode = "danger-full-access"`, MCP `default_tools_approval_mode` | config-reference |

## Gemini CLI — https://geminicli.com/docs/

| Surface | Paths | Source page |
|---|---|---|
| Settings | `~/.gemini/settings.json`, `.gemini/settings.json`, system `/etc/gemini-cli/settings.json` and `system-defaults.json` | reference/configuration |
| MCP | `mcpServers` in settings: `command`, `args`, `env`, `cwd`, `url`, `httpUrl`, `headers`, `trust`, `includeTools`, `excludeTools` | tools/mcp-server |
| Extensions | `~/.gemini/extensions/<name>/gemini-extension.json` (`mcpServers`, `contextFileName`), plus `commands/`, `hooks/hooks.json`, `skills/`, `agents/`, `policies/` | extensions/reference |
| Skills | `.gemini/skills/`, `.agents/skills/`, `~/.gemini/skills/`, `~/.agents/skills/` | cli/skills |
| Rules | `~/.gemini/GEMINI.md`, `GEMINI.md` in workspace and ancestors, JIT subdirectories; filename configurable via `context.fileName` | cli/gemini-md |
| Hooks | `hooks` key in settings files, Claude-like shape; events `BeforeTool`, `AfterTool`, `SessionStart`, … | hooks |
| Commands | `.gemini/commands/**/*.toml`, `~/.gemini/commands/` | cli/custom-commands |
| Auto-approve (LW008) | `mcpServers.<x>.trust: true`, `tools.allowed` | tools/mcp-server, reference/configuration |

## Windsurf / Devin Local — https://docs.devin.ai/ (redirected from docs.windsurf.com)

| Surface | Paths | Source page |
|---|---|---|
| MCP | `.devin/mcp_config.json`, `.devin/mcp_config.local.json`, `~/.config/devin/mcp_config.json` (Windows `%APPDATA%\devin\`); legacy `mcpServers` in `.devin/config.json`; `~/.codeium/windsurf/mcp_config.json` (legacy, undocumented) | cli/extensibility/mcp/configuration |
| Skills | `.devin/skills/`, `.agents/skills/`, `.windsurf/skills/` (legacy), `~/.config/devin/skills/`, `~/.agents/skills/` | desktop/cascade/skills |
| Rules | `AGENTS.md` (nested), `AGENTS.local.md`, `AGENT.md`, `.windsurfrules` (legacy), `.devin/rules/*.md`, `.windsurf/rules/*.md` (legacy), `.devin/global_rules.md`, `~/.devin/rules/*.md`, `~/.devin/global_rules.md`, `~/.config/devin/AGENTS.md` | cli/extensibility/rules |
| Hooks | `.devin/hooks.v1.json` (whole file is the hooks object); `hooks` key in `.devin/config.json`, `.devin/config.local.json`, `~/.config/devin/config.json`; legacy `.windsurf/hooks.json` | cli/extensibility/hooks/overview |
| Workflows | `.devin/workflows/*.md`, `.windsurf/workflows/*.md`, `~/.codeium/windsurf/global_workflows/*.md` | desktop/cascade/workflows |
| Auto-approve | `permissions.allow` (e.g. `mcp__*`) | cli/extensibility/mcp/configuration |

## GitHub Copilot — code.visualstudio.com/docs and docs.github.com

| Surface | Paths | Source page |
|---|---|---|
| MCP | `.vscode/mcp.json` (top-level `servers`, `inputs`), `.mcp.json` and `~/.copilot/mcp-config.json` (`mcpServers`), `.github/mcp.json` (CLI) | agents/reference/mcp-configuration; copilot-cli/add-mcp-servers |
| Skills | `.github/skills/`, `~/.copilot/skills/` | customization/agent-skills |
| Rules | `.github/copilot-instructions.md`, `.github/instructions/**/*.instructions.md`, `AGENTS.md` (nested), `~/.copilot/copilot-instructions.md`, `~/.copilot/instructions/**`, `.github/prompts/*.prompt.md`, `.github/agents/*.md`, `~/.copilot/agents/` | custom-instructions-reference; prompt-files; custom-agent-file-reference |
| Hooks | `.github/hooks/*.json`, `~/.copilot/hooks/*.json`, `hooks` key in `.github/copilot/settings{,.local}.json` and `~/.copilot/settings.json`; also reads `.claude/settings{,.local}.json`. Shape: `{"version":1,"hooks":{"<event>":[{"type":"command","command"/"bash"/"powershell":…}]}}` | docs.github.com copilot/reference/hooks-reference |
| Auto-approve (LW008) | `.vscode/settings.json`: `chat.tools.global.autoApprove: true`, `chat.tools.terminal.autoApprove` | agents/reference/ai-settings |

## Other auto-loaded files worth flagging in `scan-repo`

`.amazonq/mcp.json` and `.amazonq/rules/` (Amazon Q; PRD §2, CVE-2026-12957/12958), `.clinerules`, `.roo/`, `.kiro/`. These haven't been checked against upstream docs yet.
