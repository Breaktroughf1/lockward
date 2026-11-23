# GitHub Copilot adapter

Agent id: `copilot`. Base docs: https://code.visualstudio.com/docs/copilot/ and https://docs.github.com/en/copilot/

Verified against upstream docs on **2026-11-23**. When the upstream docs change, update this file, the adapter and its fixtures under `testdata/adapters/` together.

| Surface | What is read | Upstream page |
|---|---|---|
| MCP | `.vscode/mcp.json` → `servers` (JSONC), `.github/mcp.json` → `mcpServers` (project); `~/.copilot/mcp-config.json` (user). The root `.mcp.json` is owned by the claude-code adapter and lists Copilot in `loaded_by`. | agents/reference/mcp-configuration, copilot-cli/add-mcp-servers |
| Skills | `.github/skills/*/` (project), `~/.copilot/skills/*/` (user). | customization/agent-skills |
| Hooks | `.github/hooks/*.json`, `hooks` in `.github/copilot/settings.json` and `.local.json` (project); `~/.copilot/hooks/*.json`, `~/.copilot/settings.json` (user). | copilot/reference/hooks-reference |
| Rules | `.github/copilot-instructions.md`, `.github/instructions/**/*.instructions.md`, `.github/prompts/**/*.prompt.md`, `.github/agents/**/*.md`, legacy `.github/chatmodes/`; `~/.copilot/copilot-instructions.md`, `~/.copilot/instructions/`, `~/.copilot/agents/`. | custom-instructions-reference, prompt-files, custom-agent-file-reference |
| Settings | VS Code `chat.tools.*`, `chat.mcp.*`, `chat.use*`, `chat.permissions.*`, `chat.defaultConfiguration` and the `chat.*Locations` keys in `.vscode/settings.json` and the user settings file (Linux, macOS and Windows locations). | agents/reference/ai-settings |
| LW008 | `chat.tools.global.autoApprove: true`, `chat.tools.autoApprove: true`, or a catch-all `chat.tools.terminal.autoApprove` pattern set to `true`. | agents/reference/ai-settings |

## Known limits

- MCP servers configured in a repository's GitHub settings for the Copilot coding agent are not on disk and cannot be pinned.

Fixtures: `testdata/adapters/` (see `internal/discover/discover_test.go`).
