# Cursor adapter

Agent id: `cursor`. Base docs: https://cursor.com/docs/

Verified against upstream docs on **2026-11-23**. When the upstream docs change, update this file, the adapter and its fixtures under `testdata/adapters/` together.

| Surface | What is read | Upstream page |
|---|---|---|
| Skills | `.cursor/skills/*/` (root and nested), `.codex/skills/*/` (compatibility); the same under `~`. `.claude/skills` and `.agents/skills` are owned by the claude-code and generic adapters and list Cursor in `loaded_by`. | context/skills |
| MCP | `.cursor/mcp.json` and `~/.cursor/mcp.json` → `mcpServers`. | context/mcp |
| Hooks | `.cursor/hooks.json` and `~/.cursor/hooks.json` → `hooks.<event>[]`. Project hooks run from the project root, user hooks from `~/.cursor`. | agent/hooks |
| Rules | `.cursor/rules/**/*.mdc` (plain `.md` there is ignored by Cursor and by this adapter); legacy `.cursorrules`. User rules are not stored on disk. | context/rules |

## Known limits

- No file-based auto-approval setting is documented (the Run Modes page returned 404), so LW008 has nothing to check for Cursor.

Fixtures: `testdata/adapters/` (see `internal/discover/discover_test.go`).
