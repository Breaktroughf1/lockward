# Cross-agent assets adapter

Agent id: `generic`. Base docs: https://agents.md/ and the agent docs above

Verified against upstream docs on **2026-11-23**. When the upstream docs change, update this file, the adapter and its fixtures under `testdata/adapters/` together.

| Surface | What is read | Upstream page |
|---|---|---|
| Rules | `AGENTS.md` at any depth (loaded by Codex, Copilot, Cursor and Windsurf/Devin). | learn.chatgpt.com agents-md; cursor.com context/rules; VS Code custom-instructions-reference; docs.devin.ai rules |
| Skills | `.agents/skills/*/` at the root and in subdirectories, and `~/.agents/skills/*/` (Codex, Copilot, Cursor, Gemini CLI, Windsurf/Devin). | build-skills; context/skills; agent-skills; cli/skills; desktop/cascade/skills |
| Amazon Q | `.amazonq/mcp.json` → `mcpServers` (ids `amazon-q/<server>`) and `.amazonq/rules/**/*.md`, flagged because of CVE-2026-12957/12958 (PRD §2). Not checked against Amazon Q's docs yet. | PRD §2 |

MCP server and hook definitions are pinned with every field (redacted), not only the columns above (SPEC §4.2, §4.3).

## Known limits

- Claude Code reads `AGENTS.md` only when no `CLAUDE.md` exists, so it is not listed in `loaded_by`.

Fixtures: `testdata/adapters/` (see `internal/discover/discover_test.go`).
