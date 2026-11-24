# Gemini CLI adapter

Agent id: `gemini-cli`. Base docs: https://geminicli.com/docs/

Verified against upstream docs on **2026-11-23**. When the upstream docs change, update this file, the adapter and its fixtures under `testdata/adapters/` together.

| Surface | What is read | Upstream page |
|---|---|---|
| MCP | `mcpServers` in `.gemini/settings.json` and `~/.gemini/settings.json`; `url` means SSE and `httpUrl` streamable HTTP. Extension manifests `~/.gemini/extensions/<ext>/gemini-extension.json` (ids `<ext>/<server>`). | tools/mcp-server, extensions/reference |
| Hooks | `hooks` in settings files and `~/.gemini/extensions/<ext>/hooks/hooks.json`. | hooks |
| Skills / extensions | `.gemini/skills/*/` (both scopes); each `~/.gemini/extensions/<ext>/` is pinned as a tree (`extensions/<ext>`). | cli/skills, extensions/reference |
| Settings | Project scope: the whole file except `mcpServers` and `hooks`. User scope: `tools`, `mcp`, `security`, `context`, `hooksConfig`, `skills`, `policyPaths`, `adminPolicyPaths`, `general.defaultApprovalMode`, `advanced`. | reference/configuration |
| Rules | `GEMINI.md` and any `context.fileName` names at any depth (project); `~/.gemini/GEMINI.md` (user); `.gemini/commands/**/*.toml`. | cli/gemini-md, cli/custom-commands |
| LW008 | `mcpServers.<name>.trust: true`; `tools.allowed` containing `run_shell_command` or `*`. | tools/mcp-server, reference/configuration |

MCP server and hook definitions are pinned with every field (redacted), not only the columns above (SPEC §4.2, §4.3).

## Known limits

- The docs say Gemini CLI was replaced by Antigravity CLI on 18 June 2026 for unpaid and Google One users. Antigravity paths are not covered yet.
- System settings under `/etc/gemini-cli/` are not read.

Fixtures: `testdata/adapters/` (see `internal/discover/discover_test.go`).
