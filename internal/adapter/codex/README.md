# OpenAI Codex adapter

Agent id: `codex`. Base docs: https://learn.chatgpt.com/docs/ (redirected from developers.openai.com)

Verified against upstream docs on **2026-11-23**. When the upstream docs change, update this file, the adapter and its fixtures under `testdata/adapters/` together.

| Surface | What is read | Upstream page |
|---|---|---|
| MCP | `[mcp_servers.<name>]` in `.codex/config.toml` (project, trusted projects only) and `~/.codex/config.toml`. Env names come from `env`, `env_vars` and `bearer_token_env_var`; header names from `http_headers` and `env_http_headers`. | extend/mcp, config-file/config-reference |
| Hooks | `[hooks]` in `config.toml`, and `.codex/hooks.json` (location per the config reference summary). | config-file/config-reference |
| Settings | Project scope: the whole file except `mcp_servers` and `hooks`. User scope: `approval_policy`, `approvals_reviewer`, `sandbox_mode`, `sandbox_workspace_write`, `project_doc_fallback_filenames`, `project_doc_max_bytes`, `features`, `notify`, `profile`, `profiles`, `shell_environment_policy`. | config-file/config-reference |
| Rules | `AGENTS.override.md` and `project_doc_fallback_filenames` at any depth (project); `~/.codex/AGENTS.md`, `~/.codex/AGENTS.override.md` (user). `AGENTS.md` and `.agents/skills` belong to the generic adapter. | agent-configuration/agents-md |
| LW008 | `approval_policy = "never"` (top level or in a profile); MCP `default_tools_approval_mode = "approve"` or a tool's `approval_mode = "approve"`. | config-file/config-reference |

MCP server and hook definitions are pinned with every field (redacted), not only the columns above (SPEC §4.2, §4.3).

## Known limits

- `$CODEX_HOME` is not honoured; the default `~/.codex` is read.
- Admin skills in `/etc/codex/skills` are outside the home directory and not read.

Fixtures: `testdata/adapters/` (see `internal/discover/discover_test.go`).
