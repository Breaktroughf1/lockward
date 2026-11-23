# Lockward Lockfile Specification

**Version:** 1 (draft) · **Status:** open for comment · **File name:** `lockward.lock`

This document defines the on-disk format Lockward uses to pin AI-agent assets. It is intentionally tool-independent so other projects can read and write it.

The keywords MUST, SHOULD and MAY are used as in RFC 2119.

## 1. Files and scopes

| Scope | Default path | Committed to git? |
|---|---|---|
| Project | `<repo>/lockward.lock` | Yes |
| User | `$XDG_CONFIG_HOME/lockward/user.lock` (Linux), `~/Library/Application Support/lockward/user.lock` (macOS), `%APPDATA%\lockward\user.lock` (Windows) | No |

A project lockfile MUST only contain project-scope assets. User-scope assets MUST NOT leak absolute home paths into a project lockfile.

## 2. Encoding

- UTF-8 JSON, canonicalised: object keys sorted lexicographically, two-space indentation, `\n` line endings, trailing newline.
- Arrays of entries MUST be sorted by `id`.
- Paths MUST use `/` separators and be relative to the scope root (`~` for user scope, repo root for project scope).
- No timestamps inside entries (they break determinism). A single top-level `generated_by` field is allowed.

## 3. Top-level structure

```json
{
  "lockfile_version": 1,
  "generated_by": "lockward 0.1.0",
  "scope": "project",
  "hash_algorithm": "sha256",
  "entries": [ /* Entry objects, sorted by id */ ]
}
```

## 4. Entry

Common fields (all entries):

| Field | Type | Description |
|---|---|---|
| `id` | string | Stable identifier `<surface>:<agent>:<name>`, e.g. `skill:claude-code:pdf-tools` |
| `surface` | enum | `skill` · `mcp` · `hook` · `rules` |
| `agent` | enum | `claude-code` · `cursor` · `codex` · `gemini-cli` · `windsurf` · `copilot` · `generic` |
| `path` | string | Location relative to scope root |
| `digest` | string | `sha256:<hex>` — see §5 |
| `source` | object? | Optional provenance: `{ "type": "git"\|"npm"\|"pypi"\|"oci"\|"local"\|"url", "ref": "…", "resolved": "…" }` |
| `approved` | object? | `{ "by": "<git user.email or free text>" }` — written by `approve`; no timestamp |

### 4.1 `skill`

```json
{
  "id": "skill:claude-code:pdf-tools",
  "surface": "skill",
  "agent": "claude-code",
  "path": ".claude/skills/pdf-tools",
  "digest": "sha256:…",          // tree digest (§5.2)
  "files": [
    { "path": "SKILL.md", "digest": "sha256:…", "size": 2140, "mode": "0644" },
    { "path": "scripts/run.py", "digest": "sha256:…", "size": 812, "mode": "0755" }
  ]
}
```

`files` MUST list every regular file under the skill directory, including dotfiles, binaries and archives. Symlinks are recorded as `{ "path", "symlink": "<target>" }` and MUST NOT be followed.

### 4.2 `mcp`

```json
{
  "id": "mcp:cursor:github",
  "surface": "mcp",
  "agent": "cursor",
  "path": ".cursor/mcp.json#/mcpServers/github",
  "digest": "sha256:…",          // digest of the canonical server object below
  "server": {
    "transport": "stdio",        // stdio | http | sse
    "command": "npx",
    "args": ["-y", "@modelcontextprotocol/server-github@2.1.0"],
    "package": { "ecosystem": "npm", "name": "@modelcontextprotocol/server-github", "version": "2.1.0" },
    "url": null,
    "env_keys": ["GITHUB_TOKEN"]
  },
  "tools_fingerprint": "sha256:…" // optional, from tools/list (§5.4)
}
```

Environment **values** MUST NOT be stored. Header values for HTTP transports MUST NOT be stored; only header names.

### 4.3 `hook`

```json
{
  "id": "hook:claude-code:PreToolUse#0",
  "surface": "hook",
  "agent": "claude-code",
  "path": ".claude/settings.json#/hooks/PreToolUse/0",
  "digest": "sha256:…",
  "hook": { "event": "PreToolUse", "matcher": "Bash", "command": "./scripts/guard.sh" },
  "referenced_files": [ { "path": "scripts/guard.sh", "digest": "sha256:…" } ]
}
```

If a hook command references a file inside the scope root, that file MUST be pinned in `referenced_files`.

### 4.4 `rules`

```json
{
  "id": "rules:codex:AGENTS.md",
  "surface": "rules",
  "agent": "codex",
  "path": "AGENTS.md",
  "digest": "sha256:…"
}
```

## 5. Digests

All digests are SHA-256, encoded as `sha256:` + lowercase hex.

### 5.1 File digest
SHA-256 of the raw file bytes, streamed. Implementations MUST hash the entire file regardless of size (no truncation or sampling).

### 5.2 Tree digest (skills)
1. Collect every entry under the directory (no ignore rules except `.lockwardignore` explicitly configured by the user, which MUST be reported in `verify` output).
2. For each, build a line: `<type> <mode> <path> <digest-or-target>\n` where `type` is `f` (file) or `l` (symlink), `mode` is octal permission bits (`0644`/`0755`; Windows reports `0644`), `path` is relative with `/` separators.
3. Sort lines bytewise by `path`.
4. Tree digest = SHA-256 over the concatenated lines.

### 5.3 Object digest (mcp, hook)
SHA-256 over the canonical JSON (§2) of the entry's `server` or `hook` object.

### 5.4 Tools fingerprint (optional)
SHA-256 over canonical JSON of the `tools` array from an MCP `tools/list` response, keeping only `name`, `description`, `inputSchema`, sorted by `name`.

## 6. Verification semantics

For each scope, compare live discovery to the lockfile:

| Condition | Result |
|---|---|
| Entry in live state, not in lockfile | `added` |
| Entry in lockfile, not in live state | `removed` |
| Same `id`, different `digest` (or `tools_fingerprint`) | `modified` |
| Same `id` and digests | `ok` |

In `--frozen` mode, any non-`ok` result MUST cause a non-zero exit (code 1).

## 7. Versioning

`lockfile_version` increments on any breaking change. Readers MUST refuse unknown major versions with a clear error. New optional fields MAY be added without a version bump; readers MUST ignore unknown fields.
