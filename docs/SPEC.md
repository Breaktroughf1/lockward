# Lockward Lockfile Specification

**Version:** 1 (draft) · **Status:** open for comment · **File name:** `lockward.lock`

This document defines the on-disk format Lockward uses to pin AI-agent assets. It is intentionally tool-independent so other projects can read and write it; following it exactly yields byte-identical lockfiles.

The keywords MUST, SHOULD and MAY are used as in RFC 2119.

## 1. Files and scopes

| Scope | Default path | Committed to git? |
|---|---|---|
| Project | `<repo>/lockward.lock` | Yes |
| User | `$XDG_CONFIG_HOME/lockward/user.lock` (Linux, default `~/.config`), `~/Library/Application Support/lockward/user.lock` (macOS), `%APPDATA%\lockward\user.lock` (Windows) | No |

A project lockfile MUST only contain project-scope assets. User-scope assets MUST NOT leak absolute home paths into a project lockfile.

## 2. Encoding

Lockfiles, and every value hashed by §5.3 and §5.4, use this canonical JSON form:

- UTF-8 without a byte order mark. Strings MUST be valid UTF-8; an encoder MUST fail rather than substitute characters.
- Object keys sorted bytewise (by UTF-8 bytes).
- Two-space indentation; one member or element per line; `": "` between key and value; `,` directly after a value; `\n` line endings; a trailing newline after the document.
- Empty arrays and objects are written as `[]` and `{}`.
- String escaping: `"` → `\"`, `\` → `\\`, U+000A → `\n`, U+000D → `\r`, U+0009 → `\t`, any other code point below U+0020 and U+007F → `\u00xx` (lowercase hex). Everything else, including non-ASCII and U+2028/U+2029, is written as raw UTF-8.
- Numbers are written exactly as they appear in the source document (Lockward itself only emits integers).
- Optional fields that are absent or empty are omitted, never written as `null`.

Arrays of entries MUST be sorted by `id`. Paths MUST use `/` separators, be relative to the scope root (`~` for user scope, the repository root for project scope), and contain no empty, `.` or `..` segments. Paths and symlink targets MUST NOT contain control characters; an implementation MUST report an error instead of pinning such a name.

No timestamps appear in a lockfile.

## 3. Top-level structure

```json
{
  "entries": [],
  "generated_by": "lockward 0.1.0",
  "hash_algorithm": "sha256",
  "lockfile_version": 1,
  "scope": "project"
}
```

`generated_by` names the tool that wrote the file and has no effect on verification.

## 4. Entry

Common fields:

| Field | Type | Description |
|---|---|---|
| `id` | string | `<surface>:<agent>:<name>`; see §4.6 |
| `surface` | enum | `skill` · `mcp` · `hook` · `rules` · `settings` |
| `agent` | enum | Owning agent: `claude-code` · `cursor` · `codex` · `gemini-cli` · `windsurf` · `copilot` · `generic` |
| `loaded_by` | string[]? | Every agent that loads the asset, sorted, when that is more than the owner. Values outside the agent enum (e.g. `amazon-q`) MAY appear |
| `path` | string | Location relative to the scope root. Objects inside a config file use `<file>#<JSON Pointer>` (RFC 6901) |
| `digest` | string | `sha256:<hex>`, see §5 |
| `symlink` | string? | Verbatim target when the asset path itself is a symbolic link |
| `source` | object? | Provenance `{ "type", "ref", "resolved"? }`; type is `npm`, `pypi`, `oci`, `url` or `local` |
| `approved` | object? | `{ "by": "<identity>" }`, written by `approve`; no timestamp |

A shared file is pinned once. Its owner is the agent whose documentation defines the path, and other readers are listed in `loaded_by`; cross-agent standards such as `AGENTS.md` and `.agents/skills/` use `generic`.

### 4.1 `skill`

```json
{
  "agent": "claude-code",
  "digest": "sha256:…",
  "files": [
    { "digest": "sha256:…", "mode": "0644", "path": "SKILL.md", "size": 2140 },
    { "path": "latest", "symlink": "scripts/run.py" },
    { "digest": "sha256:…", "mode": "0755", "path": "scripts/run.py", "size": 812 }
  ],
  "id": "skill:claude-code:pdf-tools",
  "path": ".claude/skills/pdf-tools",
  "surface": "skill"
}
```

`files` MUST list every member of the skill directory, including dotfiles, binaries and archives, except paths excluded by a user-configured `.lockwardignore` (§4.5). Regular files carry `digest`, `size` and `mode`. Symbolic links are recorded as `{ "path", "symlink" }` and MUST NOT be followed. Other special files (FIFOs, sockets, devices) are recorded as `{ "path", "special": "fifo" | "socket" | "device" | "char-device" | "irregular" }` and MUST NOT be opened. A regular file directly inside a skills directory is pinned as a single-member skill whose member path is its file name.

### 4.2 `mcp`

```json
{
  "agent": "cursor",
  "digest": "sha256:…",
  "id": "mcp:cursor:github",
  "path": ".cursor/mcp.json#/mcpServers/github",
  "server": {
    "args": ["-y", "@modelcontextprotocol/server-github@2.1.0"],
    "command": "npx",
    "env_keys": ["GITHUB_TOKEN"],
    "package": { "ecosystem": "npm", "name": "@modelcontextprotocol/server-github", "spec": "@modelcontextprotocol/server-github@2.1.0", "version": "2.1.0" },
    "transport": "stdio"
  },
  "source": { "ref": "@modelcontextprotocol/server-github", "resolved": "@modelcontextprotocol/server-github@2.1.0", "type": "npm" },
  "surface": "mcp",
  "tools_fingerprint": "sha256:…"
}
```

`server` fields: `transport` (`stdio` · `http` · `sse` · `ws`), `command`, `args`, `cwd`, `package` (`ecosystem` npm/pypi/oci, `name`, exact `version` if pinned, OCI `digest` if pinned, raw `spec`), `url`, `env_keys`, `header_keys`, `trust` (Gemini CLI), `approval_mode` (Codex `default_tools_approval_mode`), `disabled`.

Environment and header **values** MUST NOT be stored, only their names. Secret-looking command-line arguments, URL credentials and URL query values under sensitive names MUST be replaced with `[REDACTED]` before the object is stored or hashed. As a consequence, a change to a redacted secret alone is not drift; policy rule LW007 flags inline secrets instead.

### 4.3 `hook`

```json
{
  "agent": "claude-code",
  "digest": "sha256:…",
  "hook": { "command": "\"$CLAUDE_PROJECT_DIR\"/.claude/hooks/guard.sh", "event": "PreToolUse", "matcher": "Bash", "type": "command" },
  "id": "hook:claude-code:.claude/settings.json#PreToolUse/0/0",
  "path": ".claude/settings.json#/hooks/PreToolUse/0/hooks/0",
  "referenced_files": [ { "digest": "sha256:…", "path": ".claude/hooks/guard.sh" } ],
  "surface": "hook"
}
```

One entry per hook handler. `hook` fields: `event`, `matcher`, `type`, `command`, `bash`, `powershell`, `exec`, `args`, `shell`, `cwd`, `url`, `prompt`, `server`, `tool` (redacted like §4.2). If a hook command references a regular file inside the scope root, that file MUST be pinned in `referenced_files`. References are resolved from path-like tokens, with `$CLAUDE_PROJECT_DIR`, `$GEMINI_PROJECT_DIR`, `$CURSOR_PROJECT_DIR`, `${workspaceFolder}` and `$PWD` meaning the project root, and `~`, `$HOME` meaning the user-scope root.

### 4.4 `rules`

```json
{ "agent": "generic", "digest": "sha256:…", "id": "rules:generic:AGENTS.md", "loaded_by": ["codex", "copilot", "cursor", "windsurf"], "path": "AGENTS.md", "surface": "rules" }
```

Rules and instruction files, prompt files, commands, custom agents and workflows are pinned by file digest.

### 4.5 `settings`

```json
{
  "agent": "claude-code",
  "digest": "sha256:…",
  "id": "settings:claude-code:.claude/settings.json",
  "path": ".claude/settings.json",
  "settings": { "enableAllProjectMcpServers": true, "env": { "keys": ["API_TOKEN"] }, "permissions": { "allow": ["Bash(*)", "Read"] } },
  "surface": "settings"
}
```

The security-relevant subset of an agent config file: permission and approval settings, trust lists, and settings that change which files load or which commands run. The keys kept per agent are listed in each adapter's README. Any object under a key named `env` is reduced to `{ "keys": [<sorted names>] }`, and string values are redacted as in §4.2. No entry is written when none of the keys is present.

The project's `.lockwardignore` is pinned as `settings:generic:.lockwardignore` with `settings: { "patterns": [<active pattern lines in file order>] }`, so changing what is ignored is itself drift (THREAT_MODEL T13).

A config file that cannot be parsed is pinned by file digest under the surface it would have contributed to, with the file path as its name, and a problem is reported.

### 4.6 Identifiers

| Surface | Name |
|---|---|
| skill | Directory (or file) name within the skills directory; Gemini CLI extensions use `extensions/<name>` |
| mcp | Server name; servers from Claude Code local scope use `<project>@local/<server>`, extensions `<extension>/<server>`, Amazon Q `amazon-q/<server>` |
| hook | `<file>#<event>/<group>/<handler>` for nested `{matcher, hooks: [...]}` groups, `<file>#<event>/<index>` for flat lists |
| rules, settings | Path |

When two entries would share an id, each colliding entry uses its `path` as its name instead.

## 5. Digests

All digests are SHA-256, written as `sha256:` + 64 lowercase hex digits.

### 5.1 File digest

SHA-256 of the raw file bytes, streamed. Implementations MUST hash the entire file regardless of size (no truncation or sampling) and MUST NOT open a file that is not regular.

### 5.2 Tree digest (skills)

1. Collect every non-directory member under the skill directory without following symbolic links, minus paths excluded by `.lockwardignore`. Directories contribute only through their contents.
2. For each member build the line `<type> <mode> <path> <value>\n`:
   - `type` is `f` (regular file), `l` (symbolic link) or `s` (special file);
   - `mode` is `0755` if any execute bit is set and `0644` otherwise for files (Windows reports `0644`), `0777` for symlinks and `0000` for special files;
   - `path` is relative to the skill directory with `/` separators;
   - `value` is the file digest (§5.1) for files, the SHA-256 digest of the target string for symlinks, and the SHA-256 digest of the kind name (e.g. `fifo`) for special files.
3. Sort lines bytewise by `path`.
4. The tree digest is the SHA-256 of the concatenated lines.

Because `value` always has a fixed length and paths cannot contain control characters, distinct trees cannot produce the same input.

#### 5.2.1 Symlinked skill directories

When the skill path is itself a symbolic link, its digest is the SHA-256 of `symlink <sha256 of target>\n` followed, if the target resolves inside the scope root, by `tree <tree digest of the target>\n`. A target outside the scope root is never read; only the first line is hashed and a problem is reported.

### 5.3 Object digest

SHA-256 over the canonical JSON (§2) of:

| Surface | Hashed value |
|---|---|
| mcp | the `server` object |
| hook | `{ "hook": <hook object>, "referenced_files": [...] }`, omitting `referenced_files` when empty, so a change to a referenced script changes the hook's digest |
| settings | the `settings` object |

### 5.4 Tools fingerprint (optional)

SHA-256 over the canonical JSON of the `tools` array from an MCP `tools/list` response, keeping only `name`, `description` and `inputSchema` for each tool, sorted by `name`. Tool names MUST be unique.

## 6. Verification semantics

For each scope, compare live discovery with the lockfile:

| Condition | Result |
|---|---|
| Entry in live state, not in lockfile | `added` |
| Entry in lockfile, not in live state | `removed` |
| Same `id`, different `digest` (or `tools_fingerprint`) | `modified` |
| Same `id` and digests | `ok` |

In `--frozen` mode, any non-`ok` result MUST cause a non-zero exit (code 1). Without `--frozen`, `modified` and `removed` MUST cause exit code 1 and `added` SHOULD be reported without failing. When no `tools/list` response is supplied, a verifier keeps the locked `tools_fingerprint` and SHOULD say that it was not re-checked.

## 7. Versioning

`lockfile_version` increments on any breaking change. Readers MUST refuse unknown versions with a clear error, and writers MUST NOT overwrite a lockfile they cannot read. New optional fields MAY be added without a version bump; readers MUST ignore unknown fields.
