# Using Lockward

## Concepts

- **Scope.** The *project* scope is a repository (its root is the nearest parent directory containing `.git` or `lockward.lock`, or `--root`). The *user* scope is your home directory (`--home`). Each scope has its own lockfile: `lockward.lock` in the project root, committed to git, and a user lockfile at `<user config dir>/lockward/user.lock` (`$XDG_CONFIG_HOME` or `~/.config` on Linux, `~/Library/Application Support` on macOS, `%APPDATA%` on Windows), which is personal and never committed.
- **Entry.** One pinned asset with a stable id `<surface>:<agent>:<name>`, for example `skill:claude-code:pdf-tools`, `mcp:cursor:github`, `hook:claude-code:.claude/settings.json#PreToolUse/0/0` or `rules:generic:AGENTS.md`. Surfaces are `skill`, `mcp`, `hook`, `rules` and `settings`.
- **Drift.** An entry that is `added`, `removed` or `modified` compared with the lockfile.
- **Policy finding.** A rule from [POLICY.md](POLICY.md) that matched the live state, at `error` or `warning` severity.

## Output safety

Text output shows untrusted characters from scanned files (escape sequences, other control characters, bidirectional and invisible Unicode) as visible escapes such as `\x1b` or `\u{202e}`, so a hostile repository cannot rewrite your terminal or inject CI workflow commands. JSON and SARIF keep the original strings, correctly escaped.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Clean |
| 1 | Drift (verify, status, diff) |
| 2 | Policy violation at error severity (verify, status, scan-repo) |
| 3 | Usage or configuration error (bad flags, missing or unreadable lockfile, invalid policy) |
| 4 | Internal error |

When an entry drifts *and* a policy rule fails, verify exits 1: approve or revert the change first, then policy is evaluated on the result.

## Commands

Flags may appear before or after positional arguments. `lockward help <command>` lists every flag.

### init

Writes `lockward.policy.yaml` (all rules at their defaults, with comments), an empty `.lockwardignore`, and a `.gitattributes` that keeps agent files LF on every OS (see [Windows and line endings](#windows-and-line-endings)) in the project root. Existing files are never modified: if `.gitattributes` already exists without Lockward's block, `init` prints the lines to append.

### lock

```sh
lockward lock                    # project and user scope
lockward lock --scope project
lockward lock --tools mcp:cursor:github=github-tools.json
```

Discovers every asset, hashes it and writes the lockfile. When it pins personal files that are normally gitignored (such as `CLAUDE.local.md` or `.claude/settings.local.json`), it says so: committed, they make CI report "removed" and share personal settings, so add them to `.lockwardignore` if they should stay personal. Entries whose digest is unchanged keep their `approved` record. A lockfile that exists but cannot be read (corrupt, or from a newer Lockward) is never overwritten. `lock` also saves a local snapshot of small text files so that `diff` can show sentence-level changes later (see [Snapshots](#snapshots)).

### verify

```sh
lockward verify                     # every scope that has a lockfile
lockward verify --frozen            # CI: any difference fails, additions included
lockward verify --format sarif > lockward.sarif
lockward verify --scope project --policy ci-policy.yaml
```

Without `--frozen`, modified and removed entries fail and additions are reported but tolerated, which suits local use while you work. With `--frozen`, any difference fails. Use `--frozen` in CI.

External scanner results can be attached with `--scanner-sarif scanner.sarif` (repeatable, LW-FR-16). Each SARIF 2.1.0 result is linked to the entry whose file it names, or the skill directory that contains it, and shown under "scanner findings". Imported findings are informational: they never change the exit code, so no external tool can override a drift or policy result ([ADR-0003](adr/0003-no-llm-in-decision-path.md)). They appear in text and JSON output; upload the scanner's own SARIF to code scanning separately.

Every run prints the policy file and its digest, the active `.lockwardignore` patterns and how many files they hid (THREAT_MODEL T7, T13), and any problems found during discovery, such as a config file that could not be parsed and was pinned as raw bytes instead.

### diff

```sh
lockward diff
lockward diff skill:claude-code:pdf-tools
```

For skills: added (`A`), deleted (`D`) and modified (`M`) files, mode and symlink changes, and a sentence-level diff for modified text files. For rules files: a sentence-level diff. For MCP servers, hooks and settings: a line diff of the recorded definition. Exits 1 when anything changed.

### approve

```sh
lockward approve skill:claude-code:pdf-tools mcp:cursor:github
lockward approve --all
lockward approve --scope user --all
lockward approve --by security-team@example.com rules:generic:AGENTS.md
```

Updates only the named entries from live state; an entry that no longer exists is removed. Unknown ids are an error, so a typo never approves nothing silently. The approver comes from `--by`, then `$LOCKWARD_APPROVER`, then `user.email` in the repository's git config or your global git config. Git is never run.

### status

```sh
lockward status
# lockward: clean (24 entries)
# lockward: drift (1 modified, 2 added, 0 removed); run 'lockward verify'
```

Same checks and exit code as `verify --frozen`, printed as one line.

### scan-repo

```sh
lockward scan-repo ./cloned-repo
lockward scan-repo ./cloned-repo --format json
lockward scan-repo ./cloned-repo --policy my-policy.yaml
lockward scan-repo ./cloned-repo --scanner-sarif skillspector.sarif
```

Lists every file the supported agents would auto-load from the repository, which agents load it, what it can run or connect to, and the external hosts it references, plus policy findings. Nothing is executed. The repository's own `.lockwardignore` and `lockward.policy.yaml` are ignored, so an untrusted repository cannot hide files or switch rules off; the output says when they were present. Exits 2 if a rule fails at error severity.

### bom

```sh
lockward bom > agent-bom.cdx.json
lockward bom --scope user
```

Writes a CycloneDX 1.6 BOM of the lockfile's entries, with SHA-256 hashes, package URLs for pinned npm and PyPI MCP packages, and `lockward:*` properties. The output is deterministic: no timestamp, and the serial number is derived from the entries.

## Common flags

| Flag | Commands | Meaning |
|---|---|---|
| `--root DIR` | all but scan-repo | Project root |
| `--home DIR` | lock, verify, diff, approve, status, bom | User-scope root |
| `--user-lockfile FILE` | same | User lockfile location |
| `--policy FILE` | same, scan-repo | Policy file to use instead of the default location |
| `--tools ID=FILE` | lock, verify, diff, approve | MCP `tools/list` response for an entry (repeatable) |
| `--max-files N` | same | Files per skill before failing (default 200000) |
| `--scanner-sarif FILE` | verify, scan-repo | External scanner SARIF to attach to entries (repeatable; informational) |

## MCP tool fingerprints

Lockward never launches an MCP server. To pin a server's tool descriptions (THREAT_MODEL T4), capture its `tools/list` response yourself (for example with the MCP Inspector) and pass it in:

```sh
lockward lock --tools mcp:cursor:github=github-tools.json
lockward verify --tools mcp:cursor:github=github-tools-today.json
```

Only each tool's `name`, `description` and `inputSchema` are fingerprinted. When `--tools` is not given, verify carries the locked fingerprint over and prints a note saying it was not re-checked.

## .lockwardignore

Gitignore-style patterns, relative to the scope root: `#` comments, `!` negation, a trailing `/` for directories, a leading or inner `/` to anchor, and the `*`, `?`, `[...]` and `**` wildcards. A file inside an ignored directory stays ignored. Ignored paths are left out of discovery and out of skill trees. The active patterns are pinned as the entry `settings:generic:.lockwardignore`, so changing them is itself drift, and every verify prints them.

The nested-file search used for `AGENTS.md`, `CLAUDE.md` and similar never enters `.git` or `node_modules`. Files in those directories are still hashed when they are part of a pinned skill.

## Windows and line endings

Lockward pins the exact bytes an agent reads. With Git's `core.autocrlf=true` (the default on Windows), text files are checked out with CRLF line endings, so a Windows checkout really does contain different bytes from the LF files that were locked on Linux or macOS, and `verify` reports them as modified. Keep agent files LF on every OS with `.gitattributes`. `lockward init` creates it when the file is missing, or prints these lines to append to an existing one:

```gitattributes
CLAUDE.md text=auto eol=lf
AGENTS.md text=auto eol=lf
GEMINI.md text=auto eol=lf
.mcp.json text=auto eol=lf
.claude/** text=auto eol=lf
.cursor/** text=auto eol=lf
.codex/** text=auto eol=lf
.gemini/** text=auto eol=lf
.agents/** text=auto eol=lf
.github/copilot-instructions.md text=auto eol=lf
.github/instructions/** text=auto eol=lf
lockward.lock text=auto eol=lf
lockward.policy.yaml text=auto eol=lf
.lockwardignore text=auto eol=lf
```

Use `text=auto`, not `text`: with plain `text`, Git would also rewrite line endings inside binary files in skills (images, bytecode) and corrupt them.

After adding it, run `git add --renormalize .` once and commit.

## Snapshots

`lock` and `approve` copy text files of up to 1 MiB that belong to skills and rules entries (never files with credential-like names such as `.env`, `*.pem` or `id_rsa`) into `$LOCKWARD_CACHE_DIR`, or `<user cache dir>/lockward/objects`, keyed by digest. `diff` uses them to show the previous text. Snapshots stay on your machine and are checked against their digest when read. Without one (for example in CI, or on a different machine) `diff` shows file-level changes and the new text only.

## Environment

| Variable | Effect |
|---|---|
| `LOCKWARD_APPROVER` | Approver recorded by `approve` |
| `LOCKWARD_CACHE_DIR` | Snapshot directory |
| `NO_COLOR` | Disable coloured output (colour is only used on a terminal) |
