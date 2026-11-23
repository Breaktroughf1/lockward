# Policy reference

Lockward evaluates a declarative policy on the live state of each scope during `verify`, `status` and `scan-repo`. Every rule is deterministic: there is no LLM in the decision path ([ADR-0003](adr/0003-no-llm-in-decision-path.md)).

## File

`lockward.policy.yaml` in the project root (user scope: `<user config dir>/lockward/policy.yaml`), or the file passed with `--policy`. Without a file the built-in defaults apply. `lockward init` writes a commented default.

```yaml
version: 1

rules:            # error | warning | off; omitted rules use their default
  LW004: error
  LW006: off

allow:
  sources:        # <type>:<pattern>; types npm, pypi, oci, url, local
    - npm:@modelcontextprotocol/*
    - oci:ghcr.io/github/*
    - url:mcp.stripe.com
    - local:*
  domains:        # exact host, or *.example.com for subdomains
    - github.com
    - "*.example.com"

exceptions:       # suppress one rule for matching entry ids; a reason is required
  - rule: LW006
    id: skill:claude-code:pdf-tools
    reason: Ships a reviewed helper binary (SEC-123)
```

Parsing is strict: unknown keys, unknown rule ids, invalid severities, malformed allow entries and exceptions without a reason are errors (exit code 3), so a typo cannot quietly weaken the policy. Patterns use Go's `path.Match` syntax, where `*` does not cross `/`. Exception ids may be patterns too (`mcp:cursor:*`).

Only `error` findings fail a run (exit code 2). The number of findings suppressed by exceptions is always reported. Protect the policy file with CODEOWNERS (THREAT_MODEL T7).

## Rules

### LW001

**unpinned-mcp-package** (default: error). An MCP server is launched through `npx`, `bunx`, `pnpm dlx`, `yarn dlx`, `npm exec`, `uvx`, `uv tool run` or `pipx run` without an exact version, or through `docker`/`podman run` without an image digest. Such servers fetch whatever is newest every time they start, which is how a clean package becomes a backdoor overnight.

Fix: `npx -y pkg@1.2.3`, `uvx pkg==1.2.3`, `docker run image@sha256:…`. Git specs count as pinned only with a full commit hash.

### LW002

**source-not-allowed** (default: error; inactive while `allow.sources` is empty). The source of an MCP server or skill is not in `allow.sources`. Sources are `npm:<package>`, `pypi:<package>`, `oci:<image>` (without tag or digest), `url:<host>` for remote servers, and `local:<path or command>` for skills and locally run servers.

### LW003

**hook-executes-network** (default: error). A hook command, or a script it references inside the scope root, invokes a network tool (`curl`, `wget`, `nc`, `socat`, `ssh`, `scp`, `rsync`, `Invoke-WebRequest`, `certutil` and similar), opens `/dev/tcp`, or uses common HTTP libraries. HTTP-type hooks that post events to a URL are also reported.

### LW004

**external-url-reference** (default: warning). A line in a skill, rules file or MCP argument list both contains a URL and tells the agent to fetch or execute something (`curl`, `wget`, `download`, `fetch`, `npx`, `uvx`, `pip install`, `git clone`, `| sh`, `eval` and similar), and the URL's host is not in `allow.domains` (OWASP AST05). Whole files are scanned, however large, so padding cannot push a payload out of view.

### LW005

**secret-path-reference** (default: warning). A skill, rules file, hook or MCP argument references a credential store: `~/.ssh` and SSH key names, `~/.aws`, `~/.gnupg`, `~/.kube`, `~/.azure`, `~/.docker/config.json`, `.netrc`, `.npmrc`, `.pypirc`, `.git-credentials`, gcloud and gh configs, `.env` files, macOS keychains, browser profile and login databases, or `/etc/shadow`.

### LW006

**executable-in-skill** (default: error). A skill contains compiled or packaged code: ELF, Mach-O or PE executables, shared libraries, WebAssembly, Python or Java bytecode, or archives (ZIP including Office documents, gzip, bzip2, xz, 7-Zip, RAR, zstd, tar, wheels, jars, installers). Detection uses file signatures as well as extensions, so renaming a file does not hide it.

### LW007

**env-value-inline** (default: error). An MCP server or hook config contains a secret value instead of a reference: an `env` or header value under a sensitive name (`TOKEN`, `SECRET`, `PASSWORD`, `API_KEY`, `Authorization` and similar) that is not a `${VAR}` or `$VAR` reference, a recognised credential format (GitHub, OpenAI, Anthropic, AWS, Slack, GitLab, npm, PyPI, Stripe and Google keys, JWTs, private keys) in an argument or URL, or a secret after a flag such as `--api-key`. The finding names the location (`env.API_KEY`, `args[3]`), never the value, and the lockfile stores names only.

### LW008

**auto-approve-tools** (default: error). Agent settings let tools or commands run without confirmation:

| Agent | Settings |
|---|---|
| Claude Code | `permissions.defaultMode` of `bypassPermissions` or `dontAsk`; `permissions.allow` entries `*`, `Bash`, `Bash(*)`, `mcp__*` or a whole server; `enableAllProjectMcpServers: true`; `enabledMcpjsonServers` |
| Gemini CLI | `mcpServers.<name>.trust: true`; `tools.allowed` containing `run_shell_command` or `*` |
| Codex | `approval_policy = "never"` (also in profiles); MCP `default_tools_approval_mode = "approve"` or a tool's `approval_mode = "approve"` |
| Copilot (VS Code) | `chat.tools.global.autoApprove: true`; `chat.tools.autoApprove: true`; a catch-all `chat.tools.terminal.autoApprove` pattern set to `true` |
| Windsurf / Devin | broad `permissions.allow` entries such as `mcp__*` |

Cursor documents no file-based auto-approval setting.
