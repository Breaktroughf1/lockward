# Lockward Architecture

## 1. Overview

```
            +---------------------------- lockward CLI (cmd/lockward) ---------------------------+
            |  init  lock  verify  diff  approve  status  scan-repo  bom  version                |
            +-------------------------------------+---------------------------------------------+
                                                  |
        +----------------+-----------------+------+-----------+-----------------+--------------+
        |                |                 |                  |                 |              |
   internal/discover  internal/hash   internal/lock     internal/policy   internal/report  internal/repo
   (runs adapters)    (file + tree)   (read/write/      (rules LW001…)    (text, json,     (scan-repo,
        |                              compare)                             sarif, cdx)      read-only)
        v
   internal/adapter/{claudecode,cursor,codex,geminicli,windsurf,copilot}
   each: Discover(root, scope) -> []Asset   (pure, read-only, fixture-tested)
```

Data flow for `verify`:
`discover` → `[]Asset` → `hash` → `[]Entry` → `lock.Compare(live, locked)` → `[]Result` → `policy.Evaluate` → `report.Render` → exit code.

## 2. Repository layout

```
cmd/lockward/            main package, CLI wiring only (cobra or stdlib flag — see ADR)
internal/adapter/        one package per agent; no cross-adapter imports
internal/asset/          Asset and Entry types shared across packages
internal/discover/       adapter registry, scope roots, ignore handling
internal/hash/           streaming file digest, tree digest, canonical JSON
internal/lock/           lockfile model, canonical encode/decode, compare
internal/policy/         policy schema, built-in rules, evaluation
internal/report/         renderers: text, json, sarif, cyclonedx
internal/repo/           scan-repo
internal/prose/          sentence-level diff for Markdown/text
testdata/                fixtures per adapter, golden outputs, malicious corpus
action/                  GitHub Action (action.yml + checksum-verifying wrapper)
docs/                    PRD, SPEC, threat model, ADRs
```

`internal/` keeps the API private until the lockfile spec stabilises; a public `pkg/lockfile` may follow in v0.2.

## 3. Key design decisions

| Decision | Choice | ADR |
|---|---|---|
| Language | Go, CGO disabled, static binaries | [0001](adr/0001-language-go.md) |
| Licence | Apache-2.0 | [0002](adr/0002-licence-apache-2.md) |
| No LLM in decision path | Deterministic only | [0003](adr/0003-no-llm-in-decision-path.md) |
| Offline by default | No network in default paths | [0004](adr/0004-offline-by-default.md) |

## 4. Adapter contract

```go
type Adapter interface {
    Name() string                         // "claude-code"
    Discover(ctx context.Context, fsys fs.FS, scope Scope) ([]asset.Asset, error)
}
```

Rules:
- Accept an `fs.FS` (enables in-memory fixture tests; prevents accidental writes).
- Never execute anything; never follow symlinks outside `fsys`.
- Missing config → zero assets, not an error. Malformed config → a reported finding, not a crash.
- Each adapter documents the config paths it reads, with links to upstream docs and the date verified, in `internal/adapter/<name>/README.md`.

### Initial config paths to support (verify against current upstream docs in week 1)

| Agent | Skills | MCP | Hooks | Rules |
|---|---|---|---|---|
| Claude Code | `.claude/skills/*/`, `~/.claude/skills/*/`, plugin skills | `.mcp.json`, `~/.claude.json` | `.claude/settings.json`, `.claude/settings.local.json`, `~/.claude/settings.json` | `CLAUDE.md`, `.claude/CLAUDE.md`, `~/.claude/CLAUDE.md`, `.claude/commands/`, `.claude/agents/` |
| Cursor | — | `.cursor/mcp.json`, `~/.cursor/mcp.json` | `.cursor/hooks.json` | `.cursor/rules/*.mdc`, `.cursorrules` |
| Codex | `.codex/skills/`, `~/.codex/skills/` | `~/.codex/config.toml` | — | `AGENTS.md` (+ nested) |
| Gemini CLI | extensions | `.gemini/settings.json`, `~/.gemini/settings.json` | — | `GEMINI.md` |
| Windsurf | — | `~/.codeium/windsurf/mcp_config.json` | — | `.windsurfrules`, `.windsurf/rules/` |
| Copilot | — | `.vscode/mcp.json` | — | `.github/copilot-instructions.md`, `.github/instructions/*.md` |

## 5. Dependencies policy

Minimal and justified. Expected candidates (each needs a one-line justification in an ADR or `go.mod` comment):
- CLI: `spf13/cobra` *or* stdlib `flag` (decide in week 1).
- YAML: `gopkg.in/yaml.v3` / `go.yaml.in/yaml/v3`.
- TOML (Codex): `github.com/pelletier/go-toml/v2`.
- CycloneDX: `github.com/CycloneDX/cyclonedx-go`.
- Policy expressions (optional, v0.2): `github.com/google/cel-go`.

No dependency may perform network I/O on import or in code paths we call.

## 6. Testing strategy

- Unit tests with table-driven cases; golden files under `testdata/golden/` (update with `go test ./... -update`).
- Adapter fixtures: realistic config trees under `testdata/adapters/<agent>/`.
- Security invariants from THREAT_MODEL §6 as named tests (`TestInvariant_NoExec…`).
- Fuzz: lockfile decoder, each adapter parser, prose differ.
- Offline test: CI job runs tests inside `unshare -n` (Linux) to prove no network.
- Benchmark corpus (week 7): Trail of Bits and Snyk malicious skill samples (hashes only committed if licences forbid redistribution).

## 7. Release engineering

- GoReleaser: linux/darwin/windows × amd64/arm64, `CGO_ENABLED=0`, `-trimpath`, reproducible `mod_timestamp`.
- Checksums, Sigstore keyless signatures (cosign), SLSA provenance via GitHub OIDC.
- Distribution: GitHub Releases, Homebrew tap (`breaktroughf1/tap`), `go install`, npm wrapper (`lockward`) later.
