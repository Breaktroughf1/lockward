# CLAUDE.md — working on Lockward

Lockward is an offline, cross-agent lockfile and policy gate for AI-agent assets (skills, MCP servers, hooks, rules files). Written in Go. Read these before making changes:

- `docs/PRD.md` — scope, requirement IDs (LW-FR-xx / LW-NFR-xx), CLI surface, exit codes
- `docs/SPEC.md` — lockfile format and digest algorithms (source of truth for `internal/lock` and `internal/hash`)
- `docs/THREAT_MODEL.md` — security invariants that must never be broken
- `docs/ARCHITECTURE.md` — package layout and adapter contract
- `docs/ROADMAP.md` — current week's milestone

## Non-negotiable rules

1. **Never execute, import, evaluate or launch scanned content** (files, hook commands, MCP server commands). Read bytes only.
2. **No network I/O** in any default code path. No dependency that phones home.
3. **Never write env or header values** to any output. Names only.
4. **Never follow symlinks** outside the scan root. Use `io/fs` and `fs.FS` in adapters.
5. **Determinism:** canonical JSON, sorted entries, no timestamps in entries, `/` path separators.
6. **No LLM in decision logic** (ADR-0003).
7. Hash entire files with streaming I/O. Never truncate or sample.

## Conventions

- Go version: as declared in `go.mod`; `CGO_ENABLED=0`.
- Packages under `internal/`; CLI wiring only in `cmd/lockward`.
- Errors: wrap with `fmt.Errorf("context: %w", err)`; user-facing messages include the item and the fix command.
- Tests: table-driven; golden files in `testdata/golden/` (`go test ./... -update`); security invariants as `TestInvariant_*`.
- New dependency → justify in the PR description and an ADR if significant.
- Run before proposing a commit: `gofmt -s -l .`, `go vet ./...`, `go test -race ./...`, `golangci-lint run`.

## Commits and authorship

- Conventional Commits, referencing requirement IDs: `feat(hash): tree digest per SPEC §5.2 [LW-FR-04]`.
- Sign off with `-s` (DCO).
- Commits are authored solely by the repository owner's git identity. **Do not add `Co-Authored-By`, "Generated with" lines, session links or any AI attribution** to commit messages, PR titles or PR descriptions.
- Do not change git config (user.name / user.email).
- Do not push or open PRs unless explicitly asked.

## Working style

- Work in small, reviewable steps aligned with the roadmap week. Propose a short plan before multi-file changes.
- When an agent's config location is uncertain, check upstream docs and record the URL and date in the adapter README rather than guessing.
