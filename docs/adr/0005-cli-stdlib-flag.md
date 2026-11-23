# ADR-0005: Stdlib `flag` for CLI parsing

- Status: Accepted
- Date: 2026-11-23

## Context
The v0.1 CLI (PRD §8) has nine flat commands with no nesting and a handful of flags (`--scope`, `--format`, `--frozen`, `--all`). LW-NFR-08 requires minimal dependencies, each justified, and Lockward's trust story depends on a small, auditable binary. The common alternative, `spf13/cobra`, adds `spf13/pflag` (and `inconshreveable/mousetrap` on Windows) for features we do not need yet: nested commands, generated shell completions and man pages.

The stdlib `flag` package stops parsing at the first positional argument, but PRD §8 places flags after positionals (`lockward scan-repo <path> --format json`), so interspersed arguments must be handled.

## Decision
Use the standard library `flag` package with a small dispatcher in `cmd/lockward`: a table of commands (name, summary, run function) and a short helper that re-parses remaining arguments so flags may appear before or after positionals. A literal `--` ends flag parsing. All parsing stays inside `cmd/lockward`; `internal/` packages never see `flag` types.

## Alternatives considered
- **cobra** — rich and widely used, but two extra modules in the supply chain for capabilities v0.1 does not need.
- **urfave/cli** — same trade-off as cobra.

## Consequences
- + Zero CLI dependencies; full control of exit codes (PRD §8) and of output.
- + Easy to audit; behaviour is fully covered by table-driven tests of `run`.
- − Help text is hand-written; no generated shell completions.
- − We maintain ~20 lines of interspersed-argument handling.

Revisit if Lockward needs nested commands (e.g. `policy check`) or shell completions. Because parsing is isolated in `cmd/lockward`, migrating is cheap.
