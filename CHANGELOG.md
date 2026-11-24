# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [0.2.2] - 2026-11-24

### Fixed
- **Linked agent directories were skipped without a warning.** When a directory such as `~/.claude` was a symlink, including an absolute one inside the scan root (the usual setup with GNU Stow or chezmoi), assets under it were not discovered, so `lock` pinned nothing and said nothing. Symlinks are now resolved in every path component, still only within the scan root. A file reached through a linked parent directory could also stop `lock` with a configuration error. Affects v0.1.0 to v0.2.1. After upgrading, run `lockward lock` (or `lockward verify` to see what was missing).
- A directory symlink that points outside the scan root is reported once as a problem, instead of its contents being skipped without notice.
- A dangling symlink as a rules file is reported as a problem, instead of stopping `lock` with a configuration error.
- The prose diff's table-size check cannot overflow, whatever the input sizes (CodeQL).

### Changed
- The GitHub Action installs 0.2.2 by default.

### Added
- CodeQL analysis (`security-extended`) for the Go code and the workflows, and an OpenSSF Scorecard badge.

## [0.2.1] - 2026-11-24

### Security
- **Token leak in redaction:** for a `NAME=VALUE` argument, only the value was masked, so a token earlier in the same argument could be written to `lockward.lock` (for example an MCP server launched with `bash -c "curl -H 'Authorization: Bearer <token>' https://…?pwd=1"`). Names must now look like identifiers, and token masking always runs over the whole argument. Found by fuzzing; affects v0.1.0 to v0.2.0. Re-run `lockward lock` after upgrading if a lockfile may contain such an argument.

### Changed
- The GitHub Action installs 0.2.1 by default.

### Added
- GitHub Action published from [Breaktroughf1/lockward-action](https://github.com/Breaktroughf1/lockward-action) (root `action.yml`, for the Marketplace), tested from this repository on Linux, macOS and Windows.
- Homebrew: `brew install breaktroughf1/tap/lockward` on macOS and Linux (Intel and ARM). The tap's formula is generated from each release's Sigstore-verified checksums, with no shared token.

## [0.2.0] - 2026-11-24

### Security
- **Drift in unmodelled fields:** changing a field Lockward did not record, such as an MCP server's `headersHelper` command, a hook's `if` condition or a project settings command, was not reported. Every field of MCP server and hook definitions is now pinned (redacted), and project-scope config files are pinned in full. **After upgrading, review `lockward verify` and run `lockward approve --all`**: entries whose definitions have extra fields get new digests.
- **Output injection:** escape sequences, newlines and bidirectional characters from scanned repositories reached terminals and CI logs raw. All text output now shows them as visible escapes, and the Action suspends GitHub workflow commands around Lockward's output.
- Header-style secrets such as `X-Api-Key: …` in MCP arguments and hook commands are redacted.
- The snapshot cache never stores files with credential-like names.
- `approve` only follows a `.git` file's `gitdir` into git directories.

### Added
- `--scanner-sarif` on `verify` and `scan-repo` imports external scanner findings and attaches them to entries (LW-FR-16). They are informational and never change the exit code.
- `lock` warns when it pins personal `*.local.*` files into the shared lockfile.
- CI: govulncheck and new fuzz targets.

### Changed
- The GitHub Action installs 0.2.0 by default.

### Fixed
- The Action no longer aborts when Lockward's output contains no backticks.

## [0.1.1] - 2026-11-24

### Added
- `lockward init` also writes a `.gitattributes` that keeps agent files LF on every OS, so Windows checkouts (`core.autocrlf`) do not show drift against lockfiles created on Linux or macOS. An existing `.gitattributes` is never modified; `init` prints the lines to append.

### Changed
- The GitHub Action installs 0.1.1 by default.
- The Action is now tested against the published release on Linux (x64 and arm64), macOS and Windows on every change.

### Fixed
- Documentation recommended `text eol=lf` for directory globs, which makes Git rewrite line endings in binary files too; it now uses `text=auto eol=lf`.

## [0.1.0] - 2026-11-24

First public release.

### Added
- `lockward init`, `lock`, `verify`, `diff`, `approve`, `status`, `scan-repo`, `bom` and `version`, with the exit codes from the PRD: 0 clean, 1 drift, 2 policy violation, 3 usage or configuration error, 4 internal error.
- Discovery of skills, MCP servers, hooks, rules files and security-relevant settings for Claude Code, Cursor, Codex, Gemini CLI, Windsurf (including Devin Local paths) and GitHub Copilot at project and user scope, plus cross-agent `AGENTS.md`, `.agents/skills/` and Amazon Q MCP config. Paths verified against upstream documentation on 2026-11-23.
- Lockfile format version 1 ([SPEC](docs/SPEC.md)): canonical JSON, full-file streaming SHA-256, tree digests that cover every file including dotfiles, binaries and archives, symlinks recorded and never followed outside the root, and env/header names only.
- Policy file `lockward.policy.yaml` with rules LW001–LW008, severities, allow lists and exceptions that require a reason.
- Sentence-level diffs for skills and rules files from local snapshots.
- MCP tool-description fingerprints from user-supplied `tools/list` output (`--tools`).
- Output as text, JSON, SARIF 2.1.0 and CycloneDX 1.6, validated against the official schemas in tests.
- `.lockwardignore`, with the active patterns pinned and printed on every verify.
- `scan-repo`, which never honours the scanned repository's own ignore file or policy.
- GitHub Action that verifies the release's Sigstore signature and checksum before running.
- Reproducible release builds for Linux, macOS and Windows on amd64 and arm64, with a cosign-signed `checksums.txt` and SLSA build provenance.

[0.2.2]: https://github.com/Breaktroughf1/lockward/releases/tag/v0.2.2
[0.2.1]: https://github.com/Breaktroughf1/lockward/releases/tag/v0.2.1
[0.2.0]: https://github.com/Breaktroughf1/lockward/releases/tag/v0.2.0
[0.1.1]: https://github.com/Breaktroughf1/lockward/releases/tag/v0.1.1
[0.1.0]: https://github.com/Breaktroughf1/lockward/releases/tag/v0.1.0
