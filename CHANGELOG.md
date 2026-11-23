# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

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

[0.1.0]: https://github.com/Breaktroughf1/lockward/releases/tag/v0.1.0
