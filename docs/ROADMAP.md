# Lockward Roadmap

Target: **v0.1.0 public launch mid-January 2027** (avoid the late-December holiday dead zone). Week 1 starts the week of 24 November 2026.

## v0.1.0 — "Lock it" (weeks 1–9)

| Week | Dates (approx.) | Milestone | Exit criteria |
|---|---|---|---|
| 1 | 24–30 Nov | Foundation | `go.mod`, CLI skeleton, CI green, ADRs merged, upstream config paths verified for all 6 agents |
| 2 | 1–7 Dec | Hash + lock core | `internal/hash` (file, tree, canonical JSON) with invariant tests; lockfile encode/decode per SPEC |
| 3 | 8–14 Dec | Adapters I | Claude Code, Cursor, Codex adapters with fixtures; `lock` works end-to-end |
| 4 | 15–21 Dec | Verify + diff | `verify`, `--frozen`, `diff` (file + prose), `approve`; Gemini CLI, Windsurf, Copilot adapters |
| 5 | 22–28 Dec | Policy | Policy schema, rules LW001–LW008, exit codes |
| 6 | 29 Dec–4 Jan | Outputs + scan-repo | SARIF, JSON, CycloneDX 1.6 (schema-validated), `scan-repo`; **publish SPEC.md for comment** |
| 7 | 5–11 Jan | Benchmark | Run against public malicious-skill corpora; write "what drift detection catches" results |
| 8 | 12–18 Jan | Harden + release prep | Fuzzing, offline test job, GoReleaser + signing, GitHub Action, README GIF, docs |
| 9 | 19–25 Jan | **Launch** | v0.1.0 tagged; Show HN, Reddit, LinkedIn/X, blog post, newsletter pitches |

## v0.2 — "Prove it" (Feb–Mar 2027)
- `--probe` mode to fetch MCP `tools/list` in a sandbox for tool fingerprints
- Sigstore attestation verification for skills/MCP packages that publish them
- External scanner SARIF import (SkillSpector, Cisco, Snyk)
- CEL policy expressions
- npm (`npx lockward`) and PyPI (`uvx lockward`) wrappers
- Public `pkg/lockfile` Go package

## v0.3+ (ideas, demand-driven)
- Pre-commit hook and VS Code extension
- Organisation-wide policy bundles
- Upstream proposals: lockfile spec to OWASP Agentic Skills Top 10 / agent vendors

## Next Breaktrough project after Lockward
DPDP Act compliance-as-code toolkit, targeting release before 13 May 2027.
