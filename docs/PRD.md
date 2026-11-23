# Lockward — Product Requirements Document

| Field | Value |
|---|---|
| Product | Lockward |
| Owner | Noeal Rajeev (Breaktrough / BreaktroughF1 LLP) |
| Status | Draft v0.1 — approved for development |
| Target v0.1.0 release | Mid-January 2027 (weeks 1–9, see [ROADMAP.md](ROADMAP.md)) |
| Licence | Apache-2.0 |
| Language | Go (single static binary) |

---

## 1. Summary

Lockward is an offline, cross-agent **lockfile and policy gate** for everything an AI coding agent can load: **skills, MCP servers, hooks, and rules/instruction files**. It records exactly what a developer or team approved, pins it by content hash, and fails locally or in CI when anything changes without approval.

> Scanners tell you what looks bad today. Lockward tells you what changed since you approved it — and blocks it.

Think `package-lock.json` + `npm ci --frozen` + `npm audit` for the agent layer, with no account, no network calls and no LLM in the loop.

## 2. Problem

AI coding agents (Claude Code, Cursor, Codex, Gemini CLI, Windsurf, GitHub Copilot) now load third-party code and prose that runs with the agent's privileges:

- **Skills** — directories of instructions, scripts and assets.
- **MCP servers** — processes launched from `npx`/`uvx`/`docker` commands whose *tool descriptions* steer the model.
- **Hooks** — shell commands that run on agent events.
- **Rules / instruction files** — `CLAUDE.md`, `AGENTS.md`, `.cursor/rules`, `GEMINI.md`, etc., often auto-loaded from any repo you open.

In 2026 this layer became an actively exploited supply chain:

- ClawHavoc: 1,184 malicious skill packages identified in ClawHub's history (Antiy CERT); Koi Security found 341/2,857 (11.9%) malicious in its audit.
- Snyk ToxicSkills: 36.82% of 3,984 scanned skills had security flaws; 76 confirmed malicious payloads.
- Trail of Bits ("The sorry state of skill distribution", June 2026) built four malicious skills that bypassed every scanner tested, using payload padding, hidden `.pyc`/`.docx` files and prompt-injecting the scanner's LLM judge. Their recommendation: curated sources, version pinning and a human approval gate.
- Rug-pulls: `postmark-mcp` was clean for 15 versions, then v1.0.16 silently BCC'd every email to an attacker.
- Repo-borne auto-execution: Amazon Q CVE-2026-12957/12958 executed a malicious repo's `.amazonq/mcp.json` without consent.
- OWASP Top 10 for Agentic Applications (ASI04 Supply Chain) and the OWASP Agentic Skills Top 10 (AST01, AST02, AST07 Update Drift, AST08 Poor Scanning, AST09 No Governance) all prescribe pinning, inventory, provenance and an AI-BOM.

**Root gap:** existing open-source tools are *content scanners* (Snyk agent-scan, NVIDIA SkillSpector, Cisco skill-scanner) or *single-surface lockfiles* (Vercel `skills` CLI, mcplock, MCPDrift). Nothing provides one vendor-neutral, offline trust and change-control layer across all agents and all four surfaces. Evidence and links: [RESEARCH.md](RESEARCH.md).

## 3. Goals and non-goals

### Goals (v0.1)
- **G1 Inventory:** discover every skill, MCP server, hook and rules file an agent would load, at user and project scope, for the six supported agents.
- **G2 Pin:** write a deterministic, reviewable `lockward.lock` that content-addresses every item.
- **G3 Detect drift:** `verify` fails on any unapproved addition, removal or modification, including hidden, binary and archived files.
- **G4 Explain:** `diff` shows a human-readable, sentence-level diff for prose changes (SKILL.md, tool descriptions, rules).
- **G5 Enforce policy:** a small declarative policy (allowed sources, required pinning, forbidden capabilities, external URL references).
- **G6 Pre-open check:** `scan-repo` flags agent auto-loaded files in an untrusted repo *before* it is opened in an agent/IDE.
- **G7 Integrate:** SARIF 2.1.0, CycloneDX 1.6 AI/ML-BOM, JSON and a GitHub Action with a `--frozen` mode.
- **G8 Trust by construction:** fully offline, deterministic, no telemetry, reproducible signed releases.

### Non-goals (v0.1)
- Malware detection or content classification. Lockward is change control; scanners can be plugged in.
- An LLM judge (non-deterministic and itself injectable).
- Runtime interception, proxying or sandboxing (NVIDIA OpenShell, agentgateway, etc. own that).
- A hosted registry, marketplace or web dashboard.
- Signing infrastructure beyond *verifying* existing Sigstore attestations (post-v0.1).
- Auto-remediation (it reports and blocks; humans approve).

## 4. Users and personas

| Persona | Need | Primary commands |
|---|---|---|
| **P1 Platform / AppSec engineer** standardising agents across an org | One policy, enforced in every repo's CI; an inventory for auditors | `lock`, `verify --frozen`, policy, SARIF, AI-BOM |
| **P2 Regulated / air-gapped team** (BFSI, health, government; Indian DPDP-sensitive) | Cannot send skill content to a vendor API | Everything, offline |
| **P3 Skill / MCP maintainer** | Prove what a release contains; let users pin it | `lock`, AI-BOM, hash output |
| **P4 Individual power user** with dozens of skills and servers | "Did anything change since yesterday?" | `status`, `diff`, `approve` |
| **P5 Security researcher / pentester** | Inspect an untrusted repo safely | `scan-repo` |

## 5. User stories (with acceptance criteria)

IDs are stable; reference them in commits and PRs (e.g. `feat(lock): ... [LW-FR-03]`).

**US-1 (P4)** As a developer, I run `lockward init` then `lockward lock` and get a lockfile of everything my agents load.
- AC: Lockfile lists every discovered item with surface, agent, scope, source and digest; running `lock` twice with no changes produces a byte-identical file.

**US-2 (P1)** As a platform engineer, I add the GitHub Action and CI fails if any agent asset differs from the committed lockfile.
- AC: Non-zero exit code; SARIF uploaded to code scanning with one result per drifted item; job summary lists changes.

**US-3 (P4)** As a developer, when a skill updates I see *what* changed in plain language and approve or reject it.
- AC: `lockward diff` shows added/removed/modified files and a sentence-level diff of prose; `lockward approve <id>` updates only that entry.

**US-4 (P1)** As AppSec, I forbid MCP servers launched from unpinned `npx` packages and skills from unapproved sources.
- AC: Policy violations are reported with rule ID, item and remediation hint; exit code distinguishes drift (1) from policy violation (2).

**US-5 (P5)** As a researcher, I run `lockward scan-repo ./untrusted` and learn which files Claude Code, Cursor, Codex etc. would auto-load or auto-execute.
- AC: Report lists each file, which agent loads it, whether it can execute commands (hooks, MCP launch commands), and external URLs referenced; no file in the repo is executed.

**US-6 (P2)** As a compliance owner, I export a CycloneDX AI-BOM of our agent layer.
- AC: Valid CycloneDX 1.6 JSON (validated in CI against the official schema).

**US-7 (P3)** As a maintainer, a hidden or binary file added to my skill is detected even if `SKILL.md` is unchanged.
- AC: Directory digest covers every file including dotfiles, binaries and archives; padding a README to 22 MB does not truncate hashing.

## 6. Functional requirements

| ID | Requirement | Priority |
|---|---|---|
| LW-FR-01 | Discover assets for Claude Code, Cursor, Codex, Gemini CLI, Windsurf, GitHub Copilot via versioned **adapters** | P0 |
| LW-FR-02 | Support user scope (`~`) and project scope (repo root), configurable search roots | P0 |
| LW-FR-03 | `lock`: write `lockward.lock` per [SPEC.md](SPEC.md); deterministic ordering and canonical JSON | P0 |
| LW-FR-04 | Skill digest = Merkle-style tree hash over **all** files (dotfiles, binaries, archives, symlink targets recorded not followed outside root) | P0 |
| LW-FR-05 | MCP entry records transport, command, args, package name + version / image digest, env **key names only**, and config-file digest | P0 |
| LW-FR-06 | Optional MCP tool-description fingerprint captured from a user-supplied `tools/list` JSON file (no server is launched by default) | P1 |
| LW-FR-07 | Hooks and rules files pinned by file digest with agent + event metadata | P0 |
| LW-FR-08 | `verify`: compare live state to lockfile; report added/removed/modified; `--frozen` fails on any difference | P0 |
| LW-FR-09 | `diff`: file-level diff plus sentence-level prose diff for Markdown/text | P0 |
| LW-FR-10 | `approve <id…>` / `approve --all`: update selected lock entries only | P0 |
| LW-FR-11 | Policy file `lockward.policy.yaml` with built-in rules (see §6.1) | P0 |
| LW-FR-12 | `scan-repo <path>`: static, read-only report of agent auto-loaded files; never executes or launches anything | P0 |
| LW-FR-13 | Output formats: `text` (default, TTY-aware), `json`, `sarif` (2.1.0), `cyclonedx` (1.6) | P0 |
| LW-FR-14 | GitHub Action (composite) wrapping the released binary, verifying its checksum before running | P0 |
| LW-FR-15 | `status`: one-line summary for prompts/scripts | P1 |
| LW-FR-16 | Import SARIF from external scanners (SkillSpector, Cisco, Snyk) and attach findings to lock entries | P2 |
| LW-FR-17 | `init`: create default policy and `.lockwardignore` | P1 |

### 6.1 Built-in policy rules (v0.1)

| Rule ID | Checks |
|---|---|
| `LW001 unpinned-mcp-package` | MCP server launched via `npx`/`uvx`/`pipx`/`bunx` without an exact version, or `docker` without an image digest |
| `LW002 source-not-allowed` | Skill/MCP source not in `allow.sources` |
| `LW003 hook-executes-network` | Hook command invokes `curl`, `wget`, `nc`, `Invoke-WebRequest`, etc. |
| `LW004 external-url-reference` | Skill/rules prose instructs fetching or executing from a non-allow-listed domain (OWASP AST05) |
| `LW005 secret-path-reference` | References `~/.ssh`, `~/.aws`, `.env`, keychains, browser profiles |
| `LW006 executable-in-skill` | Skill contains compiled/bytecode/binary executables or archives |
| `LW007 env-value-inline` | Secrets written inline in MCP config instead of env references |
| `LW008 auto-approve-tools` | Agent settings auto-approve all tools/commands for a third-party server |

## 7. Non-functional requirements

| ID | Requirement |
|---|---|
| LW-NFR-01 **Offline** | No network access in any default code path. Network-requiring features are opt-in flags and documented. Enforced by a test that runs the suite with networking disabled. |
| LW-NFR-02 **Deterministic** | Same inputs → byte-identical lockfile and reports across OS/arch. |
| LW-NFR-03 **Safe by default** | Never executes, imports or launches scanned content. Never follows symlinks outside the scan root. |
| LW-NFR-04 **Performance** | `verify` on 200 assets / 50 MB < 2 s on a laptop; streaming hashing with bounded memory (no full-file reads for large files). |
| LW-NFR-05 **Portability** | Linux, macOS, Windows; amd64 + arm64; single static binary, no CGO. |
| LW-NFR-06 **Privacy** | No telemetry. Env values never read into output. |
| LW-NFR-07 **Quality** | ≥ 90% line coverage on `internal/lock`, `internal/hash`, `internal/policy`; golden tests for every adapter and output format; fuzzing for parsers. |
| LW-NFR-08 **Supply chain** | SHA-pinned actions, reproducible builds, SLSA provenance, checksums + Sigstore signatures on releases, minimal dependencies (each justified in an ADR). |
| LW-NFR-09 **Usability** | Every failure prints the item, the reason, and the exact command to approve or fix. |

## 8. CLI surface (v0.1)

```
lockward init                    # write lockward.policy.yaml + .lockwardignore
lockward lock [--scope user|project|all]
lockward verify [--frozen] [--format text|json|sarif]
lockward diff [<id>]
lockward approve <id>... | --all
lockward status
lockward scan-repo <path> [--format ...]
lockward bom [--format cyclonedx]
lockward version
```

Exit codes: `0` clean · `1` drift · `2` policy violation · `3` usage/config error · `4` internal error.

## 9. Success metrics (first 90 days after launch)

- 1,000+ GitHub stars
- 10+ external contributors (mostly agent adapters)
- 25+ public repositories using the GitHub Action
- ≥ 1 mention by OWASP, a security newsletter (tl;dr sec etc.) or a vendor
- 3–5 qualified consulting conversations attributed to Lockward
- Zero confirmed false-negative drift bugs in the hashing core

## 10. Risks

| Risk | Mitigation |
|---|---|
| Platforms add native lockfiles | Be the cross-agent, vendor-neutral layer; publish SPEC.md and offer it upstream |
| Agent config formats churn | Versioned adapters with fixture tests; adapter contributions welcomed |
| False sense of security | README states clearly: change control, not malware detection |
| Similar small projects (SkillForge, skills-lock) | Win on breadth, policy, `scan-repo` and a published bypass benchmark; collaborate where sensible |
| Single-maintainer load | Tight scope; "good first issue" adapters; ARDC trainee contributors |

## 11. Open questions

1. Lockfile location for user-scope assets: `~/.config/lockward/user.lock` vs a single combined file? (Proposed: separate; see SPEC.)
2. Should `lock` optionally launch MCP servers to fetch `tools/list`? (Proposed: v0.2, behind `--probe`, sandboxed.)
3. npm wrapper (`npx lockward`) in v0.1 or v0.2? (Proposed: v0.1 if time permits.)
