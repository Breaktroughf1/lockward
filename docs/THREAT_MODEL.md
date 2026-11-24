# Lockward Threat Model

Method: STRIDE-style, asset-centric. Mitigations reference PRD requirement IDs. Review this document whenever a new surface, adapter type or network feature is added.

## 1. What Lockward protects

The integrity of the **agent layer**: the skills, MCP server definitions, hooks and rules files that an AI coding agent loads and that run with the agent's privileges (shell, file system, network, credentials).

## 2. Assets

| ID | Asset |
|---|---|
| A1 | Developer machine and credentials reachable by the agent |
| A2 | CI runners and their secrets |
| A3 | The committed `lockward.lock` (the trust anchor) |
| A4 | `lockward.policy.yaml` |
| A5 | The Lockward binary and GitHub Action themselves |

## 3. Trust boundaries

1. Third-party asset sources (skill marketplaces, npm/PyPI/OCI, git repos) → local disk.
2. Untrusted repository contents → agent auto-load.
3. Lockfile / policy changes → code review → main branch.
4. Lockward release pipeline → user's machine / CI.

## 4. Threats and mitigations

| ID | Threat (attacker goal) | Example | Mitigation | Residual risk |
|---|---|---|---|---|
| T1 | **Malicious first install** | Skill from a marketplace contains a stealer | Out of scope for detection; Lockward makes it visible: `lock` lists every file, policy rules LW002/LW004/LW005/LW006 flag risky traits, scanner SARIF import (LW-FR-16) | A human can still approve malware. Documented explicitly. |
| T2 | **Rug-pull / update drift** | Clean MCP package v1.0.15 → backdoored v1.0.16; skill auto-updated | Digest pinning; `verify --frozen` in CI; LW001 requires exact versions | MCP packages launched with unpinned `npx -y pkg` fetch at runtime; LW001 blocks this |
| T3 | **Hidden payload** | `.pyc`, `.docx`, dotfile or archive inside a skill; README padded to 22 MB | Tree digest covers every file; streaming hashing without size cut-offs (LW-FR-04, LW-NFR-04) | None for integrity; content still needs human/scanner review |
| T4 | **Tool-description poisoning** | MCP server changes a tool description to inject instructions | Optional `tools_fingerprint` (LW-FR-06) | Not covered without fingerprint; v0.2 `--probe` |
| T5 | **Repo-borne auto-execution** | Cloned repo ships `.mcp.json`, hooks or `.amazonq/mcp.json` | `scan-repo` before opening (LW-FR-12); it ignores the repository's own `.lockwardignore` and policy so the repo cannot hide files or disable rules; project lockfile review | User must run it; IDE may open first |
| T6 | **Lockfile tampering** | Attacker edits lockfile and asset together in one PR | Lockfile diff is human-readable; CODEOWNERS on `lockward.lock` and policy recommended; `approved.by` field | Compromised reviewer |
| T7 | **Policy weakening** | PR loosens `allow.sources` | Recommend CODEOWNERS; `verify` prints policy digest | Same as T6 |
| T8 | **Attacking Lockward via its inputs** | Malicious JSON/YAML/TOML, symlink loops, path traversal, giant files, zip bombs | Never execute content (LW-NFR-03); no symlink following outside root; bounded parsers; archives hashed as opaque bytes, never extracted; fuzz tests | Parser bugs; fuzzing in CI |
| T9 | **Prompt-injecting the checker** | Text in a skill targeting an LLM judge | No LLM anywhere in the decision path (ADR-0003) | None |
| T10 | **Secret leakage via Lockward output** | Env values, headers or tokens written to lockfile/SARIF | Store env/header **names** only (SPEC §4.2); secret-looking arguments, URL credentials and settings values are replaced with `[REDACTED]` before storing or hashing; LW007 flags inline secrets by location only | Secrets in formats the redaction patterns do not recognise |
| T11 | **Compromised Lockward release** | Malicious binary or Action | SHA-pinned workflows, minimal deps, reproducible builds, checksums + Sigstore + SLSA provenance; Action verifies binary checksum (LW-FR-14) | Maintainer account compromise; require 2FA and protected tags |
| T12 | **Denial of service in CI** | Asset tree of millions of files; a FIFO that blocks readers | Limits per skill (`--max-files`, default 200 000) and per project walk (2 000 000 entries) fail loudly, never silently skip; special files are recorded and never opened | — |
| T14 | **Output injection** | Repo content with terminal escape sequences, newlines or bidi controls fakes a "clean" result, injects GitHub workflow commands (`::error::`) or disguises text | All text output passes through `report.Safe`, which shows control, bidi and invisible characters as visible escapes; the Action suspends workflow commands around Lockward's output and sizes the job-summary fence to its content (`TestInvariant_OutputCannotInjectTerminalOrCICommands`) | JSON and SARIF consumers must escape strings themselves when rendering HTML |
| T15 | **Drift in unmodelled fields** | Attacker changes a config field Lockward did not record (an MCP `headersHelper` command, a hook `if` condition) | Every field of MCP server and hook objects is pinned in `options`; project-scope config files are pinned in full (`TestDriftInUnmodelledFields`) | User-scope settings files pin a security-relevant subset to avoid constant churn |
| T13 | **Ignore-file abuse** | Attacker adds `.lockwardignore` to hide a file | Ignore patterns are themselves pinned and printed on every `verify` | — |

### Residual risks

- **FIFO race:** a file is stat'ed before it is opened so FIFOs and devices are never read, but a local attacker who swaps a file for a FIFO between those two calls can stall the run. This needs a concurrent local attacker; CI runners are not exposed to it.
- **Policy and lockfile in the same PR:** a pull request can edit `lockward.lock` or `lockward.policy.yaml` together with an asset (T6, T7). Protect both with CODEOWNERS and required reviews; `verify` prints the policy digest so a change is visible.
- **Imported scanner findings** (LW-FR-16) are untrusted input: they are displayed (neutralised) and never change the exit code.

## 5. Explicit non-goals

- Detecting whether content is malicious.
- Runtime enforcement once an agent has loaded an asset.
- Protecting a machine that is already compromised.

## 6. Security invariants (must have tests)

| # | Invariant | Tests |
|---|---|---|
| 1 | Lockward never executes, imports, evaluates or launches any scanned file or command. | `TestInvariant_NeverExecutesScannedContent`, `TestInvariant_NoExecOrNetworkImports`, depguard |
| 2 | No default code path opens a network socket. | `TestInvariant_NoExecOrNetworkImports`, depguard, CI `offline` job (`unshare -n`) |
| 3 | Any byte change to any file in a pinned skill changes the tree digest. | `TestInvariant_AnyByteChangeChangesTreeDigest`, `TestInvariant_PaddedFileFullyHashed` |
| 4 | Symlinks are recorded, never followed outside the scan root. | `TestInvariant_SymlinksRecordedNotFollowed`, `TestSymlinkedSkills`, `TestSymlinkedRulesFile` |
| 5 | Env and header values never appear in any output. | `TestInvariant_NoSecretValuesInOutput`, `FuzzRedactNeverLeaksToken` |
| 6 | Unknown lockfile major version → hard failure, and the file is never overwritten. | `TestInvariant_UnknownLockfileVersionFails`, `TestNoLockfileAndCorruptLockfile` |
