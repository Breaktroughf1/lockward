# Lockward

**A lockfile and policy gate for everything your AI coding agents load.**

Lockward pins every skill, MCP server, hook and rules file used by Claude Code, Cursor, Codex, Gemini CLI, Windsurf and GitHub Copilot — then blocks anything that changes without approval. Offline. No account. No LLM in the loop.

> Scanners tell you what looks bad today. Lockward tells you what changed since you approved it — and blocks it.

> **Status: pre-alpha, under active development.** v0.1.0 is planned for January 2027. See the [roadmap](docs/ROADMAP.md). Not ready for production use yet.

---

## Why

AI agents now load third-party skills, MCP servers, hooks and instruction files that run with your shell, files and credentials. In 2026 that layer became an actively attacked supply chain: over a thousand malicious skills in one marketplace, MCP packages that turned malicious after 15 clean versions, repos whose config auto-executes when opened, and public demonstrations that every major skill scanner can be bypassed.

Security researchers converge on the same answer: **pin what you trust, review every change, keep an inventory.** Lockward makes that a one-line CI step. Background and sources: [docs/RESEARCH.md](docs/RESEARCH.md).

## What it does (v0.1 scope)

- **Discover** skills, MCP servers, hooks and rules files at user and project scope across six agents.
- **Lock** them into a deterministic, reviewable `lockward.lock` — every file hashed, including hidden files, binaries and archives.
- **Verify** in CI with `--frozen`: any addition, removal or modification fails the build.
- **Diff** changes in plain language, down to the sentence in a `SKILL.md` or tool description.
- **Enforce policy**: unpinned `npx` MCP servers, unapproved sources, hooks that hit the network, references to secret paths and more.
- **Scan untrusted repos** before you open them: see exactly which files your agent would auto-load or execute.
- **Report** as text, JSON, SARIF 2.1.0 (GitHub code scanning) and CycloneDX 1.6 AI-BOM.

## Planned usage

```sh
lockward init          # create lockward.policy.yaml
lockward lock          # pin everything your agents load
lockward verify        # what changed since approval?
lockward diff          # show it in plain language
lockward approve <id>  # accept a reviewed change
lockward scan-repo ./some-cloned-repo
```

```yaml
# .github/workflows/lockward.yml (planned)
- uses: Breaktroughf1/lockward/action@<sha>
  with:
    args: verify --frozen --format sarif
```

## What Lockward is not

- Not a malware detector. It tells you **what changed**; humans and scanners decide whether it is safe.
- Not a runtime sandbox or gateway. It works before the agent loads anything.
- Not a cloud service. Nothing leaves your machine.

## Documentation

- [Product requirements](docs/PRD.md)
- [Lockfile specification](docs/SPEC.md) — feedback welcome
- [Threat model](docs/THREAT_MODEL.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Architecture decisions](docs/adr/)

## Contributing

Agent adapters are the easiest way to help. See [CONTRIBUTING.md](CONTRIBUTING.md). Report vulnerabilities privately per [SECURITY.md](SECURITY.md).

## License

Apache-2.0. See [LICENSE](LICENSE).

---

Built and maintained by [Breaktrough](https://breaktroughf1.com) (BreaktroughF1 LLP), Bengaluru.
