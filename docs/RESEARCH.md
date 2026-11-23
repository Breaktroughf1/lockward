# Research Basis

Why Lockward, and why now. Summary of the market research done in November 2026. Re-verify numbers (especially star counts) before quoting them publicly.

## Incidents and studies
- ClawHavoc campaign — Koi Security found 341 of 2,857 ClawHub skills malicious; Antiy CERT later identified 1,184 malicious packages from 12 author IDs (AMOS stealer payloads). Reported by The Hacker News, Feb 2026.
- Snyk ToxicSkills — 3,984 skills scanned; 36.82% with security flaws; 76 confirmed malicious.
- Palo Alto Networks Unit 42, "OpenClaw's Skill Marketplace and the Emerging AI Supply Chain Threat" (23 Jun 2026) — five malicious skills evaded VirusTotal and ClawScan; one padded its README to ~22 MB.
- Trail of Bits, "The sorry state of skill distribution" (3 Jun 2026) — four malicious skills bypassed ClawHub's guard, Cisco skill-scanner and skills.sh scanners. Recommendation: curation, version pinning, human approval gate. Summary: https://mcpskills.io/blog/trail-of-bits-skill-scanners
- AIR Security, "The Story of Skills" (22 Jun 2026) — a skill passed three scanners, then served its payload from a remote domain after being trusted.
- postmark-mcp rug-pull — clean for v1.0.0–1.0.15; v1.0.16 BCC'd all email to an attacker (Koi Security, Sep 2025).
- Amazon Q CVE-2026-12957/12958 — repo-supplied `.amazonq/mcp.json` executed without consent. CSA note: https://labs.cloudsecurityalliance.org/research/csa-research-note-mcp-tool-poisoning-auto-execution-20260701/
- Internet-scale MCP study — auth weaknesses in 380 of 414 servers; 68 GHSAs: https://arxiv.org/pdf/2608.00150

## Standards
- OWASP Agentic Skills Top 10 (v1.0, Aug 2026): https://github.com/OWASP/www-project-agentic-skills-top-10 — AST01 Malicious Skills, AST02 Supply Chain Compromise, AST05 external references, AST07 Update Drift, AST08 Poor Scanning, AST09 No Governance.
- OWASP Top 10 for Agentic Applications 2026 — ASI04 Agentic Supply Chain: https://cycode.com/blog/owasp-top-10-agentic-applications/
- OWASP MCP Top 10: https://cycode.com/blog/owasp-mcp-top-10/
- CycloneDX 1.6 ML-BOM (ratified); agent/MCP BOM still a proposal.

## Landscape (as of Oct–Nov 2026)
| Tool | Type | Gap Lockward fills |
|---|---|---|
| Snyk agent-scan (Apache-2.0, ~3.1k★) | Scanner, needs `SNYK_TOKEN`, shares content with Snyk | Offline, no account, change control |
| NVIDIA SkillSpector (Apache-2.0) https://github.com/NVIDIA/SkillSpector | Static + optional LLM scanner | Lockfile, drift, policy; import its SARIF |
| Cisco skill-scanner (~2.8k★) https://cisco-ai-defense.github.io/docs/skill-scanner | Static/bytecode scanner | Same |
| Vercel `skills` CLI https://github.com/vercel-labs/skills | Lockfile for skills it installs | All surfaces, any install method, cross-agent |
| mcplock https://github.com/xuange-hu/mcplock, MCPDrift https://github.com/DangTruong96/mcp-drift | MCP-only drift | All four surfaces, one policy |
| skills-lock https://github.com/pcomans/skills-lock | Skills-only lock | Same |
| SkillForge https://pypi.org/project/agent-skillforge/0.7.0/ | Skills lockfile + AIBOM | Broader agents/surfaces, policy, scan-repo, benchmark |
| agentgateway, NVIDIA OpenShell | Runtime gateway / sandbox | Complementary (pre-runtime vs runtime) |

## Positioning
"Scanners tell you what looks bad today. Lockward tells you what changed since you approved it — and blocks it."
