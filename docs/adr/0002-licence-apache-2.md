# ADR-0002: License under Apache-2.0

- Status: Accepted
- Date: 2026-11-23

## Context
Breaktrough's first project (Flutter MFA) is MIT. Lockward targets enterprise AppSec and regulated teams and sits next to Apache-2.0 projects (SkillSpector, Snyk agent-scan, agentgateway, OpenShell). A future donation to OWASP or OpenSSF is possible.

## Decision
Apache License 2.0, with a `NOTICE` file. Contributions accepted under the DCO (`git commit -s`).

## Consequences
- + Explicit patent grant; procurement-friendly; consistent with neighbouring tools.
- − Slightly more ceremony than MIT (NOTICE, licence headers optional).
