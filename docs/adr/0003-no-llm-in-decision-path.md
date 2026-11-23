# ADR-0003: No LLM in the decision path

- Status: Accepted
- Date: 2026-11-23

## Context
Trail of Bits showed that LLM-based skill scanners can be prompt-injected by the very content they judge, and LLM output is non-deterministic.

## Decision
Every pass/fail decision in Lockward (lock, verify, policy) is deterministic and rule-based. No LLM is called in any default or optional decision path. Integrations may *import* findings from external tools, but those never override a drift result.

## Consequences
- + Reproducible results; immune to prompt injection of the checker; works offline.
- − Lockward will not "understand" content; it is positioned as change control, with scanners as plugins.
