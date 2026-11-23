# ADR-0004: Offline by default

- Status: Accepted
- Date: 2026-11-23

## Context
Key users are air-gapped or privacy-sensitive and cannot send skill content to vendor APIs. The leading alternative requires an account and uploads content.

## Decision
No default code path performs network I/O. Any future network feature (e.g. `--probe`, attestation fetching) is opt-in via an explicit flag, documented, and covered by tests. CI runs the test suite with networking disabled.

## Consequences
- + Clear trust story ("no account, no network"); deterministic CI.
- − Some enrichment (OSV lookups, registry metadata) needs explicit opt-in.
