# ADR-0001: Implement Lockward in Go

- Status: Accepted
- Date: 2026-11-23

## Context
Lockward is a security CLI that must run offline on developer laptops (Linux, macOS, Windows) and in CI with no runtime dependencies. Its users span Node (agent ecosystem), Python and platform/security teams.

## Decision
Use Go with `CGO_ENABLED=0`, distributing single static binaries for linux/darwin/windows on amd64 and arm64.

## Consequences
- + No runtime to install; trivial cross-compilation; fits the security-CLI audience (Trivy, gitleaks, osv-scanner).
- + Strong stdlib for hashing, JSON, `io/fs` (enables safe, testable adapters).
- − Agent-ecosystem users live in Node; mitigated with an `npx lockward` wrapper that downloads and checksum-verifies the binary (v0.2).
