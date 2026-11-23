# ADR-0006: Runtime and test dependencies for v0.1

- Status: Accepted
- Date: 2026-11-24

## Context
LW-NFR-08 asks for minimal dependencies, each justified. Lockward must parse YAML (the policy file) and TOML (Codex's `config.toml`), and emit SARIF 2.1.0 and CycloneDX 1.6 that validate against their official schemas. Every dependency is part of the supply chain Lockward exists to protect.

## Decision
Runtime dependencies:

| Module | Version | Why | Alternatives rejected |
|---|---|---|---|
| `go.yaml.in/yaml/v3` | v3.0.6 | Policy file format required by LW-FR-11. Maintained continuation of `gopkg.in/yaml.v3` by the YAML organisation. Strict decoding (`KnownFields`) rejects typos. | A hand-written YAML subset parser (risky); JSON policy files (breaks the PRD format) |
| `github.com/pelletier/go-toml/v2` | v2.4.3 | Codex stores MCP servers, hooks and approval settings in `config.toml`. Pure Go, no transitive runtime dependencies. | Skipping Codex config (loses an agent); `BurntSushi/toml` (equivalent; go-toml is more actively maintained) |

Test-only dependency:

| Module | Version | Why |
|---|---|---|
| `github.com/santhosh-tekuri/jsonschema/v6` | v6.0.3 | Validates SARIF (draft-04) and CycloneDX (draft-07) output against the vendored official schemas with an offline-only loader. It is imported only from `_test.go` files and never linked into the binary. |

Not added: `spf13/cobra` (ADR-0005), `CycloneDX/cyclonedx-go` and SARIF SDKs (the emitted subset is small and is schema-validated in tests), `google/cel-go` (deferred to v0.2).

All three modules were checked for network and process-execution imports on the code paths Lockward uses; none import `net`, `net/http` or `os/exec` outside their own tests and examples.

## Consequences
- + Two runtime modules in the binary; `go version -m lockward` shows the full list.
- + Output validity is proven in CI against the real schemas, without network access.
- − YAML and TOML parsers process content from untrusted repositories (`.codex/config.toml`) and the policy file; both are fuzzed through Lockward's own entry points, and Dependabot tracks updates.
