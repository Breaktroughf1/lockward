# Lockward Architecture

## 1. Overview

```
              +------------------------- lockward CLI (cmd/lockward) --------------------------+
              |  init  lock  verify  diff  approve  status  scan-repo  bom  version             |
              |  flag parsing, help, exit codes, printing only (ADR-0005)                       |
              +--------------------------+------------------------------+---------------------+
                                         |                              |
                                internal/engine                    internal/repo
                       (lock, verify, approve, diff per scope)    (scan-repo, read-only)
                                         |                              |
        +-------------+---------------+--+-----------+----------------+-+------------+
        |             |               |              |                |              |
 internal/discover internal/lock internal/policy internal/report internal/prose internal/snapshot
 (runs adapters,  (lockfile model, (rules LW001–  (text, json,    (sentence    (local text
  hashes entries)  codec, compare,  LW008, policy  sarif, cdx)     diff)        snapshots)
        |          approve)         file)
        v
 internal/adapter (Source, parsing toolkit) -> internal/adapter/{claudecode,cursor,codex,
                                               geminicli,windsurf,copilot,generic}
 shared: internal/asset (types) · internal/hash (digests, canonical JSON) · internal/redact
         internal/ignore (.lockwardignore) · internal/tools (tools/list fingerprints)
         internal/identity (approver from git config) · internal/exitcode
```

Data flow for `verify`:
`discover.Run` → adapters → `[]asset.Asset` → hashed `[]asset.Entry` → tool fingerprints → `lock.Compare(locked, live)` → `policy.Evaluate(live)` → `report.Render` → exit code.

## 2. Repository layout

```
cmd/lockward/            main package: CLI wiring only (stdlib flag, ADR-0005)
internal/adapter/        Source (scan root, cached project walk, symlink resolution) and the
                         parsing toolkit (JSONC, TOML, MCP servers, hooks, settings subsets)
internal/adapter/<agent> one package per agent; no cross-adapter imports; README with sources
internal/asset/          Asset and Entry types shared across packages
internal/discover/       adapter registry, merging, id assignment, hashing into entries
internal/engine/         lock / verify / approve / diff orchestration for one scope
internal/exitcode/       exit codes from PRD §8
internal/hash/           streaming file digest, tree digest, canonical JSON
internal/identity/       approver identity from git config files (never runs git)
internal/ignore/         .lockwardignore matcher
internal/lock/           lockfile model, canonical encode/decode, compare, approve
internal/policy/         policy schema, built-in rules, streaming text scans
internal/prose/          sentence-level diff for Markdown and text
internal/redact/         secret masking for arguments, URLs and settings
internal/repo/           scan-repo
internal/report/         renderers: text, JSON, SARIF 2.1.0, CycloneDX 1.6
internal/snapshot/       content-addressed local snapshots for diff
internal/tools/          MCP tools/list fingerprints (SPEC §5.4)
testdata/adapters/       fixture trees per agent (project and user scope, malformed)
testdata/schemas/        vendored SARIF and CycloneDX schemas (tests only)
action/                  GitHub Action (composite, verifies the release before running)
docs/                    PRD, SPEC, threat model, usage, policy, ADRs
```

`internal/` keeps the API private until the lockfile spec stabilises; a public `pkg/lockfile` may follow in v0.2.

## 3. Key design decisions

| Decision | Choice | ADR |
|---|---|---|
| Language | Go, CGO disabled, static binaries | [0001](adr/0001-language-go.md) |
| Licence | Apache-2.0 | [0002](adr/0002-licence-apache-2.md) |
| No LLM in decision path | Deterministic only | [0003](adr/0003-no-llm-in-decision-path.md) |
| Offline by default | No network in default paths | [0004](adr/0004-offline-by-default.md) |
| CLI parsing | Stdlib `flag`, no CLI framework | [0005](adr/0005-cli-stdlib-flag.md) |
| Dependencies | Two runtime modules (YAML, TOML), one test-only | [0006](adr/0006-dependencies.md) |

## 4. Adapter contract

```go
type Adapter interface {
    Name() string // "claude-code"
    Discover(ctx context.Context, src *adapter.Source) (adapter.Result, error)
}

type Source struct {
    FS      fs.FS       // os.Root-backed: refuses symlinks that escape the root
    Scope   asset.Scope // user or project
    RootDir string      // absolute root, to map absolute in-root symlinks
    Ignore  *ignore.Matcher
}
```

Rules:
- Read only through `Source`: `ReadConfig`, `Children`, `Files`, `Stat`/`Real`, and the cached project walk (`Nested`, `NestedDirs`). Never execute anything; never follow symlinks outside the root (`Source.Real` resolves chains lexically, including absolute targets inside the root).
- Each path is emitted by exactly one adapter (its owner) with `LoadedBy` listing every agent that reads it; discovery merges duplicates defensively.
- Missing config → zero assets, not an error. Malformed config → pinned as raw bytes plus a reported problem, never a crash.
- Secret values never leave the adapter: MCP and hook parsing reduce env and header maps to names and redact arguments and URLs; the locations of inline secrets travel on `Asset.InlineSecrets` for policy only and are never serialised.
- Each adapter documents the config paths it reads, with upstream links and the date verified, in `internal/adapter/<name>/README.md`. The cross-agent summary is [AGENT_PATHS.md](AGENT_PATHS.md).

## 5. Dependencies policy

Minimal and justified ([ADR-0006](adr/0006-dependencies.md)):
- `go.yaml.in/yaml/v3`: policy file.
- `github.com/pelletier/go-toml/v2`: Codex `config.toml`.
- `github.com/santhosh-tekuri/jsonschema/v6`: tests only, validates SARIF and CycloneDX output against the official schemas offline.

CycloneDX and SARIF are emitted from small local structs instead of SDKs. No dependency may perform network I/O on import or in code paths we call; depguard bans `os/exec`, `plugin`, `net`, `net/http` and `net/rpc` in non-test code.

## 6. Testing strategy

- Table-driven unit tests; golden files under each package's `testdata/golden/` (update with `go test ./... -update` and review the diff).
- Adapter fixtures under `testdata/adapters/<agent>/{project,user}` plus a malformed tree; discovery goldens record every entry and problem.
- Security invariants from THREAT_MODEL §6 as named tests (`TestInvariant_*`), plus the bypass techniques in [WHAT_IT_CATCHES.md](WHAT_IT_CATCHES.md).
- Fuzz targets: canonical JSON, lockfile decoder, policy parser, ignore parser, prose differ, redaction.
- CI: tests on Linux, macOS and Windows; a coverage gate (≥ 90% for lock, hash, policy); the suite under `unshare -n` with no network; fuzz smoke runs; cross-compilation; a byte-for-byte reproducibility check; and `lockward verify --frozen` on this repository.

## 7. Release engineering

- GoReleaser: linux/darwin/windows × amd64/arm64, `CGO_ENABLED=0`, `-trimpath`, commit-time `mod_timestamp`, source archive.
- `checksums.txt` signed keylessly with cosign (Sigstore bundle), SLSA build provenance via `actions/attest-build-provenance`.
- The GitHub Action verifies the Sigstore identity (`release.yml` at the release tag) and the archive checksum before running the binary.
- Distribution: GitHub Releases and `go install`. Homebrew tap and npm/PyPI wrappers are planned.
