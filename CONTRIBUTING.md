# Contributing to Lockward

Thanks for helping. Lockward is a security tool, so we favour small, well-tested changes.

## Ground rules

1. Read the [threat model](docs/THREAT_MODEL.md). Changes must not violate its security invariants (no executing scanned content, no default network access, no secret values in output).
2. Open an issue before large changes or new dependencies. Every new dependency needs a justification.
3. Keep PRs focused: one feature or fix per PR.

## Development setup

```sh
git clone git@github.com:Breaktroughf1/lockward.git
cd lockward
go test ./...
go vet ./...
golangci-lint run
```

Requires Go (version in `go.mod`).

## Commits

- [Conventional Commits](https://www.conventionalcommits.org/): `feat(adapter): add Windsurf rules discovery [LW-FR-01]`
- Reference PRD requirement IDs (`LW-FR-xx`, `LW-NFR-xx`) where relevant.
- Sign off every commit (DCO): `git commit -s`. By signing off you certify the [Developer Certificate of Origin](https://developercertificate.org/).

## Tests

- New behaviour needs tests. Adapters need fixtures under `testdata/adapters/<agent>/` and golden outputs.
- Update golden files with `go test ./... -update` and review the diff.
- Parsers should have a fuzz target.

## Adding an agent adapter

1. Create `internal/adapter/<agent>/` implementing the `Adapter` interface (see [ARCHITECTURE.md](docs/ARCHITECTURE.md#4-adapter-contract)).
2. Document every config path you read in `internal/adapter/<agent>/README.md`, with upstream doc links and the date you verified them.
3. Add fixtures for: empty, typical, malformed and hostile (symlinks, huge files) cases.

## Code of conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md).
