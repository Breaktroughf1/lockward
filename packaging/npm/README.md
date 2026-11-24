# lockward (npm)

Runs [Lockward](https://github.com/Breaktroughf1/lockward), the offline lockfile and policy gate for AI agent skills, MCP servers, hooks and rules files.

```sh
npx lockward init
npx lockward lock
npx lockward verify --frozen
```

This package contains no binary and no install scripts. On first run it downloads the Lockward release archive for your platform from GitHub, checks it against the SHA-256 baked into this package (copied from the release's Sigstore-verified `checksums.txt` when the package was built in CI, and published with npm provenance), extracts only the `lockward` binary into your user cache, and re-checks the binary's hash on every run. A mismatch stops it before anything runs.

The package version matches the Lockward version it installs. Other ways to install: Homebrew (`brew install breaktroughf1/tap/lockward`), `go install`, the GitHub Action, the container image and signed release downloads; see the [README](https://github.com/Breaktroughf1/lockward#install).
