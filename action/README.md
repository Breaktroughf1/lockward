# Lockward GitHub Action (development copy)

The published action is [Breaktroughf1/lockward-action](https://github.com/Breaktroughf1/lockward-action), listed on the GitHub Marketplace as [Lockward Verify](https://github.com/marketplace/actions/lockward-verify). This directory is where the action is developed and tested; at each release its files are copied there (see docs/ARCHITECTURE.md §7). Use the published repository in your workflows.

Runs `lockward` in CI and fails the job when AI-agent assets drift from `lockward.lock` or break your policy.

```yaml
name: lockward
on: [pull_request, push]
permissions:
  contents: read
  security-events: write   # only needed for SARIF upload
jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<sha>
        with:
          persist-credentials: false
      - uses: Breaktroughf1/lockward-action@bfbb98e7ac97a8ebe8361dab2d36dd4523ca1c1b # v0.2.0
        with:
          version: 0.2.0
```

## Inputs

| Input | Default | Description |
|---|---|---|
| `version` | `0.2.0` | Release to install, without the leading `v` |
| `args` | `verify --frozen` | Arguments passed to `lockward` |
| `sarif` | `true` | For `verify`, also upload a SARIF report to code scanning (needs `security-events: write`) |
| `working-directory` | `.` | Directory to run in |

## Outputs

| Output | Description |
|---|---|
| `exit-code` | `0` clean, `1` drift, `2` policy violation, `3` usage or configuration error, `4` internal error |

## What it does

1. Downloads `lockward_<version>_<os>_<arch>` from the GitHub release, plus `checksums.txt` and its Sigstore bundle.
2. Verifies the bundle with `cosign verify-blob`, requiring the certificate identity `https://github.com/Breaktroughf1/lockward/.github/workflows/release.yml@refs/tags/v<version>` and the GitHub Actions OIDC issuer.
3. Verifies the archive's SHA-256 against the signed `checksums.txt`. The binary is extracted and run only if both checks pass.
4. Runs `lockward` with `args`, writes the output to the job summary, uploads SARIF, and finally fails the step with Lockward's exit code.

Pin the action to a commit SHA, as you would any third-party action. Supported runners: Linux, macOS and Windows on x64 and arm64.
