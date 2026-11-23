# Security Policy

## Reporting a vulnerability

Please **do not** open a public issue for security problems.

Report privately via GitHub: **Security → Report a vulnerability** on this repository (private vulnerability reporting). If that is unavailable, email noealrajeev987@gmail.com with the subject `Lockward security`.

Include affected version or commit, reproduction steps, and impact. We aim to:

- acknowledge within **3 business days**,
- provide an initial assessment within **10 business days**,
- coordinate a fix and disclosure date with you (default embargo up to 90 days).

We credit reporters in release notes unless you prefer otherwise.

## Supported versions

Lockward is pre-1.0. Only the latest release receives security fixes.

## Scope

In scope: anything that breaks the invariants in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) — e.g. drift that `verify` fails to detect, Lockward executing scanned content, unintended network access, secret values in output, or compromise of the release pipeline.

Out of scope: Lockward not flagging malicious *content* on first lock (it is change control, not a malware detector).
