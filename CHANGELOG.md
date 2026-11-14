# Changelog

## 0.2.0 — 2026-11-14

Security hardening after the baseline review (`docs/baseline-review.md`).

**Upgrade:** reinstall (`uv tool install --force <repo>`) and restart the daemon;
migrations `0004` and `0005` run on start. Agent tokens without an allowed
command list are now rejected: recreate them with `--allow` or `--any-command`.
Take a backup first: `envvault backup <dir>`.

### Security
- Agent tokens need an explicit command list or `--any-command` (ADR 0003).
- Allowed commands are matched argv element by element (`bun` no longer allows `bunx`).
- The vault locks after at most 12 hours unlocked, even with continuous use; a
  watchdog enforces both locks and kills running commands (ADR 0004).
- Audit chain keyed with an HMAC derived from the DEK, with the head pinned in
  `meta`; rewriting or truncating it is detected by `envvault verify`.
- `daemon.log` is kept at `0600`.
- README documents the same-user boundary (ADR 0002).

### Fixed
- No orphan process when the concurrency limit is reached (HTTP 429).
- A client that disconnects early no longer leaves the child running.
- `--cwd` resolves from the project root; without it, the current directory is
  used when it is inside the project.
- `envvault generate` no longer crashes after printing.

### Added
- `envvault backup` (consistent copy of the encrypted database, never overwrites).

### Changed
- Everything is in English: CLI, dashboard, API messages and docs (ADR 0005).
- `cli.py` split into the `cli/` package; dashboard split into ES modules.
- Test coverage 74% → 95%, CI floor 90%.

## 0.1.0

Initial version.
