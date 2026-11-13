# ADR 0002 — Accept the same-user boundary

- **Status:** accepted
- **Date:** 2026-11-13

## Context

Agents (Claude Code, scripts) run as the same OS user as the daemon. That user can
read `/proc/<pid>/environ` of every child the daemon starts and every file in
`~/.envvault/agent-tokens/`. Redaction stops accidental leaks (logs, build output,
chat), not an agent that deliberately wants a value.

## Decision

Keep the daemon and its children under the user's own account and document the
boundary plainly in the README. Running the daemon as a dedicated OS user (real
isolation, but needs sudo/systemd and a heavier install) is a possible future step,
not planned.

## Consequences

- Install stays one command; the threat model is honest.
- Defences that do not rely on OS isolation get priority: explicit command lists
  (ADR 0003), absolute unlock limit (ADR 0004), keyed audit chain (S3).
