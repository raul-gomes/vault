# ADR 0003 — Agent tokens need an explicit command list

- **Status:** accepted
- **Date:** 2026-11-13

## Context

A token created without `allowed_commands` accepts any argv, including
`python3 -c "..."` that can re-encode a secret past the redactor. The open behaviour
was the default.

## Decision

Creating a token requires at least one allowed command, or an explicit
`--any-command` (shown as such in the dashboard). Matching compares argv element by
element. Tokens stored without a list are rejected until they are recreated.

## Consequences

- The safe choice is the default; the unsafe one is visible and deliberate.
- Existing tokens (one today: `nacaopatina`) must be recreated after the upgrade.
