# ADR 0004 — Absolute unlock limit of 12 hours

- **Status:** accepted
- **Date:** 2026-11-13

## Context

The idle lock is renewed by every agent call, so a busy agent keeps the vault
unlocked forever.

## Decision

Besides the idle lock, the vault locks 12 hours after it was unlocked, regardless of
activity. Locking kills running commands, as the normal lock does. The limit is
configurable in the dashboard.

## Consequences

- The passphrase is typed about once per working day.
- A forgotten long-running command (`npm run dev`) cannot hold secrets for days.
