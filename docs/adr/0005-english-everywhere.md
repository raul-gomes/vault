# ADR 0005 — English everywhere

- **Status:** accepted
- **Date:** 2026-11-13

## Context

The owner's general rule is code in English and user interface in pt-BR. The repo
mixed both (pt-BR CLI, dashboard and README; English API messages). It is now public.

## Decision

Everything in this project is in English: code, API messages, CLI, dashboard,
README, docs and commits. This overrides the general pt-BR UI rule for EnvVault only.
The existing pt-BR text is translated in one dedicated PR after the security items;
new docs are written in English right away.

## Consequences

- One language for readers outside Brazil and for agents.
- Until the translation PR lands, the repo stays mixed.
