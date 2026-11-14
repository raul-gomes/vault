# ADR 0001 — Static dashboard without a framework

- **Status:** accepted
- **Date:** 2026-11-09
- **Context:** front-end decision for EnvVault v0.1

## Context

EnvVault is a local secret vault. The web interface is a sensitive surface: it
can reveal values and trigger commands with injection. Every front-end
dependency (framework, router, UI library, build toolchain) adds code running
in the same origin as the authenticated session.

The dashboard needs: login, lists, forms, modals, environment tabs, a console
with SSE streaming, and a password generator. It does not need SEO,
server-side rendering, stable deep routes or component sharing between teams.

## Decision

Serve a minimal SPA in plain HTML/CSS/JS, embedded in the Python package:

- `web/index.html` — shell, login and modal `<dialog>`
- `web/app.css` — dark theme with CSS variables
- `web/js/*.js` — native ES modules (entry `main.js`), no build

Rules:

1. No `innerHTML` with user data; the `el()` helper creates nodes and attaches
   text via `document.createTextNode`.
2. No external dependency or CDN. All assets are served from `/static` by the
   package itself.
3. State in a simple `state` object; navigation via `location.hash`.
4. The execution console reads a `ReadableStream` and parses SSE frames manually.

## Consequences

**Positive**

- Minimal attack and supply-chain surface: there is no `node_modules` at
  runtime, and no third-party script in the authenticated origin.
- Trivial deploy: the wheel already contains the UI; nothing to compile.
- CSP and code audit are feasible: the whole app is readable in three files.
- No framework version mismatch when upgrading Python/FastAPI.

**Negative**

- No reactive componentization; screens are functions that rebuild the DOM.
- No front-end type-checking; the API contract depends on discipline and on
  backend tests.
- No UI unit tests in the repository (the Playwright smoke test lives outside,
  because it needs a browser binary).
- If the UI grows a lot, maintenance gets more expensive than with a framework.

## Alternatives considered

- **React + Vite:** productivity and ecosystem, but adds a build, hundreds of
  transitive dependencies and a bundle served in the session origin.
- **HTMX/Alpine via CDN:** little code, but depends on third parties at runtime.
- **Server-side templates (Jinja):** simple, but the SSE console and the modals
  get more verbose and interactivity needs more round trips to the server.

The decision can be revisited if the UI passes ~2,000 lines of JS or needs
complex shared state.
