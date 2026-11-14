# Open items

Scheduled work lives in [`action-plan.md`](action-plan.md) (order and status).
This file keeps every finding; details in [`baseline-review.md`](baseline-review.md).
When done: tick `[x]`, write `DONE` and the commit.

- [x] **S6** `~/.envvault/daemon.log` is `0664` (group/other readable). Plan item 2. Fixed in PR #4.

## Bugs (regression test first)
- [x] **B1** Relative `cwd` resolved against the daemon directory (`src/envvault/services/runner.py:39`). Resolve relative to the project directory; the CLI must send the current `cwd` when it is inside the project (`src/envvault/cli.py:788`). Fixed in PR #5.
- [x] **B2** Command filter by text prefix (`src/envvault/services/tokens.py:150`). Compare argv element by element. Fixed in PR #6.
- [x] **B3** Orphan process when the execution limit is exceeded: `Popen` before `add_exec` (`src/envvault/services/runner.py:129`/`152`). Reserve the slot before starting and map the error to 429. Fixed in PR #3.
- [x] **B4** Confirmed: a client that disconnected before the first SSE event left the child running and its slot taken. `ExecStreamingResponse` now finalizes (kill, unregister, `exec.cancel`) exactly once. Fixed in this PR.

## Security
- [x] **S1** Document in the README that the same user reads `/proc/<pid>/environ` of the children and the token files. Evaluate a daemon with its own user and `hidepid`. Documented in PR #10 (verified on Ubuntu with `ptrace_scope=1`).
- [x] **S2** Token without `allowed_commands` accepts everything. Decided: explicit list or `--any-command` (ADR 0003). Done in PR #7.
- [x] **S3** Audit log with DEK-derived HMAC and chain head in `meta` (`src/envvault/services/audit.py`). Done in PR #11.
- [x] **S4** Absolute maximum unlock time, even with an active agent (`src/envvault/services/vault.py:178`). Done in PR #8.
- [x] **S5** `envvault backup` + restore steps. Done in PR #9.

## Quality
- [ ] **Q1** Coverage 73% → 90% with a floor in CI (`cli.py` 20%, `daemon.py` 0%).
- [ ] **Q2** Typecheck (`mypy --strict` or `pyright`) in CI; remove `# type: ignore` de `src/envvault/app.py:70`.
- [ ] **Q3** Split `src/envvault/cli.py` and `src/envvault/web/app.js`.
- [ ] **Q4** Make `_terminate_process_group` public and import it at the top of `runner.py`.
- [x] **Q5** Everything in English (ADR 0005); AGENTS.md fixed in the translation PR.
- [ ] **Q6** Replace `httpx` with `httpx2` in the tests (Starlette warning).
- [x] **Q7** `LICENSE` file (MIT). DONE.
- [ ] **Q8** UI smoke test inside the repo, or remove the mention from `AGENTS.md`.

## Process
- [x] Public GitHub repo `raul-gomes/vault`, `main` + `develop` pushed. DONE (2026-11-13).
- [ ] Branch protection on `main`/`develop` (free on public repos).
- [x] CI green on the first PR (public repo: Actions free). DONE (PR #1).
