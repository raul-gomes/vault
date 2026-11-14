# Action plan

Agreed with the owner on 2026-11-13, from [`baseline-review.md`](baseline-review.md).
Goal: run the vault day to day in a secure way. Personal tool, public repo, MIT.

Rules for every item:

- One PR per item against `develop`, starting with a failing test that reproduces
  the problem. The owner reviews and merges.
- Tests added by each item push coverage towards 90%; the CI floor rises with it.
- `mypy --strict` joins the CI early (first item that touches typing).
- `cli.py` and `web/app.js` are split only when an item already touches them.
- New docs are written in English (ADR 0005).

| # | Item | Change | Status |
| --- | --- | --- | --- |
| 1 | **B3** orphan process | Reserve the execution slot before `Popen`. Over the limit: HTTP 429 with a clear message, no process started. | done (PR #3) |
| 2 | **S6** log permissions | `daemon.log` created and kept at `0600`; fix the existing file on start. | done (PR #4) |
| 3 | **B1** working directory | Relative `--cwd` resolves from the project path. Without `--cwd`, the CLI sends the current directory when it is inside the project; otherwise the project root is used. Paths outside the project stay rejected. No extra paths per project. | done (PR #5) |
| 4 | **B2** command filter | Compare allowed commands argv element by element, not as a string prefix. | done (PR #6) |
| 5 | **S2** explicit command list | A token needs at least one allowed command, or an explicit `--any-command`. Existing tokens without a list are rejected until recreated (ADR 0003). Recreate the `nacaopatina` token. | done (PR #7) |
| 6 | **S4** absolute unlock limit | Lock after 12 h unlocked even with continuous use, killing running commands; configurable in the dashboard (ADR 0004). | done (PR #8) |
| 7 | **S5** backup | `envvault backup <destination>`: consistent copy of the still-encrypted database (SQLite backup API), refuses to overwrite; restore steps in the README. No automatic backup. | done (PR #9) |
| 8 | **S1** same-user boundary | Document in the README what an agent running as the same OS user can reach (`/proc/<pid>/environ`, token files) (ADR 0002). | done (PR #10) |
| 9 | **S3** keyed audit chain | HMAC with a key derived from the DEK; chain head and count stored in `meta`. | done (PR #11) |
| 10 | **Translation** | One PR moving CLI, dashboard, API messages, README and docs to English (ADR 0005). | in review (this PR) |

Backlog (not scheduled): B4 and Q3–Q8 in [`open-items.md`](open-items.md).
