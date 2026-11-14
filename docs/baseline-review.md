# EnvVault baseline review (2026-11-13)

Code read at `5d16a07` (9 commits, all from 2026-11-09). The actionable items
are in [`open-items.md`](open-items.md), with the same IDs (B1, S1...).

## Summary

The base is good for a 4-day project. The cryptography is right, the split
between the human session and the agent token is clear, and the README is
honest about the threat model. Four risks deserve attention first: two bugs in
command execution (B1 and B3), the command filter that matches a text prefix
(B2), and the real protection limit when the agent runs as the same system user
(S1).

## Measured state

| Item | Value |
| --- | --- |
| Code | ~10.3k lines (Python ~6.7k, web ~2.8k) |
| Tests | 86 passing (`uv run pytest`, 5 s) |
| Coverage | 73% overall; `cli.py` 20%, `daemon.py` 0%, `db.py` 71% |
| Lint and formatting | `ruff check` and `ruff format --check` clean |
| Typecheck | not configured |
| CI | none (added in this change) |
| Git remote | none; single `master` branch (now `main` + `develop`) |
| Secrets in history | none found (scan for key/token patterns; only the `cf-token` test fixture) |

## Strengths

- **Correct key envelope.** Argon2id (3 iterations, 64 MiB) derives the KEK,
  which wraps a random DEK. Each secret uses AES-256-GCM with AAD
  `project/environment/key/version`, so a ciphertext cannot be moved elsewhere
  or rolled back to an old version. Changing the passphrase only re-wraps the DEK.
- **Two separate authentication planes.** Browser session (`HttpOnly` +
  `SameSite=Strict` cookie + CSRF + `Origin` and `Host` checks against DNS
  rebinding) and agent token (`Bearer`, only the SHA-256 hash in the database).
  The agent has no route that returns a value.
- **Execution without a shell.** The command is an argv list. The child runs in
  a new session and the whole group is terminated on timeout, lock and
  cancellation. `ENVVAULT_*` does not leak to the child.
- **Redaction with common encodings.** Plain value, URL-encoded and base64, with
  a buffer that avoids cutting a secret in half between two output chunks.
- **Hash-chained audit log**, written in the same transaction as the mutation.
- **Owner-only file permissions** (`0700` on the directory, `0600` on the
  database and tokens). A token file with open permissions or a symlink is refused.
- **Above-average documentation:** README with setup, cheatsheet, security and
  troubleshooting, plus `AGENTS.md` with the invariants.

## Bugs (read from the code, no regression test yet)

**B1. Relative `cwd` is resolved against the daemon directory, not the project's.**
`services/runner.py:39` does `Path(requested).expanduser().resolve()`. This uses
the directory the daemon was started in. `/v1/agent/context` itself suggests
`"cwd": "frontend"`, which does not point to `<project>/frontend`. The CLI sends
`--cwd` as typed (`cli.py:788`). Without `--cwd`, the command always runs in the
project root, even when called from a subdirectory (`envvault run` inside
`admin/` runs in the root).

**B2. Command filter compares text, not argv.** `services/tokens.py:150` tests
`" ".join(command).startswith(prefix)`. With the prefix `bun`, `bunx anything`
passes. With `npm run`, `npm run-script` passes. It should compare the first
argv elements, one by one.

**B3. Orphan process when the execution limit is hit.** `runner.spawn` calls
`Popen` (line 129) **before** `state.add_exec` (line 152). If the limit of 8
executions is exceeded, `add_exec` raises `RuntimeError`. The process is already
running with the secrets, is untracked (it does not die on lock or timeout) and
the API returns 500 (there is no handler for `RuntimeError`). The audit log has
already recorded `exec.start`.

**B4 (to confirm). Client that disconnects before the first byte.** Cleanup
(removing the record, killing the group, auditing the end) lives in the `finally`
of the SSE generator. If the generator never starts being consumed, it does not run.

## Security (design decisions)

**S1. The agent runs as the same system user.** This is the project's real
limit. The README already says it does not protect against a "local process of
the same user reading the daemon's memory", but there are two simpler paths that
are not written down:
- an agent with a shell reads `/proc/<pid>/environ` of any child the daemon
  started (the child belongs to the same user);
- the tokens of **all** projects live in `~/.envvault/agent-tokens/`, readable by
  the same user.

Redaction protects against accidental leaks (log, build, conversation), not
against an agent that wants the value. Options: document this in the README, run
the daemon and the children as a different system user (real boundary, but the
setup gets much more complex) and mount `/proc` with `hidepid`.

**S2. A token without `allowed_commands` accepts any command.** The default is
the most open (`python3 -c "print(os.environ)"` passes; redaction catches the
plain value, but not `rev` or `base32`). Under the general rule "default fallback
= the safest", the default should be an explicit list, or at least a strong
warning at creation.

**S3. Audit chain without a key.** The hash is plain SHA-256. Anyone with write
access to the database (the same user) can rewrite the whole chain and recompute
the hashes, and deleting the last rows does not break verification. Improvement:
HMAC with a key derived from the DEK (rewriting requires the passphrase) and
store the head hash and count in `meta`.

**S4. An active agent prevents the idle lock.** Every agent call renews the clock
(`vault.enforce_idle`). With an agent running commands, the vault never locks by
itself. Consider an absolute maximum unlock time (e.g. 12 h) that requires the
passphrase again.

**S5. No backup or recovery.** Losing the passphrase or the disk loses
everything. Missing: an `envvault backup` (consistent copy of the encrypted
`vault.db` via the SQLite backup API) and the restore steps.

## Quality and maintenance

- **Q1.** Coverage of 73%, no floor. `cli.py` (1,348 lines) has 20%. Goal: 90%
  with a floor in CI, like the other projects.
- **Q2.** No typecheck. Add `mypy --strict` or `pyright`; there is an unexplained
  `# type: ignore` at `app.py:70`.
- **Q3.** `cli.py` (1,348 lines) and `web/app.js` (1,972 lines) hold everything.
  Split by command group and by screen before they grow further.
- **Q4.** `runner.py` imports `_terminate_process_group` (private) from `runtime`
  inside a function, in two places. Make it public and import at the top.
- **Q5.** `AGENTS.md` says the API `detail` messages are in pt-BR, but almost all
  are in English (`"vault is locked"`, `"invalid token"`). Decide which one holds
  and align.
- **Q6.** Deprecation warning in the tests: Starlette's `TestClient` asks for
  `httpx2` instead of `httpx`.
- **Q7.** `pyproject.toml` and README say MIT, but there is no `LICENSE` file.
- **Q8.** The UI smoke test mentioned in `AGENTS.md` lives outside the repo
  (`/tmp/opencode/...`). Bring it into `tests/e2e/` (outside the default run) or
  remove the mention.

## Product ideas (for you to decide)

- `envvault doctor`: checks daemon, permissions, tokens with open permissions,
  projects with a missing directory and the audit chain, all at once.
- Import the existing `.env` files in `~/HD_Repos/*` in one go (`app_amarelhinhas`
  still has no token in the vault).
- Rotation reminder: show the age of each secret and highlight old ones.
- Tokens with an expiry (`expires_at`), so old tokens are not left active.
