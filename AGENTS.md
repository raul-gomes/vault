# AGENTS.md

Guidance for agents working in this repository.

## General practices and project docs

Cross-project rules (TDD, security, quality, git flow, living docs) live in the
second brain: `~/HD_Repos/cerebro/20_Praticas/Praticas-Essenciais.md` (private repo
`github.com/raul-gomes/cerebro`). This file only holds what is specific to EnvVault
and wins on conflict.

Living docs in `docs/` (update in the same commit as the change): `comandos.md`
(every useful command), `lineage.md` (SQLite schema + migrations), `tree_files.md`
(file responsibilities), `pendencias.md` (open items), `GLOSSARY.md`,
`analise-inicial.md` (baseline review), `adr/`.

Git flow: `feature/*` from `develop`, PR back to `develop`; `main` only receives
`release/*` and `hotfix/*`.

## What this project is

EnvVault is a local, encrypted vault for project `.env` secrets. A daemon owns
the data key, decrypts secrets, spawns child processes with them injected, and
returns **redacted** output. Agents get scoped bearer tokens that can list key
names and execute commands — never reveal values.

## Non-negotiable invariants

1. **Plaintext never crosses the HTTP boundary.** Secret values and credential
   fields may exist only: in the daemon's memory, in the child process
   environment, and in the `reveal`/`export` responses for the *human* session.
2. **The daemon spawns the process.** Never add a CLI path that decrypts locally
   or passes plaintext to an agent process.
3. **Agent tokens cannot reveal/export or access credentials** and cannot use
   session endpoints. The two auth planes stay separate (`require_session` vs
   `require_agent`).
4. **Every mutation is audited.** New actions append an entry through
   `services/audit.append` and commit in the same transaction.
5. **The audit log is append-only and hash-chained.** Do not update/delete rows.
6. **Redact before writing to a response.** All child output goes through
   `services/redact.Redactor`.
7. **No `innerHTML` / `eval` in the web UI.** Build DOM with `document.createElement`.
8. **Never log secret values** or include them in error messages.

## Language conventions

- Python: identifiers, docstrings and comments in English.
- User-facing strings: Portuguese (pt-BR). This includes CLI help/messages, API
  `detail` messages and the entire web UI.
- Commit messages: English, imperative mood.

## Architecture map

| Path | Responsibility |
| --- | --- |
| `src/envvault/crypto.py` | Argon2id KDF, DEK wrap/unwrap, AES-256-GCM secrets with AAD |
| `src/envvault/runtime.py` | In-memory DEK, sessions, login throttle, exec registry |
| `src/envvault/services/vault.py` | init/unlock/lock, passphrase change, idle enforcement |
| `src/envvault/services/secrets.py` | encrypted CRUD, reveal, import/export, exec material |
| `src/envvault/services/credentials.py` | global/project service credentials, encrypted payload, audited reveal |
| `src/envvault/services/runner.py` | spawn child, assemble env, redact stream, timeout/process-group kill |
| `src/envvault/services/tokens.py` | token creation and scope authorization |
| `src/envvault/services/audit.py` | append-only hash chain |
| `src/envvault/api/` | FastAPI routers and auth dependencies |
| `src/envvault/web/` | dependency-free dashboard |
| `src/envvault/cli.py` | Typer CLI |
| `src/envvault/migrations/` | Alembic schema |

Data flow for execution:

```
client -> POST /v1/exec -> decrypt in daemon -> Popen(env=secrets)
       <- SSE (redacted) <- reader thread + Redactor
```

The child runs with `start_new_session=True`; termination signals the whole
process group. `ENVVAULT_*` variables are stripped from the child env.

## Auth and request rules

- Browser sessions: `envvault_session` cookie (`HttpOnly`, `SameSite=Strict`) +
  `x-csrf-token` header on mutations. `Origin` and `Host` are validated.
- Agent requests: `Authorization: Bearer ev_...`; token hash stored in SQLite.
- The CLI keeps **one token file per project** in
  `$ENVVAULT_HOME/agent-tokens/<slug>.token` (`0600` file, `0700` directory).
  `ENVVAULT_TOKEN` overrides the file. Saving never prints the value; a file
  with group/other permissions or a symlink is refused. This lets a shell at
  the workspace root run any project with `-p` without exporting per project.
- Idle timeout applies to both planes via `vault.enforce_idle`.
- Locking clears the DEK, drops every session and terminates executions.

## Exec request rules

- `command` is an argv list; it never passes through a shell.
- Optional `env` overrides are merged by the daemon. They cannot use the
  `ENVVAULT_*` prefix or shadow a key stored in the vault; the request fails
  with `400` instead of silently replacing the secret.
- Audit entries store only the override **key names**, never their values.
- `timeout_seconds` terminates the whole process group; the `exit` SSE event
  and the audit entry carry `timed_out`.

## Database

- SQLite with `foreign_keys=ON`, WAL and `busy_timeout`.
- Files are `0600`; the home directory is `0700`.
- Schema changes require a new Alembic revision in `migrations/versions/`.
  Never edit a released revision.
- Secret AAD binds `project_id/environment/key/version`; increment `version` on
  every write so old ciphertext cannot be swapped in.
- Environments are first-class rows in `environments` (unique per project) so an
  empty environment still shows in the UI. Creating a secret also registers its
  environment. Deleting an environment is only allowed when it has no secrets.
- Credentials are global when `credentials.project_id` is null and scoped to one
  project otherwise. Only `name`, `category` and the association are plaintext;
  the other fields live in an encrypted JSON payload whose AAD binds
  `credential_id/version`. Deleting a project cascades its credentials; globals
  survive.

## Web UI rules

- Plain modules, no bundler, no external CDN.
- `el()` helper creates nodes; append text nodes for user data.
- pt-BR copy, dark theme tokens in `app.css`.
- Any new fetch must send the CSRF header for mutations and handle 401/423 by
  returning to the login view.

## Testing

```bash
uv run pytest
uv run ruff check .
uv run ruff format --check .
```

Tests use `tests/conftest.py` fixtures with fast KDF settings. When adding a
secret-related feature, assert that the plaintext does not appear in the
response body or on disk (see `test_secret_is_encrypted_at_rest`).

A UI smoke test can be run against a live daemon with Playwright
(`/tmp/opencode/ui/smoke.mjs` in the original environment); it is not part of
the repo because it needs a browser binary.

## Common pitfalls

- `enforce_idle` touches activity; read-only endpoints still count as activity.
- `Redactor` ignores values shorter than 6 chars on purpose.
- `render_env` quoting: `$` must be escaped so dotenv loaders do not expand it.
- Pydantic models validate at the boundary; domain services raise `ValueError`
  subclasses mapped to HTTP 400 in `app.py`.
- Do not call `os.killpg` on a pid you did not start with a new session.
