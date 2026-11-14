# File tree

Updated on 2026-11-13. Responsibility of each versioned file.

```
.github/workflows/ci.yml     CI: ruff (lint + format) and pytest with coverage
AGENTS.md                    Security invariants and rules for agents
README.md                    Setup, daily use, security, troubleshooting
pyproject.toml / uv.lock     Python project (hatch), locked dependencies
docs/
  action-plan.md             Ordered action plan (one PR per item)
  adr/0001-static-ui.md      Decision: static web dashboard, no bundler/CDN
  adr/0002..0005             Same-user boundary, command list, 12 h unlock limit, English
  baseline-review.md         Review of 2026-11-13 (strengths, bugs, risks, ideas)
  commands.md                All useful commands
  GLOSSARY.md                Domain terms
  lineage.md                 SQLite schema and migrations
  open-items.md              Open items
  tree_files.md              This file
src/envvault/
  __init__.py                Package version
  app.py                     FastAPI factory, Host guard, error handlers, static files
  cli/                       Typer CLI `envvault`, one module per command group
    __init__.py              Imports the command modules (order = help order); `main`
    __main__.py              `python -m envvault.cli`
    _common.py               Apps, console, CliError, daemon/session/HTTP helpers
    vault.py                 init, serve, stop, status, unlock, lock
    secrets.py               link, set, list, remove, reveal, import, export
    runtime.py               run, context, keys (agent-token helpers)
    maintenance.py           audit, backup, verify, passwd
    pwgen.py                 generate
    projects.py              `project` sub-commands
    tokens.py                `token` sub-commands
    credentials.py           `credential` sub-commands
  config.py                  Settings from ENVVAULT_* (paths, port, KDF)
  crypto.py                  Argon2id, DEK wrapping, AES-256-GCM with AAD
  daemon.py                  Starts the daemon's uvicorn
  db.py                      SQLite engine (WAL, FK, busy_timeout) and 0600 permissions
  migrate.py                 Programmatic Alembic upgrade
  models.py                  SQLAlchemy models
  passwords.py               Password generator (CSPRNG)
  runtime.py                 In-memory state: DEK, sessions, login throttle, executions
  schemas.py                 Pydantic input/output models
  tokenstore.py              Per-project token files (0600, refuses symlinks)
  api/
    auth.py                  Health, session, login/unlock, logout, lock, passphrase change
    credentials.py           Credential CRUD and audited reveal
    deps.py                  Dependencies: database, session + CSRF + Origin, agent token
    exec.py                  Execution by session and by agent (SSE), agent context and keys
    projects.py              Project and environment CRUD
    secrets.py               Secret CRUD, import/export, reveal
    serializers.py           Model to response conversion
    system.py                Overview, audit log and verification, settings, password generator
    tokens.py                Create, list and revoke tokens
  services/
    audit.py                 Append-only audit log with DEK-derived HMAC and head pinned in meta
    backup.py                Consistent copy of the encrypted database (envvault backup)
    credentials.py           Encrypted credentials (global or per project)
    envfile.py               .env parser/generator
    projects.py              Projects and environments
    redact.py                Output redaction (value, URL-encoded, base64)
    runner.py                Starts the child, injects env, redacts output, kills the group
    secrets.py               Encrypted secrets, reveal, import/export, values for exec
    tokens.py                Tokens and scope/command authorization
    vault.py                 init/unlock/lock, passphrase change, idle lock
  migrations/                Alembic (env.py, versions/0001..0005)
  web/                       Dashboard: index.html, app.js, app.css
tests/                       pytest (conftest with fast KDF); one file per area
```
