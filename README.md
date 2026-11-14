# EnvVault

Local encrypted vault for your projects' `.env` files. The core idea: an agent
(Claude, scripts, local CI) **uses** the secrets without **seeing** them. The
vault daemon decrypts and injects; the output comes back redacted.

> **There is no passphrase recovery.** If you lose it, the secrets are
> unrecoverable. Keep it in a password manager and back up `~/.envvault` (a
> backup without the passphrase is useless).

---

## 1. What it is and what it is not

**It is:**
- A single local SQLite vault that manages the secrets of several projects.
- An execution broker: it receives a command, injects the variables and returns
  the **redacted** output.
- A local (loopback) web dashboard for you to manage everything.
- An append-only, hash-chained audit log.

**It is not:**
- A `.env` inside each project. Projects do not store secrets.
- A cloud secret manager.
- A sandbox against a malicious command (see [limitations](#9-security)).

---

## 2. How it works

### 2.1 Overview

```
┌──────────────────────┐        ┌────────────────────────────────────┐
│  you (browser)       │        │  EnvVault daemon                   │
│  or CLI              │──────▶ │  127.0.0.1:8787                    │
└──────────────────────┘        │                                    │
                                │  ~/.envvault/vault.db (encrypted)  │
┌──────────────────────┐        │  data key (DEK) in memory only     │
│  agent (token ev_…)  │──────▶ │                                    │
└──────────────────────┘        └───────────────┬────────────────────┘
                                                │ decrypts
                                                ▼
                                   ┌──────────────────────────┐
                                   │ child process            │
                                   │ env with the secrets     │
                                   └────────────┬─────────────┘
                                                │ stdout/stderr
                                                ▼
                                   redactor → redacted SSE → client
```

The critical point: **the daemon starts the process**. The plain value is never
serialized in an HTTP response. It exists only in the daemon's memory and in the
child process environment.

### 2.2 The vault is global; projects are records

```
~/.envvault/                 ← one vault for everything
  vault.db                   ← encrypted database
  daemon.log
  daemon.pid

~/projects/app-a/            ← registered project
  .envvault.toml             ← pointer, no secrets
  src/...

~/projects/app-b/            ← another project, same vault
  .envvault.toml
```

- `envvault init` creates the vault **once**.
- `envvault project add app-a --path ~/projects/app-a` only stores the slug +
  path in the database. Nothing is copied into the project.
- `.envvault.toml` is optional and can be committed: it only says which
  project/environment to use when you are in that directory.
- Isolation is logical: each secret belongs to `project + environment + key`,
  and each agent token is bound to one project and specific environments.

### 2.3 Cryptography

- The master passphrase derives a **KEK** with **Argon2id** (random salt,
  configurable cost).
- The KEK wraps (AES-256-GCM) a random **DEK**, which is the key that actually
  encrypts the secrets.
- Each secret is encrypted with AES-256-GCM and an **AAD** bound to
  `project_id/environment/key/version`. This prevents swapping ciphertext
  between projects/environments/keys or rolling back to an old version.
- The DEK lives **in memory only**. Changing the passphrase re-wraps the DEK;
  the secrets are not re-encrypted.
- Vault files: `0600`; directory: `0700`.

### 2.4 Two access planes

| | Human session (you) | Agent token |
|---|---|---|
| How it authenticates | passphrase → cookie + CSRF | `Authorization: Bearer ev_…` |
| Lists key names | yes | yes, if `can_list` |
| Runs with injection | yes | yes, if `can_inject` |
| Reveals a value | **yes**, re-checking the passphrase | **never** |
| Exports `.env` | **yes**, re-checking the passphrase | **never** |
| Manages tokens/projects | yes | no |

### 2.5 Output redaction

The daemon replaces occurrences of the values with `[REDACTED:KEY]`, including:

- the raw value;
- URL-encoded and `quote_plus`;
- standard and URL-safe base64.

Values shorter than 6 characters are not redacted (so `8080` or `true` do not
turn into noise).

### 2.6 Lock and audit log

- After `N` minutes of inactivity, the DEK leaves memory, sessions drop and
  running processes are terminated.
- Every relevant action records an event. Each event contains the hash of the
  previous one; `envvault verify` recomputes the chain and detects tampering.

---

## 3. Getting it running

### 3.1 Requirements

- Python **3.12+**
- [`uv`](https://docs.astral.sh/uv/)
- Linux or macOS (the runner uses POSIX process groups)

### 3.2 Installation

```bash
cd /path/to/envvault
uv sync
```

This creates `.venv` and installs the dependencies. The commands below use
`uv run envvault` from inside the repository.

To use it from any directory, install the binary once:

```bash
uv tool install /path/to/envvault
# now: envvault <command>
```

### 3.3 Step 1 — create the vault

```bash
uv run envvault init
```

- Asks for the master passphrase (minimum 10 characters) with confirmation.
- Creates `~/.envvault/vault.db`.
- Starts the daemon in the background at `http://127.0.0.1:8787`.

Check:

```bash
uv run envvault status
```

### 3.4 Step 2 — register a project

```bash
cd ~/projects/my-app
uv run --project /path/to/envvault envvault project add my-app --path .
```

The path must exist. The command asks for the passphrase (the CLI does not keep
a session between runs).

### 3.5 Step 3 — link the directory (optional, recommended)

```bash
cd ~/projects/my-app
uv run --project /path/to/envvault envvault link --project my-app -e dev
```

Creates `.envvault.toml`:

```toml
project = "my-app"
environment = "dev"
```

From then on, inside that directory, you can omit `--project` and
`--environment`.

### 3.6 Step 4 — bring in the secrets

Import the existing `.env`:

```bash
uv run --project /path/to/envvault envvault import .env --delete-file
```

- `--delete-file` deletes the `.env` after importing (the vault becomes the
  source of truth). Asks for confirmation.
- `--replace` overwrites keys that already exist.
- The parser accepts comments, `export`, single/double quotes and **never
  executes** the content.

Or create manually:

```bash
uv run --project /path/to/envvault envvault set API_TOKEN
# asks for the value (hidden)
```

### 3.7 Step 5 — run with injection

```bash
uv run --project /path/to/envvault envvault run -- npm run dev
```

The command does **not** go through a shell: each argument is preserved. The
process runs inside the project directory.

Examples:

```bash
envvault run -- python manage.py migrate
envvault run --cwd sub/dir -- npm test

# variables set up by the vault (without overriding secrets)
envvault run --env PORT=3001 --env NODE_ENV=development -- npm run dev

# ends the process group after 120s (useful for dev servers)
envvault run --env PORT=3001 --timeout 120 -- npm run dev
```

The vault builds the process environment like this:

1. the daemon's current environment (without any `ENVVAULT_*` variable);
2. the project/environment secrets, decrypted in memory;
3. extra variables sent in the request (`env`).

`ENVVAULT_*` keys are reserved and an extra variable **cannot** override a key
that exists in the vault — the request is rejected with `400`. The audit log
records only the **names** of the extra variables, never the values.

If the vault is locked, the CLI asks for the passphrase.

### 3.8 Step 6 — open the dashboard

<http://127.0.0.1:8787>

There you find the overview, projects, environment tabs, secrets, password
generator, execution console, import/export, tokens, audit log and settings.
The daemon listens **only** on loopback.

### 3.9 Step 7 — give Claude access

Create a restricted token:

```bash
uv run envvault token create \
  --name claude-my-app \
  --project my-app \
  --environment dev \
  --allow "npm run" \
  --allow "pytest"
```

By default the value is **not printed**: it is saved to
`~/.envvault/agent-tokens/my-app.token` with `0600` permissions (directory
`0700`). One file per project — so you run commands from **any directory**,
without exporting a token and without `cd`:

```bash
cd ~/HD_Repos
envvault run -p my-app -- npm run dev
envvault keys -p my-app -e dev      # key names (never values)
envvault context -p my-app          # token scope
```

The command runs in the directory you are in, if it is inside the project's
registered directory (e.g. `admin/`). Called from outside the project, it runs
in the project root. `--cwd sub/dir` is always relative to the project root; a
directory outside the project is refused.

If you want the raw value (another machine, another agent), use `--no-save`; the
CLI prints the token only once. `ENVVAULT_TOKEN` still works as an explicit
override and takes priority over the project file.

Every token that executes needs at least one `--allow` (matched word by word:
`--allow "npm run"` allows `npm run dev`, but not `npm run-script`). To allow
everything, use `--any-command` on purpose. Old tokens without a list are
refused: recreate them (ADR 0003).
`envvault token list` shows in the `local` column which token is saved on disk,
and `envvault token revoke` removes the file when it matches the revoked token.

#### Direct request (Claude, scripts, integrations)

The agent can build the execution by sending the command **and** extra variables:

```bash
curl -sN http://127.0.0.1:8787/v1/agent/exec \
  -H "Authorization: Bearer $ENVVAULT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "environment": "dev",
    "command": ["npm", "run", "dev"],
    "cwd": "frontend",
    "env": {"PORT": "3001", "NODE_ENV": "development"},
    "timeout_seconds": 120
  }'
```

The response is an SSE stream (`start`, `output`, `exit`). The daemon:

- decrypts the secrets and builds the environment;
- validates the extra variables (name, size, `ENVVAULT_` prefix and collision
  with vault keys);
- runs the argv without a shell, in its own process group;
- redacts any secret before sending the output;
- ends the group when `timeout_seconds` elapses.

The example uses `ENVVAULT_TOKEN`. With the token saved to a file, prefer the CLI
(`envvault run -p <project> -- ...`), which resolves the token by itself; to call
HTTP directly, create the token with `--no-save` and export the value only for
that command.

On `GET /v1/agent/context` the token itself describes its scope, limits and an
example request — this is what the second-brain skill consults.

---

## 4. Daily use (cheatsheet)

```bash
# lifecycle
envvault init                     # creates the vault and starts the daemon
envvault status                   # daemon + vault state
envvault unlock                   # unlocks in memory
envvault lock                     # discards the key and kills executions
envvault serve                    # runs the daemon in the foreground
envvault stop                     # stops the daemon
envvault passwd                   # changes the passphrase

# projects
envvault project add <slug> --path .
envvault project list
envvault project remove <slug>
envvault link --project <slug> -e dev

# secrets
envvault set KEY                  # hidden value
envvault set KEY --generate       # generates and stores a password
envvault list                     # names and versions (never values)
envvault remove KEY
envvault reveal KEY --copy        # re-checks passphrase, audits
envvault import .env [--replace] [--delete-file]
envvault export --out .env.local  # generates a temporary file

# execution
envvault run -- <argv...>
envvault run -p app -- npm run dev          # from any directory
envvault run -p app --env PORT=3001 --timeout 120 -- npm run dev

# tokens
envvault token create -n claude -p app -e dev --allow "npm run"   # saves 0600
envvault token create -n claude -p app --allow pytest --no-save    # prints once
envvault token list
envvault token revoke claude
envvault context -p app            # scope of the project's token
envvault keys -p app -e dev        # key names (agent)

# service credentials (global or per project)
envvault credential add hostinger -c hosting -p my-app
envvault credential add cloudflare -c dns          # global
envvault credential list [--project my-app | --global]
envvault credential show hostinger                # audited reveal
envvault credential update hostinger --username new@example.com
envvault credential remove hostinger

# audit log and utilities
envvault audit --limit 50
envvault verify
envvault generate -l 48 --count 5
```

---

### Backup and restore

```bash
envvault backup ~/Backups/                 # creates envvault-backup-<date>.db (0600)
envvault backup /media/hd/vault-nov.db     # or a new file (never overwrites)
```

The backup is a consistent copy of the **still-encrypted** database (SQLite
backup API): it needs neither the daemon nor the passphrase and can go to an
external disk or the cloud. It only opens with the passphrase **that was in use
when the backup was made**; if you change the passphrase afterwards, keep the old
one with that backup or make a new backup. Without the passphrase there is no
recovery, by design.

Restore:

```bash
envvault stop
mv ~/.envvault/vault.db ~/.envvault/vault.db.old    # keep until verified
cp /media/hd/vault-nov.db ~/.envvault/vault.db
chmod 600 ~/.envvault/vault.db
envvault unlock                                     # passphrase from the backup time
envvault verify                                     # checks the audit log
```

Agent tokens in `~/.envvault/agent-tokens/` are not part of the backup: after
restoring, recreate the ones created after the backup date.

## 5. `.envvault.toml`

Committable file, **no secrets**:

```toml
project = "my-app"
environment = "dev"
```

The CLI looks in the current directory and its parents. It only exists so you do
not repeat `--project`/`--environment`.

---

## 6. Password generator

```bash
envvault generate                      # 32 characters
envvault generate -l 48 --count 5
envvault generate --no-symbols --json
envvault set DB_PASSWORD --generate
```

Uses the system CSPRNG, removes ambiguous characters (`I`, `l`, `1`, `O`, `0`)
and guarantees at least one character from each selected set. The UI exposes the
same generator in the secret form.

---

## 7. Service credentials

Besides `.env` variables, the vault stores **logins for external services**
(Hostinger, Cloudflare, Gmail, SMTP, API dashboards…). Each credential can be:

- **global** — shared by all projects (e.g. your personal Cloudflare account);
- **per project** — specific to a client/context (e.g. client A's Hostinger
  dashboard).

Name, category and scope are visible for search. Username, password, URL and
notes are encrypted together in a single AES-256-GCM payload, with an AAD binding
the credential's id and version. The version is incremented on every edit.

```bash
# global
envvault credential add cloudflare -c dns --username me@example.com
# for a project
envvault credential add hostinger -c hosting -p client-a --url https://hpanel.hostinger.com
# list by scope
envvault credential list
envvault credential list --project client-a
envvault credential list --global
# view (re-checks the passphrase and audits)
envvault credential show hostinger
envvault credential show hostinger --copy
# move between scopes or change the password
envvault credential update hostinger -p client-b
envvault credential update hostinger --global --generate
```

In the dashboard, the **Credentials** area lets you create, search, filter by
project, reveal with the passphrase and delete. Each project's page also shows a
**Project credentials** section, with that project's credentials and the
available global ones, direct reveal and creation already scoped to the project.

Security rules:

- agent tokens have **no access** to credentials;
- listings never return username, password, URL or notes;
- reveal requires the master passphrase and is recorded as `credential.reveal`;
- deleting a project removes only that project's credentials; global ones
  remain.

---

## 8. Environment variables

| Variable | Default | Effect |
|---|---|---|
| `ENVVAULT_HOME` | `~/.envvault` | database, log and PID |
| `ENVVAULT_HOST` | `127.0.0.1` | daemon bind |
| `ENVVAULT_PORT` | `8787` | port |
| `ENVVAULT_LOCK_TIMEOUT_MINUTES` | `30` | idle lock |
| `ENVVAULT_MAX_UNLOCK_HOURS` | `12` | absolute lock, even with continuous use (ADR 0004) |
| `ENVVAULT_SESSION_IDLE_MINUTES` | `30` | session validity |
| `ENVVAULT_MAX_EXECS` | `8` | simultaneous executions |
| `ENVVAULT_KDF_TIME_COST` | `3` | Argon2id cost |
| `ENVVAULT_KDF_MEMORY_KIB` | `65536` | Argon2id memory (KiB) |
| `ENVVAULT_KDF_PARALLELISM` | `4` | Argon2id parallelism |

---

## 9. Security

**Protects against:**
- reading the database without the passphrase;
- accidental leaks in logs/build/conversation (redaction);
- exposure of service credentials in listings (only the audited reveal shows them);
- silent tampering with the log: the chain uses an HMAC with a key derived from
  the DEK and the last entry is pinned, so rewriting or deleting the tail
  requires the passphrase;
- CSRF, DNS rebinding and use of the dashboard from another origin;
- a forgotten session (idle lock and a 12 h absolute lock, enforced even without
  requests, terminating running commands).

**Does not protect against** (decision recorded in ADR 0002):
- **any process of the same system user**, including an agent with a shell.
  The daemon runs as your user, so that process can:
  - read `/proc/<pid>/environ` of any command the daemon started and see the
    injected secrets while it runs;
  - read the tokens of **all** projects in `~/.envvault/agent-tokens/`;
  - read the daemon's memory.
  Redaction prevents **accidental** leaks (log, build, conversation with the
  agent); it does not stop an agent that wants the value on purpose. To reduce
  the damage: tokens with a command list (ADR 0003), a 12 h absolute lock
  (ADR 0004) and the audit log. Real isolation would require running the daemon
  and the commands as a different system user, which is not planned;
- a **deliberately malicious** command authorized by the token — it receives the
  variables and can encode/exfiltrate them in ways textual redaction does not
  follow;
- a compromised kernel/Python/dependencies;
- a vault backup together with the passphrase.

**Known limitations:**
- values shorter than 6 characters are not redacted;
- arbitrary transformations (hash, cipher, split) are not detected;
- a token created with `--any-command` accepts any argv, including
  `python3 -c "import os; …"`;
- SQLite is not a hardware vault — protection at rest depends on the
  passphrase.

---

## 10. Troubleshooting

| Message / symptom | Cause | Fix |
|---|---|---|
| `daemon is not running` | daemon stopped | `envvault serve` (foreground) or `envvault init` |
| `not authenticated` | session expired | run the command again and enter the passphrase |
| `vault is locked; …` | inactivity | `envvault unlock` |
| `vault locked after the maximum unlock time` | 12 h since unlock | `envvault unlock` |
| `provide --project …` | outside a directory with `.envvault.toml` | `envvault link …` or pass `--project` |
| `project not found: X` | project not registered | `envvault project add X --path .` |
| `file not found: .env` | there is no `.env` in the directory | run in the right directory or create the `.env` |
| `a vault already exists at …` | `init` run twice | use the existing vault; do not run `init` |
| `npm error … package.json` | the directory is not a Node project | run the command in the real project |
| `HTTP 423` | vault locked | unlock it |
| `HTTP 429` | too many passphrase attempts | wait ~1 minute |
| port in use | another process on `8787` | `ENVVAULT_PORT=8790 envvault serve` |
| forgot the passphrase | — | **no recovery**; restore a backup with a known passphrase |

> The CLI asks for the passphrase on every command (it does not persist a
> session). This is intentional: the key is never in a file or an environment
> variable.

---

## 11. Code layout

```
src/envvault/
  api/          FastAPI routes and authentication dependencies
  services/     vault, secrets, credentials, projects, tokens, audit, runner, redact, envfile
  migrations/   Alembic
  web/          static dashboard (HTML/CSS/JS, no build)
  cli.py        command-line interface
  crypto.py     Argon2id + AES-256-GCM
  runtime.py    in-memory state (DEK, sessions, executions)
tests/          tests (pytest)
docs/adr/       architecture decisions
AGENTS.md       conventions and invariants for agents
```

## 12. Development

```bash
uv sync
uv run pytest
uv run ruff check .
uv run ruff format --check .
```

## 13. License

MIT.
