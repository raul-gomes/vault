# Useful commands

Every command to develop, run and use EnvVault. Used, created or changed a
command? Update this file in the same commit. Usage details are in `README.md`.

## Development (repo root)

| Command | When to use |
| --- | --- |
| `uv sync` | Install dependencies (includes the `dev` group). |
| `uv run pytest` | Tests. `uv run pytest tests/<file>.py` runs only the related ones. |
| `uv run pytest --cov=envvault --cov-report=term-missing` | Coverage per file. |
| `uv run ruff check .` | Lint. `--fix` fixes what is automatic. |
| `uv run ruff format .` | Format. `--check` only checks (what CI runs). |
| `ENVVAULT_HOME=$(mktemp -d) uv run envvault serve` | Test daemon in the foreground, with a throwaway vault. |
| _(no `alembic.ini`)_ | New migration: create `src/envvault/migrations/versions/000N_<name>.py` following the previous one (`down_revision` pointing to it). The daemon applies it on startup (`migrate.upgrade`). Never edit a published revision. |

## Install the tool on the machine

| Command | When to use |
| --- | --- |
| `uv tool install --force ~/HD_Repos/vault` | Install or update the global `envvault` after changing the code. |
| `envvault --help` | List all commands. |

## Daemon and vault

| Command | When to use |
| --- | --- |
| `envvault init` | First time: creates the vault, asks for the passphrase and starts the daemon. |
| `envvault status` | Daemon and vault state. |
| `envvault unlock` / `envvault lock` | Unlock / lock (lock kills running commands). |
| `envvault serve` | Daemon in the foreground (debugging; log in `~/.envvault/daemon.log`). |
| `envvault stop` | Stop the background daemon. |
| `envvault passwd` | Change the master passphrase. |
| Web dashboard: http://127.0.0.1:8787 | Manage everything from the browser. |

## Projects and secrets

| Command | When to use |
| --- | --- |
| `envvault project add` / `list` / `update <slug> --path <directory>` / `remove` | Register and maintain projects. |
| `envvault link` | Create `.envvault.toml` in the project directory (no secrets). |
| `envvault import .env -p <slug> -e <environment> --delete-file` | Bring an existing `.env` into the vault and delete the file (`--create` creates the project). |
| `envvault set <KEY> -p <slug> -e <environment>` | Create or change a secret (value is prompted, hidden). |
| `envvault list -p <slug> -e <environment>` | Names and versions (never values). |
| `envvault remove <KEY> -p <slug> -e <environment>` | Delete a secret. |
| `envvault reveal <KEY> -p <slug>` | View a value (asks for the passphrase, audited). Human only. |
| `envvault export -p <slug> -e <environment>` | Generate a temporary `.env`. Human only. |
| `envvault generate` | Generate a strong local password. |

## Run commands with secrets

| Command | When to use |
| --- | --- |
| `envvault run -p <slug> -- <command>` | Run with secrets injected and output redacted. |
| `envvault run -p <slug> --env PORT=3001 --timeout 120 -- <command>` | Extra non-secret variable and a time limit. |
| `envvault run -p <slug> --cwd <subdirectory> -- <command>` | Run in a subdirectory, relative to the project root. Without `--cwd`, runs in the current directory if it is inside the project; otherwise, in the root. |

## Agent tokens

| Command | When to use |
| --- | --- |
| `envvault token create -n <name> -p <slug> --allow "npm run" --allow pytest` | Create a token (saved in `~/.envvault/agent-tokens/<slug>.token`, `0600`). At least one `--allow`, matched word by word. |
| `envvault token create -n <name> -p <slug> --any-command` | Token that accepts any command (explicit choice, not recommended). |
| `envvault token list` / `envvault token revoke <name>` | List / revoke. |
| `envvault context -p <slug>` / `envvault keys -p <slug>` | What the token can do / key names. |

## Service credentials

| Command | When to use |
| --- | --- |
| `envvault credential add` / `list` / `update` / `remove` | Logins for hosting, DNS, email (global or per project). |
| `envvault credential show <name>` | View the fields (audited). Human only. |

## Backup

| Command | When to use |
| --- | --- |
| `envvault backup <directory-or-file>` | Copy of the still-encrypted database (`0600`, never overwrites). Restore steps in the README. |

## Audit log

| Command | When to use |
| --- | --- |
| `envvault audit` | Latest events. |
| `envvault verify` | Check the integrity of the hash chain. |

## Git and CI

| Command | When to use |
| --- | --- |
| `git switch develop && git pull && git switch -c feature/<name>` | Start a change. |
| `gh pr create --base develop` | Open the feature PR. |
| `gh pr checks <number>` / `gh run view <id> --log-failed` | See CI and why it failed. |
