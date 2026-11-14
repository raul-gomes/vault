# Database lineage (SQLite)

Updated on 2026-11-13 (revision `0005`). Quick reference; the source of truth
is `src/envvault/models.py` + `src/envvault/migrations/versions/`.

Database: `~/.envvault/vault.db` (or `$ENVVAULT_HOME/vault.db`), `0600`, WAL,
`foreign_keys=ON`. The daemon applies the migrations on startup (`migrate.upgrade`).

## Tables

| Table | Purpose | Columns (plain text) | Encrypted columns |
| --- | --- | --- | --- |
| `meta` | Vault key/value | `key` (PK), `value` | — (holds the KDF and the **wrapped** DEK) |
| `projects` | Registered projects | `id` (uuid), `slug` (unique), `name`, `path`, `created_at`, `updated_at` | — |
| `environments` | Environments of a project (exist even without secrets) | `id`, `project_id` → `projects` (CASCADE), `name`; unique (`project_id`, `name`) | — |
| `secrets` | Environment variables | `id`, `project_id` → `projects` (CASCADE), `environment`, `key`, `version`, dates; unique (`project_id`, `environment`, `key`) | `nonce` + `ciphertext` (AES-256-GCM; AAD `project:environment:key:version`) |
| `credentials` | Service logins (hosting, DNS, email...) | `id`, `project_id` → `projects` (CASCADE, **null = global**), `name`, `category`, `version`, dates | `nonce` + `ciphertext` (JSON with the remaining fields; AAD `id:version`) |
| `api_tokens` | Agent tokens | `id`, `name`, `token_hash` (SHA-256, unique), `prefix`, `project_id` → `projects` (CASCADE), `environments` (JSON), `can_list`, `can_inject`, `allowed_commands` (JSON), `any_command` (bool, explicit choice; with no list and without it the token is refused), `created_at`, `last_used_at`, `revoked_at` | — (the token value is never stored) |
| `audit_log` | Append-only audit log | `id` (autoinc), `ts`, `actor_type`, `actor_name`, `action`, `project_slug`, `environment`, `key_names` (JSON), `command`, `result`, `detail` (JSON), `prev_hash`, `hash`, `mac` (`hmac` with a DEK-derived key; `sha256` only for a denied unlock before a key exists; `legacy` = before `0005`) | — (never contains values) |

## `meta` keys

| Key | Content |
| --- | --- |
| `kdf` | Argon2id parameters (salt, time, memory, parallelism) |
| `dek_wrapped` / `dek_nonce` | DEK encrypted by the KEK derived from the passphrase |
| `lock_timeout_minutes` | Idle lock configured in the dashboard |
| `max_unlock_hours` | Absolute lock in hours (default 12; absent = `ENVVAULT_MAX_UNLOCK_HOURS`) |
| `created_at` | Vault creation date |
| `audit_head` | Latest HMAC entry (`id`, `hash`) + HMAC tag: detects deletion of the audit log tail |

## Rules

- `version` increases on every secret/credential write and goes into the AAD (an old ciphertext cannot come back).
- Deleting a project deletes its environments, secrets, tokens and credentials; global credentials stay.
- An environment can only be deleted when empty.
- `audit_log` never gets UPDATE/DELETE. Rewriting or truncating the chain requires the DEK (HMAC + `audit_head`).

## Migrations and schema origin

| Revision | File | What it did |
| --- | --- | --- |
| `0001` | `0001_initial.py` | `meta`, `projects`, `secrets`, `api_tokens`, `audit_log` and indexes |
| `0002` | `0002_environments.py` | `environments` (environments become rows; backfilled from `secrets`) |
| `0003` | `0003_credentials.py` | `credentials` and indexes by project, name and category |
| `0004` | `0004_token_any_command.py` | `api_tokens.any_command` (default false: an old token without a list stops working) |
| `0005` | `0005_audit_mac.py` | `audit_log.mac` (old entries become `legacy`) |
