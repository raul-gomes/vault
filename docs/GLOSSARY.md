# Glossary

| Term | Meaning |
| --- | --- |
| **Vault** | The `vault.db` database with everything encrypted, plus the daemon that opens it. |
| **Daemon** | Local process (`127.0.0.1:8787`) that holds the DEK in memory, decrypts and runs the commands. |
| **Passphrase** | The human's master password. Derives the KEK; never stored. |
| **KEK** | Key derived from the passphrase (Argon2id). Only used to wrap the DEK. |
| **DEK** | Random key that encrypts secrets and credentials. Stored wrapped in `meta` and, when unlocked, only in the daemon's memory. |
| **AAD** | AES-GCM associated data: binds the ciphertext to its place and version. |
| **Unlock / lock** | Put / remove the DEK in memory. Locking also drops sessions and kills executions. |
| **Project** | A registered local repo (slug + directory). Commands only run inside its directory. |
| **Environment** | A project's set of secrets (`dev`, `prod`...). |
| **Secret** | An encrypted environment variable (`KEY=value`). |
| **Credential** | Service login (hosting, DNS, email), global or for one project. |
| **Agent token** | `ev_...` scoped to a project, environments and commands. Can list names and run commands; never reveals a value. |
| **Session** | Human login in the dashboard or CLI (cookie + CSRF). The only one that can reveal/export. |
| **Redaction** | Replacing secret values with `[REDACTED:KEY]` in command output. |
| **Reveal / export** | Show a value / generate a `.env`. Only through the human session, audited. |
| **Audit log** | Append-only log chained with HMAC (DEK-derived key); the last entry is pinned in `meta`. `envvault verify` checks it (with the vault unlocked). |
