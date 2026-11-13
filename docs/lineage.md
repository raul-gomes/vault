# Lineage do banco (SQLite)

Atualizado em 2026-11-13 (revisão `0003`). Referência rápida; a fonte da verdade
é `src/envvault/models.py` + `src/envvault/migrations/versions/`.

Banco: `~/.envvault/vault.db` (ou `$ENVVAULT_HOME/vault.db`), `0600`, WAL,
`foreign_keys=ON`. O daemon aplica as migrations ao subir (`migrate.upgrade`).

## Tabelas

| Tabela | Para quê | Colunas (texto puro) | Colunas cifradas |
| --- | --- | --- | --- |
| `meta` | Chave/valor do cofre | `key` (PK), `value` | — (guarda o KDF e a DEK **embrulhada**) |
| `projects` | Projetos registrados | `id` (uuid), `slug` (único), `name`, `path`, `created_at`, `updated_at` | — |
| `environments` | Ambientes de um projeto (existem mesmo sem segredo) | `id`, `project_id` → `projects` (CASCADE), `name`; único (`project_id`, `name`) | — |
| `secrets` | Variáveis de ambiente | `id`, `project_id` → `projects` (CASCADE), `environment`, `key`, `version`, datas; único (`project_id`, `environment`, `key`) | `nonce` + `ciphertext` (AES-256-GCM; AAD `projeto:ambiente:chave:versão`) |
| `credentials` | Logins de serviços (hosting, DNS, e-mail…) | `id`, `project_id` → `projects` (CASCADE, **nulo = global**), `name`, `category`, `version`, datas | `nonce` + `ciphertext` (JSON com os demais campos; AAD `id:versão`) |
| `api_tokens` | Tokens de agente | `id`, `name`, `token_hash` (SHA-256, único), `prefix`, `project_id` → `projects` (CASCADE), `environments` (JSON), `can_list`, `can_inject`, `allowed_commands` (JSON), `created_at`, `last_used_at`, `revoked_at` | — (o valor do token nunca é guardado) |
| `audit_log` | Auditoria append-only | `id` (autoinc), `ts`, `actor_type`, `actor_name`, `action`, `project_slug`, `environment`, `key_names` (JSON), `command`, `result`, `detail` (JSON), `prev_hash`, `hash` | — (nunca contém valores) |

## Chaves de `meta`

| Chave | Conteúdo |
| --- | --- |
| `kdf` | Parâmetros do Argon2id (salt, tempo, memória, paralelismo) |
| `dek_wrapped` / `dek_nonce` | DEK cifrada pela KEK derivada da passphrase |
| `lock_timeout_minutes` | Bloqueio por inatividade configurado no painel |
| `created_at` | Data de criação do cofre |

## Regras

- `version` sobe a cada escrita de segredo/credencial e entra no AAD (ciphertext antigo não pode voltar).
- Apagar um projeto apaga ambientes, segredos, tokens e credenciais dele; credenciais globais ficam.
- Ambiente só pode ser apagado vazio.
- `audit_log` nunca recebe UPDATE/DELETE.

## Migrations e origem do schema

| Revisão | Arquivo | O que fez |
| --- | --- | --- |
| `0001` | `0001_initial.py` | `meta`, `projects`, `secrets`, `api_tokens`, `audit_log` e índices |
| `0002` | `0002_environments.py` | `environments` (ambientes viram linhas; preenche a partir de `secrets`) |
| `0003` | `0003_credentials.py` | `credentials` e índices por projeto, nome e categoria |
