# Comandos úteis

Todo comando para desenvolver, rodar e usar o EnvVault. Usou, criou ou mudou um
comando? Atualize este arquivo no mesmo commit. Detalhes de uso no `README.md`.

## Desenvolvimento (raiz do repo)

| Comando | Quando usar |
| --- | --- |
| `uv sync` | Instalar dependências (inclui o grupo `dev`). |
| `uv run pytest` | Testes. `uv run pytest tests/<arquivo>.py` roda só os relacionados. |
| `uv run pytest --cov=envvault --cov-report=term-missing` | Cobertura por arquivo. |
| `uv run ruff check .` | Lint. `--fix` corrige o que for automático. |
| `uv run ruff format .` | Formatar. `--check` só confere (o que o CI roda). |
| `ENVVAULT_HOME=$(mktemp -d) uv run envvault serve` | Daemon de teste em primeiro plano, com cofre descartável. |
| _(sem `alembic.ini`)_ | Nova migration: crie `src/envvault/migrations/versions/000N_<nome>.py` no padrão da anterior (`down_revision` apontando para ela). O daemon aplica sozinho ao subir (`migrate.upgrade`). Nunca edite uma revisão publicada. |

## Instalar a ferramenta na máquina

| Comando | Quando usar |
| --- | --- |
| `uv tool install --force ~/HD_Repos/vault` | Instalar ou atualizar o `envvault` global depois de mudar o código. |
| `envvault --help` | Ver todos os comandos. |

## Daemon e cofre

| Comando | Quando usar |
| --- | --- |
| `envvault init` | Primeira vez: cria o cofre, pede a passphrase e sobe o daemon. |
| `envvault status` | Estado do daemon e do cofre. |
| `envvault unlock` / `envvault lock` | Desbloquear / bloquear (o lock mata os comandos em execução). |
| `envvault serve` | Daemon em primeiro plano (depurar; log em `~/.envvault/daemon.log`). |
| `envvault stop` | Parar o daemon em segundo plano. |
| `envvault passwd` | Trocar a passphrase mestra. |
| Painel web: http://127.0.0.1:8787 | Gerenciar tudo pelo navegador. |

## Projetos e segredos

| Comando | Quando usar |
| --- | --- |
| `envvault project add` / `list` / `update <slug> --path <pasta>` / `remove` | Registrar e manter projetos. |
| `envvault link` | Criar `.envvault.toml` na pasta do projeto (sem segredos). |
| `envvault import .env -p <slug> -e <ambiente> --delete-file` | Trazer um `.env` existente para o cofre e apagar o arquivo (`--create` cria o projeto). |
| `envvault set <CHAVE> -p <slug> -e <ambiente>` | Criar ou trocar um segredo (valor pedido oculto). |
| `envvault list -p <slug> -e <ambiente>` | Nomes e versões (nunca valores). |
| `envvault remove <CHAVE> -p <slug> -e <ambiente>` | Apagar um segredo. |
| `envvault reveal <CHAVE> -p <slug>` | Ver um valor (pede a passphrase, auditado). Só humano. |
| `envvault export -p <slug> -e <ambiente>` | Gerar `.env` temporário. Só humano. |
| `envvault generate` | Gerar senha forte local. |

## Rodar comandos com os segredos

| Comando | Quando usar |
| --- | --- |
| `envvault run -p <slug> -- <comando>` | Rodar com os segredos injetados e a saída redigida. |
| `envvault run -p <slug> --env PORT=3001 --timeout 120 -- <comando>` | Variável extra não secreta e limite de tempo. |
| `envvault run -p <slug> --cwd <subpasta> -- <comando>` | Rodar numa subpasta, relativa à raiz do projeto. Sem `--cwd`, roda na pasta atual se ela estiver dentro do projeto; senão, na raiz. |

## Tokens de agente

| Comando | Quando usar |
| --- | --- |
| `envvault token create -p <slug>` | Criar token (salvo em `~/.envvault/agent-tokens/<slug>.token`, `0600`). Prefira restringir os comandos. |
| `envvault token list` / `envvault token revoke <nome>` | Listar / revogar. |
| `envvault context -p <slug>` / `envvault keys -p <slug>` | O que o token pode fazer / nomes das chaves. |

## Credenciais de serviços

| Comando | Quando usar |
| --- | --- |
| `envvault credential add` / `list` / `update` / `remove` | Logins de hosting, DNS, e-mail (globais ou por projeto). |
| `envvault credential show <nome>` | Ver os campos (auditado). Só humano. |

## Auditoria

| Comando | Quando usar |
| --- | --- |
| `envvault audit` | Últimos eventos. |
| `envvault verify` | Conferir a integridade da cadeia de hash. |

## Git e CI

| Comando | Quando usar |
| --- | --- |
| `git switch develop && git pull && git switch -c feature/<nome>` | Começar uma mudança. |
| `gh pr create --base develop` | Abrir PR da feature. |
| `gh pr checks <número>` / `gh run view <id> --log-failed` | Ver o CI e por que falhou. |
