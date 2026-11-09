# EnvVault

Cofre local e criptografado para os `.env` dos seus projetos. O objetivo: um
agente (Claude, scripts, CI local) usa os segredos **sem vê-los**. O daemon
injeta as variáveis em um processo filho e **redige os valores da saída** antes
de devolver qualquer coisa ao agente. Você continua dono de tudo: criação,
leitura, export, tokens e auditoria.

- Banco SQLite local em `~/.envvault/vault.db`
- AES-256-GCM para cada segredo; chave de dados (DEK) aleatória embrulhada por
  uma chave derivada da passphrase com **Argon2id**
- Chave de dados só em memória; o cofre bloqueia por inatividade
- Dois planos de acesso: sessão humana (pode revelar/exportar) e token de
  agente (só lista nomes de chaves e executa)
- Log de auditoria append-only, encadeado por hash
- Gerador de senhas embutido (CLI + UI)
- Interface web local sem dependências de front-end

> **Não há recuperação de passphrase.** Se você perdê-la, os segredos são
> irrecuperáveis. Faça backup do diretório `~/.envvault` (o backup continua
> inútil sem a passphrase) e guarde a passphrase em um gerenciador de senhas.

---

## Requisitos

- Python 3.12+
- [`uv`](https://docs.astral.sh/uv/)
- Linux/macOS (o runner usa grupos de processo POSIX)

## Instalação

```bash
git clone <este-repo> envvault
cd envvault
uv sync
```

O executável fica disponível como `uv run envvault` dentro do projeto, ou
`~/.local/bin/envvault` após `uv tool install .`. O restante deste documento usa
`envvault` como atalho.

## Início rápido

```bash
# 1. Cria o cofre (pede a passphrase mestra) e sobe o daemon
envvault init

# 2. Registra um projeto local
cd ~/projetos/meu-app
envvault project add meu-app --name "Meu App" --path .

# 3. Vincula o diretório ao projeto (cria .envvault.toml, sem segredos)
envvault link --project meu-app --environment dev

# 4. Importa o .env existente e (opcionalmente) apaga o arquivo
envvault import .env --delete-file

# 5. A partir daqui o cofre é a fonte da verdade
envvault list
envvault run -- npm run dev
```

O dashboard fica em <http://127.0.0.1:8787>. Ele escuta apenas em loopback.

## Comandos

### Ciclo de vida

| Comando | O que faz |
| --- | --- |
| `envvault init` | Cria o cofre, grava KDF/DEK e sobe o daemon |
| `envvault serve` | Roda o daemon em primeiro plano |
| `envvault stop` | Para o daemon em segundo plano |
| `envvault status` | Mostra daemon, estado do cofre e timeout |
| `envvault unlock` | Desbloqueia em memória por uma sessão curta |
| `envvault lock` | Descarta a chave, encerra sessões e mata execuções |
| `envvault passwd` | Troca a passphrase (re-embrulha a DEK) |

### Projetos e segredos

| Comando | O que faz |
| --- | --- |
| `envvault project add <slug> --path .` | Registra um diretório |
| `envvault project list` | Lista projetos e contagens |
| `envvault project remove <slug>` | Remove projeto, segredos e tokens |
| `envvault link --project <slug> -e dev` | Cria `.envvault.toml` |
| `envvault set KEY [--generate]` | Cria/substitui um segredo |
| `envvault list` | Lista nomes e versões (nunca valores) |
| `envvault remove KEY` | Remove um segredo |
| `envvault reveal KEY [--copy]` | Mostra o valor (revalida passphrase, audita) |
| `envvault import .env [--replace] [--delete-file]` | Importa um dotenv |
| `envvault export [--out FILE]` | Gera um `.env` temporário (auditado) |

### Execução

| Comando | O que faz |
| --- | --- |
| `envvault run -- <argv...>` | Executa com os segredos injetados |

`run` usa a sessão humana quando `ENVVAULT_TOKEN` não está definido; com o
token definido, usa o plano de agente. O comando **não** passa por um shell:
cada argumento é preservado.

```bash
envvault run -- python manage.py migrate
envvault run --cwd sub/dir -- npm test
```

### Tokens de agente

| Comando | O que faz |
| --- | --- |
| `envvault token create --name claude --project app -e dev` | Cria um token (mostrado uma vez) |
| `envvault token list` | Lista tokens e escopos |
| `envvault token revoke <nome>` | Revoga imediatamente |
| `envvault context` | Mostra o escopo do `ENVVAULT_TOKEN` atual |

Restrinja sempre que possível:

```bash
envvault token create \
  --name claude-app \
  --project meu-app \
  --environment dev \
  --allow "npm run" \
  --allow "pytest"
```

Sem `--allow`, o token aceita qualquer argv. Isso é conveniente, mas um comando
arbitrário pode imprimir o ambiente inteiro — a redação é a última linha de
defesa, não uma sandbox.

### Gerador de senhas

```bash
envvault generate                      # 32 caracteres
envvault generate -l 48 --count 5      # cinco senhas
envvault generate --no-symbols --json  # saída para scripts
envvault set API_KEY --generate        # gera e grava direto
```

Usa o CSPRNG do sistema, remove caracteres ambíguos (`I`, `l`, `1`, `O`, `0`) e
garante ao menos um caractere de cada conjunto selecionado.

### Auditoria

```bash
envvault audit --limit 50
envvault verify          # recomputa a cadeia de hashes
```

## `.envvault.toml`

Arquivo versionável (sem segredos) que define o alvo padrão:

```toml
project = "meu-app"
environment = "dev"
```

A CLI procura esse arquivo no diretório atual e nos pais. Assim `envvault run`,
`list`, `set`, etc. funcionam sem `--project`/`--environment`.

## Usando com o Claude

1. Crie um token restrito ao projeto e ambiente.
2. Exporte no ambiente do agente:

   ```bash
   export ENVVAULT_TOKEN=ev_...
   ```

3. Peça ao agente para usar a CLI:

   ```bash
   envvault context                    # escopo visível ao agente
   envvault run -- pytest -q
   ```

O agente **não** tem endpoint para revelar valores. A API dele só expõe:

- `GET /v1/agent/context` — escopo do token
- `GET /v1/agent/keys?environment=dev` — nomes de chaves (sem valores)
- `POST /v1/agent/exec` — executa argv com injeção; retorna SSE redigido

Fluxo de segurança:

```
agente -> POST /v1/agent/exec -> daemon (descriptografa)
                                     |
                                     v
                              processo filho (recebe env)
                                     |
                          stdout/stderr -> redator -> SSE -> agente
```

O valor em claro nunca é serializado em uma resposta HTTP. Ele existe apenas na
memória do daemon e no ambiente do processo filho.

### Exemplo de prompt para o agente

> Use `envvault run -- <comando>` para rodar qualquer coisa que precise de
> variáveis de ambiente. Nunca tente imprimir segredos; a saída é redigida e o
> token não tem permissão de reveal.

## Variáveis de ambiente

| Variável | Padrão | Efeito |
| --- | --- | --- |
| `ENVVAULT_HOME` | `~/.envvault` | Diretório do banco, log e PID |
| `ENVVAULT_HOST` | `127.0.0.1` | Endereço de bind do daemon |
| `ENVVAULT_PORT` | `8787` | Porta do daemon |
| `ENVVAULT_LOCK_TIMEOUT_MINUTES` | `30` | Bloqueio por inatividade |
| `ENVVAULT_SESSION_IDLE_MINUTES` | `30` | Validade da sessão web/CLI |
| `ENVVAULT_MAX_EXECS` | `8` | Execuções simultâneas |
| `ENVVAULT_KDF_TIME_COST` | `3` | Custo do Argon2id |
| `ENVVAULT_KDF_MEMORY_KIB` | `65536` | Memória do Argon2id (KiB) |
| `ENVVAULT_KDF_PARALLELISM` | `4` | Paralelismo do Argon2id |

## Modelo de ameaça

Protege contra:

- Leitura casual do banco (`vault.db`) sem a passphrase
- Vazamento acidental de valores em logs, saída de build e conversas com o
  agente (redação de valor cru, URL-encoded, `quote_plus` e base64)
- Alteração silenciosa do log (cadeia de hash)
- CSRF, DNS rebinding e uso do dashboard por outra origem (`Host`/`Origin`
  guard, cookie `SameSite=Strict`, CSRF header)
- Sessões esquecidas (bloqueio por inatividade; a DEK sai da memória)

**Não** protege contra:

- Processo local com o mesmo usuário do sistema lendo a memória do daemon
  (`ptrace`, `/proc/<pid>/mem`)
- Um comando **deliberadamente malicioso** autorizado pelo token: ele recebe os
  segredos no ambiente e pode encodá-los/exfiltrá-los de formas que um replacedor
  de strings não acompanha
- Comprometimento do kernel, do Python ou das dependências
- Backup do cofre junto com a passphrase no mesmo lugar

Mitigações recomendadas: token por projeto/ambiente, prefixos de comando
permitidos, rotação de segredos, revisão da auditoria e `envvault lock` quando
não estiver usando.

### Limitações conhecidas

- Valores com menos de 6 caracteres não são redigidos (evita ruído em portas,
  flags etc.).
- A redação é textual: transformações arbitrárias (hash, cifra, split) não são
  detectadas.
- Tokens com `allowed_commands` vazio aceitam qualquer argv, inclusive
  `python3 -c "import os; ..."`, que lê todo o ambiente.
- O daemon escuta em loopback; qualquer processo local do mesmo usuário pode
  falar com ele (mas precisa de sessão ou token).
- SQLite não é um cofre de hardware; a proteção em repouso depende da
  passphrase.

## API HTTP (resumo)

Sessão humana (cookie + `x-csrf-token`):

- `GET/POST/PATCH/DELETE /v1/projects...`
- `GET/PUT/DELETE /v1/projects/{id}/secrets...`
- `POST /v1/projects/{id}/secrets/{key}/reveal`
- `POST /v1/projects/{id}/import`
- `POST /v1/projects/{id}/export`
- `POST /v1/exec`
- `GET/POST/DELETE /v1/tokens...`
- `GET /v1/audit`, `GET /v1/audit/verify`
- `GET/PUT /v1/settings`
- `POST /v1/generate`

Agente (header `Authorization: Bearer ev_...`):

- `GET /v1/agent/context`
- `GET /v1/agent/keys`
- `POST /v1/agent/exec`

Documentação interativa: <http://127.0.0.1:8787/api/docs>.

## Desenvolvimento

```bash
uv sync
uv run pytest
uv run ruff check .
uv run ruff format --check .
```

Estrutura:

```
src/envvault/
  api/          rotas FastAPI e dependências de autenticação
  services/     vault, secrets, projects, tokens, audit, runner, redact, envfile
  migrations/   Alembic
  web/          dashboard estático (HTML/CSS/JS, sem build)
  cli.py        interface de linha de comando
  crypto.py     Argon2id + AES-256-GCM
  runtime.py    estado em memória (DEK, sessões, execuções)
```

## Licença

MIT.
