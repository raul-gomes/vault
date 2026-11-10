# EnvVault

Cofre local e criptografado para os `.env` dos seus projetos. A ideia central:
um agente (Claude, scripts, CI local) **usa** os segredos sem **vê-los**. Quem
descriptografa e injeta é o daemon do cofre; a saída volta redigida.

> **Não há recuperação de passphrase.** Se você perdê-la, os segredos são
> irrecuperáveis. Guarde-a num gerenciador de senhas e faça backup de
> `~/.envvault` (o backup sem a passphrase não serve para nada).

---

## 1. O que é e o que não é

**É:**
- Um cofre único, local, em SQLite, que gerencia os segredos de vários projetos.
- Um broker de execução: recebe um comando, injeta as variáveis e devolve a
  saída **redigida**.
- Um painel web local (loopback) para você gerenciar tudo.
- Um log de auditoria append-only, encadeado por hash.

**Não é:**
- Um `.env` dentro de cada projeto. Os projetos não guardam segredos.
- Um gerenciador de segredos na nuvem.
- Uma sandbox contra comando malicioso (veja [limitações](#8-segurança)).

---

## 2. Como funciona

### 2.1 Visão geral

```
┌──────────────────────┐        ┌────────────────────────────────────┐
│  você (navegador)    │        │  daemon do EnvVault                │
│  ou CLI              │──────▶ │  127.0.0.1:8787                    │
└──────────────────────┘        │                                    │
                                │  ~/.envvault/vault.db (cripto)     │
┌──────────────────────┐        │  chave de dados (DEK) só na memória│
│  agente (token ev_…) │──────▶ │                                    │
└──────────────────────┘        └───────────────┬────────────────────┘
                                                │ descriptografa
                                                ▼
                                   ┌──────────────────────────┐
                                   │ processo filho           │
                                   │ env com os segredos      │
                                   └────────────┬─────────────┘
                                                │ stdout/stderr
                                                ▼
                                   redator → SSE redigido → cliente
```

O ponto crítico: **o daemon inicia o processo**. O valor em claro nunca é
serializado em uma resposta HTTP. Ele existe só na memória do daemon e no
ambiente do processo filho.

### 2.2 O cofre é global; os projetos são registros

```
~/.envvault/                 ← um cofre para tudo
  vault.db                   ← banco criptografado
  daemon.log
  daemon.pid

~/projetos/app-a/            ← projeto registrado
  .envvault.toml             ← ponteiro, sem segredo
  src/...

~/projetos/app-b/            ← outro projeto, mesmo cofre
  .envvault.toml
```

- `envvault init` cria o cofre **uma vez**.
- `envvault project add app-a --path ~/projetos/app-a` apenas grava slug +
  caminho no banco. Nada é copiado para o projeto.
- `.envvault.toml` é opcional e versionável: diz apenas qual projeto/ambiente
  usar quando você está naquele diretório.
- O isolamento é lógico: cada segredo pertence a `projeto + ambiente + chave`,
  e cada token de agente é preso a um projeto e a ambientes específicos.

### 2.3 Criptografia

- A passphrase mestra deriva uma **KEK** com **Argon2id** (salt aleatório,
  custo configurável).
- A KEK embrulha (AES-256-GCM) uma **DEK** aleatória, que é a chave que
  realmente cifra os segredos.
- Cada segredo é cifrado com AES-256-GCM e **AAD** ligado a
  `project_id/environment/key/version`. Isso impede trocar ciphertext entre
  projetos/ambientes/chaves ou voltar para uma versão antiga.
- A DEK fica **só na memória**. Trocar a passphrase re-embrulha a DEK; os
  segredos não são re-criptografados.
- Arquivos do cofre: `0600`; diretório: `0700`.

### 2.4 Dois planos de acesso

| | Sessão humana (você) | Token de agente |
|---|---|---|
| Como autentica | passphrase → cookie + CSRF | `Authorization: Bearer ev_…` |
| Lista nomes de chaves | sim | sim, se `can_list` |
| Executa com injeção | sim | sim, se `can_inject` |
| Revela valor | **sim**, revalidando a passphrase | **nunca** |
| Exporta `.env` | **sim**, revalidando a passphrase | **nunca** |
| Gerencia tokens/projetos | sim | não |

### 2.5 Redação da saída

O daemon substitui ocorrências dos valores por `[REDACTED:CHAVE]`, incluindo:

- valor cru;
- URL-encoded e `quote_plus`;
- base64 padrão e URL-safe.

Valores com menos de 6 caracteres não são redigidos (para não transformar
`8080` ou `true` em ruído).

### 2.6 Bloqueio e auditoria

- Após `N` minutos sem atividade, a DEK sai da memória, as sessões caem e os
  processos em execução são encerrados.
- Toda ação relevante grava um evento. Cada evento contém o hash do anterior;
  `envvault verify` recomputa a cadeia e detecta adulteração.

---

## 3. Como colocar para funcionar

### 3.1 Requisitos

- Python **3.12+**
- [`uv`](https://docs.astral.sh/uv/)
- Linux ou macOS (o runner usa grupos de processo POSIX)

### 3.2 Instalação

```bash
cd /caminho/para/envvault
uv sync
```

Isso cria o `.venv` e instala as dependências. Os comandos abaixo usam
`uv run envvault` de dentro do repositório.

Para usar de qualquer diretório, instale o binário uma vez:

```bash
uv tool install /caminho/para/envvault
# agora: envvault <comando>
```

### 3.3 Passo 1 — criar o cofre

```bash
uv run envvault init
```

- Pede a passphrase mestra (mínimo 10 caracteres) com confirmação.
- Cria `~/.envvault/vault.db`.
- Sobe o daemon em segundo plano em `http://127.0.0.1:8787`.

Confira:

```bash
uv run envvault status
```

### 3.4 Passo 2 — registrar um projeto

```bash
cd ~/projetos/meu-app
uv run --project /caminho/para/envvault envvault project add meu-app --path .
```

O caminho precisa existir. O comando pede a passphrase (a CLI não mantém sessão
entre execuções).

### 3.5 Passo 3 — vincular o diretório (opcional, recomendado)

```bash
cd ~/projetos/meu-app
uv run --project /caminho/para/envvault envvault link --project meu-app -e dev
```

Cria `.envvault.toml`:

```toml
project = "meu-app"
environment = "dev"
```

A partir daí, dentro desse diretório, você pode omitir `--project` e
`--environment`.

### 3.6 Passo 4 — trazer os segredos

Importe o `.env` existente:

```bash
uv run --project /caminho/para/envvault envvault import .env --delete-file
```

- `--delete-file` apaga o `.env` depois de importar (o cofre vira a fonte da
  verdade). Pede confirmação.
- `--replace` sobrescreve chaves que já existem.
- O parser aceita comentários, `export`, aspas simples/duplas e **nunca executa**
  o conteúdo.

Ou crie manualmente:

```bash
uv run --project /caminho/para/envvault envvault set API_TOKEN
# pede o valor oculto
```

### 3.7 Passo 5 — executar com injeção

```bash
uv run --project /caminho/para/envvault envvault run -- npm run dev
```

O comando **não** passa por shell: cada argumento é preservado. O processo roda
dentro do diretório do projeto.

Exemplos:

```bash
envvault run -- python manage.py migrate
envvault run --cwd sub/dir -- npm test

# configuração de variáveis montada pelo cofre (sem sobrescrever segredos)
envvault run --env PORT=3001 --env NODE_ENV=development -- npm run dev

# encerra o grupo de processos depois de 120s (útil para servidores de dev)
envvault run --env PORT=3001 --timeout 120 -- npm run dev
```

O cofre monta o ambiente do processo assim:

1. ambiente atual do daemon (sem nenhuma variável `ENVVAULT_*`);
2. segredos do projeto/ambiente, descriptografados em memória;
3. variáveis extras enviadas na requisição (`env`).

Chaves `ENVVAULT_*` são reservadas e uma variável extra **não pode** sobrescrever
uma chave que existe no cofre — a requisição é rejeitada com `400`. A auditoria
registra apenas os **nomes** das variáveis extras, nunca os valores.

Se o vault estiver bloqueado, a CLI pede a passphrase.

### 3.8 Passo 6 — abrir o dashboard

<http://127.0.0.1:8787>

Lá você encontra visão geral, projetos, abas de ambiente, segredos, gerador de
senha, console de execução, import/export, tokens, auditoria e configurações.
O daemon escuta **somente** em loopback.

### 3.9 Passo 7 — dar acesso ao Claude

Crie um token restrito:

```bash
uv run envvault token create \
  --name claude-meu-app \
  --project meu-app \
  --environment dev \
  --allow "npm run" \
  --allow "pytest"
```

Por padrão o valor **não é impresso**: ele é gravado em
`~/.envvault/agent-tokens/meu-app.token` com permissões `0600` (diretório
`0700`). Um arquivo por projeto — assim você roda comandos de **qualquer
pasta**, sem exportar token e sem `cd`:

```bash
cd ~/HD_Repos
envvault run -p meu-app -- npm run dev
envvault keys -p meu-app -e dev      # nomes de chaves (nunca valores)
envvault context -p meu-app          # escopo do token
```

O daemon executa o processo **dentro da pasta registrada do projeto**, mesmo
que o seu shell esteja em outro diretório. Use `--cwd sub/dir` para descer a
partir dela.

Se quiser o valor bruto (outra máquina, outro agente), use `--no-save`; a CLI
imprime o token uma única vez. `ENVVAULT_TOKEN` continua funcionando como
override explícito e tem prioridade sobre o arquivo do projeto.

Sem `--allow`, o token aceita qualquer argv. Restrinja sempre que possível.
`envvault token list` mostra na coluna `local` qual token está salvo no disco, e
`envvault token revoke` remove o arquivo quando ele corresponde ao token
revogado.

#### Requisição direta (Claude, scripts, integrações)

O agente pode montar a execução enviando o comando **e** variáveis extras:

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

A resposta é um stream SSE (`start`, `output`, `exit`). O daemon:

- descriptografa os segredos e monta o ambiente;
- valida as variáveis extras (nome, tamanho, prefixo `ENVVAULT_` e colisão com
  chaves do cofre);
- roda o argv sem shell, com grupo de processos próprio;
- redige qualquer segredo antes de enviar a saída;
- encerra o grupo ao fim do `timeout_seconds`.

O exemplo usa `ENVVAULT_TOKEN`. Com o token salvo em arquivo, prefira a CLI
(`envvault run -p <projeto> -- ...`), que resolve o token sozinha; para chamar
o HTTP direto, crie o token com `--no-save` e exporte o valor só naquele
comando.

Em `GET /v1/agent/context` o próprio token descreve o escopo, os limites e um
exemplo de requisição — é o que a skill do segundo cérebro consulta.

---

## 4. Uso diário (cheatsheet)

```bash
# ciclo de vida
envvault init                     # cria o cofre e sobe o daemon
envvault status                   # daemon + estado do cofre
envvault unlock                   # desbloqueia em memória
envvault lock                     # descarta a chave e mata execuções
envvault serve                    # roda o daemon em primeiro plano
envvault stop                     # para o daemon
envvault passwd                   # troca a passphrase

# projetos
envvault project add <slug> --path .
envvault project list
envvault project remove <slug>
envvault link --project <slug> -e dev

# segredos
envvault set KEY                  # valor oculto
envvault set KEY --generate       # gera e grava uma senha
envvault list                     # nomes e versões (nunca valores)
envvault remove KEY
envvault reveal KEY --copy        # revalida passphrase, audita
envvault import .env [--replace] [--delete-file]
envvault export --out .env.local  # gera arquivo temporário

# execução
envvault run -- <argv...>
envvault run -p app -- npm run dev          # de qualquer pasta
envvault run -p app --env PORT=3001 --timeout 120 -- npm run dev

# tokens
envvault token create -n claude -p app -e dev --allow "npm run"   # salva 0600
envvault token create -n claude -p app --no-save                   # imprime uma vez
envvault token list
envvault token revoke claude
envvault context -p app            # escopo do token do projeto
envvault keys -p app -e dev        # nomes de chaves (agente)

# credenciais de serviços (globais ou por projeto)
envvault credential add hostinger -c hosting -p meu-app
envvault credential add cloudflare -c dns          # global
envvault credential list [--project meu-app | --global]
envvault credential show hostinger                # reveal auditado
envvault credential update hostinger --username novo@exemplo.com
envvault credential remove hostinger

# auditoria e utilidades
envvault audit --limit 50
envvault verify
envvault generate -l 48 --count 5
```

---

## 5. `.envvault.toml`

Arquivo versionável, **sem segredos**:

```toml
project = "meu-app"
environment = "dev"
```

A CLI procura no diretório atual e nos pais. Serve só para não repetir
`--project`/`--environment`.

---

## 6. Gerador de senhas

```bash
envvault generate                      # 32 caracteres
envvault generate -l 48 --count 5
envvault generate --no-symbols --json
envvault set DB_PASSWORD --generate
```

Usa o CSPRNG do sistema, remove caracteres ambíguos (`I`, `l`, `1`, `O`, `0`) e
garante ao menos um caractere de cada conjunto selecionado. A UI expõe o mesmo
gerador no formulário de segredo.

---

## 7. Credenciais de serviços

Além das variáveis de `.env`, o cofre guarda **logins de serviços externos**
(Hostinger, Cloudflare, Gmail, SMTP, painéis de API…). Cada credencial pode ser:

- **global** — compartilhada por todos os projetos (ex.: sua conta pessoal de
  Cloudflare);
- **de projeto** — específica de um cliente/contexto (ex.: o painel da Hostinger
  do cliente A).

Nome, categoria e escopo ficam visíveis para busca. Usuário, senha, URL e notas
são criptografados juntos em um único payload AES-256-GCM, com AAD amarrando o
id e a versão da credencial. A versão é incrementada a cada edição.

```bash
# global
envvault credential add cloudflare -c dns --username eu@exemplo.com
# de um projeto
envvault credential add hostinger -c hosting -p cliente-a --url https://hpanel.hostinger.com
# listar por escopo
envvault credential list
envvault credential list --project cliente-a
envvault credential list --global
# ver (revalida a passphrase e audita)
envvault credential show hostinger
envvault credential show hostinger --copy
# mover entre escopos ou trocar a senha
envvault credential update hostinger -p cliente-b
envvault credential update hostinger --global --generate
```

No dashboard, a área **Credenciais** permite criar, buscar, filtrar por projeto,
revelar com passphrase e excluir. A página de cada projeto também mostra a seção
**Credenciais do projeto**, com as credenciais daquele projeto e as globais
disponíveis, revelação direta e criação já no escopo do projeto.

Regras de segurança:

- tokens de agente **não têm acesso** a credenciais;
- listagens nunca devolvem usuário, senha, URL ou notas;
- o reveal exige a passphrase mestra e é registrado em `credential.reveal`;
- excluir um projeto remove apenas as credenciais daquele projeto; as globais
  continuam.

---

## 8. Variáveis de ambiente

| Variável | Padrão | Efeito |
|---|---|---|
| `ENVVAULT_HOME` | `~/.envvault` | banco, log e PID |
| `ENVVAULT_HOST` | `127.0.0.1` | bind do daemon |
| `ENVVAULT_PORT` | `8787` | porta |
| `ENVVAULT_LOCK_TIMEOUT_MINUTES` | `30` | bloqueio por inatividade |
| `ENVVAULT_SESSION_IDLE_MINUTES` | `30` | validade da sessão |
| `ENVVAULT_MAX_EXECS` | `8` | execuções simultâneas |
| `ENVVAULT_KDF_TIME_COST` | `3` | custo do Argon2id |
| `ENVVAULT_KDF_MEMORY_KIB` | `65536` | memória do Argon2id (KiB) |
| `ENVVAULT_KDF_PARALLELISM` | `4` | paralelismo do Argon2id |

---

## 9. Segurança

**Protege contra:**
- leitura do banco sem a passphrase;
- vazamento acidental em logs/build/conversa (redação);
- exposição de credenciais de serviços em listagens (só o reveal auditado as mostra);
- adulteração silenciosa do log (cadeia de hash);
- CSRF, DNS rebinding e uso do dashboard por outra origem;
- sessão esquecida (bloqueio por inatividade).

**Não protege contra:**
- processo local do mesmo usuário lendo a memória do daemon;
- comando **deliberadamente malicioso** autorizado pelo token — ele recebe as
  variáveis e pode codificá-las/exfiltrá-las de formas que a redação textual não
  acompanha;
- kernel/Python/dependências comprometidos;
- backup do cofre junto com a passphrase.

**Limitações conhecidas:**
- valores com menos de 6 caracteres não são redigidos;
- transformações arbitrárias (hash, cifra, split) não são detectadas;
- token sem `allowed_commands` aceita qualquer argv, inclusive
  `python3 -c "import os; …"`;
- SQLite não é um cofre de hardware — a proteção em repouso depende da
  passphrase.

---

## 10. Solução de problemas

| Mensagem / sintoma | Causa | Correção |
|---|---|---|
| `daemon não está rodando` | daemon parado | `envvault serve` (primeiro plano) ou `envvault init` |
| `não autenticado` | sessão expirada | rode o comando de novo e informe a passphrase |
| `vault bloqueado; …` | inatividade | `envvault unlock` |
| `informe --project` | fora de um diretório com `.envvault.toml` | `envvault link …` ou passe `--project` |
| `projeto não encontrado: X` | projeto não registrado | `envvault project add X --path .` |
| `arquivo não encontrado: .env` | não há `.env` no diretório | rode no diretório certo ou crie o `.env` |
| `já existe um cofre em …` | `init` rodado duas vezes | use o cofre existente; não rode `init` |
| `npm error … package.json` | o diretório não é um projeto Node | execute o comando do projeto real |
| `HTTP 423` | cofre bloqueado | desbloqueie |
| `HTTP 429` | muitas tentativas de passphrase | espere ~1 minuto |
| porta ocupada | outro processo em `8787` | `ENVVAULT_PORT=8790 envvault serve` |
| esqueci a passphrase | — | **não há recuperação**; restaure um backup com a passphrase conhecida |

> A CLI pede a passphrase a cada comando (não persiste sessão). Isso é
> intencional: a chave não fica em arquivo nem em variável de ambiente.

---

## 11. Estrutura do código

```
src/envvault/
  api/          rotas FastAPI e dependências de autenticação
  services/     vault, secrets, credentials, projects, tokens, audit, runner, redact, envfile
  migrations/   Alembic
  web/          dashboard estático (HTML/CSS/JS, sem build)
  cli.py        interface de linha de comando
  crypto.py     Argon2id + AES-256-GCM
  runtime.py    estado em memória (DEK, sessões, execuções)
tests/          testes (pytest)
docs/adr/       decisões de arquitetura
AGENTS.md       convenções e invariantes para agentes
```

## 12. Desenvolvimento

```bash
uv sync
uv run pytest
uv run ruff check .
uv run ruff format --check .
```

## 13. Licença

MIT.
