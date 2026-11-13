# Árvore de arquivos

Atualizado em 2026-11-13. Responsabilidade de cada arquivo versionado.

```
.github/workflows/ci.yml     CI: ruff (lint + formato) e pytest com cobertura
AGENTS.md                    Invariantes de segurança e regras para agentes
README.md                    Setup, uso diário, segurança, solução de problemas
pyproject.toml / uv.lock     Projeto Python (hatch), dependências travadas
docs/
  adr/0001-static-ui.md      Decisão: painel web estático, sem bundler/CDN
  analise-inicial.md         Análise de 2026-11-13 (forças, bugs, riscos, ideias)
  comandos.md                Todos os comandos úteis
  GLOSSARY.md                Termos do domínio
  lineage.md                 Schema do SQLite e migrations
  pendencias.md              Itens abertos
  tree_files.md              Este arquivo
src/envvault/
  __init__.py                Versão do pacote
  app.py                     Fábrica FastAPI, guarda de Host, handlers de erro, estáticos
  cli.py                     CLI Typer `envvault` (todos os comandos)
  config.py                  Settings a partir de ENVVAULT_* (caminhos, porta, KDF)
  crypto.py                  Argon2id, embrulho da DEK, AES-256-GCM com AAD
  daemon.py                  Sobe o uvicorn do daemon
  db.py                      Engine SQLite (WAL, FK, busy_timeout) e permissões 0600
  migrate.py                 Upgrade Alembic programático
  models.py                  Modelos SQLAlchemy
  passwords.py               Gerador de senhas (CSPRNG)
  runtime.py                 Estado em memória: DEK, sessões, throttle de login, execuções
  schemas.py                 Modelos Pydantic de entrada/saída
  tokenstore.py              Arquivos de token por projeto (0600, recusa symlink)
  api/
    auth.py                  Health, sessão, login/unlock, logout, lock, troca de passphrase
    credentials.py           CRUD de credenciais e reveal auditado
    deps.py                  Dependências: banco, sessão + CSRF + Origin, token de agente
    exec.py                  Execução pela sessão e pelo agente (SSE), contexto e chaves do agente
    projects.py              CRUD de projetos e ambientes
    secrets.py               CRUD de segredos, import/export, reveal
    serializers.py           Conversão modelo → resposta
    system.py                Visão geral, auditoria e verificação, configurações, gerador de senha
    tokens.py                Criar, listar e revogar tokens
  services/
    audit.py                 Cadeia de hash append-only
    credentials.py           Credenciais cifradas (globais ou por projeto)
    envfile.py               Parser/gerador de .env
    projects.py              Projetos e ambientes
    redact.py                Redação da saída (valor, URL-encoded, base64)
    runner.py                Inicia o filho, injeta env, redige a saída, mata o grupo
    secrets.py               Segredos cifrados, reveal, import/export, valores para exec
    tokens.py                Tokens e autorização por escopo/comando
    vault.py                 init/unlock/lock, troca de passphrase, bloqueio por inatividade
  migrations/                Alembic (env.py, versions/0001..0003)
  web/                       Painel: index.html, app.js, app.css
tests/                       pytest (conftest com KDF rápido); um arquivo por área
```
