# Open items

Scheduled work lives in [`action-plan.md`](action-plan.md) (order and status).
This file keeps every finding; details in [`analise-inicial.md`](analise-inicial.md).
When done: tick `[x]`, write `DONE` and the commit.

- [x] **S6** `~/.envvault/daemon.log` is `0664` (group/other readable). Plan item 2. Fixed in PR #4.

## Bugs (teste de regressão primeiro)
- [x] **B1** `cwd` relativo resolvido contra a pasta do daemon (`src/envvault/services/runner.py:39`). Resolver relativo à pasta do projeto; a CLI deve mandar o `cwd` atual quando ele estiver dentro do projeto (`src/envvault/cli.py:788`). Fixed in PR #5.
- [x] **B2** Filtro de comandos por prefixo de texto (`src/envvault/services/tokens.py:150`). Comparar elemento a elemento do argv. Fixed in PR #6.
- [x] **B3** Processo órfão quando estoura o limite de execuções: `Popen` antes de `add_exec` (`src/envvault/services/runner.py:129`/`152`). Reservar a vaga antes de iniciar e mapear o erro para 429. Fixed in PR #2.
- [ ] **B4** Confirmar a limpeza quando o cliente desconecta antes do primeiro evento SSE (`src/envvault/services/runner.py:156`).

## Segurança
- [x] **S1** Documentar no README que o mesmo usuário lê `/proc/<pid>/environ` dos filhos e os arquivos de token. Avaliar daemon com usuário próprio e `hidepid`. Documented in PR #10 (verified on Ubuntu with `ptrace_scope=1`).
- [x] **S2** Token sem `allowed_commands` aceita tudo. Decided: explicit list or `--any-command` (ADR 0003). Done in PR #7.
- [x] **S3** Auditoria com HMAC derivado da DEK e cabeça da cadeia em `meta` (`src/envvault/services/audit.py`). Done in PR #11.
- [x] **S4** Tempo máximo absoluto de desbloqueio, mesmo com agente ativo (`src/envvault/services/vault.py:178`). Done in PR #8.
- [x] **S5** `envvault backup` + passo a passo de restauração. Done in PR #9.

## Qualidade
- [ ] **Q1** Cobertura 73% → 90% com piso no CI (`cli.py` 20%, `daemon.py` 0%).
- [ ] **Q2** Typecheck (`mypy --strict` ou `pyright`) no CI; remover `# type: ignore` de `src/envvault/app.py:70`.
- [ ] **Q3** Dividir `src/envvault/cli.py` e `src/envvault/web/app.js`.
- [ ] **Q4** Tornar pública `_terminate_process_group` e importar no topo de `runner.py`.
- [ ] **Q5** Decided: everything in English (ADR 0005); fix AGENTS.md in the translation PR.
- [ ] **Q6** Trocar `httpx` por `httpx2` nos testes (aviso do Starlette).
- [x] **Q7** `LICENSE` file (MIT). DONE.
- [ ] **Q8** Smoke test de UI dentro do repo ou tirar a menção do `AGENTS.md`.

## Processo
- [x] Public GitHub repo `raul-gomes/vault`, `main` + `develop` pushed. DONE (2026-11-13).
- [ ] Proteção de branch em `main`/`develop` (free on public repos).
- [x] CI green on the first PR (public repo: Actions free). DONE (PR #1).
