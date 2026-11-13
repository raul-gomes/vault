# Pendências

Itens abertos. Detalhe e motivo de cada código em [`analise-inicial.md`](analise-inicial.md).
Ao resolver: marque `[x]`, escreva `FEITA` e o commit.

## Bugs (teste de regressão primeiro)
- [ ] **B1** `cwd` relativo resolvido contra a pasta do daemon (`src/envvault/services/runner.py:39`). Resolver relativo à pasta do projeto; a CLI deve mandar o `cwd` atual quando ele estiver dentro do projeto (`src/envvault/cli.py:788`).
- [ ] **B2** Filtro de comandos por prefixo de texto (`src/envvault/services/tokens.py:150`). Comparar elemento a elemento do argv.
- [ ] **B3** Processo órfão quando estoura o limite de execuções: `Popen` antes de `add_exec` (`src/envvault/services/runner.py:129`/`152`). Reservar a vaga antes de iniciar e mapear o erro para 429.
- [ ] **B4** Confirmar a limpeza quando o cliente desconecta antes do primeiro evento SSE (`src/envvault/services/runner.py:156`).

## Segurança
- [ ] **S1** Documentar no README que o mesmo usuário lê `/proc/<pid>/environ` dos filhos e os arquivos de token. Avaliar daemon com usuário próprio e `hidepid`.
- [ ] **S2** Token sem `allowed_commands` aceita tudo. Exigir lista explícita ou aviso forte (decisão do Raul).
- [ ] **S3** Auditoria com HMAC derivado da DEK e cabeça da cadeia em `meta` (`src/envvault/services/audit.py`).
- [ ] **S4** Tempo máximo absoluto de desbloqueio, mesmo com agente ativo (`src/envvault/services/vault.py:178`).
- [ ] **S5** `envvault backup` + passo a passo de restauração.

## Qualidade
- [ ] **Q1** Cobertura 73% → 90% com piso no CI (`cli.py` 20%, `daemon.py` 0%).
- [ ] **Q2** Typecheck (`mypy --strict` ou `pyright`) no CI; remover `# type: ignore` de `src/envvault/app.py:70`.
- [ ] **Q3** Dividir `src/envvault/cli.py` e `src/envvault/web/app.js`.
- [ ] **Q4** Tornar pública `_terminate_process_group` e importar no topo de `runner.py`.
- [ ] **Q5** Idioma das mensagens `detail` da API (AGENTS diz pt-BR; código está em inglês).
- [ ] **Q6** Trocar `httpx` por `httpx2` nos testes (aviso do Starlette).
- [ ] **Q7** Arquivo `LICENSE` (MIT declarado no `pyproject.toml`).
- [ ] **Q8** Smoke test de UI dentro do repo ou tirar a menção do `AGENTS.md`.

## Processo
- [ ] Repositório privado no GitHub (`raul-gomes/vault`) e push de `main`/`develop` (aguardando permissão do Raul).
- [ ] Proteção de branch em `main`/`develop` (em repo privado exige plano pago do GitHub).
- [ ] CI verde no primeiro PR (a conta GitHub está com problema de cobrança; os jobs não iniciam).
