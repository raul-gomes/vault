# Análise inicial do EnvVault (2026-11-13)

Leitura do código em `5d16a07` (9 commits, todos de 2026-11-09). Os itens
acionáveis estão em [`pendencias.md`](pendencias.md), com o mesmo código (B1, S1…).

## Resumo

A base é boa para um projeto de 4 dias. A criptografia está certa, a separação
entre sessão humana e token de agente é clara, e o README é honesto sobre o
modelo de ameaça. Os riscos que valem atenção primeiro são quatro: dois bugs na
execução de comandos (B1 e B3), o filtro de comandos por prefixo de texto (B2) e
o limite real de proteção quando o agente roda com o mesmo usuário do sistema (S1).

## Estado medido

| Item | Valor |
| --- | --- |
| Código | ~10,3 mil linhas (Python ~6,7 mil, web ~2,8 mil) |
| Testes | 86 passando (`uv run pytest`, 5 s) |
| Cobertura | 73% no total; `cli.py` 20%, `daemon.py` 0%, `db.py` 71% |
| Lint e formatação | `ruff check` e `ruff format --check` limpos |
| Typecheck | não configurado |
| CI | não havia (adicionado nesta mudança) |
| Remoto Git | não havia; branch única `master` (agora `main` + `develop`) |
| Segredos no histórico | nenhum encontrado (varredura por padrões de chave/token; só a fixture `cf-token` dos testes) |

## Pontos fortes

- **Envelope de chaves correto.** Argon2id (3 iterações, 64 MiB) deriva a KEK, que
  embrulha uma DEK aleatória. Cada segredo usa AES-256-GCM com AAD
  `projeto/ambiente/chave/versão`, então um ciphertext não pode ser trocado de
  lugar nem voltar para uma versão antiga. Trocar a passphrase só re-embrulha a DEK.
- **Dois planos de autenticação separados.** Sessão do navegador (cookie
  `HttpOnly` + `SameSite=Strict` + CSRF + checagem de `Origin` e `Host` contra DNS
  rebinding) e token de agente (`Bearer`, só o hash SHA-256 no banco). O agente
  não tem rota que devolva valor.
- **Execução sem shell.** O comando é uma lista de argv. O filho roda em nova
  sessão e o grupo inteiro é encerrado no timeout, no bloqueio e no cancelamento.
  `ENVVAULT_*` não vaza para o filho.
- **Redação com codificações comuns.** Valor puro, URL-encoded e base64, com
  buffer que evita cortar um segredo ao meio entre dois pedaços de saída.
- **Auditoria encadeada por hash**, gravada na mesma transação da mutação.
- **Arquivos com permissão de dono** (`0700` na pasta, `0600` no banco e nos tokens).
  Arquivo de token com permissão aberta ou symlink é recusado.
- **Documentação acima da média:** README com setup, cheatsheet, segurança e
  solução de problemas, além de `AGENTS.md` com as invariantes.

## Bugs (lidos no código, sem teste de regressão ainda)

**B1. `cwd` relativo é resolvido contra a pasta do daemon, não do projeto.**
`services/runner.py:39` faz `Path(requested).expanduser().resolve()`. Isso usa o
diretório em que o daemon foi iniciado. O próprio `/v1/agent/context` sugere
`"cwd": "frontend"`, que não aponta para `<projeto>/frontend`. A CLI manda o
`--cwd` como foi digitado (`cli.py:788`). Sem `--cwd`, o comando roda sempre na
raiz do projeto, mesmo chamado de uma subpasta (`envvault run` dentro de `admin/`
roda na raiz).

**B2. Filtro de comandos compara texto, não argv.** `services/tokens.py:150`
testa `" ".join(command).startswith(prefix)`. Com o prefixo `bun`, passa
`bunx qualquer-coisa`. Com `npm run`, passa `npm run-script`. Deveria comparar
os primeiros elementos do argv, um por um.

**B3. Processo órfão quando bate o limite de execuções.** `runner.spawn` chama
`Popen` (linha 129) **antes** de `state.add_exec` (linha 152). Se o limite de 8
execuções estoura, `add_exec` lança `RuntimeError`. O processo já está rodando com
os segredos, fica sem registro (não morre no lock nem no timeout) e a API devolve
500 (não há handler para `RuntimeError`). A auditoria já gravou `exec.start`.

**B4 (a confirmar). Cliente que desconecta antes do primeiro byte.** A limpeza
(remover o registro, matar o grupo, auditar o fim) fica no `finally` do gerador
do SSE. Se o gerador nunca começar a ser consumido, ela não roda.

## Segurança (decisões de desenho)

**S1. O agente roda com o mesmo usuário do sistema.** Esse é o limite real do
projeto. O README já diz que não protege contra "processo local do mesmo usuário
lendo a memória do daemon", mas há dois caminhos mais simples que não estão
escritos:
- um agente com shell lê `/proc/<pid>/environ` de qualquer filho que o daemon
  iniciou (o filho pertence ao mesmo usuário);
- os tokens de **todos** os projetos ficam em `~/.envvault/agent-tokens/`, legíveis
  pelo mesmo usuário.

A redação protege contra vazamento acidental (log, build, conversa), não contra
um agente que queira o valor. Opções: documentar isso no README, rodar o daemon e
os filhos com outro usuário do sistema (fronteira real, mas o setup fica bem mais
complexo) e montar `/proc` com `hidepid`.

**S2. Token sem `allowed_commands` aceita qualquer comando.** O padrão é o mais
aberto (`python3 -c "print(os.environ)"` passa; a redação pega o valor puro, mas
não `rev` ou `base32`). Pela regra geral "fallback padrão = o mais seguro", o
padrão deveria ser uma lista explícita, ou pelo menos um aviso forte na criação.

**S3. Cadeia de auditoria sem chave.** O hash é SHA-256 puro. Quem tem escrita no
banco (o mesmo usuário) pode reescrever a cadeia inteira e recalcular os hashes,
e apagar as últimas linhas não quebra a verificação. Melhoria: HMAC com chave
derivada da DEK (reescrever exige a passphrase) e guardar o hash e a contagem da
cabeça em `meta`.

**S4. Agente ativo impede o bloqueio por inatividade.** Toda chamada de agente
renova o relógio (`vault.enforce_idle`). Com um agente rodando comandos, o cofre
nunca bloqueia sozinho. Considerar um tempo máximo absoluto de desbloqueio
(ex.: 12 h) que exija a passphrase de novo.

**S5. Sem backup nem recuperação.** Perder a passphrase ou o disco perde tudo.
Faltam um `envvault backup` (cópia consistente do `vault.db` cifrado pela API de
backup do SQLite) e o passo a passo de restauração.

## Qualidade e manutenção

- **Q1.** Cobertura de 73%, sem piso. `cli.py` (1.348 linhas) tem 20%. Meta: 90%
  com piso no CI, igual aos outros projetos.
- **Q2.** Sem typecheck. Adicionar `mypy --strict` ou `pyright`; há um
  `# type: ignore` sem motivo em `app.py:70`.
- **Q3.** `cli.py` (1.348 linhas) e `web/app.js` (1.972 linhas) concentram tudo.
  Dividir por grupo de comando e por tela antes de crescerem mais.
- **Q4.** `runner.py` importa `_terminate_process_group` (privada) de `runtime`
  dentro de função, em dois lugares. Tornar pública e importar no topo.
- **Q5.** O `AGENTS.md` diz que as mensagens `detail` da API são em pt-BR, mas
  quase todas estão em inglês (`"vault is locked"`, `"invalid token"`). Decidir
  qual vale e alinhar.
- **Q6.** Aviso de depreciação nos testes: o `TestClient` do Starlette pede
  `httpx2` no lugar de `httpx`.
- **Q7.** `pyproject.toml` e README dizem MIT, mas não há arquivo `LICENSE`.
- **Q8.** O smoke test de UI citado no `AGENTS.md` mora fora do repo
  (`/tmp/opencode/...`). Trazer para `tests/e2e/` (fora do run padrão) ou remover a menção.

## Ideias de produto (para você decidir)

- `envvault doctor`: confere daemon, permissões, tokens com permissão aberta,
  projetos com pasta inexistente e cadeia de auditoria, tudo de uma vez.
- Importar de uma vez os `.env` existentes em `~/HD_Repos/*` (o `app_amarelhinhas`
  ainda não tem token no cofre).
- Lembrete de rotação: mostrar a idade de cada segredo e destacar os antigos.
- Tokens com validade (`expires_at`), para não esquecer tokens antigos ativos.
